package org.securemail.client.lifecycle;

import java.io.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

/** Client-only, account-signed lifecycle events inside the existing E2EE packet format.
 * The relay is opaque transport. State and retry queues are encrypted and forced before ACK.
 * A peer must advertise signed capabilities before receiving internal events. */
public final class LifecycleService implements AutoCloseable {
  private static final int STATE_MAX=8*1024*1024,MAX_MESSAGES=4096,MAX_EVENTS=8192,MAX_QUEUE=256;
  private static final long DELIVERY=7L*86400_000,RETRY=60_000;
  private final LocalStore local;private final LocalFeatures features;private final int maxCipher;
  private final AutomaticEncryption crypto;
  private Identity device;private NetworkService network;private boolean readReceipts=true,closed,friendshipChanged;
  private final Map<String,Peer> peers=new LinkedHashMap<>();
  private final Map<String,Tracked> messages=new LinkedHashMap<>();
  private final Map<String,byte[]> processed=new LinkedHashMap<>();
  private final Map<String,Queued> queue=new LinkedHashMap<>();
  private static final class Peer {UserInfo user;DeviceCapabilities caps;ContactAssertion ours,theirs;long lastConsent;Peer(UserInfo user){this.user=user;}}
  private static final class Tracked {
    String id;UserInfo peer;byte[] digest;boolean outgoing,relayAccepted,deliveryQueued,readQueued,pending;long created,deadline,ttl,delivered,displayed,nextAttempt;
  }
  private static final class Queued {LifecycleEvent event;UserInfo peer;EncryptedPacket packet;long nextAttempt;Queued(LifecycleEvent event,UserInfo peer){this.event=event;this.peer=peer;}}
  public LifecycleService(LocalStore local,LocalFeatures features,int maximum)throws IOException,GeneralSecurityException {
    this.local=local;this.features=features;maxCipher=maximum;
    crypto=new AutomaticEncryption(new Clock(){public java.time.ZoneId getZone(){return java.time.ZoneOffset.UTC;}public Clock withZone(java.time.ZoneId z){return this;}public java.time.Instant instant(){return java.time.Instant.ofEpochMilli(local.now());}});
    byte[] data=local.readExtension("state-v1",STATE_MAX);
    if(data==null){device=Identity.create();save();}else try{load(data);}finally{Arrays.fill(data,(byte)0);}
  }
  public synchronized void network(NetworkService value){network=value;}
  public synchronized boolean readReceipts(){return readReceipts;}
  public synchronized void readReceipts(boolean value)throws IOException,GeneralSecurityException{ensureOpen();readReceipts=value;save();}
  public DeviceCapabilities capabilities(byte[] challenge){try{return DeviceCapabilities.create(local.identity(),device,local.now()+30L*86400_000,DeviceCapabilities.FRIENDS|DeviceCapabilities.RECEIPTS,challenge);}catch(Exception failure){throw new IllegalStateException("Capability signing failed",failure);}}
  public synchronized boolean capable(String id,int flag){Peer peer=peers.get(id);return peer!=null&&peer.caps!=null&&peer.caps.expiresAt()>local.now()&&peer.caps.supports(flag);}
  public synchronized boolean takeFriendshipChanged(){boolean changed=friendshipChanged;friendshipChanged=false;return changed;}
  public synchronized String friendshipStatus(String id){if(features.friend(id))return "Друзья";return capable(id,DeviceCapabilities.FRIENDS)?"Ожидается подтверждение":"Ожидается совместимый клиент";}
  /** Takes only root-verified capabilities; useful for a bounded signed onion probe. */
  public synchronized void learn(UserInfo user,DeviceCapabilities caps)throws IOException,GeneralSecurityException {
    ensureOpen();caps.verify(user,null,local.now());Peer peer=peers.get(user.userId());
    if(peer==null){if(peers.size()>=128)throw new IOException("Peer quota");peer=new Peer(new UserInfo(user.userId(),user.nickname(),user.publicKey(),null));peers.put(user.userId(),peer);}
    if(!MessageDigest.isEqual(peer.user.publicKey(),user.publicKey()))throw new GeneralSecurityException("Peer key conflict");peer.caps=caps;save();
  }
  /** A malformed authenticated control packet is quarantined/deleted locally, never a queue blocker. */
  public synchronized Receipt accept(EncryptedPacket packet)throws IOException,GeneralSecurityException {
    ensureOpen();if(!AutomaticEncryption.supports(packet))return local.accept(packet);
    LifecycleEvent event=null;boolean malformed=false;
    try(var plain=crypto.decrypt(packet,local.identity(),maxCipher)) {event=LifecycleEvent.fromText(plain.text().getBytes(java.nio.charset.StandardCharsets.UTF_8));if(event!=null)validatePayload(event);}
    catch(Exception invalid){malformed=true;}
    Receipt ack=local.accept(packet,event==null&&!malformed);
    if(malformed){local.delete(packet.messageId());return ack;}
    if(event!=null){
      try{receive(event,packet);}catch(GeneralSecurityException|IllegalArgumentException invalid){/* No trusted event is produced. Its durable packet ACK frees the relay queue. */}
      local.delete(packet.messageId());return ack;
    }
    if(!messages.containsKey(packet.messageId())){
      if(messages.size()>=MAX_MESSAGES)prune();if(messages.size()>=MAX_MESSAGES)throw new IOException("Lifecycle message quota");
      Tracked tracked=track(packet,new UserInfo(packet.senderId(),packet.senderNickname(),packet.senderPublicKey(),null),false);tracked.delivered=ack.deliveredAt();messages.put(tracked.id,tracked);save();
    }
    queueReceipts(messages.get(packet.messageId()));return ack;
  }
  private static void validatePayload(LifecycleEvent e)throws IOException {
    try(var i=new DataInputStream(new ByteArrayInputStream(e.payload()))){
      if(e.kind()==LifecycleEvent.CONSENT)ContactAssertion.read(i);
      else if(e.kind()==LifecycleEvent.ACK)Limits.messageId(Binary.text(i,36));
      else {Limits.messageId(Binary.text(i,36));if(Binary.bytes(i,32).length!=32||i.readLong()<1)throw new IOException("Receipt fields");}Binary.end(i);
    }catch(IllegalArgumentException bad){throw new IOException("Event payload",bad);}
  }
  private Tracked track(EncryptedPacket p,UserInfo peer,boolean outgoing)throws IOException,GeneralSecurityException {
    Tracked t=new Tracked();t.id=p.messageId();t.peer=new UserInfo(peer.userId(),peer.nickname(),peer.publicKey(),null);t.digest=Identity.digest(p);t.outgoing=outgoing;t.created=p.createdAt();t.deadline=p.deliveryDeadline();t.ttl=p.ttlAfterDelivery();return t;
  }
  /** Persist encrypted outgoing mail before the first network attempt. Never accepts plaintext. */
  public NetworkService.DeliveryResult send(EncryptedPacket packet,UserInfo recipient)throws Exception {
    Tracked tracked;NetworkService transport;
    synchronized(this){
      ensureOpen();transport=network;if(transport==null||!transport.loggedIn())throw new IOException("Нет соединения с сервером");
      if(!packet.recipientId().equals(recipient.userId())||!Identity.verifyPacket(packet)||!packet.senderId().equals(local.identity().userId()))throw new GeneralSecurityException("Outgoing identity mismatch");
      if(messages.size()>=MAX_MESSAGES)prune();if(messages.size()>=MAX_MESSAGES)throw new IOException("Lifecycle message quota");
      tracked=track(packet,recipient,true);tracked.pending=true;
      byte[] data=PacketCodec.encode(packet);try{local.writeExtension("out-"+packet.messageId(),data,maxCipher+8192);}finally{Arrays.fill(data,(byte)0);}
      messages.put(tracked.id,tracked);save();local.saveSent(packet,recipient.nickname(),0);
    }
    try {var result=transport.deliverDetailed(packet);synchronized(this){ensureOpen();confirmSent(tracked,result);}return result;}
    catch(IOException failure){synchronized(this){if(!closed){tracked.nextAttempt=local.now()+RETRY;save();}}throw failure;}
  }
  private void confirmSent(Tracked tracked,NetworkService.DeliveryResult result)throws IOException,GeneralSecurityException {
    tracked.pending=false;tracked.relayAccepted=result.delivery()==NetworkService.Delivery.RELAY_QUEUED;if(result.delivery()==NetworkService.Delivery.P2P_CONFIRMED)tracked.delivered=result.confirmedAt();save();local.deleteExtension("out-"+tracked.id);
  }
  public synchronized String status(String id,String legacy){Tracked t=messages.get(id);if(t==null||!t.outgoing)return legacy;return t.displayed>0?"Прочитано":t.delivered>0?"Доставлено на устройство":t.relayAccepted?"Принято Relay":t.pending?"Отправлено · ожидает сети":"Отправлено";}
  /** Called after content was displayed, never by list rendering or password entry. */
  public synchronized void displayed(String id)throws IOException,GeneralSecurityException {
    ensureOpen();Tracked t=messages.get(id);if(t==null||t.outgoing||t.displayed>0||features.blocked(id,t.peer.userId())||!readReceipts)return;
    t.displayed=local.now();save();queueReceipts(t);
  }
  private void queueReceipts(Tracked t)throws IOException,GeneralSecurityException {
    if(t==null||t.outgoing||features.blocked(t.id,t.peer.userId())||!capable(t.peer.userId(),DeviceCapabilities.RECEIPTS))return;
    if(t.delivered>0&&!t.deliveryQueued){enqueue(t.peer,LifecycleEvent.DELIVERED,receiptPayload(t,t.delivered));t.deliveryQueued=true;save();}
    if(t.displayed>0&&!t.readQueued){enqueue(t.peer,LifecycleEvent.DISPLAYED,receiptPayload(t,t.displayed));t.readQueued=true;save();}
  }
  private static byte[] receiptPayload(Tracked t,long when)throws IOException{return Binary.encode(o->{Binary.text(o,t.id);Binary.bytes(o,t.digest);o.writeLong(when);});}
  private void enqueue(UserInfo target,int kind,byte[] payload)throws IOException,GeneralSecurityException {
    if(queue.size()>=MAX_QUEUE)throw new IOException("Lifecycle retry queue full");var event=LifecycleEvent.create(local.identity(),target.userId(),local.now(),kind,payload,capabilities(Secrets.random(32)));
    queue.put(event.id(),new Queued(event,target));save();
  }
  private void receive(LifecycleEvent event,EncryptedPacket packet)throws IOException,GeneralSecurityException {
    event.verify(packet,local.now());byte[] digest=event.semanticDigest(),previous=processed.get(event.id());
    if(previous!=null&&!MessageDigest.isEqual(previous,digest))throw new GeneralSecurityException("Event ID conflict");
    UserInfo sender=new UserInfo(packet.senderId(),packet.senderNickname(),packet.senderPublicKey(),null);
    if(event.kind()==LifecycleEvent.ACK){try(var in=new DataInputStream(new ByteArrayInputStream(event.payload()))){String id=Binary.text(in,36);Binary.end(in);Queued outstanding=queue.get(id);if(outstanding!=null&&outstanding.peer.userId().equals(sender.userId())){queue.remove(id);save();}}return;}
    if(event.capabilities().expiresAt()>local.now())learn(sender,event.capabilities());
    if(previous==null){
      if(processed.size()>=MAX_EVENTS)throw new IOException("Lifecycle replay quota");
      if(event.kind()==LifecycleEvent.CONSENT){
        try(var in=new DataInputStream(new ByteArrayInputStream(event.payload()))){var assertion=ContactAssertion.read(in);Binary.end(in);
          if(!assertion.ownerId().equals(sender.userId())||!assertion.targetId().equals(local.identity().userId())||!MessageDigest.isEqual(assertion.publicKey(),sender.publicKey())||!Identity.verify(sender.publicKey(),assertion.signingBytes(),assertion.signature()))throw new GeneralSecurityException("Consent origin");
          Peer peer=peers.get(sender.userId());if(peer==null)throw new GeneralSecurityException("Missing capability");
          if(peer.theirs!=null&&(assertion.revision()<peer.theirs.revision()||assertion.revision()==peer.theirs.revision()&&!MessageDigest.isEqual(assertion.signingBytes(),peer.theirs.signingBytes())))throw new GeneralSecurityException("Consent rollback");
          peer.theirs=assertion;applyFriendship(peer);
        }
      }else {
        try(var in=new DataInputStream(new ByteArrayInputStream(event.payload()))){String id=Binary.text(in,36);byte[] packetDigest=Binary.bytes(in,32);long when=in.readLong();Binary.end(in);Tracked t=messages.get(id);
          if(t==null||!t.outgoing||!t.peer.userId().equals(sender.userId())||packetDigest.length!=32||!MessageDigest.isEqual(packetDigest,t.digest)||when<t.created-300_000||when>local.now()+300_000)throw new GeneralSecurityException("Receipt binding");
          if(event.kind()==LifecycleEvent.DELIVERED){if(t.delivered==0||when<t.delivered)t.delivered=when;}
          else {if(t.delivered>0&&when<t.delivered-300_000)throw new GeneralSecurityException("Read precedes delivery");if(t.displayed==0||when<t.displayed)t.displayed=when;if(t.delivered==0)t.delivered=when;}
        }
      }
      processed.put(event.id(),digest);save();
    }
    // Durable application ACK, distinct from relay deletion ACK. Retries never invent status.
    if(queue.values().stream().noneMatch(q->q.event.kind()==LifecycleEvent.ACK&&q.peer.userId().equals(sender.userId())&&ackId(q.event).equals(event.id())))enqueue(sender,LifecycleEvent.ACK,Binary.encode(o->Binary.text(o,event.id())));
  }
  private static String ackId(LifecycleEvent e){try(var i=new DataInputStream(new ByteArrayInputStream(e.payload()))){return Binary.text(i,36);}catch(IOException bad){return "";}}
  private void applyFriendship(Peer peer)throws IOException,GeneralSecurityException {
    UserInfo contact=local.contact(peer.user.nickname());if(contact!=null&&contact.userId().equals(peer.user.userId())&&features.friendship(contact,peer.ours,peer.theirs))friendshipChanged=true;
  }
  public void sync(UserInfo selected)throws Exception {
    NetworkService transport;synchronized(this){ensureOpen();transport=network;}if(transport==null||!transport.loggedIn())return;
    List<UserInfo> contacts=local.contacts();if(selected==null&&!contacts.isEmpty())selected=contacts.get(Math.floorMod((int)(local.now()/15_000),contacts.size()));
    if(selected==null){synchronized(this){for(Tracked t:messages.values())if(!t.outgoing&&!capable(t.peer.userId(),DeviceCapabilities.RECEIPTS)){selected=t.peer;break;}}}
    if(selected!=null){try{DeviceCapabilities caps=transport.probe(selected);if(caps!=null)learn(selected,caps);}catch(IOException unavailable){/* No signed new endpoint: ordinary protocol-1 mail remains usable. */}}
    synchronized(this){
      ensureOpen();prune();
      for(var contact:contacts){Peer peer=peers.get(contact.userId());if(peer!=null&&capable(contact.userId(),DeviceCapabilities.FRIENDS))syncConsent(peer,true);}
      for(Peer peer:peers.values())if(contacts.stream().noneMatch(c->c.userId().equals(peer.user.userId()))||features.blockedSender(peer.user.userId()))if(capable(peer.user.userId(),DeviceCapabilities.FRIENDS))syncConsent(peer,false);
      for(Tracked t:messages.values())if(!t.outgoing)queueReceipts(t);
    }
    retry();
  }
  private void syncConsent(Peer peer,boolean contactExists)throws IOException,GeneralSecurityException {
    boolean active=contactExists&&features.consent(peer.user.userId())&&!features.blockedSender(peer.user.userId());
    if(peer.ours==null||peer.ours.active()!=active){long floor=Math.max(peer.ours==null?0:peer.ours.revision(),features.friendRevision(peer.user.userId(),true));peer.ours=local.identity().consent(peer.user.userId(),Math.max(local.now(),floor+1),active);peer.lastConsent=0;save();}
    if(peer.lastConsent==0||local.now()-peer.lastConsent>=86400_000){enqueue(peer.user,LifecycleEvent.CONSENT,Binary.encode(peer.ours::write));peer.lastConsent=local.now();save();}
    applyFriendship(peer);
  }
  public void retry()throws Exception {
    NetworkService transport;List<Tracked> pending;List<Queued> events;
    synchronized(this){ensureOpen();transport=network;if(transport==null||!transport.loggedIn())return;long now=local.now();pending=messages.values().stream().filter(t->t.outgoing&&t.pending&&t.nextAttempt<=now).limit(4).toList();events=queue.values().stream().filter(q->q.nextAttempt<=now).limit(4).toList();}
    for(Tracked t:pending){
      EncryptedPacket packet;
      synchronized(this){ensureOpen();if(!t.pending)continue;byte[] bytes=local.readExtension("out-"+t.id,maxCipher+8192);if(bytes==null)throw new IOException("Pending ciphertext missing");try{packet=PacketCodec.decode(bytes,maxCipher);}finally{Arrays.fill(bytes,(byte)0);}if(packet.deliveryDeadline()<=local.now()){t.pending=false;save();local.deleteExtension("out-"+t.id);continue;}t.nextAttempt=local.now()+RETRY;save();}
      try{var result=transport.deliverDetailed(packet);synchronized(this){if(!closed&&t.pending)confirmSent(t,result);}}catch(IOException unavailable){/* Durable encrypted retry is retained. */}
    }
    for(Queued q:events){
      EncryptedPacket packet;
      synchronized(this){ensureOpen();if(!queue.containsKey(q.event.id()))continue;
        if(q.packet==null||q.packet.deliveryDeadline()<=local.now()){
          try(var plain=new PlainMessage(q.event.text(),"",new byte[0])){q.packet=crypto.encrypt(plain,7*86400,DELIVERY,local.identity(),local.nickname(),q.peer);}save();
        }
        packet=q.packet;q.nextAttempt=local.now()+RETRY;save();
      }
      try{transport.deliverControl(packet,q.peer);synchronized(this){if(!closed&&queue.containsKey(q.event.id())){if(q.event.kind()==LifecycleEvent.ACK)queue.remove(q.event.id());else q.nextAttempt=local.now()+15*60_000;save();}}}catch(IOException unavailable){/* Lost ACK reuses ID and ciphertext, never direct TCP. */}
    }
  }
  public synchronized void cleanup()throws IOException,GeneralSecurityException {if(!closed){prune();}}
  private void prune()throws IOException,GeneralSecurityException {
    boolean changed=false;for(var it=messages.entrySet().iterator();it.hasNext();){var entry=it.next();Tracked t=entry.getValue();if(local.now()>t.deadline+t.ttl*1000+300_000){local.deleteExtension("out-"+t.id);it.remove();changed=true;}}
    if(changed)save();
  }
  private void save()throws IOException,GeneralSecurityException {
    byte[] data=Binary.encode(o->{o.writeInt(1);Binary.bytes(o,device.publicKey());byte[] privateKey=device.privateKey();try{Binary.bytes(o,privateKey);}finally{Arrays.fill(privateKey,(byte)0);}o.writeBoolean(readReceipts);
      o.writeInt(peers.size());for(Peer p:peers.values()){p.user.write(o);o.writeBoolean(p.caps!=null);if(p.caps!=null)p.caps.write(o);o.writeBoolean(p.ours!=null);if(p.ours!=null)p.ours.write(o);o.writeBoolean(p.theirs!=null);if(p.theirs!=null)p.theirs.write(o);o.writeLong(p.lastConsent);}
      o.writeInt(messages.size());for(Tracked t:messages.values()){Binary.text(o,t.id);t.peer.write(o);Binary.bytes(o,t.digest);o.writeBoolean(t.outgoing);o.writeBoolean(t.relayAccepted);o.writeBoolean(t.deliveryQueued);o.writeBoolean(t.readQueued);o.writeBoolean(t.pending);o.writeLong(t.created);o.writeLong(t.deadline);o.writeLong(t.ttl);o.writeLong(t.delivered);o.writeLong(t.displayed);o.writeLong(t.nextAttempt);}
      o.writeInt(processed.size());for(var p:processed.entrySet()){Binary.text(o,p.getKey());Binary.bytes(o,p.getValue());}
      o.writeInt(queue.size());for(Queued q:queue.values()){Binary.bytes(o,q.event.encode());q.peer.write(o);o.writeBoolean(q.packet!=null);if(q.packet!=null)PacketCodec.write(o,q.packet);o.writeLong(q.nextAttempt);}
    });try{local.writeExtension("state-v1",data,STATE_MAX);}finally{Arrays.fill(data,(byte)0);}
  }
  private static int count(DataInput i,int max)throws IOException{int n=i.readInt();if(n<0||n>max)throw new IOException("Lifecycle state quota");return n;}
  private void load(byte[] bytes)throws IOException,GeneralSecurityException {
    try(var i=new DataInputStream(new ByteArrayInputStream(bytes))){if(i.readInt()!=1)throw new IOException("Lifecycle state schema");byte[] publicKey=Binary.bytes(i,44),privateKey=Binary.bytes(i,128);try{device=Identity.restore(publicKey,privateKey);}finally{Arrays.fill(privateKey,(byte)0);}readReceipts=i.readBoolean();
      for(int n=count(i,128);n>0;n--){var p=new Peer(UserInfo.read(i));if(i.readBoolean())p.caps=DeviceCapabilities.read(i);if(i.readBoolean())p.ours=ContactAssertion.read(i);if(i.readBoolean())p.theirs=ContactAssertion.read(i);p.lastConsent=i.readLong();if(peers.put(p.user.userId(),p)!=null)throw new IOException("Duplicate peer");}
      for(int n=count(i,MAX_MESSAGES);n>0;n--){var t=new Tracked();t.id=Binary.text(i,36);Limits.messageId(t.id);t.peer=UserInfo.read(i);t.digest=Binary.bytes(i,32);if(t.digest.length!=32)throw new IOException("Packet digest length");t.outgoing=i.readBoolean();t.relayAccepted=i.readBoolean();t.deliveryQueued=i.readBoolean();t.readQueued=i.readBoolean();t.pending=i.readBoolean();t.created=i.readLong();t.deadline=i.readLong();t.ttl=i.readLong();t.delivered=i.readLong();t.displayed=i.readLong();t.nextAttempt=i.readLong();if(t.created<1||t.deadline<t.created||t.ttl<1||t.ttl>7*86400||t.delivered<0||t.displayed<0||messages.put(t.id,t)!=null)throw new IOException("Invalid message state");}
      for(int n=count(i,MAX_EVENTS);n>0;n--){String id=Binary.text(i,36);Limits.messageId(id);byte[] digest=Binary.bytes(i,32);if(digest.length!=32||processed.put(id,digest)!=null)throw new IOException("Invalid replay state");}
      for(int n=count(i,MAX_QUEUE);n>0;n--){var event=LifecycleEvent.decode(Binary.bytes(i,8192));var q=new Queued(event,UserInfo.read(i));if(i.readBoolean())q.packet=PacketCodec.read(i,32_768);q.nextAttempt=i.readLong();if(!event.owner().equals(local.identity().userId())||!event.target().equals(q.peer.userId())||queue.put(event.id(),q)!=null)throw new IOException("Invalid outbox");}Binary.end(i);
    }catch(IllegalArgumentException bad){throw new IOException("Повреждено состояние доставки",bad);}
  }
  private void ensureOpen()throws IOException {if(closed)throw new IOException("Lifecycle closed");}
  @Override public synchronized void close(){closed=true;}
}
