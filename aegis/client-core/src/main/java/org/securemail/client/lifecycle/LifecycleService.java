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
  private static final class RetryQueueFull extends IOException {private static final long serialVersionUID=1L;RetryQueueFull(){super("Lifecycle retry queue full");}}
  private static final long DELIVERY=7L*86400_000,RETRY=60_000;
  private final LocalStore local;private final LocalFeatures features;private final int maxCipher;
  private final AutomaticEncryption crypto;
  private Identity device;private final ExpiryGuard guard;private NetworkService network;private boolean readReceipts=true,closed,friendshipChanged;
  private final Map<String,Peer> peers=new LinkedHashMap<>();
  private final Map<String,Tracked> messages=new LinkedHashMap<>();
  private final Map<String,byte[]> processed=new LinkedHashMap<>();
  private final Map<String,Queued> queue=new LinkedHashMap<>();
  private static final class Peer {UserInfo user;DeviceCapabilities caps;ContactAssertion ours,theirs;long lastConsent;Peer(UserInfo user){this.user=user;}}
  private static final class Tracked {
    String id;UserInfo peer;byte[] digest;boolean outgoing,relayAccepted,deliveryQueued,readQueued,pending;long created,deadline,ttl,delivered,displayed,nextAttempt;
  }
  private static final class Timed {String id,nickname;boolean outgoing,expired;long time,seconds,displayed;}
  private final Map<String,Timed> timed=new LinkedHashMap<>();
  private static final class Queued {LifecycleEvent event;UserInfo peer;EncryptedPacket packet;long nextAttempt;Queued(LifecycleEvent event,UserInfo peer){this.event=event;this.peer=peer;}}
  public LifecycleService(LocalStore local,LocalFeatures features,int maximum)throws IOException,GeneralSecurityException {
    this.local=local;this.features=features;maxCipher=maximum;
    crypto=new AutomaticEncryption(new Clock(){public java.time.ZoneId getZone(){return java.time.ZoneOffset.UTC;}public Clock withZone(java.time.ZoneId z){return this;}public java.time.Instant instant(){return java.time.Instant.ofEpochMilli(local.now());}});
    byte[] data=local.readExtension("state-v1",STATE_MAX);
    if(data==null){device=Identity.create();save();}else try{load(data);}finally{Arrays.fill(data,(byte)0);}
    guard=new ExpiryGuard(local,device.userId(),data==null);guard.recover();recoverCarriers();
  }
  private void recoverCarriers()throws IOException,GeneralSecurityException {
    for(var item:local.inbox())if(!messages.containsKey(item.messageId())){var packet=local.load(item.messageId());if(!AutomaticEncryption.supports(packet))continue;
      boolean internal=false;try(var plain=crypto.decrypt(packet,local.identity(),maxCipher)){internal=ExpiringEnvelope.isCarrier(plain)||plain.text().startsWith(LifecycleEvent.PREFIX);}catch(Exception bad){continue;}
      if(internal)try{accept(packet);}catch(IOException|GeneralSecurityException notDeliverable){/* Original durable ciphertext retained for repair. */}
    }
  }
  public synchronized void network(NetworkService value){network=value;}
  public synchronized boolean readReceipts(){return readReceipts;}
  public synchronized void readReceipts(boolean value)throws IOException,GeneralSecurityException{ensureOpen();readReceipts=value;save();}
  public DeviceCapabilities capabilities(byte[] challenge){try{return DeviceCapabilities.create(local.identity(),device,local.now()+30L*86400_000,DeviceCapabilities.FRIENDS|DeviceCapabilities.RECEIPTS|(guard.available()?DeviceCapabilities.EXPIRING:0),challenge);}catch(Exception failure){throw new IllegalStateException("Capability signing failed",failure);}}
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
    LifecycleEvent event=null;ExpiringEnvelope expiring=null;boolean malformed=false;
    try(var plain=crypto.decrypt(packet,local.identity(),maxCipher)) {event=LifecycleEvent.fromText(plain.text().getBytes(java.nio.charset.StandardCharsets.UTF_8));if(event!=null)validatePayload(event);else {expiring=ExpiringEnvelope.read(plain,maxCipher);if(expiring!=null)expiring.verify(packet);}}
    catch(Exception invalid){malformed=true;}
    Receipt ack=local.accept(packet,event==null&&!malformed);
    if(expiring!=null){rememberTimed(packet,expiring,false,ack.deliveredAt());local.delete(packet.messageId());}
    if(malformed){local.delete(packet.messageId());return ack;}
    if(event!=null){
      try{receive(event,packet);}catch(GeneralSecurityException|IllegalArgumentException invalid){/* No trusted event is produced. Its durable packet ACK frees the relay queue. */}
      local.delete(packet.messageId());return ack;
    }
    if(!messages.containsKey(packet.messageId())){
      if(messages.size()>=MAX_MESSAGES)prune();if(messages.size()>=MAX_MESSAGES)throw new IOException("Lifecycle message quota");
      Tracked tracked=track(packet,new UserInfo(packet.senderId(),packet.senderNickname(),packet.senderPublicKey(),null),false);tracked.delivered=ack.deliveredAt();messages.put(tracked.id,tracked);save();
    }
    try{queueReceipts(messages.get(packet.messageId()));}catch(RetryQueueFull defer){/* Durable delivery state retries when queue drains. */}return ack;
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
      try(var carrier=crypto.decrypt(packet,local.identity(),maxCipher)){var expiry=ExpiringEnvelope.read(carrier,maxCipher);if(expiry!=null){expiry.verify(packet);rememberTimed(packet,expiry,true,packet.createdAt());}}
      byte[] data=PacketCodec.encode(packet);try{local.writeExtension("out-"+packet.messageId(),data,maxCipher+8192);}finally{Arrays.fill(data,(byte)0);}
      messages.put(tracked.id,tracked);save();if(!timed.containsKey(packet.messageId()))local.saveSent(packet,recipient.nickname(),0);
    }
    try {var result=transport.deliverDetailed(packet);synchronized(this){ensureOpen();confirmSent(tracked,result);}return result;}
    catch(IOException failure){synchronized(this){if(!closed){tracked.nextAttempt=local.now()+RETRY;save();}}throw failure;}
  }
  private void confirmSent(Tracked tracked,NetworkService.DeliveryResult result)throws IOException,GeneralSecurityException {
    tracked.pending=false;tracked.relayAccepted=result.delivery()==NetworkService.Delivery.RELAY_QUEUED;if(result.delivery()==NetworkService.Delivery.P2P_CONFIRMED)tracked.delivered=result.confirmedAt();save();local.deleteExtension("out-"+tracked.id);
  }
  public synchronized String status(String id,String legacy){Tracked t=messages.get(id);if(t==null||!t.outgoing)return legacy;if(timed.containsKey(id)&&timed.get(id).expired)return "Письмо исчезло";return t.displayed>0?"Прочитано":t.delivered>0?"Доставлено на устройство":t.relayAccepted?"Принято Relay":t.pending?"Отправлено · ожидает сети":"Отправлено";}
  /** Called after content was displayed, never by list rendering or password entry. */
  public synchronized void displayed(String id)throws IOException,GeneralSecurityException {
    ensureOpen();Tracked t=messages.get(id);if(t==null||t.outgoing||t.displayed>0||features.blocked(id,t.peer.userId()))return;
    Timed expiry=timed.get(id);if(expiry==null&&!readReceipts)return;
    long when=local.now();
    if(expiry!=null){if(expiry.expired)throw new IOException("Письмо исчезло");guard.confirm(id,when,when);when=guard.firstDisplay(id);expiry.displayed=when;}
    t.displayed=when;save();queueReceipts(t);
  }
  public synchronized boolean expiring(String id){return timed.containsKey(id);}
  public synchronized long remaining(String id)throws IOException,GeneralSecurityException {
    Timed t=timed.get(id);if(t==null)return Long.MAX_VALUE;if(t.expired)return 0;
    if(t.outgoing&&t.displayed==0)return Long.MAX_VALUE;
    return guard.remaining(id,local.now());
  }
  /** Legacy clients cannot decrypt the actual body, even if they download the outer carrier. */
  public synchronized EncryptedPacket encryptExpiring(PlainMessage plain,UserInfo recipient,long seconds,long delivery)throws Exception {
    ensureOpen();if(seconds<60||seconds>30L*86400)throw new IOException("Срок исчезновения: от 1 минуты до 30 дней");
    Peer peer=peers.get(recipient.userId());if(!capable(recipient.userId(),DeviceCapabilities.EXPIRING)||peer==null||!MessageDigest.isEqual(peer.user.publicKey(),recipient.publicKey()))throw new IOException("Получатель должен подключить АЕГИС 1.2.0 для исчезающих писем");
    UserInfo recipientDevice=new UserInfo(Identity.id(peer.caps.deviceKey()),recipient.nickname(),peer.caps.deviceKey(),null);
    EncryptedPacket inner=crypto.encrypt(plain,7*86400,delivery,local.identity(),local.nickname(),recipientDevice);
    try(var carrier=new ExpiringEnvelope(seconds,recipientDevice.userId(),inner).carrier()){return crypto.encrypt(carrier,7*86400,delivery,local.identity(),local.nickname(),recipient);}
  }
  private void rememberTimed(EncryptedPacket outer,ExpiringEnvelope envelope,boolean outgoing,long time)throws IOException,GeneralSecurityException {
    Timed previous=timed.get(outer.messageId());if(previous!=null)return;
    if(timed.size()>=MAX_MESSAGES)throw new IOException("Expiring letter quota");
    // Inner recipient is one root-certified device. A second account clone cannot open this body.
    Timed t=new Timed();t.id=outer.messageId();t.outgoing=outgoing;t.nickname=outgoing?local.contacts().stream().filter(c->c.userId().equals(outer.recipientId())).findFirst().map(UserInfo::nickname).orElseThrow(()->new IOException("Missing contact")):outer.senderNickname();t.time=time;t.seconds=envelope.seconds();
    byte[] data=PacketCodec.encode(outer);try{local.writeExtension("mail-"+t.id,data,maxCipher+8192);}finally{Arrays.fill(data,(byte)0);}timed.put(t.id,t);save();
  }
  public synchronized LocalStore.HistoryItem loadHistory(String id,boolean outgoing)throws IOException,GeneralSecurityException {
    Timed t=timed.get(id);if(t==null)return local.loadHistory(id,outgoing);if(t.outgoing!=outgoing||t.expired)throw new IOException("Письмо исчезло");
    byte[] bytes=local.readExtension("mail-"+id,maxCipher+8192);if(bytes==null)throw new IOException("Исчезающее письмо недоступно");
    try{var packet=PacketCodec.decode(bytes,maxCipher);long left=remaining(id);if(left<=0)throw new IOException("Письмо исчезло");long expires=left==Long.MAX_VALUE?Long.MAX_VALUE:local.now()+left;return new LocalStore.HistoryItem(id,t.nickname,outgoing,status(id,"Получено"),t.time,expires,packet);}finally{Arrays.fill(bytes,(byte)0);}
  }
  /** The body is decrypted in RAM only, after a durable reveal guard was prepared. */
  public synchronized PlainMessage open(LocalStore.HistoryItem item,int maximum,boolean mandatoryReceiptConsent)throws Exception {
    if(!item.outgoing()&&timed.containsKey(item.id())&&!readReceipts&&!mandatoryReceiptConsent)throw new IOException("Нужно согласие на обязательное подтверждение прочтения");
    PlainMessage carrier=crypto.decrypt(item.packet(),local.identity(),maxCipher);Timed t=timed.get(item.id());if(t==null)return carrier;
    try{if(t.expired||remaining(t.id)<=0)throw new IOException("Письмо исчезло");var envelope=ExpiringEnvelope.read(carrier,maxCipher);if(envelope==null)throw new IOException("Missing expiring envelope");envelope.verify(item.packet());
      if(!t.outgoing){if(!envelope.deviceId().equals(device.userId()))throw new IOException("Это письмо адресовано другому устройству аккаунта");guard.prepare(t.id,t.seconds*1000,local.now());}
      return crypto.decrypt(envelope.inner(),t.outgoing?local.identity():device,maximum);
    }finally{carrier.close();}
  }
  public synchronized List<LocalStore.MailItem> mailboxIndex(boolean outgoing)throws IOException,GeneralSecurityException {
    var result=new ArrayList<LocalStore.MailItem>();for(var item:local.mailboxIndex(outgoing))if(!timed.containsKey(item.id()))result.add(new LocalStore.MailItem(item.id(),item.contact(),item.outgoing(),status(item.id(),item.status()),item.time(),item.expiresAt()));
    for(Timed t:timed.values())if(t.outgoing==outgoing){long left=t.expired?0:remaining(t.id);long expiry=left==0||left==Long.MAX_VALUE?Long.MAX_VALUE:local.now()+left;result.add(new LocalStore.MailItem(t.id,t.nickname,outgoing,left<=0?"Письмо исчезло":status(t.id,"Получено"),t.time,expiry));}return List.copyOf(result);
  }
  public synchronized boolean expired(String id){Timed t=timed.get(id);return t!=null&&t.expired;}
  public synchronized String peerId(String id){Tracked t=messages.get(id);return t==null?"":t.peer.userId();}
  public synchronized void delete(String id,boolean outgoing)throws IOException,GeneralSecurityException {Timed t=timed.get(id);if(t==null){local.deleteHistory(id,outgoing);return;}if(t.outgoing!=outgoing)throw new IOException("Direction mismatch");if(guard.available())guard.expire(id);t.expired=true;local.deleteExtension("mail-"+id);local.deleteExtension("out-"+id);Tracked tracked=messages.get(id);if(tracked!=null)tracked.pending=false;save();}
  private void queueReceipts(Tracked t)throws IOException,GeneralSecurityException {
    if(t==null||t.outgoing||features.blocked(t.id,t.peer.userId())||!capable(t.peer.userId(),DeviceCapabilities.RECEIPTS))return;
    if(t.delivered>0&&!t.deliveryQueued){enqueue(t.peer,LifecycleEvent.DELIVERED,receiptPayload(t,t.delivered));t.deliveryQueued=true;save();}
    if(t.displayed>0&&!t.readQueued){enqueue(t.peer,LifecycleEvent.DISPLAYED,receiptPayload(t,t.displayed));t.readQueued=true;save();}
  }
  private static byte[] receiptPayload(Tracked t,long when)throws IOException{return Binary.encode(o->{Binary.text(o,t.id);Binary.bytes(o,t.digest);o.writeLong(when);});}
  private void enqueue(UserInfo target,int kind,byte[] payload)throws IOException,GeneralSecurityException {
    if(queue.size()>=MAX_QUEUE)throw new RetryQueueFull();var event=LifecycleEvent.create(local.identity(),target.userId(),local.now(),kind,payload,capabilities(Secrets.random(32)));
    queue.put(event.id(),new Queued(event,target));save();
  }
  private void receive(LifecycleEvent event,EncryptedPacket packet)throws IOException,GeneralSecurityException {
    event.verify(packet,local.now());byte[] digest=event.semanticDigest(),previous=processed.get(event.id());
    if(previous!=null&&!MessageDigest.isEqual(previous,digest))throw new GeneralSecurityException("Event ID conflict");
    UserInfo sender=new UserInfo(packet.senderId(),packet.senderNickname(),packet.senderPublicKey(),null);
    if(event.kind()==LifecycleEvent.ACK){try(var in=new DataInputStream(new ByteArrayInputStream(event.payload()))){String id=Binary.text(in,36);Binary.end(in);Queued outstanding=queue.get(id);if(outstanding!=null&&outstanding.peer.userId().equals(sender.userId())){queue.remove(id);save();}}return;}
    UserInfo contact=local.contact(sender.nickname());boolean pinned=contact!=null&&contact.userId().equals(sender.userId())&&MessageDigest.isEqual(contact.publicKey(),sender.publicKey());
    boolean related=pinned||peers.containsKey(sender.userId())||messages.values().stream().anyMatch(t->t.outgoing&&t.peer.userId().equals(sender.userId()));
    if(!related)return; // Unknown roots cannot exhaust the privileged control state or stall ordinary delivery.
    if(event.capabilities().expiresAt()>local.now())learn(sender,event.capabilities());
    if(previous==null){
      if(processed.size()>=MAX_EVENTS)throw new IOException("Lifecycle replay quota");
      if(event.kind()==LifecycleEvent.CONSENT){
        try(var in=new DataInputStream(new ByteArrayInputStream(event.payload()))){var assertion=ContactAssertion.read(in);Binary.end(in);
          if(!assertion.ownerId().equals(sender.userId())||!assertion.targetId().equals(local.identity().userId())||!MessageDigest.isEqual(assertion.publicKey(),sender.publicKey())||!Identity.verify(sender.publicKey(),assertion.signingBytes(),assertion.signature()))throw new GeneralSecurityException("Consent origin");
          Peer peer=peers.get(sender.userId());if(peer==null)throw new GeneralSecurityException("Missing capability");
          if(peer.theirs!=null&&(assertion.revision()<peer.theirs.revision()||assertion.revision()==peer.theirs.revision()&&!MessageDigest.isEqual(assertion.signingBytes(),peer.theirs.signingBytes())))throw new GeneralSecurityException("Consent rollback");
          boolean newConsent=peer.theirs==null||peer.theirs.revision()!=assertion.revision();peer.theirs=assertion;
          if(newConsent&&pinned){peer.lastConsent=0;syncConsent(peer,true);}applyFriendship(peer);
        }
      }else {
        try(var in=new DataInputStream(new ByteArrayInputStream(event.payload()))){String id=Binary.text(in,36);byte[] packetDigest=Binary.bytes(in,32);long when=in.readLong();Binary.end(in);Tracked t=messages.get(id);
          if(t==null||!t.outgoing||!t.peer.userId().equals(sender.userId())||packetDigest.length!=32||!MessageDigest.isEqual(packetDigest,t.digest)||when<t.created-300_000||when>local.now()+300_000)throw new GeneralSecurityException("Receipt binding");
          if(event.kind()==LifecycleEvent.DELIVERED){if(t.delivered==0||when<t.delivered)t.delivered=when;}
          else {if(t.delivered>0&&when<t.delivered-300_000)throw new GeneralSecurityException("Read precedes delivery");if(t.displayed==0||when<t.displayed)t.displayed=when;if(t.delivered==0)t.delivered=when;Timed timedLetter=timed.get(id);if(timedLetter!=null&&timedLetter.displayed==0){timedLetter.displayed=when;try{guard.prepare(id,timedLetter.seconds*1000,when);guard.confirm(id,when,local.now());}catch(IOException|GeneralSecurityException uncertain){timedLetter.expired=true;local.deleteExtension("mail-"+id);local.deleteExtension("out-"+id);}}}
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
    retry();
    List<UserInfo> contacts=local.contacts();if(selected==null&&!contacts.isEmpty())selected=contacts.get(Math.floorMod((int)(local.now()/15_000),contacts.size()));
    if(selected==null){synchronized(this){for(Tracked t:messages.values())if(!t.outgoing&&!capable(t.peer.userId(),DeviceCapabilities.RECEIPTS)){selected=t.peer;break;}}}
    if(selected!=null){try{DeviceCapabilities caps=transport.probe(selected);if(caps!=null)learn(selected,caps);}catch(IOException unavailable){/* No signed new endpoint: ordinary protocol-1 mail remains usable. */}}
    synchronized(this){
      ensureOpen();prune();
      try{for(var contact:contacts){Peer peer=peers.get(contact.userId());if(peer!=null&&capable(contact.userId(),DeviceCapabilities.FRIENDS))syncConsent(peer,true);}
      for(Peer peer:peers.values())if(contacts.stream().noneMatch(c->c.userId().equals(peer.user.userId()))||features.blockedSender(peer.user.userId()))if(capable(peer.user.userId(),DeviceCapabilities.FRIENDS))syncConsent(peer,false);
      for(Tracked t:messages.values())if(!t.outgoing)queueReceipts(t);}catch(RetryQueueFull defer){/* Persisted state is retried; a full outbox must still drain. */}
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
  public synchronized void cleanup()throws IOException,GeneralSecurityException {if(!closed){
    boolean changed=false;for(Timed t:timed.values())if(!t.expired){long left;try{left=remaining(t.id);}catch(IOException|GeneralSecurityException uncertain){left=0;}if(left<=0){t.expired=true;local.deleteExtension("mail-"+t.id);local.deleteExtension("out-"+t.id);local.deleteHistory(t.id,t.outgoing);Tracked tracked=messages.get(t.id);if(tracked!=null)tracked.pending=false;changed=true;}}
    if(changed)save();prune();}}
  private void prune()throws IOException,GeneralSecurityException {
    boolean changed=false;for(var it=messages.entrySet().iterator();it.hasNext();){var entry=it.next();Tracked t=entry.getValue();if(!timed.containsKey(t.id)&&local.now()>t.deadline+t.ttl*1000+300_000){local.deleteExtension("out-"+t.id);it.remove();changed=true;}}
    if(changed)save();
  }
  private void save()throws IOException,GeneralSecurityException {
    byte[] data=Binary.encode(o->{o.writeInt(1);Binary.bytes(o,device.publicKey());byte[] privateKey=device.privateKey();try{Binary.bytes(o,privateKey);}finally{Arrays.fill(privateKey,(byte)0);}o.writeBoolean(readReceipts);
      o.writeInt(peers.size());for(Peer p:peers.values()){p.user.write(o);o.writeBoolean(p.caps!=null);if(p.caps!=null)p.caps.write(o);o.writeBoolean(p.ours!=null);if(p.ours!=null)p.ours.write(o);o.writeBoolean(p.theirs!=null);if(p.theirs!=null)p.theirs.write(o);o.writeLong(p.lastConsent);}
      o.writeInt(messages.size());for(Tracked t:messages.values()){Binary.text(o,t.id);t.peer.write(o);Binary.bytes(o,t.digest);o.writeBoolean(t.outgoing);o.writeBoolean(t.relayAccepted);o.writeBoolean(t.deliveryQueued);o.writeBoolean(t.readQueued);o.writeBoolean(t.pending);o.writeLong(t.created);o.writeLong(t.deadline);o.writeLong(t.ttl);o.writeLong(t.delivered);o.writeLong(t.displayed);o.writeLong(t.nextAttempt);}
      o.writeInt(processed.size());for(var p:processed.entrySet()){Binary.text(o,p.getKey());Binary.bytes(o,p.getValue());}
      o.writeInt(timed.size());for(Timed t:timed.values()){Binary.text(o,t.id);Binary.text(o,t.nickname);o.writeBoolean(t.outgoing);o.writeBoolean(t.expired);o.writeLong(t.time);o.writeLong(t.seconds);o.writeLong(t.displayed);}
      o.writeInt(queue.size());for(Queued q:queue.values()){Binary.bytes(o,q.event.encode());q.peer.write(o);o.writeBoolean(q.packet!=null);if(q.packet!=null)PacketCodec.write(o,q.packet);o.writeLong(q.nextAttempt);}
    });try{local.writeExtension("state-v1",data,STATE_MAX);}finally{Arrays.fill(data,(byte)0);}
  }
  private static int count(DataInput i,int max)throws IOException{int n=i.readInt();if(n<0||n>max)throw new IOException("Lifecycle state quota");return n;}
  private void load(byte[] bytes)throws IOException,GeneralSecurityException {
    try(var i=new DataInputStream(new ByteArrayInputStream(bytes))){if(i.readInt()!=1)throw new IOException("Lifecycle state schema");byte[] publicKey=Binary.bytes(i,44),privateKey=Binary.bytes(i,128);try{device=Identity.restore(publicKey,privateKey);}finally{Arrays.fill(privateKey,(byte)0);}readReceipts=i.readBoolean();
      for(int n=count(i,128);n>0;n--){var p=new Peer(UserInfo.read(i));if(i.readBoolean())p.caps=DeviceCapabilities.read(i);if(i.readBoolean())p.ours=ContactAssertion.read(i);if(i.readBoolean())p.theirs=ContactAssertion.read(i);p.lastConsent=i.readLong();if(peers.put(p.user.userId(),p)!=null)throw new IOException("Duplicate peer");}
      for(int n=count(i,MAX_MESSAGES);n>0;n--){var t=new Tracked();t.id=Binary.text(i,36);Limits.messageId(t.id);t.peer=UserInfo.read(i);t.digest=Binary.bytes(i,32);if(t.digest.length!=32)throw new IOException("Packet digest length");t.outgoing=i.readBoolean();t.relayAccepted=i.readBoolean();t.deliveryQueued=i.readBoolean();t.readQueued=i.readBoolean();t.pending=i.readBoolean();t.created=i.readLong();t.deadline=i.readLong();t.ttl=i.readLong();t.delivered=i.readLong();t.displayed=i.readLong();t.nextAttempt=i.readLong();if(t.created<1||t.deadline<t.created||t.ttl<1||t.ttl>7*86400||t.delivered<0||t.displayed<0||messages.put(t.id,t)!=null)throw new IOException("Invalid message state");}
      for(int n=count(i,MAX_EVENTS);n>0;n--){String id=Binary.text(i,36);Limits.messageId(id);byte[] digest=Binary.bytes(i,32);if(digest.length!=32||processed.put(id,digest)!=null)throw new IOException("Invalid replay state");}
      for(int n=count(i,MAX_MESSAGES);n>0;n--){var t=new Timed();t.id=Binary.text(i,36);Limits.messageId(t.id);t.nickname=Binary.text(i,32);Limits.nickname(t.nickname);t.outgoing=i.readBoolean();t.expired=i.readBoolean();t.time=i.readLong();t.seconds=i.readLong();t.displayed=i.readLong();if(t.time<1||t.seconds<60||t.seconds>30L*86400||t.displayed<0||timed.put(t.id,t)!=null)throw new IOException("Expiring state");}
      for(int n=count(i,MAX_QUEUE);n>0;n--){var event=LifecycleEvent.decode(Binary.bytes(i,8192));var q=new Queued(event,UserInfo.read(i));if(i.readBoolean())q.packet=PacketCodec.read(i,32_768);q.nextAttempt=i.readLong();if(!event.owner().equals(local.identity().userId())||!event.target().equals(q.peer.userId())||queue.put(event.id(),q)!=null)throw new IOException("Invalid outbox");}Binary.end(i);
    }catch(IllegalArgumentException bad){throw new IOException("Повреждено состояние доставки",bad);}
  }
  private void ensureOpen()throws IOException {if(closed)throw new IOException("Lifecycle closed");}
  @Override public synchronized void close(){closed=true;try{guard.close();}catch(IOException ignored){}}
}
