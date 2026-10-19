package org.securemail.client;

import java.io.*;
import java.time.Clock;
import java.util.concurrent.*;
import org.securemail.client.crypto.*;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;

public final class ClientSession implements AutoCloseable {
  private final ClientConfig config;
  private final LocalStore local;
  private final NetworkService network;
  private final LocalFeatures features;
  private final org.securemail.client.lifecycle.LifecycleService lifecycle;
  private final org.securemail.client.voice.VoiceCallService calls;
  private final org.securemail.client.community.CommunityClient community;
  private final org.securemail.client.community.VoiceGrantCache voiceGrants;
  private int contactCursor;
  private int revocationCursor;
  private volatile int relayCapabilities=-1;
  private volatile String publicStatus="";
  private final EncryptionService crypto = new EncryptionService(Clock.systemUTC());
  private final ScheduledExecutorService poll = Executors.newSingleThreadScheduledExecutor(),
      cleanup = Executors.newSingleThreadScheduledExecutor();
  private volatile org.securemail.client.attachments600.MailAttachmentManager600 attachmentManager;
  public org.securemail.client.attachments600.MailAttachmentManager600 attachments600(){return attachmentManager;}
  public void attachments600(org.securemail.client.attachments600.MailAttachmentManager600 manager){synchronized(routingLock){if(closed){manager.close();return;}if(attachmentManager!=null)throw new IllegalStateException("Вложения уже подключены");attachmentManager=manager;if(peer!=null)configureAttachmentFeatures(peer);}}
  private void configureAttachmentFeatures(PeerServer server){server.attachmentFeatures(challenge->{var manager=attachmentManager;if(manager==null)throw new IllegalStateException("Потоковые вложения не настроены");try{return manager.features(challenge);}catch(Exception denied){throw new IllegalStateException("Возможности вложений недоступны");}});}
  private PeerServer peer;
  private TorControl control;
  private String onion;
  private volatile String status = "Локальный режим · сеть отключена";
  private volatile boolean closed;
  private boolean polling;
  private boolean deliverySuspended=System.getenv("AEGIS_UPDATE_JOB")!=null;
  private final Object routingLock=new Object();
  private final java.util.concurrent.atomic.AtomicBoolean friendshipChanged=new java.util.concurrent.atomic.AtomicBoolean();
  public boolean takeFriendshipEvent(){return friendshipChanged.getAndSet(false);}

  public ClientSession(ClientConfig config, char[] vaultPassword) throws Exception {
    this(config,new LocalStore(config.storagePath(),vaultPassword,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage()));
  }
  public ClientSession(ClientConfig config,LocalStore unlocked)throws IOException,java.security.GeneralSecurityException {
    this.config=config;local=unlocked;
    try{features=new LocalFeatures(local);lifecycle=new org.securemail.client.lifecycle.LifecycleService(local,features,config.maxCiphertext());}catch(IOException|java.security.GeneralSecurityException failure){local.close();throw failure;}
    network =
        config.relayOnionAddress().isEmpty()
            ? null
            : new NetworkService(
                new TorTransport(config.torSocksAddress(), config.torSocksPort()),
                config.relayOnionAddress(),
                config.relayPort(),
                local,
                config.maxCiphertext());
    if(network!=null){network.packetAcceptor(lifecycle::accept);lifecycle.network(network);}
    try{calls=new org.securemail.client.voice.VoiceCallService(local,features,network);}catch(IOException|java.security.GeneralSecurityException failure){lifecycle.close();local.close();throw failure;}
    community=new org.securemail.client.community.CommunityClient(config,local);
    voiceGrants=new org.securemail.client.community.VoiceGrantCache(community,local,calls);
    calls.setOrganizationAuthorizer(voiceGrants);
    cleanup.scheduleAtFixedRate(
        () -> {
          try {
            local.cleanup();
            lifecycle.cleanup();
            features.removeExpired(local.drainExpiredMetadata());
          } catch (Exception e) {
            status = "Ошибка локального удаления: проверьте диск";
          }
        },
        1,
        1,
        TimeUnit.SECONDS);
  }

  public void login(String nick, char[] password, boolean register) throws Exception {
    if (network == null) throw new IOException("Укажите onion-адрес вашего relay в настройках");
    network.authenticate(nick, password, register);
    if(!deliverySuspended)beginPolling();
  }
  public void resume(String token)throws Exception {
    if(network==null)throw new IOException("Relay address missing");network.resume(token);if(!deliverySuspended)beginPolling();
  }
  public synchronized void activateDelivery()throws IOException{if(!deliverySuspended)return;deliverySuspended=false;if(network!=null&&network.loggedIn())beginPolling();}
  private synchronized void beginPolling()throws IOException {
    if(polling){torRestarted();return;}polling=true;
    rebuildPeerRoute();
    sync();
    poll.scheduleWithFixedDelay(this::sync, 15, 15, TimeUnit.SECONDS);
  }
  private void rebuildPeerRoute(){synchronized(routingLock){
    closeRouting();if(closed||network==null||!network.loggedIn())return;
    try {
      peer = new PeerServer(config.localServicePort(), local, config.maxCiphertext(),p->{var receipt=lifecycle.accept(p);local.deliveryRoute(p.messageId(),"P2P");return receipt;},lifecycle::capabilities,calls::handleIncoming);
      configureAttachmentFeatures(peer);peer.start();
      control = new TorControl(config.torControlPort(), config.torCookiePath());
      onion = control.publish(peer.port());
    } catch (Exception e) {
      closeRouting();
    }
  }}
  private void closeRouting(){
    calls.networkAvailable(false);
    if(control!=null)try{control.close();}catch(IOException ignored){}control=null;onion=null;
    if(peer!=null)try{peer.close();}catch(IOException ignored){}peer=null;
  }
  /** Called before stopping our Tor; a stale onion is never republished. */
  public void torUnavailable(){voiceGrants.invalidate();synchronized(routingLock){closeRouting();}status="Нет соединения через Tor";}
  /** New SAFECOOKIE, new ephemeral onion, existing identity and account session. */
  public void torRestarted(){if(!closed&&polling)poll.execute(()->{if(!closed){rebuildPeerRoute();sync();}});}
  public void reauthenticate(char[] password)throws Exception {if(network==null)throw new IOException("Relay missing");network.authenticate(local.nickname(),password,false);if(deliverySuspended)return;if(polling)sync();else beginPolling();}

  private void sync() {
    if (closed || network == null || !network.loggedIn()) return;
    try {
      boolean p2p = false;
      synchronized(routingLock){
      if(control==null)rebuildPeerRoute();
      if (control != null)
        try {
          if (control.bootstrapped()) {
            p2p = true;
            try{network.publish(local.identity().route(onion, org.securemail.client.lifecycle.DeviceCapabilities.ONION_PORT, local.now() + 90_000));}catch(IOException relayUnavailable){status="Tor ●  Relay недоступен  P2P ●";/* A directory outage must not close our live peer onion/Control channel. */}
          }
        } catch (Exception ignored) {closeRouting();
        }
      }
      lifecycle.retry();
      network.fetchAndAcknowledge();
      local.checkpoint();
      status = "Tor ●  Relay ●  P2P " + (p2p ? "●" : "недоступен");
      try{syncPublicData(null);}catch(Exception rejected){publicStatus="Публичные данные пока не синхронизированы";}
    } catch (Exception e) {
      if(e instanceof org.securemail.client.net.RequestRejected rejected&&rejected.code()==1)network.forgetSession();
      status = peer!=null?"Tor ●  Relay недоступен  P2P ●":"Синхронизация не завершена · проверьте Tor, вход и доверенные контакты";
    }
    calls.networkAvailable(p2pReady());
  }
  private boolean p2pReady(){synchronized(routingLock){if(control==null)return false;try{return control.bootstrapped();}catch(Exception unavailable){return false;}}}
  public synchronized void syncPublicData(org.securemail.protocol.UserInfo selected)throws Exception{
    if(!online()||deliverySuspended)return;
    lifecycle.sync(selected);if(lifecycle.takeFriendshipChanged())friendshipChanged.set(true);
    relayCapabilities=network.capabilities();
    if(relayCapabilities==0){publicStatus="Сервер поддерживает базовую почту";return;}
    boolean profileSynced=true;
    var localProfile=features.profileState();
    try{if((relayCapabilities&1)!=0&&localProfile.pending()){
      var previous=network.profile(local.nickname());long revision=Math.max(local.now(),previous==null?1:previous.revision()+1);
      byte[] avatar=localProfile.visible()?local.avatar(local.nickname()):null,pixels=null;try{
        // Also sanitize older stored avatars created before the storage boundary
        // enforced PNG normalization. The identity and profile wire format stay unchanged.
        pixels=avatar==null?new byte[0]:org.securemail.client.storage.AvatarCodec.normalize(avatar);
        var profile=local.identity().profile(local.nickname(),revision,localProfile.visible(),localProfile.about(),pixels);
        network.publishProfile(profile);local.cacheProfile(profile);features.profilePublished(localProfile);
      }finally{if(avatar!=null)java.util.Arrays.fill(avatar,(byte)0);if(pixels!=null)java.util.Arrays.fill(pixels,(byte)0);}
    }
    }catch(IOException|java.security.GeneralSecurityException profileFailure){profileSynced=false;}
    if((relayCapabilities&2)!=0){
      var revoked=features.revokedConsentTargets();
      if(!revoked.isEmpty()){
        String target=revoked.get(Math.floorMod(revocationCursor++,revoked.size()));var ours=network.relationship(target).ours();
        if(ours!=null&&(!ours.ownerId().equals(local.identity().userId())||!ours.targetId().equals(target)||!java.security.MessageDigest.isEqual(ours.publicKey(),local.identity().publicKey())||!Identity.verify(ours.publicKey(),ours.signingBytes(),ours.signature())))throw new java.security.GeneralSecurityException("Invalid own consent");
        if(ours==null||ours.active())network.publishConsent(local.identity().consent(target,Math.max(local.now(),ours==null?1:Math.addExact(ours.revision(),1)),false));
      }
    }
    var contacts=local.contacts();if(selected==null&&!contacts.isEmpty())selected=contacts.get(Math.floorMod(contactCursor++,contacts.size()));
    if(selected!=null){
      if((relayCapabilities&1)!=0)try{var profile=network.profile(selected.nickname());if(profile!=null)local.cacheProfile(profile);}catch(IOException|java.security.GeneralSecurityException profileFailure){profileSynced=false;}
      if((relayCapabilities&2)!=0){
        var relationship=network.relationship(selected);boolean active=features.consent(selected.userId());
        if(relationship.ours()==null||relationship.ours().active()!=active){
          long revision=Math.max(local.now(),relationship.ours()==null?1:relationship.ours().revision()+1);
          var ours=local.identity().consent(selected.userId(),revision,active);network.publishConsent(ours);
          relationship=new NetworkService.Relationship(ours,relationship.theirs());
        }
        if(features.friendship(selected,relationship.ours(),relationship.theirs()))friendshipChanged.set(true);
      }
    }
    publicStatus=(relayCapabilities&1)==0?"Сервер не поддерживает публичные профили · изменения сохранены на устройстве":profileSynced?"Публичные данные синхронизированы":"Профиль пока не синхронизирован";
  }
  public org.securemail.client.community.CommunityClient community(){return community;}
  public void prepareVoiceCall(org.securemail.protocol.UserInfo contact,org.securemail.client.voice.VoiceCallService.Direction direction)throws IOException{voiceGrants.prepare(contact,direction);}
  /** Password stays on the existing account channel; the community server independently verifies TOTP. */
  public String adminStepUp(char[] password,String otp)throws Exception {
    if(otp==null||!otp.matches("[0-9]{8}"))throw new IOException("Введите восьмизначный одноразовый код второго фактора");
    reauthenticate(password);
    var trustedService=community.settings();
    var challenge=community.rpc("admin.stepup.begin",new com.google.gson.JsonObject());
    if(!trustedService.equals(community.settings()))throw new IOException("Доверенный сервер изменён. Повторите подтверждение личности");
    String nonce=challenge.get("challenge").getAsString();long expires=challenge.get("expires").getAsLong();
    if(!nonce.matches("[A-Za-z0-9_-]{22,86}")||expires<=local.now()||expires>local.now()+65_000)throw new IOException("Подтверждение личности истекло");
    byte[] expected=("AEGIS-COMMUNITY-STEPUP-v2\n"+org.securemail.community.protocol.CommunityAuth.id(java.util.Base64.getDecoder().decode(trustedService.serverPublicKey()))+"\n"+local.identity().userId()+"\n"+nonce+"\n"+expires).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    // Never sign arbitrary bytes supplied by a remote service.
    byte[] supplied=java.util.Base64.getDecoder().decode(challenge.get("signingBytesBase64").getAsString());
    if(!java.security.MessageDigest.isEqual(expected,supplied))throw new IOException("Некорректный запрос подтверждения личности");
    var args=new com.google.gson.JsonObject();args.addProperty("challenge",nonce);args.addProperty("signatureBase64",java.util.Base64.getEncoder().encodeToString(local.identity().sign(expected)));args.addProperty("code",otp);
    if(!trustedService.equals(community.settings()))throw new IOException("Доверенный сервер изменён. Повторите подтверждение личности");
    var result=community.rpc("admin.stepup.finish",args);String token=result.get("token").getAsString();if(!token.matches("[A-Za-z0-9_-]{22,86}"))throw new IOException("Некорректное подтверждение личности");return token;
  }
  public LocalFeatures features(){return features;}
  public org.securemail.client.voice.VoiceCallService calls(){return calls;}
  public org.securemail.client.lifecycle.LifecycleService lifecycle(){return lifecycle;}
  public int relayCapabilities(){return relayCapabilities;}
  public String publicStatus(){return publicStatus;}

  public LocalStore local() {
    return local;
  }

  public NetworkService network() {
    return network;
  }

  public EncryptionService crypto() {
    return crypto;
  }

  public ClientConfig config() {
    return config;
  }

  public String status() {
    return status;
  }

  public boolean online() {
    return network != null && network.loggedIn();
  }

  @Override
  public void close() throws IOException {
    if (closed) return;
    closed = true;
    voiceGrants.close();
    community.close();
    calls.close();
    var transfers=attachmentManager;if(transfers!=null)transfers.close();
    poll.shutdownNow();
    cleanup.shutdownNow();
    if (network != null) network.forgetSession();
    synchronized(routingLock){closeRouting();}
    lifecycle.close();
    local.close();
  }
}
