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
  private int contactCursor;
  private volatile int relayCapabilities=-1;
  private volatile String publicStatus="";
  private final EncryptionService crypto = new EncryptionService(Clock.systemUTC());
  private final ScheduledExecutorService poll = Executors.newSingleThreadScheduledExecutor(),
      cleanup = Executors.newSingleThreadScheduledExecutor();
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
    try{features=new LocalFeatures(local);}catch(IOException|java.security.GeneralSecurityException failure){local.close();throw failure;}
    network =
        config.relayOnionAddress().isEmpty()
            ? null
            : new NetworkService(
                new TorTransport(config.torSocksAddress(), config.torSocksPort()),
                config.relayOnionAddress(),
                config.relayPort(),
                local,
                config.maxCiphertext());
    cleanup.scheduleAtFixedRate(
        () -> {
          try {
            local.cleanup();
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
      peer = new PeerServer(config.localServicePort(), local, config.maxCiphertext());
      peer.start();
      control = new TorControl(config.torControlPort(), config.torCookiePath());
      onion = control.publish(peer.port());
    } catch (Exception e) {
      closeRouting();
    }
  }}
  private void closeRouting(){
    if(control!=null)try{control.close();}catch(IOException ignored){}control=null;onion=null;
    if(peer!=null)try{peer.close();}catch(IOException ignored){}peer=null;
  }
  /** Called before stopping our Tor; a stale onion is never republished. */
  public void torUnavailable(){synchronized(routingLock){closeRouting();}status="Нет соединения через Tor";}
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
            network.publish(local.identity().route(onion, 80, local.now() + 90_000));
            p2p = true;
          }
        } catch (Exception ignored) {closeRouting();
        }
      }
      network.fetchAndAcknowledge();
      local.checkpoint();
      status = "Tor ●  Relay ●  P2P " + (p2p ? "●" : "недоступен");
      try{syncPublicData(null);}catch(Exception rejected){publicStatus="Публичные данные пока не синхронизированы";}
    } catch (Exception e) {
      if(e instanceof org.securemail.client.net.RequestRejected rejected&&rejected.code()==1)network.forgetSession();
      status = "Синхронизация не завершена · проверьте Tor, вход и доверенные контакты";
    }
  }
  public synchronized void syncPublicData(org.securemail.protocol.UserInfo selected)throws Exception{
    if(!online()||deliverySuspended)return;relayCapabilities=network.capabilities();
    if(relayCapabilities==0){publicStatus="Сервер поддерживает базовую почту";return;}
    if((relayCapabilities&1)!=0&&features.profilePending()){
      var previous=network.profile(local.nickname());long revision=Math.max(local.now(),previous==null?1:previous.revision()+1);
      byte[] avatar=local.avatar(local.nickname());try{
        var profile=local.identity().profile(local.nickname(),revision,features.visible(),features.about(),avatar==null?new byte[0]:avatar);
        network.publishProfile(profile);local.cacheProfile(profile);features.profilePublished();
      }finally{if(avatar!=null)java.util.Arrays.fill(avatar,(byte)0);}
    }
    var contacts=local.contacts();if(selected==null&&!contacts.isEmpty())selected=contacts.get(Math.floorMod(contactCursor++,contacts.size()));
    if(selected!=null){
      var profile=network.profile(selected.nickname());if(profile!=null)local.cacheProfile(profile);
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
    publicStatus="Публичные данные синхронизированы";
  }
  public LocalFeatures features(){return features;}
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
    poll.shutdownNow();
    cleanup.shutdownNow();
    if (network != null) network.forgetSession();
    synchronized(routingLock){closeRouting();}
    local.close();
  }
}
