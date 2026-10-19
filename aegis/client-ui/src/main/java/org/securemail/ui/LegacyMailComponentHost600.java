package org.securemail.ui;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;
import javafx.application.*;
import org.securemail.client.ecosystem.*;
import org.securemail.client.ecosystemauth.*;
import org.securemail.client.net.TorTransport;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ui.ecosystem.ComponentHost;

/** Production Mail adapter. Reuses the complete existing mail/archive UI, never opens a Mail vault in Core or Glas. */
public final class LegacyMailComponentHost600 implements ComponentHost {
  private final CompletableFuture<MessengerApp> started=new CompletableFuture<>();
  private final ScheduledExecutorService revocation=Executors.newSingleThreadScheduledExecutor(r->{Thread thread=new Thread(r,"aegis-mail-authorization");thread.setDaemon(true);return thread;});
  private IdentityClient600 identity;private CorePublicConfig600 config;private ComponentLease lease;private LocalIpc.Channel channel;
  @Override public void connected(LocalIpc.Channel channel){this.channel=channel;}
  @Override public synchronized void verifyAuthorization(ComponentLease candidate)throws IOException {
    if(candidate.component()!=ComponentId.MAIL||candidate.auxiliaryPublic().length!=0)throw new IOException("Глас требует отдельный протокол делегированной голосовой идентичности");
    if(config==null)config=CorePublicConfig600.fromDefaultFile();
    try {
      String wire=new String(candidate.capability(),StandardCharsets.US_ASCII);IdentityProtocol.Capability cap=IdentityProtocol.decodeCapability(wire);
      byte[] publicKey=candidate.proofPublicX509();
      if(cap.appId!=IdentityProtocol.App.MAIL || !cap.accountId.equals(candidate.accountId()) || cap.generation!=candidate.generation()
          || !IdentityProtocol.verifyCapability(cap,config.identityPublicKey(),System.currentTimeMillis())
          || publicKey.length!=44 || !MessageDigest.isEqual(publicKey,cap.proofKey)
          || IdentityProtocol.id(publicKey).equals(cap.accountId) || IdentityProtocol.id(publicKey).equals(cap.deviceId))throw new IOException("Разрешение Почты не подтверждено");
      byte[] encoded=candidate.proofPrivatePkcs8();
      try {
        PrivateKey proof=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        byte[] probe="AEGIS-MAIL-PROOF-KEY-CHECK/v1".getBytes(StandardCharsets.US_ASCII);
        if(!IdentityProtocol.verify(publicKey,probe,IdentityProtocol.sign(proof,probe)))throw new IOException("Ключ приложения не соответствует разрешению");
      }finally{Arrays.fill(encoded,(byte)0);}
    }catch(GeneralSecurityException|IllegalArgumentException invalid){throw new IOException("Невозможно проверить разрешение Почты",invalid);}
  }
  @Override public void verifyStartupAuthorization(ComponentLease candidate)throws IOException {verifyLive(candidate);}
  private synchronized void verifyLive(ComponentLease candidate)throws IOException {
    verifyAuthorization(candidate);
    if(identity==null)identity=new IdentityClient600(config.identityOnion(),config.identityPort(),config.identityPublicKey(),new TorTransport("127.0.0.1",config.socksPort()));
    byte[] encoded=candidate.proofPrivatePkcs8();
    try {
      PrivateKey proof=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
      var body=new ByteArrayOutputStream();var data=new DataOutputStream(body);data.writeUTF("AEGIS-MAIL-LOCAL-OPEN/v1");data.writeUTF(candidate.accountId());data.writeLong(candidate.generation());
      identity.authorizeDigest(new String(candidate.capability(),StandardCharsets.US_ASCII),proof,"mail.read",body.toByteArray());
      if(!identity.isActive(new String(candidate.capability(),StandardCharsets.US_ASCII)))throw new IOException("Поколение сессии Почты отозвано");
    }catch(GeneralSecurityException invalid){throw new IOException("Невозможно подтвердить ключ Почты",invalid);}
    finally{Arrays.fill(encoded,(byte)0);}
  }
  @Override public void run(ComponentLease candidate)throws Exception {
    lease=candidate;MailComponentGate600 gate=new MailComponentGate600(candidate,this::verifyLive);
    java.nio.file.Path relayConfig=org.securemail.client.AppPaths.root().resolve("core600/relay600.properties");
    for(java.nio.file.Path parent=relayConfig.toAbsolutePath();parent!=null;parent=parent.getParent())if(java.nio.file.Files.isSymbolicLink(parent))throw new IOException("Ссылка в настройке доверия Relay запрещена");
    if(!java.nio.file.Files.isRegularFile(relayConfig)||java.nio.file.Files.size(relayConfig)>4096)throw new IOException("Не настроен доверенный сервер Relay 6.0.0");
    Properties properties=new Properties();try(var input=java.nio.file.Files.newInputStream(relayConfig)){properties.load(input);}
    if(!properties.stringPropertyNames().equals(Set.of("servicePublicKey")))throw new IOException("Некорректная настройка доверия Relay");
    byte[] encoded=candidate.proofPrivatePkcs8();try{PrivateKey appKey=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));gate.networkCredentials(new IdentityRelayCredentials600(IdentityProtocol.unb64(properties.getProperty("servicePublicKey"),44),config.identityPublicKey(),new String(candidate.capability(),StandardCharsets.US_ASCII),appKey));}finally{Arrays.fill(encoded,(byte)0);}
    MessengerApp.configureMailComponent(gate,started::complete);MessengerApp.componentSignals(()->{try{if(channel!=null)channel.send(LocalIpc.Packet.command(LocalIpc.Type.USER_ACTIVITY));}catch(IOException ignored){}},count->{try{if(channel!=null)channel.send(LocalIpc.Packet.count(count));}catch(IOException ignored){}});MessengerApp.componentLinks(url->{try{if(channel==null)throw new IOException("IPC absent");channel.send(LocalIpc.Packet.openUrl(url));}catch(IOException e){throw new UncheckedIOException(e);}});
    revocation.scheduleWithFixedDelay(()->{try{
      verifyAuthorization(candidate);if(identity==null||!identity.isActive(new String(candidate.capability(),StandardCharsets.US_ASCII)))throw new IOException("Session revoked");
    }catch(Exception failed){gate.lock();try{lockProtectedData();persistQueuesAndStop();}catch(Exception ignored){/* Parent also revokes its owned process; no plaintext fallback. */}}},2,2,TimeUnit.SECONDS);
    try{Application.launch(MessengerApp.class);}finally{revocation.shutdownNow();if(identity!=null)identity.close();}
  }
  @Override public void lockProtectedData()throws Exception {MessengerApp app=started.get(10,TimeUnit.SECONDS);app.componentLock().get(12,TimeUnit.SECONDS);}
  @Override public void persistQueuesAndStop()throws Exception {
    revocation.shutdownNow();MessengerApp app=started.get(10,TimeUnit.SECONDS);
    Platform.runLater(app::stop);app.componentShutdown().get(15,TimeUnit.SECONDS);
    if(identity!=null)identity.close();if(lease!=null)lease.close();
  }
}
