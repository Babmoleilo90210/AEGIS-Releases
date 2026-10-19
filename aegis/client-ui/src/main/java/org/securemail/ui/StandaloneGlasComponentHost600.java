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
import org.securemail.client.voice600.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;
import org.securemail.ui.ecosystem.ComponentHost;

/** Dedicated voice host. It never creates ClientSession or opens the legacy Mail vault. */
public final class StandaloneGlasComponentHost600 implements ComponentHost {
  private final CompletableFuture<GlasApp600> started=new CompletableFuture<>();private final ScheduledExecutorService guard=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"glas-identity-guard");t.setDaemon(true);return t;});
  private CorePublicConfig600 config;private IdentityClient600 identity;private ComponentLease lease;private LocalIpc.Channel channel;
  @Override public boolean supports(ComponentId component){return component==ComponentId.GLAS;}
  @Override public void connected(LocalIpc.Channel channel){this.channel=channel;}
  @Override public void verifyAuthorization(ComponentLease lease)throws IOException{
    if(lease.component()!=ComponentId.GLAS)throw new IOException("Неверное приложение Гласа");if(config==null)config=CorePublicConfig600.fromDefaultFile();
    try{var cap=IdentityProtocol.decodeCapability(new String(lease.capability(),StandardCharsets.US_ASCII));var grant=GlasGrant600.decode(lease.auxiliaryPublic());
      if(cap.appId!=IdentityProtocol.App.GLAS||!cap.accountId.equals(lease.accountId())||cap.generation!=lease.generation()||!IdentityProtocol.verifyCapability(cap,config.identityPublicKey(),System.currentTimeMillis())||!MessageDigest.isEqual(cap.proofKey,lease.proofPublicX509())||!GlasProtocol600.verifyDelegation(grant.delegation(),cap,config.identityPublicKey(),System.currentTimeMillis())||!grant.verify(grant.delegation().accountPublic(),IdentityProtocol.id(config.identityPublicKey()),System.currentTimeMillis()))throw new IOException("Разрешение Гласа или контакты отозваны");
      PrivateKey key=proofKey(lease);byte[] probe="AEGIS-GLAS-LOCAL-KEY-CHECK/v1".getBytes(StandardCharsets.US_ASCII);if(!IdentityProtocol.verify(cap.proofKey,probe,IdentityProtocol.sign(key,probe)))throw new IOException("Ключ приложения не соответствует допуску");
    }catch(GeneralSecurityException|IllegalArgumentException invalid){throw new IOException("Допуск Гласа не подтверждён",invalid);}
  }
  private static PrivateKey proofKey(ComponentLease lease)throws GeneralSecurityException{byte[] secret=lease.proofPrivatePkcs8();try{return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(secret));}finally{Arrays.fill(secret,(byte)0);}}
  @Override public void verifyStartupAuthorization(ComponentLease lease)throws IOException{
    verifyAuthorization(lease);identity=new IdentityClient600(config.identityOnion(),config.identityPort(),config.identityPublicKey(),new TorTransport("127.0.0.1",config.socksPort()));try{identity.authorizeDigest(new String(lease.capability(),StandardCharsets.US_ASCII),proofKey(lease),"glas.call",GlasGrant600.CONSENT_BODY);if(!identity.isActive(new String(lease.capability(),StandardCharsets.US_ASCII)))throw new IOException("Поколение Гласа отозвано");}catch(GeneralSecurityException invalid){throw new IOException("Ключ Гласа недействителен",invalid);}
  }
  @Override public void run(ComponentLease lease)throws Exception{
    this.lease=lease;GlasApp600.prepare(lease,config,channel,started::complete);guard.scheduleWithFixedDelay(()->{try{verifyAuthorization(lease);if(!identity.isActive(new String(lease.capability(),StandardCharsets.US_ASCII)))throw new IOException("Session revoked");}catch(Exception revoked){try{lockProtectedData();persistQueuesAndStop();}catch(Exception ignored){}}},2,2,TimeUnit.SECONDS);
    try{Application.launch(GlasApp600.class);}finally{guard.shutdownNow();if(identity!=null)identity.close();}
  }
  @Override public void lockProtectedData()throws Exception{started.get(10,TimeUnit.SECONDS).lock().get(12,TimeUnit.SECONDS);}
  @Override public void persistQueuesAndStop()throws Exception{guard.shutdownNow();GlasApp600 app=started.get(10,TimeUnit.SECONDS);app.shutdown().get(15,TimeUnit.SECONDS);if(identity!=null)identity.close();if(lease!=null)lease.close();}
  @Override public void limitedIncomingCall(boolean accept)throws Exception{started.get(10,TimeUnit.SECONDS).lockedIncoming(accept);}
}
