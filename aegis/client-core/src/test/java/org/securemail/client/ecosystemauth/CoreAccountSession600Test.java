package org.securemail.client.ecosystemauth;

import com.google.gson.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.ecosystem.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import org.securemail.identity.*;
import static org.junit.jupiter.api.Assertions.*;

/** Actual Identity HTTP + SQL + JCA; loopback connector is explicitly not a Tor acceptance test. */
class CoreAccountSession600Test {
  @TempDir Path dir;
  private static KeyPair key()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
  private static final char[] PASSWORD="Только тестовый пароль устройства 600!".toCharArray();
  @Test void deviceVaultRoundtripContainsOnlyDevicePrivateAndDistinctPublicKeys()throws Exception {
    KeyPair root=key(),device=key(),recovery=key();var path=dir.resolve("core/device.vault");
    try(var credentials=new DeviceCredentials600(root.getPublic().getEncoded(),device,recovery.getPublic().getEncoded())){
      var vault=new DeviceCredentialStore600(path);vault.create(credentials,PASSWORD);
      byte[] encrypted=Files.readAllBytes(path);assertFalse(contains(encrypted,root.getPrivate().getEncoded()));assertFalse(contains(encrypted,device.getPrivate().getEncoded()));assertTrue(encrypted.length<1024);
      try(var restored=vault.unlock(PASSWORD)){assertEquals(IdentityProtocol.id(root.getPublic().getEncoded()),restored.accountId());assertArrayEquals(device.getPublic().getEncoded(),restored.devicePublic());byte[] challenge="device proof".getBytes();assertTrue(IdentityProtocol.verify(device.getPublic().getEncoded(),challenge,restored.sign(challenge)));}
      assertThrows(java.io.IOException.class,()->vault.create(credentials,PASSWORD));
      assertThrows(java.io.IOException.class,()->vault.unlock("неправильный пароль 600".toCharArray()));
      for(int index:new int[]{0,30,encrypted.length-1}){byte[] changed=encrypted.clone();changed[index]^=1;Files.write(path,changed);assertThrows(java.io.IOException.class,()->vault.unlock(PASSWORD));}Files.write(path,encrypted);
    }
  }
  @Test void deviceVaultRejectsRootReuseShortPasswordAndSymlink()throws Exception {
    KeyPair root=key(),device=key(),recovery=key();assertThrows(IllegalArgumentException.class,()->new DeviceCredentials600(root.getPublic().getEncoded(),root,recovery.getPublic().getEncoded()));
    try(var c=new DeviceCredentials600(root.getPublic().getEncoded(),device,recovery.getPublic().getEncoded())){
      assertThrows(java.io.IOException.class,()->new DeviceCredentialStore600(dir.resolve("short/device")).create(c,new char[]{'x'}));
      Path target=Files.createDirectory(dir.resolve("target")),link=dir.resolve("link");Files.createSymbolicLink(link,target);
      assertThrows(java.io.IOException.class,()->new DeviceCredentialStore600(link.resolve("device")).create(c,PASSWORD));assertFalse(Files.exists(target.resolve("device")));
      c.close();assertThrows(IllegalStateException.class,()->c.sign(new byte[0]));
    }
  }
  @Test void actualRegistrationSeparateApplicationProofKeysAndGenerationRevocation()throws Exception {
    try(Fixture f=new Fixture()){
      f.register();assertEquals(1,f.session.generation());assertEquals(IdentityProtocol.id(f.root.getPublic().getEncoded()),f.session.profile().get("accountId").getAsString());
      ComponentLease mail=f.session.authorize(ComponentId.MAIL),glas=f.session.authorize(ComponentId.GLAS);f.session.validate(mail);f.session.validate(glas);
      Capability mc=IdentityProtocol.decodeCapability(new String(mail.capability(),java.nio.charset.StandardCharsets.US_ASCII)),gc=IdentityProtocol.decodeCapability(new String(glas.capability(),java.nio.charset.StandardCharsets.US_ASCII));
      assertEquals(App.MAIL,mc.appId);assertEquals(App.GLAS,gc.appId);assertFalse(Arrays.equals(mc.proofKey,gc.proofKey));assertFalse(Arrays.equals(mc.proofKey,f.device.getPublic().getEncoded()));assertFalse(Arrays.equals(mc.proofKey,f.root.getPublic().getEncoded()));
      assertEquals(Set.of(Scope.MAIL_READ,Scope.MAIL_SEND,Scope.CONTACTS_READ),mc.capabilities);assertFalse(mc.capabilities.contains(Scope.ADMIN));
      try(var other=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),f.credentials())){other.login();assertEquals(2,other.generation());assertThrows(java.io.IOException.class,()->f.session.validate(mail));}
    }
  }
  @Test void lockPreventsNewGrantsButRetainsBoundedExistingCallValidationAndLogoutRevokes()throws Exception {
    try(Fixture f=new Fixture()){
      f.register();assertTrue(f.session.canContinueOffline());var lease=f.session.authorize(ComponentId.GLAS);f.session.lock();assertTrue(f.session.locked());assertFalse(f.session.canContinueOffline());
      assertThrows(java.io.IOException.class,()->f.session.authorize(ComponentId.MAIL));assertThrows(java.io.IOException.class,()->f.session.profile());f.session.validate(lease);
      String token=new String(lease.capability(),java.nio.charset.StandardCharsets.US_ASCII);assertTrue(f.client.isActive(token));f.session.logout();assertFalse(f.client.isActive(token));assertThrows(java.io.IOException.class,()->f.session.validate(lease));
    }
  }
  @Test void offlinePresenceHasOnlyPreviouslySignedReadScopeAndDoesNotCallNetwork()throws Exception {
    try(Fixture f=new Fixture()){
      f.register();var calls=new java.util.concurrent.atomic.AtomicInteger();var offline=new java.util.concurrent.atomic.AtomicBoolean();
      CoreAccountSession600.Rpc counting=(operation,args)->{calls.incrementAndGet();if(offline.get())throw new java.io.IOException("fixture network unavailable");return f.client.rpc(operation,args);};
      try(var session=new CoreAccountSession600(counting,f.service.getPublic().getEncoded(),f.credentials(),Clock.systemUTC(),System::nanoTime)){
        session.login();var management=session.coreGrant();var presence=session.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ));
        assertTrue(management.capability().capabilities.contains(Scope.DEVICE_MANAGE));assertEquals(management.capability().issuedAt,management.capability().offlineUntil);
        assertEquals(Set.of(Scope.ACCOUNT_READ),presence.capability().capabilities);assertTrue(presence.capability().offlineUntil>presence.capability().issuedAt);
        offline.set(true);int before=calls.get();assertTrue(session.canContinueOffline());assertEquals(before,calls.get());
        assertThrows(java.io.IOException.class,()->session.grant(App.GLAS,Set.of(Scope.VOICE_CALL)));assertThrows(java.io.IOException.class,session::profile);
        session.lock();assertFalse(session.canContinueOffline());
      }
    }
  }
  @Test void localLockDoesNotWaitForRemoteProfileOrGrantAndLateResultsAreRejected()throws Exception {
    for(String operation:List.of("profile","issueCapability"))try(Fixture f=new Fixture()){
      f.register();CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
      CoreAccountSession600.Rpc delayed=(op,args)->{JsonObject response=f.client.rpc(op,args);if(op.equals(operation)&&(op.equals("profile")||args.get("appId").getAsString().equals("MAIL"))){entered.countDown();try{if(!release.await(5,TimeUnit.SECONDS))throw new java.io.IOException("fixture deadline");}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new java.io.IOException(interrupted);}}return response;};
      try(var session=new CoreAccountSession600(delayed,f.service.getPublic().getEncoded(),f.credentials(),Clock.systemUTC(),System::nanoTime);var pool=Executors.newSingleThreadExecutor()){
        session.login();Future<?> pending=pool.submit(()->{assertThrows(java.io.IOException.class,()->{if(operation.equals("profile"))session.profile();else session.authorize(ComponentId.MAIL);});});
        try{assertTrue(entered.await(2,TimeUnit.SECONDS));assertTimeout(Duration.ofSeconds(1),session::lock);assertTrue(session.locked());assertEquals(f.session.accountId(),session.accountId());}
        finally{release.countDown();}pending.get(3,TimeUnit.SECONDS);
      }
    }
  }
  @Test void forgedRootRegistrationNeverReachesServerAndUnprivilegedAdminIsDenied()throws Exception {
    try(Fixture f=new Fixture()){
      long time=System.currentTimeMillis();assertThrows(java.io.IOException.class,()->f.session.register("Тест",time,IdentityProtocol.nonce(),new byte[64]));
      f.register();assertThrows(java.io.IOException.class,()->f.session.grant(App.AEGIS,EnumSet.of(Scope.ACCOUNT_READ,Scope.ADMIN)));
      var mail=f.session.authorize(ComponentId.MAIL);var forged=new ComponentLease(ComponentId.GLAS,mail.accountId(),mail.generation(),mail.capability(),mail.proofPrivatePkcs8(),mail.proofPublicX509());assertThrows(java.io.IOException.class,()->f.session.validate(forged));
    }
  }
  @Test void alteredSignedCapabilityBindingIsRejectedAtEnrollment()throws Exception {
    try(Fixture f=new Fixture()){
      // Signature remains valid, but a server/test adapter sends a grant for the wrong requested application.
      CoreAccountSession600.Rpc altered=(op,args)->{JsonObject result=f.client.rpc(op,args);if(op.equals("issueCapability")){Capability cap=IdentityProtocol.decodeCapability(result.get("capability").getAsString());Capability wrong=new Capability(cap.audience,cap.accountId,cap.deviceId,App.MAIL,cap.generation,cap.tokenId,cap.issuedAt,cap.expiresAt,cap.offlineUntil,cap.proofKey,Set.of(Scope.MAIL_READ),new byte[0]);wrong=wrong.signed(IdentityProtocol.sign(f.service.getPrivate(),IdentityProtocol.capabilityBytes(wrong)));result.addProperty("capability",IdentityProtocol.encodeCapability(wrong));}return result;};
      try(var session=new CoreAccountSession600(altered,f.service.getPublic().getEncoded(),f.credentials(),Clock.systemUTC(),System::nanoTime)){
        long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] proof=IdentityProtocol.sign(f.root.getPrivate(),IdentityProtocol.registration(f.client.audience(),f.root.getPublic().getEncoded(),f.device.getPublic().getEncoded(),f.recovery.getPublic().getEncoded(),"Проверка",time,nonce));
        assertThrows(java.io.IOException.class,()->session.register("Проверка",time,nonce,proof));
      }
    }
  }
  @Test void newDeviceNeedsExplicitExistingDeviceStepUpAndCannotSubstituteFingerprint()throws Exception {
    try(Fixture f=new Fixture();var candidate=new DeviceCredentials600(f.root.getPublic().getEncoded(),key(),f.recovery.getPublic().getEncoded())){
      f.register();DeviceApproval600 request=DeviceApproval600.request(f.client,candidate);assertEquals(request.encode(),DeviceApproval600.parse(request.encode()).encode());
      try(var newer=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),candidate)){
        assertThrows(java.io.IOException.class,newer::login);assertThrows(java.io.IOException.class,()->f.session.approveDevice(request));
        var challenge=f.store.stepUpChallenge(f.session.accountId(),f.session.deviceId(),f.session.generation());byte[] payload=IdentityProtocol.stepUp(f.client.audience(),f.session.accountId(),f.session.deviceId(),challenge.challenge(),challenge.expiresAt());f.session.completeStepUp(challenge.challenge(),challenge.expiresAt(),IdentityProtocol.sign(f.root.getPrivate(),payload));
        DeviceApproval600 altered=new DeviceApproval600(request.audience(),request.accountId(),request.challenge(),key().getPublic().getEncoded(),request.expiresAt());assertThrows(java.io.IOException.class,()->f.session.approveDevice(altered));
        var old=f.session.authorize(ComponentId.MAIL);f.session.approveDevice(request);assertThrows(java.io.IOException.class,()->f.session.approveDevice(request));newer.login();assertEquals(f.session.generation()+1,newer.generation());assertThrows(java.io.IOException.class,()->f.session.validate(old));
      }
      assertThrows(java.io.IOException.class,()->DeviceApproval600.parse(request.encode().replace("\"schema\":1","\"schema\":2")));assertThrows(java.io.IOException.class,()->DeviceApproval600.parse(request.encode().replace("\"expiresAt\":","\"unused\":0,\"expiresAt\":")));assertThrows(java.io.IOException.class,()->request.verifyTarget("a".repeat(64),request.accountId(),System.currentTimeMillis()));
    }
  }
  @Test void wallClockRollbackAndLongMonotonicElapsedDenyFurtherUse()throws Exception {
    try(Fixture f=new Fixture()){
      f.register();AtomicLong offset=new AtomicLong();Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId ignored){return this;}public Instant instant(){return Instant.now().plusMillis(offset.get());}};
      try(var session=new CoreAccountSession600(f.client::rpc,f.service.getPublic().getEncoded(),f.credentials(),clock,System::nanoTime)){
        session.login();assertTrue(session.canContinueOffline());ComponentLease lease=session.authorize(ComponentId.MAIL);offset.set(-120_000);assertThrows(java.io.IOException.class,()->session.validate(lease));assertFalse(session.canContinueOffline());offset.set(25*60*60_000L);assertThrows(java.io.IOException.class,()->session.authorize(ComponentId.GLAS));assertFalse(session.canContinueOffline());
      }
    }
  }
  @Test void typedRootConsentIsNeededForAdministrativeStepUp()throws Exception {
    try(Fixture f=new Fixture()){
      f.register();var owner=f.store.ownerChallenge(f.session.accountId());f.store.bootstrapOwner(f.session.accountId(),owner.challenge(),IdentityProtocol.sign(f.root.getPrivate(),IdentityProtocol.ownerBootstrap(f.client.audience(),f.session.accountId(),owner.challenge(),owner.expiresAt())));
      // Bootstrap changes server authority and invalidates the earlier User capability.
      try(var ownerSession=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),f.credentials())){
        ownerSession.login();
      assertThrows(java.io.IOException.class,()->ownerSession.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ,Scope.ADMIN)));
      var grant=ownerSession.coreGrant();long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();JsonObject args=new JsonObject();args.addProperty("capability",grant.wire());args.addProperty("time",time);args.addProperty("nonce",nonce);args.addProperty("proof",IdentityProtocol.b64(IdentityProtocol.sign(grant.proofPrivate(),IdentityProtocol.request(grant.capability(),"account.read",new byte[0],time,nonce))));JsonObject challenge=f.client.rpc("stepUpChallenge",args);
      String id=challenge.get("challenge").getAsString();long until=challenge.get("expiresAt").getAsLong();assertThrows(java.io.IOException.class,()->ownerSession.completeStepUp(id,until,new byte[64]));
      byte[] payload=IdentityProtocol.stepUp(f.client.audience(),ownerSession.accountId(),ownerSession.deviceId(),id,until);ownerSession.completeStepUp(id,until,IdentityProtocol.sign(f.root.getPrivate(),payload));
      var admin=ownerSession.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ,Scope.ADMIN));assertTrue(admin.capability().capabilities.contains(Scope.ADMIN));assertTrue(f.client.isActive(admin.wire()));assertThrows(java.io.IOException.class,()->ownerSession.completeStepUp(id,until,IdentityProtocol.sign(f.root.getPrivate(),payload)));
      }
    }
  }
  @Test void installedInventoryRejectsModifiedJarsAndEscapingNames()throws Exception {
    Path bundle=Files.createDirectory(dir.resolve("bundle"));Path runtime=Files.createDirectories(bundle.resolve("runtime/bin"));Path app=Files.createDirectory(bundle.resolve("app"));Files.write(runtime.resolve("java"),new byte[]{1,2,3});
    for(String name:List.of("core.jar","ui.jar","common.jar"))Files.write(app.resolve(name),new byte[]{4,5,6});InstallationInventory600.writeForPackaging(bundle);assertEquals(3,InstallationInventory600.load(bundle).classpath().size());
    byte[] inventory=Files.readAllBytes(bundle.resolve("components600.json"));Files.write(app.resolve("core.jar"),new byte[]{9});assertThrows(java.io.IOException.class,()->InstallationInventory600.load(bundle));Files.write(app.resolve("core.jar"),new byte[]{4,5,6});
    String escaped=new String(inventory,java.nio.charset.StandardCharsets.UTF_8).replace("app/core.jar","app/../core.jar");Files.writeString(bundle.resolve("components600.json"),escaped);assertThrows(java.io.IOException.class,()->InstallationInventory600.load(bundle));
    Files.write(bundle.resolve("components600.json"),inventory);Files.delete(app.resolve("core.jar"));Files.createSymbolicLink(app.resolve("core.jar"),app.resolve("ui.jar"));assertThrows(java.io.IOException.class,()->InstallationInventory600.load(bundle));
  }
  private static boolean contains(byte[] haystack,byte[] needle){for(int p=0;p<=haystack.length-needle.length;p++){boolean equal=true;for(int n=0;n<needle.length;n++)if(haystack[p+n]!=needle[n]){equal=false;break;}if(equal)return true;}return false;}
  private final class Fixture implements AutoCloseable {
    final KeyPair root=key(),device=key(),recovery=key(),service=key();final IdentityStore store;final IdentityHttpServer http;final IdentityClient600 client;final CoreAccountSession600 session;
    Fixture()throws Exception{
      store=new IdentityStore(dir.resolve(UUID.randomUUID()+".db"),service,new byte[32],Clock.systemUTC());http=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),store,service);http.start();
      client=new IdentityClient600("a".repeat(56)+".onion",80,service.getPublic().getEncoded(),(host,port,observer)->{Socket socket=new Socket();observer.opened(socket);socket.connect(new InetSocketAddress("127.0.0.1",http.port()));return socket;},Clock.systemUTC());
      session=new CoreAccountSession600(client,service.getPublic().getEncoded(),credentials());
    }
    DeviceCredentials600 credentials(){return new DeviceCredentials600(root.getPublic().getEncoded(),device,recovery.getPublic().getEncoded());}
    void register()throws Exception {long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();session.register("Испытатель",time,nonce,IdentityProtocol.sign(root.getPrivate(),IdentityProtocol.registration(client.audience(),root.getPublic().getEncoded(),device.getPublic().getEncoded(),recovery.getPublic().getEncoded(),"Испытатель",time,nonce)));}
    public void close()throws Exception {session.close();client.close();http.close();store.close();}
  }
}
