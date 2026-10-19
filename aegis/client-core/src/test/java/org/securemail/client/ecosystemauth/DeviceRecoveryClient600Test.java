package org.securemail.client.ecosystemauth;

import java.net.*;import java.nio.file.*;import java.security.*;import java.time.*;import java.util.*;import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.*;import org.junit.jupiter.api.io.TempDir;
import org.securemail.identity.*;import org.securemail.ecosystem.protocol.IdentityProtocol;import org.securemail.ecosystem.protocol.IdentityProtocol.*;import org.securemail.client.ecosystem.MailPairing600;
import static org.junit.jupiter.api.Assertions.*;

/** Real unknown-device signed HTTP/SQL and encrypted Core filesystem; Mail proofs are generated fixture keys only. */
class DeviceRecoveryClient600Test {
 @TempDir Path dir;static final char[] PASSWORD="Тестовый пароль нового устройства 600!".toCharArray();
 static KeyPair key()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
 @Test void freshDeviceRecoveryPersistsBeforeEnrollmentRevokesOldAndRequiresSensitiveApproval()throws Exception{
  try(Fixture f=new Fixture();var recovery=new DeviceRecoveryClient600(f.client,f.vault,f.account(),PASSWORD)){
   var r=recovery.begin();assertFalse(f.vault.exists());var i=recovery.inspection();assertTrue(IdentityProtocol.verify(r.newDevicePublic(),IdentityProtocol.deviceRecoveryInspection(r,i.time(),i.nonce()),i.proof()));
   recovery.recover(f.result(r,f.recovery),PASSWORD);assertTrue(f.vault.exists());assertTrue(recovery.completed());assertFalse(f.client.isActive(f.old.coreGrant().wire()));
   try(var credentials=f.vault.unlock(PASSWORD);var session=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),credentials)){
    assertEquals(IdentityProtocol.id(r.newDevicePublic()),credentials.deviceId());assertArrayEquals(f.root.getPublic().getEncoded(),credentials.accountPublic());assertArrayEquals(f.recovery.getPublic().getEncoded(),credentials.recoveryPublic());session.login();assertThrows(java.io.IOException.class,()->session.grant(App.LIBRARY,Set.of(Scope.LIBRARY_READ)));
   }
  }
 }
 @Test void staleRecoveryFileDoesNotEnrollAndRetryPreservesDeviceKeyWhileCorrectingPublicMetadata()throws Exception{
  try(Fixture f=new Fixture()){
   KeyPair wrong=key();byte[] candidate;
   try(var first=new DeviceRecoveryClient600(f.client,f.vault,f.account(),PASSWORD)){var r=first.begin();candidate=r.newDevicePublic();assertThrows(java.io.IOException.class,()->first.recover(f.result(r,wrong),PASSWORD));assertTrue(f.client.isActive(f.old.coreGrant().wire()));}
   byte[] challenge="same device secret".getBytes(java.nio.charset.StandardCharsets.US_ASCII),before;
   try(var credentials=f.vault.unlock(PASSWORD)){assertArrayEquals(candidate,credentials.devicePublic());assertArrayEquals(wrong.getPublic().getEncoded(),credentials.recoveryPublic());before=credentials.sign(challenge);}
   try(var retry=new DeviceRecoveryClient600(f.client,f.vault,f.account(),PASSWORD)){var r=retry.begin();assertArrayEquals(candidate,r.newDevicePublic());retry.recover(f.result(r,f.recovery),PASSWORD);}
   try(var credentials=f.vault.unlock(PASSWORD)){assertArrayEquals(before,credentials.sign(challenge));assertArrayEquals(candidate,credentials.devicePublic());assertArrayEquals(f.recovery.getPublic().getEncoded(),credentials.recoveryPublic());}
   try(var files=Files.list(dir.resolve("core"))){assertEquals(1,files.filter(p->p.getFileName().toString().endsWith(".before-recovery.encrypted")).count());}assertFalse(f.client.isActive(f.old.coreGrant().wire()));
  }
 }
 @Test void cancellationBeforeMailProofDoesNotPersistOrEnrollAndMalformedProofFailsLocally()throws Exception{
  try(Fixture f=new Fixture()){
   AtomicBoolean cancel=new AtomicBoolean();try(var attempt=new DeviceRecoveryClient600(f.client,f.vault,f.account(),PASSWORD,cancel::get)){
    var r=attempt.begin();var actual=f.result(r,f.recovery);var bad=new MailPairing600.DeviceRecoveryResult(actual.accountPublic(),actual.recoveryPublic(),r,new byte[64],actual.recoveryProof());assertThrows(java.io.IOException.class,()->attempt.recover(bad,PASSWORD));assertFalse(f.vault.exists());cancel.set(true);assertThrows(java.io.IOException.class,()->attempt.recover(actual,PASSWORD));assertFalse(f.vault.exists());assertTrue(f.client.isActive(f.old.coreGrant().wire()));
   }
  }
 }
 @Test void wrongExistingAccountCannotBeReboundOrOverwritten()throws Exception{
  try(Fixture f=new Fixture();var credentials=new DeviceCredentials600(f.root.getPublic().getEncoded(),key(),f.recovery.getPublic().getEncoded())){
   f.vault.create(credentials,PASSWORD);byte[] before=Files.readAllBytes(dir.resolve("core/device.vault"));String other=IdentityProtocol.id(key().getPublic().getEncoded());assertThrows(java.io.IOException.class,()->new DeviceRecoveryClient600(f.client,f.vault,other,PASSWORD));assertArrayEquals(before,Files.readAllBytes(dir.resolve("core/device.vault")));assertThrows(java.io.IOException.class,()->new DeviceRecoveryClient600(f.client,f.vault,f.account(),new char[]{'x'}));
  }
 }
 final class Fixture implements AutoCloseable{
  final KeyPair service=key(),root=key(),device=key(),recovery=key();final IdentityStore store;final IdentityHttpServer http;final IdentityClient600 client;final CoreAccountSession600 old;final DeviceCredentialStore600 vault=new DeviceCredentialStore600(dir.resolve("core/device.vault"));
  Fixture()throws Exception{store=new IdentityStore(dir.resolve(UUID.randomUUID()+".db"),service,new byte[32],Clock.systemUTC());http=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),store,service);http.start();client=new IdentityClient600("a".repeat(56)+".onion",80,service.getPublic().getEncoded(),(host,port,observer)->{Socket s=new Socket();observer.opened(s);s.connect(new InetSocketAddress("127.0.0.1",http.port()));return s;},Clock.systemUTC());old=new CoreAccountSession600(client,service.getPublic().getEncoded(),new DeviceCredentials600(root.getPublic().getEncoded(),device,recovery.getPublic().getEncoded()));long t=System.currentTimeMillis();String n=IdentityProtocol.nonce();old.register("Восстановление",t,n,IdentityProtocol.sign(root.getPrivate(),IdentityProtocol.registration(client.audience(),root.getPublic().getEncoded(),device.getPublic().getEncoded(),recovery.getPublic().getEncoded(),"Восстановление",t,n)));}
  String account(){return IdentityProtocol.id(root.getPublic().getEncoded());}
  MailPairing600.DeviceRecoveryResult result(DeviceRecovery r,KeyPair recovery){byte[] b=IdentityProtocol.deviceRecoveryBytes(r);return new MailPairing600.DeviceRecoveryResult(root.getPublic().getEncoded(),recovery.getPublic().getEncoded(),r,IdentityProtocol.sign(root.getPrivate(),b),IdentityProtocol.sign(recovery.getPrivate(),b));}
  public void close()throws Exception{old.close();client.close();http.close();store.close();}
 }
}
