package org.securemail.client;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.lifecycle.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

class LifecycleSecurityTest {
  @TempDir Path temp;
  static final char[] PASSWORD="lifecycle independent vault password".toCharArray();
  @Test void capabilitiesAreRootSignedChallengeBoundAndNeverReplaceAccountIdentity()throws Exception {
    Identity root=Identity.create(),device=Identity.create(),impostor=Identity.create();byte[] nonce=Secrets.random(32);long now=System.currentTimeMillis();UserInfo owner=new UserInfo(root.userId(),"raven",root.publicKey(),null);
    var caps=DeviceCapabilities.create(root,device,now+86400_000,7,nonce);caps.verify(owner,nonce,now);
    assertThrows(GeneralSecurityException.class,()->caps.verify(owner,Secrets.random(32),now));
    assertThrows(GeneralSecurityException.class,()->caps.verify(new UserInfo(impostor.userId(),"raven",impostor.publicKey(),null),nonce,now));
    assertThrows(GeneralSecurityException.class,()->caps.verify(owner,nonce,now+86400_000));
    assertNotEquals(root.userId(),Identity.id(caps.deviceKey()));assertEquals(root.userId(),caps.ownerId());
  }
  @Test void durableEventRemainsVerifiableAfterItsOuterRetryWasRewrapped()throws Exception {
    Identity sender=Identity.create(),recipient=Identity.create(),device=Identity.create();long issued=System.currentTimeMillis(),later=issued+40L*86400_000;var caps=DeviceCapabilities.create(sender,device,issued+30L*86400_000,3,Secrets.random(32));
    var event=LifecycleEvent.create(sender,recipient.userId(),issued,LifecycleEvent.ACK,Binary.encode(o->Binary.text(o,UUID.randomUUID().toString())),caps);var encryption=new AutomaticEncryption(Clock.fixed(Instant.ofEpochMilli(later),ZoneOffset.UTC));
    try(var text=new PlainMessage(event.text(),"",new byte[0])){var packet=encryption.encrypt(text,604800,86400000,sender,"raven",new UserInfo(recipient.userId(),"blackfox",recipient.publicKey(),null));event.verify(packet,later);assertThrows(GeneralSecurityException.class,()->caps.verify(new UserInfo(sender.userId(),"raven",sender.publicKey(),null),null,later));}
  }
  static final class Boot implements BootClock {String id="test-boot-a";long uptime=100_000;public Stamp stamp(){return new Stamp(id,uptime);}}
  @Test void wallRollbackCannotExtendCountdownAndProfileRestoreDoesNotResetLedger()throws Exception {
    var boot=new Boot();String id=UUID.randomUUID().toString();long wall=1_800_000_000_000L;
    try(var local=new LocalStore(temp.resolve("vault"),PASSWORD,Clock.systemUTC(),200_000,8_000_000)){
      String device=Identity.create().userId();Path ledger=temp.resolve("ledger");
      try(var guard=new ExpiryGuard(local,device,true,ledger,boot)){assertTrue(guard.available());guard.prepare(id,60_000,wall);assertEquals(Long.MAX_VALUE,guard.remaining(id,wall));guard.confirm(id,wall,wall);boot.uptime+=20_000;assertEquals(40_000,guard.remaining(id,wall-600_000));}
      try(var guard=new ExpiryGuard(local,device,false,ledger,boot)){assertTrue(guard.available());guard.recover();boot.uptime+=40_001;assertEquals(0,guard.remaining(id,wall-600_000));}
      try(var guard=new ExpiryGuard(local,device,false,ledger,boot)){guard.recover();assertEquals(0,guard.remaining(id,wall));}
    }
  }
  @Test void rebootAndInterruptedRevealFailClosedWithoutInventingARead()throws Exception {
    var boot=new Boot();String read=UUID.randomUUID().toString(),pending=UUID.randomUUID().toString();long wall=System.currentTimeMillis();
    try(var local=new LocalStore(temp.resolve("vault"),PASSWORD,Clock.systemUTC(),200_000,8_000_000)){
      String device=Identity.create().userId();Path ledger=temp.resolve("ledger");
      try(var guard=new ExpiryGuard(local,device,true,ledger,boot)){guard.prepare(read,60_000,wall);guard.confirm(read,wall,wall);guard.prepare(pending,60_000,wall);assertFalse(guard.confirmed(pending));}
      boot.id="test-boot-b";boot.uptime=100;
      try(var guard=new ExpiryGuard(local,device,false,ledger,boot)){guard.recover();assertEquals(0,guard.remaining(read,wall));assertEquals(0,guard.remaining(pending,wall));assertFalse(guard.confirmed(pending));}
    }
  }
  @Test void missingOrDamagedLedgerBlocksOnlyExpiringMail()throws Exception {
    var boot=new Boot();try(var local=new LocalStore(temp.resolve("vault"),PASSWORD,Clock.systemUTC(),200_000,8_000_000)){
      String device=Identity.create().userId();Path ledger=temp.resolve("ledger");
      try(var guard=new ExpiryGuard(local,device,false,ledger,boot)){assertFalse(guard.available());assertThrows(java.io.IOException.class,()->guard.prepare(UUID.randomUUID().toString(),60_000,local.now()));}
      Files.write(ledger.resolve(device+".enc"),new byte[]{1,2,3});
      try(var guard=new ExpiryGuard(local,device,false,ledger,boot)){assertFalse(guard.available());assertTrue(local.inbox().isEmpty());assertNotNull(local.identity());}
    }
  }
  @Test void expiredEnvelopeNeverExposesBodyToLegacyAccountKey()throws Exception {
    Identity sender=Identity.create(),recipient=Identity.create(),device=Identity.create();var crypto=new AutomaticEncryption(Clock.systemUTC());UserInfo account=new UserInfo(recipient.userId(),"blackfox",recipient.publicKey(),null),receiverDevice=new UserInfo(device.userId(),"blackfox",device.publicKey(),null);String body="EXPIRY-INNER-CONTENT-"+UUID.randomUUID();
    EncryptedPacket outer;try(var plain=PlainMessage.text(body)){var inner=crypto.encrypt(plain,604800,86400_000,sender,"raven",receiverDevice);try(var carrier=new ExpiringEnvelope(2592000,device.userId(),inner).carrier()){outer=crypto.encrypt(carrier,604800,86400_000,sender,"raven",account);}}
    try(var legacy=crypto.decrypt(outer,recipient,200_000)){assertFalse(legacy.text().contains(body));var wrapper=ExpiringEnvelope.read(legacy,200_000);wrapper.verify(outer);assertThrows(GeneralSecurityException.class,()->crypto.decrypt(wrapper.inner(),recipient,200_000));try(var opened=crypto.decrypt(wrapper.inner(),device,200_000)){assertEquals(body,opened.text());}}
  }
  @Test void actualOsClockSupportsProcessRestartAndUsesNoWallClockAsItsOnlySource()throws Exception {
    var clock=BootClock.system();var first=clock.stamp();Thread.sleep(25);var next=clock.stamp();assertEquals(first.boot(),next.boot());assertTrue(next.elapsed()>=first.elapsed());
  }
  @Test void encryptedLifecycleStateAndDeviceIdentitySurviveReopen()throws Exception {
    try(var local=new LocalStore(temp.resolve("vault"),PASSWORD,Clock.systemUTC(),200_000,8_000_000)){
      local.bindNickname("raven");String root=local.identity().userId();byte[] device;
      try(var service=new LifecycleService(local,new LocalFeatures(local),200_000)){device=service.capabilities(Secrets.random(32)).deviceKey();service.readReceipts(false);}
      try(var service=new LifecycleService(local,new LocalFeatures(local),200_000)){assertFalse(service.readReceipts());assertArrayEquals(device,service.capabilities(Secrets.random(32)).deviceKey());assertEquals(root,local.identity().userId());}
      byte[] stored=Files.readAllBytes(local.root().resolve("lifecycle/state-v1.enc"));assertFalse(new String(stored,java.nio.charset.StandardCharsets.ISO_8859_1).contains(root));
    }
  }
}
