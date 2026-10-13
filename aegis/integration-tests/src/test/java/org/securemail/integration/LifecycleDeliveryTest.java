package org.securemail.integration;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.client.lifecycle.*;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;
import org.securemail.relay.*;

/** Real TCP/SOCKS framing, SQLite, ciphertext delivery and independent signed identities.
 * Synthetic onion routing is test-only; this is not native Tor or owner-account acceptance. */
class LifecycleDeliveryTest {
  @TempDir Path temp;
  final char[] vault="lifecycle vault passphrase".toCharArray(),password="lifecycle account passphrase".toCharArray();
  RelayConfig config(){return new RelayConfig(temp.resolve("relay/relay.db"),"127.0.0.1",0,604800000,1_000_000,16_000_000,256,3,true,Set.of("raven","blackfox","wolf"));}
  @Test void friendsReceiptsRevokeBlockAndOpaqueOfflineRelay()throws Exception {
    var clock=Clock.systemUTC();var config=config();String aliceOnion="c".repeat(56)+".onion";
    try(var store=new RelayStore(config,clock);var relay=new RelayServer(config,store,clock);var socks=new SocksHarness();var a=new LocalStore(temp.resolve("a"),vault,clock,2_000_000,16_000_000);var b=new LocalStore(temp.resolve("b"),vault,clock,2_000_000,16_000_000)){
      relay.start();socks.destinations.put(SocksHarness.RELAY,relay.port());var na=new NetworkService(new TorTransport("127.0.0.1",socks.port()),SocksHarness.RELAY,80,a,2_000_000);var nb=new NetworkService(new TorTransport("127.0.0.1",socks.port()),SocksHarness.RELAY,80,b,2_000_000);na.authenticate("raven",password,true);nb.authenticate("blackfox",password,true);var au=nb.find("raven");var bu=na.find("blackfox");a.trust(bu);b.trust(au);var af=new LocalFeatures(a);var bf=new LocalFeatures(b);
      try(var al=new LifecycleService(a,af,2_000_000);var bl=new LifecycleService(b,bf,2_000_000);var pa=new PeerServer(0,a,2_000_000,al::accept,al::capabilities);var pb=new PeerServer(0,b,2_000_000,bl::accept,bl::capabilities)){
        al.network(na);bl.network(nb);na.packetAcceptor(al::accept);nb.packetAcceptor(bl::accept);pa.start();pb.start();socks.destinations.put(aliceOnion,pa.port());socks.destinations.put(SocksHarness.PEER,pb.port());na.publish(a.identity().route(aliceOnion,81,a.now()+90_000));nb.publish(b.identity().route(SocksHarness.PEER,81,b.now()+90_000));
        assertFalse(af.friend(bu.userId()));al.sync(bu);assertFalse(af.friend(bu.userId()),"One unilateral addition is not proof of friendship");bl.sync(au);al.sync(bu);assertTrue(af.friend(bu.userId()));assertTrue(bf.friend(au.userId()));assertTrue(a.inbox().isEmpty());assertTrue(b.inbox().isEmpty(),"Internal events are not user letters");
        socks.destinations.remove(SocksHarness.PEER);socks.destinations.remove(aliceOnion);
        String secret="REAL-LIFECYCLE-BODY-"+UUID.randomUUID();EncryptedPacket p;try(var text=PlainMessage.text(secret)){p=new AutomaticEncryption(clock).encrypt(text,86400,604800000,a.identity(),"raven",bu);}
        assertEquals(NetworkService.Delivery.RELAY_QUEUED,al.send(p,bu).delivery());assertEquals("Принято Relay",al.status(p.messageId(),""));assertFalse(new String(Files.readAllBytes(config.databasePath()),java.nio.charset.StandardCharsets.ISO_8859_1).contains(secret));
        nb.fetchAndAcknowledge();assertEquals(1,b.inbox().size());bl.retry();na.fetchAndAcknowledge();assertEquals("Доставлено на устройство",al.status(p.messageId(),""));assertNotEquals("Прочитано",al.status(p.messageId(),""));
        var impostor=org.securemail.client.crypto.Identity.create();var forged=LifecycleEvent.create(impostor,a.identity().userId(),a.now(),LifecycleEvent.DISPLAYED,Binary.encode(o->{Binary.text(o,p.messageId());Binary.bytes(o,org.securemail.client.crypto.Identity.digest(p));o.writeLong(a.now());}),DeviceCapabilities.create(impostor,org.securemail.client.crypto.Identity.create(),a.now()+86400000,3,Secrets.random(32)));
        try(var text=new PlainMessage(forged.text(),"",new byte[0])){al.accept(new AutomaticEncryption(clock).encrypt(text,86400,86400000,impostor,"blackfox",au));}
        assertEquals("Доставлено на устройство",al.status(p.messageId(),""),"An account with the same display nickname cannot forge the recipient's read event");
        bl.displayed(p.messageId());bl.retry();na.fetchAndAcknowledge();assertEquals("Прочитано",al.status(p.messageId(),""));assertEquals(0,a.inbox().size());
        al.learn(bu,DeviceCapabilities.create(b.identity(),org.securemail.client.crypto.Identity.create(),a.now()+86400000,3,Secrets.random(32)));
        try(var text=PlainMessage.text("never sent")){assertThrows(IOException.class,()->al.encryptExpiring(text,bu,60,86400000));}
        bf.consent(au.userId(),false);b.removeContact("raven");bl.sync(null);na.fetchAndAcknowledge();assertFalse(af.friend(bu.userId()));assertFalse(bf.friend(au.userId()));assertEquals(1,b.inbox().size(),"Removing friendship preserves mail");
        af.blockSender(bu.userId(),true);assertFalse(af.friend(bu.userId()));assertTrue(socks.hosts.stream().allMatch(h->h.endsWith(".onion")));
      }
    }
  }
  @Test void unshownProtectedExpiringLetterSurvivesAppRestartWithoutStartingTimer()throws Exception {
    var clock=Clock.systemUTC();try(var a=new LocalStore(temp.resolve("a"),vault,clock,1_000_000,16_000_000);var b=new LocalStore(temp.resolve("b"),vault,clock,1_000_000,16_000_000)){
      a.bindNickname("raven");b.bindNickname("blackfox");var au=new UserInfo(a.identity().userId(),"raven",a.identity().publicKey(),null);var bu=new UserInfo(b.identity().userId(),"blackfox",b.identity().publicKey(),null);a.trust(bu);b.trust(au);var af=new LocalFeatures(a);var bf=new LocalFeatures(b);String id;
      try(var al=new LifecycleService(a,af,1_000_000);var bl=new LifecycleService(b,bf,1_000_000)){
        al.learn(bu,bl.capabilities(Secrets.random(32)));EncryptedPacket p;try(var plain=PlainMessage.letter("Protected timed",LetterEnvelope.seal("Secret fixture","letter passphrase".toCharArray(),"FF1-code".toCharArray()),null,200000)){p=al.encryptExpiring(plain,bu,60,86400000);}id=p.messageId();bl.accept(p);try(var opened=bl.open(bl.loadHistory(id,false),200000,true)){assertTrue(opened.protectedLetter());}assertEquals(Long.MAX_VALUE,bl.remaining(id));
      }
      try(var reopened=new LifecycleService(b,bf,1_000_000)){assertEquals(Long.MAX_VALUE,reopened.remaining(id));assertFalse(reopened.expired(id));try(var opened=reopened.open(reopened.loadHistory(id,false),200000,true)){reopened.prepareDisplay(id);reopened.cancelUnshown(id);}assertEquals(Long.MAX_VALUE,reopened.remaining(id));}
    }
  }
  @Test void forgedReadEventFromAnotherRootCannotAlterDeliveryStatus()throws Exception {
    var clock=Clock.systemUTC();try(var a=new LocalStore(temp.resolve("a"),vault,clock,1_000_000,16_000_000);var b=new LocalStore(temp.resolve("b"),vault,clock,1_000_000,16_000_000)){
      a.bindNickname("raven");b.bindNickname("blackfox");var au=new UserInfo(a.identity().userId(),"raven",a.identity().publicKey(),null);var bu=new UserInfo(b.identity().userId(),"blackfox",b.identity().publicKey(),null);a.trust(bu);var af=new LocalFeatures(a);
      try(var al=new LifecycleService(a,af,1_000_000)){
        var impostor=org.securemail.client.crypto.Identity.create();var caps=DeviceCapabilities.create(impostor,org.securemail.client.crypto.Identity.create(),a.now()+86400000,3,Secrets.random(32));byte[] payload=Binary.encode(o->{Binary.text(o,UUID.randomUUID().toString());Binary.bytes(o,Secrets.random(32));o.writeLong(a.now());});
        var event=LifecycleEvent.create(impostor,au.userId(),a.now(),LifecycleEvent.DISPLAYED,payload,caps);
        try(var plain=new PlainMessage(event.text(),"",new byte[0])){var p=new AutomaticEncryption(clock).encrypt(plain,86400,86400000,impostor,"blackfox",au);assertNotNull(al.accept(p));assertTrue(a.inbox().isEmpty());assertFalse(af.friend(impostor.userId()));}
      }
    }
  }
  @Test void disabledReceiptsMalformedControlAndUnknownSenderNeverBlockInbox()throws Exception {
    var clock=Clock.systemUTC();try(var a=new LocalStore(temp.resolve("a"),vault,clock,1_000_000,16_000_000);var b=new LocalStore(temp.resolve("b"),vault,clock,1_000_000,16_000_000)){
      a.bindNickname("raven");b.bindNickname("blackfox");var af=new LocalFeatures(a);var bf=new LocalFeatures(b);var au=new UserInfo(a.identity().userId(),"raven",a.identity().publicKey(),null);var bu=new UserInfo(b.identity().userId(),"blackfox",b.identity().publicKey(),null);
      try(var al=new LifecycleService(a,af,1_000_000);var bl=new LifecycleService(b,bf,1_000_000)){
        bl.learn(au,al.capabilities(Secrets.random(32)));bl.readReceipts(false);var encryption=new AutomaticEncryption(clock);EncryptedPacket p;try(var plain=PlainMessage.text("Unknown but signed")){p=encryption.encrypt(plain,86400,86400000,a.identity(),"raven",bu);}bl.accept(p);bl.displayed(p.messageId());assertEquals(1,b.inbox().size());assertTrue(b.contacts().isEmpty());
        try(var plain=PlainMessage.text(LifecycleEvent.PREFIX+"%%%invalid")){var bad=encryption.encrypt(plain,86400,86400000,a.identity(),"raven",bu);assertNotNull(bl.accept(bad));assertEquals(2,b.inbox().size(),"Literal reserved-prefix text remains ordinary mail, never a privileged event");}
        try(var plain=PlainMessage.text("A following ordinary message")){var next=encryption.encrypt(plain,86400,86400000,a.identity(),"raven",bu);assertNotNull(bl.accept(next));assertEquals(3,b.inbox().size());}
      }
    }
  }
  @Test void expiringBodyIsDeviceBoundNoPreviewAndNoRetroactiveTimers()throws Exception {
    var clock=new DeliveryTest.MutableClock();try(var a=new LocalStore(temp.resolve("a"),vault,clock,1_000_000,16_000_000);var b=new LocalStore(temp.resolve("b"),vault,clock,1_000_000,16_000_000)){
      a.bindNickname("raven");b.bindNickname("blackfox");var au=new UserInfo(a.identity().userId(),"raven",a.identity().publicKey(),null);var bu=new UserInfo(b.identity().userId(),"blackfox",b.identity().publicKey(),null);a.trust(bu);b.trust(au);var af=new LocalFeatures(a);var bf=new LocalFeatures(b);
      try(var al=new LifecycleService(a,af,1_000_000);var bl=new LifecycleService(b,bf,1_000_000)){
        al.learn(bu,bl.capabilities(Secrets.random(32)));bl.learn(au,al.capabilities(Secrets.random(32)));EncryptedPacket outer;String marker="TIMED-SECRET-"+UUID.randomUUID();try(var plain=PlainMessage.text(marker)){outer=al.encryptExpiring(plain,bu,60,86400000);}
        bl.accept(outer);assertTrue(b.inbox().isEmpty(),"The legacy TTL store must not own the new countdown");assertTrue(bl.expiring(outer.messageId()));assertEquals(Long.MAX_VALUE,bl.remaining(outer.messageId()));
        var found=LocalMailSearch.find(b,bf,bl,new LocalMailSearch.Query("","",0,Long.MAX_VALUE,LocalMailSearch.Scope.ALL),200000);assertEquals(1,found.size());assertEquals("",found.getFirst().snippet());assertFalse(found.getFirst().subject().contains(marker));
        bl.readReceipts(false);var item=bl.loadHistory(outer.messageId(),false);assertThrows(IOException.class,()->bl.open(item,200000,false));try(var opened=bl.open(item,200000,true)){assertEquals(marker,opened.text());bl.displayed(outer.messageId());}
        clock.now+=61_000;bl.cleanup();assertTrue(bl.expired(outer.messageId()));assertFalse(Files.exists(b.root().resolve("lifecycle/mail-"+outer.messageId()+".enc")));assertEquals("Письмо исчезло",bl.mailboxIndex(false).getFirst().status());assertThrows(IOException.class,()->bl.loadHistory(outer.messageId(),false));
      }
    }
  }
}
