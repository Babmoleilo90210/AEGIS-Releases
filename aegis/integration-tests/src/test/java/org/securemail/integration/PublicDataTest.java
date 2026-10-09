package org.securemail.integration;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;
import org.securemail.relay.*;
import org.securemail.client.*;

/** Real SQLite and wire protocol through a controlled SOCKS harness, not native Tor acceptance. */
class PublicDataTest {
  @TempDir Path root;
  static final char[] PASSWORD="integration account passphrase".toCharArray();
  RelayConfig config(){return new RelayConfig(root.resolve("server/relay.db"),"127.0.0.1",0,604800000,1000000,8000000,256,8,true,Set.of());}
  NetworkService network(SocksHarness socks,LocalStore local){return new NetworkService(new TorTransport("127.0.0.1",socks.port()),SocksHarness.RELAY,80,local,1000000);}
  @Test void signedProfileIsOwnedHiddenReplayProtectedAndMutualFriendshipRevokesWithoutRemovingMail()throws Exception{
    var config=config();Clock clock=Clock.systemUTC();
    try(var relay=new RelayStore(config,clock);var server=new RelayServer(config,relay,clock);var socks=new SocksHarness();var a=new LocalStore(root.resolve("a"),PASSWORD,clock,1000000,8000000);var b=new LocalStore(root.resolve("b"),PASSWORD,clock,1000000,8000000)){
      server.start();socks.destinations.put(SocksHarness.RELAY,server.port());var na=network(socks,a);var nb=network(socks,b);na.authenticate("raven",PASSWORD,true);nb.authenticate("blackfox",PASSWORD,true);
      a.trust(na.find("blackfox"));b.trust(nb.find("raven"));assertEquals(3,na.capabilities());
      long revision=clock.millis();var visible=a.identity().profile("raven",revision,true,"Public about",new byte[0]);na.publishProfile(visible);assertEquals("Public about",nb.profile("raven").about());
      assertThrows(RequestRejected.class,()->nb.publishProfile(visible));assertThrows(RequestRejected.class,()->na.publishProfile(a.identity().profile("raven",revision-1,true,"Replay",new byte[0])));
      var spoof=new PublicProfile(visible.userId(),visible.nickname(),revision+1,true,"Spoof",new byte[0],visible.publicKey(),new byte[64]);assertThrows(RequestRejected.class,()->na.publishProfile(spoof));
      na.publishProfile(a.identity().profile("raven",revision+1,false,"Private local about",new byte[0]));var hidden=nb.profile("raven");assertFalse(hidden.visible());assertTrue(hidden.about().isEmpty());b.cacheProfile(hidden);
      var local=new LocalFeatures(b);var raven=b.contact("raven");na.publishConsent(a.identity().consent(b.identity().userId(),revision,true));var relation=nb.relationship(raven);local.friendship(raven,relation.ours(),relation.theirs());assertFalse(local.friend(raven.userId()));
      nb.publishConsent(b.identity().consent(a.identity().userId(),revision,true));relation=nb.relationship(raven);local.friendship(raven,relation.ours(),relation.theirs());assertTrue(local.friend(raven.userId()));
      EncryptedPacket packet;try(var plain=PlainMessage.text("Retained mail")){packet=new AutomaticEncryption(clock).encrypt(plain,300,60000,a.identity(),"raven",na.find("blackfox"));}na.deliver(packet);nb.fetchAndAcknowledge();
      local.consent(raven.userId(),false);nb.publishConsent(b.identity().consent(a.identity().userId(),revision+1,false));relation=nb.relationship(raven);local.friendship(raven,relation.ours(),relation.theirs());assertFalse(local.friend(raven.userId()));assertNotNull(b.contact("raven"));assertEquals(1,b.inbox().size());
      assertThrows(RequestRejected.class,()->nb.publishConsent(b.identity().consent(a.identity().userId(),revision,true)));assertThrows(RequestRejected.class,()->na.publishConsent(b.identity().consent(a.identity().userId(),revision+2,true)));
    }
    try(var reopened=new RelayStore(config,clock)){assertEquals(2,reopened.userCount());assertNotNull(reopened.profile("raven"));assertFalse(reopened.profile("raven").visible());}
  }
  @Test void unknownSenderAheadOfKnownSenderIsAcknowledgedAndDoesNotBlockQueueOrBlockedFolder()throws Exception{
    var config=config();Clock clock=Clock.systemUTC();
    try(var relay=new RelayStore(config,clock);var server=new RelayServer(config,relay,clock);var socks=new SocksHarness();var unknown=new LocalStore(root.resolve("unknown"),PASSWORD,clock,1000000,8000000);var known=new LocalStore(root.resolve("known"),PASSWORD,clock,1000000,8000000);var b=new LocalStore(root.resolve("b"),PASSWORD,clock,1000000,8000000)){
      server.start();socks.destinations.put(SocksHarness.RELAY,server.port());var nu=network(socks,unknown);var nk=network(socks,known);var nb=network(socks,b);nu.authenticate("unknown",PASSWORD,true);nk.authenticate("raven",PASSWORD,true);nb.authenticate("blackfox",PASSWORD,true);b.trust(nb.find("raven"));unknown.trust(nu.find("blackfox"));known.trust(nk.find("blackfox"));
      var crypto=new AutomaticEncryption(clock);EncryptedPacket first,second;
      try(var plain=PlainMessage.text("Unknown confidential mail")){first=crypto.encrypt(plain,300,60000,unknown.identity(),"unknown",nu.find("blackfox"));}
      try(var plain=PlainMessage.text("Known confidential mail")){second=crypto.encrypt(plain,300,60000,known.identity(),"raven",nk.find("blackfox"));}
      nu.deliver(first);nk.deliver(second);assertEquals(2,relay.packetCount());assertEquals(2,nb.fetchAndAcknowledge());assertEquals(0,relay.packetCount());assertEquals(2,b.inbox().size());assertNull(b.contact("unknown"));
      var features=new LocalFeatures(b);features.blockSender(unknown.identity().userId(),true);
      var visible=LocalMailSearch.find(b,features,new LocalMailSearch.Query("","",0,Long.MAX_VALUE,LocalMailSearch.Scope.INBOX),1000000);assertEquals(1,visible.size());assertEquals("raven",visible.getFirst().item().contact());
      var blocked=LocalMailSearch.find(b,features,new LocalMailSearch.Query("","",0,Long.MAX_VALUE,LocalMailSearch.Scope.BLOCKED),1000000);assertEquals(1,blocked.size());assertTrue(blocked.getFirst().unknown());assertTrue(blocked.getFirst().signatureValid());
      nu.deliver(first);assertEquals(0,nb.fetchAndAcknowledge());assertEquals(2,b.inbox().size());
    }
  }
  @Test void offlineContactRemovalStillRevokesRelayConsentAfterReconnect()throws Exception{
    Clock clock=Clock.systemUTC();var config=config();
    try(var relay=new RelayStore(config,clock);var server=new RelayServer(config,relay,clock);var socks=new SocksHarness();var a=new LocalStore(root.resolve("a"),PASSWORD,clock,1000000,8000000);var b=new LocalStore(root.resolve("b"),PASSWORD,clock,1000000,8000000)){
      server.start();socks.destinations.put(SocksHarness.RELAY,server.port());var na=network(socks,a);var nb=network(socks,b);na.authenticate("raven",PASSWORD,true);nb.authenticate("blackfox",PASSWORD,true);a.trust(na.find("blackfox"));b.trust(nb.find("raven"));
      long now=clock.millis();na.publishConsent(a.identity().consent(b.identity().userId(),now,true));nb.publishConsent(b.identity().consent(a.identity().userId(),now,true));
      var clientConfig=new ClientConfig("127.0.0.1",socks.port(),19051,root.resolve("no-control-cookie"),19120,300,SocksHarness.RELAY,80,root.resolve("b"),1000000,8000000,60000);
      try(var session=new ClientSession(clientConfig,b)){
        session.features().consent(a.identity().userId(),false);b.removeContact("raven");assertNull(b.contact("raven"));assertTrue(na.relationship(b.identity().userId()).theirs().active());
        session.network().authenticate("blackfox",PASSWORD,false);session.syncPublicData(null);
        assertFalse(na.relationship(b.identity().userId()).theirs().active());assertNull(b.contact("raven"));assertFalse(session.features().friend(a.identity().userId()));
      }
    }
  }
}
