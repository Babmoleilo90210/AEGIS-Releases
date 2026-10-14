package org.securemail.integration;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;
import org.securemail.relay.*;

class DeliveryTest {
  @TempDir Path temp;
  static final char[] VAULT = "private local vault password".toCharArray(),
      ACCOUNT = "independent account password".toCharArray(),
      MESSAGE = "independent message password".toCharArray();
  static final String MARKER = "TOP-SECRET-NO-RELAY-PLAINTEXT-2ebc8b4274";

  RelayConfig config(int quota) {
    return new RelayConfig(
        temp.resolve("server/relay.db"),
        "127.0.0.1",
        0,
        604800000,
        1024 * 1024,
        16 * 1024 * 1024,
        quota,
        3,
        true,
        Set.of("raven", "blackfox", "wolf"));
  }

  EncryptedPacket encrypt(LocalStore a, LocalStore b, String text) throws Exception {
    try (var m = PlainMessage.text(text)) {
      return new AutomaticEncryption(Clock.systemUTC()).encrypt(m,60,86400_000,a.identity(),"raven",new UserInfo(b.identity().userId(),"blackfox",b.identity().publicKey(),null));
    }
  }

  @Test
  void offlineP2pFallbackLostAckAndNoPlaintextAtRelay() throws Exception {
    Clock clock = Clock.systemUTC();
    RelayConfig c = config(256);
    try (var relay = new RelayStore(c, clock);
        var server = new RelayServer(c, relay, clock);
        var socks = new SocksHarness();
        var a = new LocalStore(temp.resolve("a"), VAULT, clock, 2_000_000, 16_000_000);
        var b = new LocalStore(temp.resolve("b"), VAULT, clock, 2_000_000, 16_000_000)) {
      server.start();
      socks.destinations.put(SocksHarness.RELAY, server.port());
      var na =
          new NetworkService(
              new TorTransport("127.0.0.1", socks.port()), SocksHarness.RELAY, 80, a, 2_000_000);
      var nb =
          new NetworkService(
              new TorTransport("127.0.0.1", socks.port()), SocksHarness.RELAY, 80, b, 2_000_000);
      na.authenticate("raven", ACCOUNT, true);
      nb.authenticate("blackfox", ACCOUNT, true);
      a.trust(na.find("blackfox"));
      b.trust(nb.find("raven"));
      var first = encrypt(a, b, MARKER);
      assertEquals(NetworkService.Delivery.RELAY_QUEUED, na.deliver(first));
      assertEquals(1, relay.packetCount());
      var bu = new UserInfo(b.identity().userId(), "blackfox", b.identity().publicKey(), null);
      assertNotNull(relay.fetch(bu));
      assertEquals(1, relay.packetCount(), "Fetch is not ACK");
      na.deliver(first);
      assertEquals(1, relay.packetCount());
      assertEquals(1, nb.fetchAndAcknowledge());
      assertEquals(0, relay.packetCount());
      assertEquals(1, b.inbox().size());
      na.deliver(first);
      assertEquals(0, relay.packetCount());
      try (var peer = new PeerServer(0, b, 2_000_000)) {
        peer.start();
        socks.destinations.put(SocksHarness.PEER, peer.port());
        nb.publish(b.identity().route(SocksHarness.PEER, 80, clock.millis() + 90_000));
        var second = encrypt(a, b, "P2P-only confidential text");
        assertEquals(NetworkService.Delivery.P2P_CONFIRMED, na.deliver(second));
        assertEquals(0, relay.packetCount());
        assertEquals(2, b.inbox().size());
        socks.dropNextPeerReply.set(true);
        var third = encrypt(a, b, "Lost ACK test");
        assertEquals(NetworkService.Delivery.RELAY_QUEUED, na.deliver(third));
        assertEquals(1, relay.packetCount());
        assertEquals(3, b.inbox().size());
        long original =
            b.inbox().stream()
                .filter(x -> x.messageId().equals(third.messageId()))
                .findFirst()
                .orElseThrow()
                .receivedAt();
        nb.fetchAndAcknowledge();
        assertEquals(0, relay.packetCount());
        assertEquals(3, b.inbox().size());
        assertEquals(
            original,
            b.inbox().stream()
                .filter(x -> x.messageId().equals(third.messageId()))
                .findFirst()
                .orElseThrow()
                .receivedAt());
      }
      socks.destinations.remove(SocksHarness.PEER);
      assertEquals(NetworkService.Delivery.RELAY_QUEUED, na.deliver(encrypt(a, b, "Offline peer")));
      assertEquals(1, relay.packetCount());
      assertTrue(socks.hosts.contains(SocksHarness.PEER));
      assertTrue(socks.hosts.stream().allMatch(h -> h.endsWith(".onion")));
      synchronized (socks.relayBytes) {
        assertFalse(socks.relayBytes.toString(StandardCharsets.ISO_8859_1).contains(MARKER));
      }
      assertFalse(
          new String(Files.readAllBytes(c.databasePath()), StandardCharsets.ISO_8859_1)
              .contains(MARKER));
      try (var plain =
          new AutomaticEncryption(clock).decrypt(b.load(first.messageId()), b.identity(), 1024)) {
        assertEquals(MARKER, plain.text());
      }
    }
  }

  @Test void cachedRootSignedRouteWorksAfterRelayStopsWithoutPayloadOrDuplicate()throws Exception {
    Clock clock=Clock.systemUTC();var c=config(256);
    try(var relay=new RelayStore(c,clock);var server=new RelayServer(c,relay,clock);var socks=new SocksHarness();var a=new LocalStore(temp.resolve("a"),VAULT,clock,2_000_000,16_000_000);var b=new LocalStore(temp.resolve("b"),VAULT,clock,2_000_000,16_000_000);var peer=new PeerServer(0,b,2_000_000)){
      server.start();peer.start();socks.destinations.put(SocksHarness.RELAY,server.port());socks.destinations.put(SocksHarness.PEER,peer.port());
      var na=new NetworkService(new TorTransport("127.0.0.1",socks.port()),SocksHarness.RELAY,80,a,2_000_000);var nb=new NetworkService(new TorTransport("127.0.0.1",socks.port()),SocksHarness.RELAY,80,b,2_000_000);
      na.authenticate("raven",ACCOUNT,true);nb.authenticate("blackfox",ACCOUNT,true);b.trust(nb.find("raven"));nb.publish(b.identity().route(SocksHarness.PEER,80,clock.millis()+90_000));a.trust(na.find("blackfox"));
      int coordinatedBytes; synchronized(socks.relayBytes){coordinatedBytes=socks.relayBytes.size();}server.close();socks.destinations.remove(SocksHarness.RELAY);
      var packet=encrypt(a,b,"relay-offline private fixture");assertEquals(NetworkService.Delivery.P2P_CONFIRMED,na.deliver(packet));assertEquals("P2P",a.deliveryRoute(packet.messageId()));assertEquals(NetworkService.Delivery.P2P_CONFIRMED,na.deliver(packet));assertEquals(1,b.inbox().size());assertEquals(0,relay.packetCount());
      synchronized(socks.relayBytes){assertEquals(coordinatedBytes,socks.relayBytes.size(),"No Relay request after coordination");}assertEquals(a.identity().userId(),b.load(packet.messageId()).senderId());
    }
  }

  @Test
  void forgedAckQuotaSignatureAndExpiredQueue() throws Exception {
    var time = new MutableClock();
    var c = config(1);
    var a = Identity.create();
    var b = Identity.create();
    try (var relay = new RelayStore(c, time)) {
      var au = relay.register("raven", Secrets.utf8(ACCOUNT), a.publicKey());
      var bu = relay.register("blackfox", Secrets.utf8(ACCOUNT), b.publicKey());
      var crypto = new EncryptionService(time);
      EncryptedPacket p, q;
      try (var m = PlainMessage.text("one")) {
        p = crypto.encrypt(m, MESSAGE, Algorithm.AES_256_GCM, 60, 60_000, a, "raven", b.userId());
      }
      try (var m = PlainMessage.text("two")) {
        q = crypto.encrypt(m, MESSAGE, Algorithm.AES_256_GCM, 60, 60_000, a, "raven", b.userId());
      }
      relay.store(au, p);
      assertThrows(IOException.class, () -> relay.store(au, q));
      assertThrows(IOException.class, () -> relay.acknowledge(bu, a.receipt(p, time.millis())));
      assertEquals(1, relay.packetCount());
      byte[] bytes = p.ciphertext();
      bytes[0] ^= 1;
      var altered =
          new EncryptedPacket(
              p.messageId(),
              p.senderId(),
              p.senderNickname(),
              p.recipientId(),
              p.createdAt(),
              p.deliveryDeadline(),
              60,
              p.algorithm(),
              p.salt(),
              p.nonce(),
              bytes,
              p.senderPublicKey(),
              p.signature());
      assertThrows(IOException.class, () -> relay.store(au, altered));
      time.now += 61_000;
      relay.cleanup();
      assertEquals(0, relay.packetCount());
      assertNull(relay.fetch(bu));
      assertThrows(IOException.class, () -> relay.store(au, p));
    }
  }

  @Test
  void torFailureNoFallbackAndTypedMessageApi() throws Exception {
    int unavailable;
    try (var probe = new ServerSocket(0)) {
      unavailable = probe.getLocalPort();
    }
    var tor = new TorTransport("127.0.0.1", unavailable);
    assertThrows(IOException.class, () -> tor.connect(SocksHarness.RELAY, 80));
    assertThrows(IllegalArgumentException.class, () -> tor.connect("example.com", 80));
    assertThrows(IllegalArgumentException.class, () -> new TorTransport("8.8.8.8", 9050));
    assertEquals(
        1, NetworkService.class.getMethod("deliver", EncryptedPacket.class).getParameterCount());
    assertTrue(
        Arrays.stream(NetworkService.class.getMethods())
            .noneMatch(m -> m.getName().equals("send")));
  }

  @Test
  void recipientDeleteCannotDeleteAnotherMailboxAndReplayStaysDeleted() throws Exception {
    var clock = Clock.systemUTC();
    var a = Identity.create();
    var b = Identity.create();
    try (var relay = new RelayStore(config(256), clock)) {
      var au = relay.register("raven", Secrets.utf8(ACCOUNT), a.publicKey());
      var bu = relay.register("blackfox", Secrets.utf8(ACCOUNT), b.publicKey());
      EncryptedPacket p;
      try (var m = PlainMessage.text("discard this encrypted packet")) {
        p =
            new EncryptionService(clock)
                .encrypt(m, MESSAGE, Algorithm.AES_256_GCM, 60, 86400_000, a, "raven", b.userId());
      }
      relay.store(au, p);
      relay.discard(au, p.messageId());
      assertEquals(1, relay.packetCount());
      relay.discard(bu, p.messageId());
      assertEquals(0, relay.packetCount());
      relay.store(au, p);
      assertEquals(0, relay.packetCount());
    }
  }

  static class MutableClock extends Clock {
    long now = 1_800_000_000_000L;

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId z) {
      return this;
    }

    @Override
    public Instant instant() {
      return Instant.ofEpochMilli(now);
    }

    @Override
    public long millis() {
      return now;
    }
  }
}
