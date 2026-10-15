package org.securemail.client;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.securemail.client.crypto.*;
import org.securemail.protocol.*;

class CryptoTest {
  final Identity sender = create(), receiver = create();
  final EncryptionService crypto = new EncryptionService(Clock.systemUTC());
  static final char[] PASSWORD = "five independent words with random suffix 9812".toCharArray();

  static Identity create() {
    try {
      return Identity.create();
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  EncryptedPacket packet(Algorithm a) throws Exception {
    try (var m =
        new PlainMessage(
            "Письмо ☀".getBytes(StandardCharsets.UTF_8), "sample.zip", new byte[] {1, 2, 3, 4})) {
      return crypto.encrypt(m, PASSWORD, a, 60, 86400_000, sender, "raven", receiver.userId());
    }
  }

  @ParameterizedTest
  @EnumSource(value = Algorithm.class, names = "ENIGMA", mode = EnumSource.Mode.EXCLUDE)
  void roundTripWrongKeyTamperAndAuthenticatedMetadata(Algorithm a) throws Exception {
    var p = packet(a);
    try (var m = crypto.decrypt(p, PASSWORD, 1024)) {
      assertEquals("Письмо ☀", m.text());
      assertEquals("sample.zip", m.filename());
      assertEquals(4, m.fileSize());
    }
    assertThrows(
        GeneralSecurityException.class,
        () -> crypto.decrypt(p, "completely different wrong key".toCharArray(), 1024));
    byte[] cipher = p.ciphertext();
    cipher[0] ^= 1;
    var changed =
        new EncryptedPacket(
            p.messageId(),
            p.senderId(),
            p.senderNickname(),
            p.recipientId(),
            p.createdAt(),
            p.deliveryDeadline(),
            60,
            a,
            p.salt(),
            p.nonce(),
            cipher,
            p.senderPublicKey(),
            p.signature());
    assertFalse(Identity.verifyPacket(changed));
    var resigned = sender.signPacket(changed);
    assertThrows(GeneralSecurityException.class, () -> crypto.decrypt(resigned, PASSWORD, 1024));
    var ttlChanged =
        sender.signPacket(
            new EncryptedPacket(
                p.messageId(),
                p.senderId(),
                p.senderNickname(),
                p.recipientId(),
                p.createdAt(),
                p.deliveryDeadline(),
                120,
                a,
                p.salt(),
                p.nonce(),
                p.ciphertext(),
                p.senderPublicKey(),
                new byte[0]));
    assertThrows(GeneralSecurityException.class, () -> crypto.decrypt(ttlChanged, PASSWORD, 1024));
  }

  @ParameterizedTest
  @EnumSource(value = Algorithm.class, names = "ENIGMA", mode = EnumSource.Mode.EXCLUDE)
  void freshNonceSaltAndNoFilenameInPacket(Algorithm a) throws Exception {
    var p = packet(a);
    var q = packet(a);
    assertEquals(16, p.salt().length);
    assertEquals(a.nonceLength, p.nonce().length);
    assertFalse(Arrays.equals(p.salt(), q.salt()));
    assertFalse(Arrays.equals(p.nonce(), q.nonce()));
    byte[] wire = PacketCodec.encode(p);
    assertArrayEquals(Identity.digest(p), Identity.digest(PacketCodec.decode(wire, 1_000_000)));
    String visible = new String(wire, StandardCharsets.ISO_8859_1);
    assertFalse(visible.contains("sample.zip"));
    assertFalse(visible.contains(new String(PASSWORD)));
  }

  @Test
  void historicalKnownVector() {
    assertEquals("BDZGO", Enigma.transform("AAAAA", "AAA".toCharArray()));
    assertEquals("AAAAA", Enigma.transform("BDZGO", "AAA".toCharArray()));
    assertNotEquals("AAAAA", Enigma.transform("BDZGO", "BBB".toCharArray()));
  }

  @Test
  void anyFileTypeAndTraversal() {
    for (String s : List.of("../a.zip", "a/b.zip", "a\\b.zip", "a\n.zip"))
      assertThrows(IllegalArgumentException.class, () -> PlainMessage.validateFilename(s));
    for (String s : List.of("a.tar.gz", "a.zip", "a.7z", "a.tar", "a.txt", "script.sh", "photo.png", "random.bin", "document.pdf"))
      PlainMessage.validateFilename(s);
  }

  @Test
  void defensiveCopies() throws Exception {
    var p = packet(Algorithm.AES_256_GCM);
    byte[] c = p.ciphertext();
    c[0] ^= 1;
    assertTrue(Identity.verifyPacket(p));
  }
}
