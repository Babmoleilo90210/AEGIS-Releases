package org.securemail.client.crypto;

import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Clock;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.securemail.protocol.*;

public final class EncryptionService {
  private final Clock clock;

  public EncryptionService(Clock c) {
    clock = c;
  }

  public EncryptedPacket encrypt(
      PlainMessage message,
      char[] password,
      Algorithm a,
      long ttl,
      long deliveryWait,
      Identity identity,
      String nickname,
      String recipient)
      throws IOException, GeneralSecurityException {
    long now = clock.millis();
    byte[] salt = a == Algorithm.ENIGMA ? new byte[0] : Secrets.random(16),
        nonce = Secrets.random(a.nonceLength);
    var p =
        new EncryptedPacket(
            UUID.randomUUID().toString(),
            identity.userId(),
            Limits.nickname(nickname),
            recipient,
            now,
            Math.addExact(now, deliveryWait),
            ttl,
            a,
            salt,
            nonce,
            new byte[16],
            identity.publicKey(),
            new byte[0]);
    byte[] input = null, key = null, cipher;
    try {
      if (a == Algorithm.ENIGMA) {
        if (!message.filename().isEmpty())
          throw new IllegalArgumentException("Enigma не поддерживает вложения");
        cipher = Enigma.transform(message.text(), password).getBytes(StandardCharsets.US_ASCII);
      } else {
        input = message.encode();
        key = Secrets.derive(password, salt);
        byte[] aad = PacketCodec.associatedData(p);
        if (a == Algorithm.XCHACHA20_POLY1305) {
          byte[] all = new XChaCha20Poly1305(key).encrypt(input, aad);
          nonce = Arrays.copyOf(all, 24);
          cipher = Arrays.copyOfRange(all, 24, all.length);
        } else cipher = crypt(true, a, key, nonce, aad, input);
      }
      return identity.signPacket(
          new EncryptedPacket(
              p.messageId(),
              p.senderId(),
              p.senderNickname(),
              recipient,
              now,
              p.deliveryDeadline(),
              ttl,
              a,
              salt,
              nonce,
              cipher,
              identity.publicKey(),
              new byte[0]));
    } finally {
      if (input != null) Arrays.fill(input, (byte) 0);
      if (key != null) Arrays.fill(key, (byte) 0);
    }
  }

  public PlainMessage decrypt(EncryptedPacket p, char[] password, int maxFile)
      throws IOException, GeneralSecurityException {
    if (!Identity.verifyPacket(p)) throw new GeneralSecurityException("Неверная подпись письма");
    if (p.algorithm() == Algorithm.ENIGMA)
      return PlainMessage.text(
          Enigma.transform(new String(p.ciphertext(), StandardCharsets.US_ASCII), password));
    byte[] key = Secrets.derive(password, p.salt()), plain = null;
    try {
      byte[] aad = PacketCodec.associatedData(p);
      if (p.algorithm() == Algorithm.XCHACHA20_POLY1305) {
        byte[] c = p.ciphertext(), all = new byte[24 + c.length];
        System.arraycopy(p.nonce(), 0, all, 0, 24);
        System.arraycopy(c, 0, all, 24, c.length);
        plain = new XChaCha20Poly1305(key).decrypt(all, aad);
      } else plain = crypt(false, p.algorithm(), key, p.nonce(), aad, p.ciphertext());
      return PlainMessage.decode(plain, maxFile);
    } finally {
      Arrays.fill(key, (byte) 0);
      if (plain != null) Arrays.fill(plain, (byte) 0);
    }
  }

  private static byte[] crypt(
      boolean encrypt, Algorithm a, byte[] key, byte[] nonce, byte[] aad, byte[] input)
      throws GeneralSecurityException {
    if (a == Algorithm.CAMELLIA_256_GCM) {
      var c = GCMBlockCipher.newInstance(new CamelliaEngine());
      c.init(encrypt, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
      byte[] out = new byte[c.getOutputSize(input.length)];
      try {
        int n = c.processBytes(input, 0, input.length, out, 0);
        n += c.doFinal(out, n);
        return Arrays.copyOf(out, n);
      } catch (org.bouncycastle.crypto.InvalidCipherTextException e) {
        throw new AEADBadTagException("Authentication failed");
      } finally {
        Arrays.fill(out, (byte) 0);
        c.reset();
      }
    }
    var c =
        Cipher.getInstance(a == Algorithm.AES_256_GCM ? "AES/GCM/NoPadding" : "ChaCha20-Poly1305");
    c.init(
        encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, a == Algorithm.AES_256_GCM ? "AES" : "ChaCha20"),
        a == Algorithm.AES_256_GCM ? new GCMParameterSpec(128, nonce) : new IvParameterSpec(nonce));
    c.updateAAD(aad);
    return c.doFinal(input);
  }
}
