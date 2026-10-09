package org.securemail.client.crypto;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import org.securemail.protocol.*;

/** Ed25519 identity. In 0.2.0 libsodium converts it to X25519 for sealed message keys. */
public final class Identity {
  private final KeyPair pair;

  public Identity(KeyPair p) {
    pair = p;
  }

  public static Identity create() throws GeneralSecurityException {
    return new Identity(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
  }

  public byte[] publicKey() {
    return pair.getPublic().getEncoded();
  }
  public PublicProfile profile(String nickname,long revision,boolean visible,String about,byte[] avatar)throws IOException,GeneralSecurityException{
    var p=new PublicProfile(userId(),nickname,revision,visible,visible?about:"",visible?avatar:new byte[0],publicKey(),new byte[0]);
    return new PublicProfile(p.userId(),p.nickname(),p.revision(),p.visible(),p.about(),p.avatar(),p.publicKey(),sign(p.signingBytes()));
  }
  public ContactAssertion consent(String target,long revision,boolean active)throws IOException,GeneralSecurityException{
    var a=new ContactAssertion(userId(),target,revision,active,publicKey(),new byte[0]);
    return new ContactAssertion(a.ownerId(),a.targetId(),a.revision(),a.active(),a.publicKey(),sign(a.signingBytes()));
  }

  public byte[] privateKey() {
    return pair.getPrivate().getEncoded();
  }

  public static Identity restore(byte[] pub, byte[] secret) throws GeneralSecurityException {
    var k = KeyFactory.getInstance("Ed25519");
    var i =
        new Identity(
            new KeyPair(
                k.generatePublic(new X509EncodedKeySpec(pub)),
                k.generatePrivate(new PKCS8EncodedKeySpec(secret))));
    byte[] probe = Secrets.random(32);
    if (!verify(pub, probe, i.sign(probe))) throw new GeneralSecurityException("Identity mismatch");
    return i;
  }

  public String userId() {
    return id(publicKey());
  }

  public static String id(byte[] pub) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(pub));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static String fingerprint(byte[] pub) {
    return id(pub).replaceAll("(.{8})(?!$)", "$1 ");
  }

  public byte[] sign(byte[] data) throws GeneralSecurityException {
    var s = Signature.getInstance("Ed25519");
    s.initSign(pair.getPrivate());
    s.update(data);
    return s.sign();
  }

  public static boolean verify(byte[] pub, byte[] data, byte[] signature) {
    try {
      if (signature.length != 64) return false;
      var s = Signature.getInstance("Ed25519");
      s.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pub)));
      s.update(data);
      return s.verify(signature);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  public static byte[] digest(EncryptedPacket p) throws IOException {
    try {
      var md = MessageDigest.getInstance("SHA-256");
      try (var o =
          new DataOutputStream(new DigestOutputStream(OutputStream.nullOutputStream(), md))) {
        PacketCodec.unsigned(o, p);
      }
      return md.digest();
    } catch (GeneralSecurityException e) {
      throw new IOException("Digest unavailable");
    }
  }

  public EncryptedPacket signPacket(EncryptedPacket p)
      throws GeneralSecurityException, IOException {
    return new EncryptedPacket(
        p.messageId(),
        p.senderId(),
        p.senderNickname(),
        p.recipientId(),
        p.createdAt(),
        p.deliveryDeadline(),
        p.ttlAfterDelivery(),
        p.algorithm(),
        p.salt(),
        p.nonce(),
        p.ciphertext(),
        p.senderPublicKey(),
        sign(digest(p)));
  }

  public static boolean verifyPacket(EncryptedPacket p) throws IOException {
    return id(p.senderPublicKey()).equals(p.senderId())
        && verify(p.senderPublicKey(), digest(p), p.signature());
  }

  public Receipt receipt(EncryptedPacket p, long time)
      throws IOException, GeneralSecurityException {
    var r = new Receipt(p.messageId(), digest(p), time, new byte[0]);
    return new Receipt(r.messageId(), r.packetDigest(), time, sign(r.signingBytes()));
  }

  public Route route(String onion, int port, long expires)
      throws IOException, GeneralSecurityException {
    var r = new Route(userId(), onion, port, expires, new byte[0]);
    return new Route(r.userId(), r.onionAddress(), port, expires, sign(r.signingBytes()));
  }
}
