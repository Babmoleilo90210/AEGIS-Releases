package org.securemail.relay;

import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import org.securemail.protocol.*;

/** Public signature verification only. */
final class Signatures {
  private Signatures() {}

  static String id(byte[] pub) throws GeneralSecurityException {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(pub));
  }

  static boolean verify(byte[] pub, byte[] data, byte[] sig) {
    try {
      if (sig.length != 64) return false;
      var s = Signature.getInstance("Ed25519");
      s.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pub)));
      s.update(data);
      return s.verify(sig);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  static byte[] digest(EncryptedPacket p) throws IOException, GeneralSecurityException {
    var d = MessageDigest.getInstance("SHA-256");
    try (var o = new DataOutputStream(new DigestOutputStream(OutputStream.nullOutputStream(), d))) {
      PacketCodec.unsigned(o, p);
    }
    return d.digest();
  }
}
