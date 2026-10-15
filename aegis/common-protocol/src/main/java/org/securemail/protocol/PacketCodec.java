package org.securemail.protocol;

import java.io.*;

public final class PacketCodec {
  private PacketCodec() {}

  public static void metadata(DataOutput out, EncryptedPacket p) throws IOException {
    Binary.header(out);
    Binary.text(out, p.messageId());
    Binary.text(out, p.senderId());
    Binary.text(out, p.senderNickname());
    Binary.text(out, p.recipientId());
    out.writeLong(p.createdAt());
    out.writeLong(p.deliveryDeadline());
    out.writeLong(p.ttlAfterDelivery());
    out.writeInt(p.algorithm().code);
    Binary.bytes(out, p.salt());
    Binary.bytes(out, p.senderPublicKey());
  }

  public static byte[] associatedData(EncryptedPacket p) throws IOException {
    return Binary.encode(out -> metadata(out, p));
  }

  public static void unsigned(DataOutput out, EncryptedPacket p) throws IOException {
    metadata(out, p);
    Binary.bytes(out, p.nonce());
    Binary.bytes(out, p.ciphertext());
  }

  public static void write(DataOutput out, EncryptedPacket p) throws IOException {
    unsigned(out, p);
    Binary.bytes(out, p.signature());
  }

  public static byte[] encode(EncryptedPacket p) throws IOException {
    return Binary.encode(out -> write(out, p));
  }

  public static EncryptedPacket read(DataInput in, int max) throws IOException {
    try {
      Binary.header(in);
      String id = Binary.text(in, 36),
          sender = Binary.text(in, 64),
          nick = Binary.text(in, 32),
          recipient = Binary.text(in, 64);
      long created = in.readLong(), deadline = in.readLong(), ttl = in.readLong();
      Algorithm a = Algorithm.fromCode(in.readInt());
      byte[] salt = Binary.bytes(in, 16),
          pub = Binary.bytes(in, 44),
          nonce = Binary.bytes(in, 24),
          cipher =
              Binary.bytes(in, Math.min(max, Limits.HARD_FILE_BYTES + Limits.PAYLOAD_OVERHEAD)),
          sig = Binary.bytes(in, 64);
      if (sig.length != 64) throw new IOException("Missing signature");
      return new EncryptedPacket(
          id, sender, nick, recipient, created, deadline, ttl, a, salt, nonce, cipher, pub, sig);
    } catch (IllegalArgumentException e) {
      throw new IOException("Malformed packet");
    }
  }

  public static EncryptedPacket decode(byte[] b, int max) throws IOException {
    try (var in = new DataInputStream(new ByteArrayInputStream(b))) {
      var p = read(in, max);
      Binary.end(in);
      return p;
    }
  }
}
