package org.securemail.protocol;

import java.io.*;

public record Receipt(String messageId, byte[] packetDigest, long deliveredAt, byte[] signature) {
  public Receipt {
    Limits.messageId(messageId);
    if (packetDigest.length != 32
        || deliveredAt <= 0
        || (signature.length != 0 && signature.length != 64))
      throw new IllegalArgumentException("Invalid ACK");
    packetDigest = packetDigest.clone();
    signature = signature.clone();
  }

  @Override
  public byte[] packetDigest() {
    return packetDigest.clone();
  }

  @Override
  public byte[] signature() {
    return signature.clone();
  }

  public byte[] signingBytes() throws IOException {
    return Binary.encode(
        o -> {
          Binary.text(o, "secure-mail/ack/v1");
          Binary.text(o, messageId);
          Binary.bytes(o, packetDigest);
          o.writeLong(deliveredAt);
        });
  }

  public void write(DataOutput o) throws IOException {
    Binary.text(o, messageId);
    Binary.bytes(o, packetDigest);
    o.writeLong(deliveredAt);
    Binary.bytes(o, signature);
  }

  public static Receipt read(DataInput i) throws IOException {
    try {
      return new Receipt(
          Binary.text(i, 36), Binary.bytes(i, 32), i.readLong(), Binary.bytes(i, 64));
    } catch (IllegalArgumentException e) {
      throw new IOException("Bad ACK");
    }
  }

  @Override
  public String toString() {
    return "Receipt[redacted]";
  }
}
