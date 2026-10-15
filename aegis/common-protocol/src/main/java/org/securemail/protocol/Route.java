package org.securemail.protocol;

import java.io.*;

public record Route(
    String userId, String onionAddress, int port, long expiresAt, byte[] signature) {
  public Route {
    Limits.userId(userId);
    Limits.onion(onionAddress);
    if (port < 1
        || port > 65535
        || expiresAt <= 0
        || (signature.length != 0 && signature.length != 64))
      throw new IllegalArgumentException("Invalid route");
    signature = signature.clone();
  }

  @Override
  public byte[] signature() {
    return signature.clone();
  }

  public byte[] signingBytes() throws IOException {
    return Binary.encode(
        o -> {
          Binary.text(o, "secure-mail/route/v1");
          Binary.text(o, userId);
          Binary.text(o, onionAddress);
          o.writeInt(port);
          o.writeLong(expiresAt);
        });
  }

  public void write(DataOutput o) throws IOException {
    Binary.text(o, userId);
    Binary.text(o, onionAddress);
    o.writeInt(port);
    o.writeLong(expiresAt);
    Binary.bytes(o, signature);
  }

  public static Route read(DataInput i) throws IOException {
    try {
      return new Route(
          Binary.text(i, 64), Binary.text(i, 62), i.readInt(), i.readLong(), Binary.bytes(i, 64));
    } catch (IllegalArgumentException e) {
      throw new IOException("Bad route");
    }
  }
}
