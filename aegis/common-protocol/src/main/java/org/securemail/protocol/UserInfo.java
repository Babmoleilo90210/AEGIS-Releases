package org.securemail.protocol;

import java.io.*;

public record UserInfo(String userId, String nickname, byte[] publicKey, Route route) {
  public UserInfo {
    Limits.userId(userId);
    nickname = Limits.nickname(nickname);
    if (publicKey.length != 44) throw new IllegalArgumentException("Invalid public key");
    publicKey = publicKey.clone();
  }

  @Override
  public byte[] publicKey() {
    return publicKey.clone();
  }

  public void write(DataOutput o) throws IOException {
    Binary.text(o, userId);
    Binary.text(o, nickname);
    Binary.bytes(o, publicKey);
    o.writeBoolean(route != null);
    if (route != null) route.write(o);
  }

  public static UserInfo read(DataInput i) throws IOException {
    try {
      return new UserInfo(
          Binary.text(i, 64),
          Binary.text(i, 32),
          Binary.bytes(i, 44),
          i.readBoolean() ? Route.read(i) : null);
    } catch (IllegalArgumentException e) {
      throw new IOException("Bad user");
    }
  }
}
