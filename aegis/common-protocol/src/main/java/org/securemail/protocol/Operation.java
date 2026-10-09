package org.securemail.protocol;

public enum Operation {
  REGISTER(1),
  LOGIN(2),
  FIND(3),
  PUBLISH(4),
  STORE(5),
  FETCH(6),
  ACK(7),
  LOGOUT(8),
  DELIVER(9),
  DELETE(10),
  CAPABILITIES(11),
  PROFILE_PUT(12),
  PROFILE_GET(13),
  CONTACT_PUT(14),
  CONTACT_GET(15);
  public final int code;

  Operation(int code) {
    this.code = code;
  }

  public static Operation fromCode(int code) {
    for (var o : values()) if (o.code == code) return o;
    throw new IllegalArgumentException("Bad operation");
  }
}
