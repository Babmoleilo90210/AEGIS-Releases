package org.securemail.protocol;

import java.util.*;

public final class Limits {
  private Limits() {}

  public static final int VERSION = 1,
      MAGIC = 0x534d3031,
      DEFAULT_FILE_BYTES = 16 * 1024 * 1024,
      HARD_FILE_BYTES = 100 * 1024 * 1024,
      PAYLOAD_OVERHEAD = 128 * 1024,
      TEXT_BYTES = 64 * 1024;
  public static final long MAX_TTL_SECONDS = 7 * 86400, MAX_DELIVERY_MILLIS = 7 * 86400_000L;

  public static String nickname(String s) {
    if (s == null || !s.matches("[A-Za-z0-9_]{3,32}"))
      throw new IllegalArgumentException("Nickname: 3–32 латинских букв, цифр или _");
    return s.toLowerCase(Locale.ROOT);
  }

  public static String userId(String s) {
    if (s == null || !s.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Bad user ID");
    return s;
  }

  public static String messageId(String s) {
    if (s == null || !UUID.fromString(s).toString().equals(s))
      throw new IllegalArgumentException("Bad message ID");
    return s;
  }

  public static String onion(String s) {
    if (s == null || !s.matches("[a-z2-7]{56}\\.onion"))
      throw new IllegalArgumentException("Требуется адрес onion v3");
    return s;
  }
}
