package org.securemail.protocol;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import org.junit.jupiter.api.Test;

class WireTest {
  @Test
  void oversizedLengthRejectedBeforeAllocation() throws Exception {
    for (int n : new int[] {-1, Integer.MAX_VALUE, 1025}) {
      byte[] b = Binary.encode(o -> o.writeInt(n));
      assertThrows(
          IOException.class,
          () -> Binary.bytes(new DataInputStream(new ByteArrayInputStream(b)), 1024));
    }
  }

  @Test
  void unsupportedVersionRejected() throws Exception {
    byte[] b =
        Binary.encode(
            o -> {
              o.writeInt(Limits.MAGIC);
              o.writeInt(999);
            });
    assertThrows(
        IOException.class, () -> Binary.header(new DataInputStream(new ByteArrayInputStream(b))));
  }

  @Test
  void strictUtf8() throws Exception {
    byte[] b = Binary.encode(o -> Binary.bytes(o, new byte[] {(byte) 0xc0, (byte) 0xaf}));
    assertThrows(
        IOException.class, () -> Binary.text(new DataInputStream(new ByteArrayInputStream(b)), 20));
  }

  @Test
  void onlyOnionV3() {
    for (String s :
        new String[] {
          "example.com",
          "127.0.0.1",
          "http://example.com",
          "short.onion",
          "a".repeat(56) + ".onion.evil"
        }) assertThrows(IllegalArgumentException.class, () -> Limits.onion(s));
    assertEquals("a".repeat(56) + ".onion", Limits.onion("a".repeat(56) + ".onion"));
  }
}
