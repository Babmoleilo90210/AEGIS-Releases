package org.securemail.protocol;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;

/** Bounded fields, strict UTF-8; never Java object serialization. */
public final class Binary {
  private Binary() {}

  public static void bytes(DataOutput out, byte[] b) throws IOException {
    out.writeInt(b.length);
    out.write(b);
  }

  public static byte[] bytes(DataInput in, int max) throws IOException {
    int n = in.readInt();
    if (n < 0 || n > max) throw new IOException("Invalid field length");
    byte[] b = new byte[n];
    in.readFully(b);
    return b;
  }

  public static void text(DataOutput out, String s) throws IOException {
    bytes(out, s.getBytes(StandardCharsets.UTF_8));
  }

  public static String text(DataInput in, int max) throws IOException {
    return StandardCharsets.UTF_8
        .newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes(in, max)))
        .toString();
  }

  @FunctionalInterface
  public interface Writer {
    void write(DataOutputStream out) throws IOException;
  }

  public static byte[] encode(Writer w) throws IOException {
    var b = new ByteArrayOutputStream();
    try (var o = new DataOutputStream(b)) {
      w.write(o);
    }
    return b.toByteArray();
  }

  public static void header(DataOutput out) throws IOException {
    out.writeInt(Limits.MAGIC);
    out.writeInt(Limits.VERSION);
  }

  public static void header(DataInput in) throws IOException {
    if (in.readInt() != Limits.MAGIC || in.readInt() != Limits.VERSION)
      throw new IOException("Unsupported protocol");
  }

  public static void end(DataInputStream in) throws IOException {
    if (in.available() != 0) throw new IOException("Trailing bytes");
  }
}
