package org.securemail.client.attachments600;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Actual 500 MiB stream, intended to run in a separate JVM with -Xmx96m. */
class LargeStreamingAttachment600Test {
  @TempDir Path directory;
  @Test void authenticatesFiveHundredMiBWithNinetySixMiBHeap() throws Exception {
    long size = StreamingAttachmentCipher.MAX_PLAINTEXT;
    var context = new StreamingAttachmentCipher.Context(UUID.randomUUID().toString(), "a".repeat(64), "b".repeat(64), size);
    byte[] key = StreamingAttachmentCipher.newFileKey(); Path encrypted = directory.resolve("encrypted.spool"), decrypted = directory.resolve("restored.bin");
    StreamingAttachmentCipher.Result result; long start = System.nanoTime();
    try (InputStream source = new PatternInput(size); OutputStream out = Files.newOutputStream(encrypted, StandardOpenOption.CREATE_NEW)) {
      result = StreamingAttachmentCipher.encrypt(source, out, context, key, () -> true);
    }
    assertEquals(size, result.plaintextBytes()); assertEquals(result.ciphertextBytes(), Files.size(encrypted));
    try (InputStream in = Files.newInputStream(encrypted)) {
      var restored = StreamingAttachmentCipher.decryptToNewFile(in, decrypted, context, key, result.plaintextSha256(), result.ciphertextSha256(), () -> true);
      assertEquals(result, restored);
    } finally { Arrays.fill(key, (byte) 0); }
    assertEquals(size, Files.size(decrypted));
    System.out.println("{\"scope\":\"actual-local-Tink-stream-not-Tor\",\"plaintextBytes\":" + size + ",\"ciphertextBytes\":" + result.ciphertextBytes() + ",\"heapMaxBytes\":" + Runtime.getRuntime().maxMemory() + ",\"durationMillis\":" + ((System.nanoTime() - start) / 1_000_000) + "}");
  }
  private static final class PatternInput extends InputStream {
    private final long limit; private long position; PatternInput(long limit) { this.limit = limit; }
    @Override public int read() { return position == limit ? -1 : (int) ((position++ * 17 + 29) & 255); }
    @Override public int read(byte[] bytes, int offset, int length) {
      if (position == limit) return -1; int count = (int) Math.min(length, limit - position);
      for (int i = 0; i < count; i++) bytes[offset + i] = (byte) ((position++ * 17 + 29) & 255); return count;
    }
  }
}
