package org.securemail.client.attachments600;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StreamingAttachmentCipherTest {
  @TempDir Path directory;
  private static final String A = "a".repeat(64), B = "b".repeat(64);
  private StreamingAttachmentCipher.Context context(long size) { return new StreamingAttachmentCipher.Context(UUID.randomUUID().toString(), A, B, size); }
  private record Encrypted(byte[] key, StreamingAttachmentCipher.Context context, byte[] ciphertext, StreamingAttachmentCipher.Result result) {}
  private Encrypted encrypt(int size) throws Exception {
    byte[] key = StreamingAttachmentCipher.newFileKey(), input = new byte[size]; new Random(4).nextBytes(input);
    var context = context(size); var bytes = new ByteArrayOutputStream();
    var result = StreamingAttachmentCipher.encrypt(new ByteArrayInputStream(input), bytes, context, key, () -> true);
    return new Encrypted(key, context, bytes.toByteArray(), result);
  }
  private void decrypt(Encrypted value, byte[] cipher, StreamingAttachmentCipher.Context context, Path target) throws Exception {
    StreamingAttachmentCipher.decryptToNewFile(new ByteArrayInputStream(cipher), target, context, value.key(), value.result().plaintextSha256(), value.result().ciphertextSha256(), () -> true);
  }
  @Test void actualTinkRoundTripCrossesSegmentsAndNoWholeFileBuffers() throws Exception {
    var value = encrypt(3 * 1024 * 1024 + 17); Path file = directory.resolve("получено.bin"); decrypt(value, value.ciphertext(), value.context(), file);
    assertEquals(value.context().plaintextBytes(), Files.size(file)); assertEquals(StreamingAttachmentCipher.ciphertextSize(Files.size(file)), value.ciphertext().length);
    assertTrue(Files.getPosixFilePermissions(file).stream().noneMatch(p -> p.name().startsWith("OTHERS_") || p.name().startsWith("GROUP_")));
  }
  @Test void emptyFileHasAuthenticatedFinalSegment() throws Exception { var value = encrypt(0); Path file = directory.resolve("empty"); decrypt(value, value.ciphertext(), value.context(), file); assertEquals(0, Files.size(file)); }
  @Test void modifiedCiphertextNeverPublishesPartialPlaintext() throws Exception {
    var value = encrypt(2 * 1024 * 1024 + 33); byte[] changed = value.ciphertext().clone(); changed[changed.length - 1] ^= 1; Path target = directory.resolve("bad");
    assertThrows(IOException.class, () -> decrypt(value, changed, value.context(), target)); assertFalse(Files.exists(target));
    try (var entries = Files.list(directory)) { assertEquals(0, entries.count()); }
  }
  @Test void truncatedFinalSegmentRejectedAfterEarlierAuthenticatedSegments() throws Exception {
    var value = encrypt(3 * 1024 * 1024); byte[] cut = Arrays.copyOf(value.ciphertext(), 2 * 1024 * 1024); Path target = directory.resolve("truncated");
    assertThrows(IOException.class, () -> decrypt(value, cut, value.context(), target)); assertFalse(Files.exists(target));
  }
  @Test void reorderedSegmentsAndWrongRecipientAreRejected() throws Exception {
    var value = encrypt(4 * 1024 * 1024); byte[] reordered = value.ciphertext().clone(); int n = 1024 * 1024;
    System.arraycopy(value.ciphertext(), n * 2, reordered, n, n); System.arraycopy(value.ciphertext(), n, reordered, n * 2, n);
    assertThrows(IOException.class, () -> decrypt(value, reordered, value.context(), directory.resolve("reordered")));
    var wrong = new StreamingAttachmentCipher.Context(value.context().transferId(), A, "c".repeat(64), value.context().plaintextBytes());
    assertThrows(IOException.class, () -> decrypt(value, value.ciphertext(), wrong, directory.resolve("wrong")));
  }
  @Test void encryptionIsRandomizedAndInputSizeCannotLie() throws Exception {
    byte[] key = StreamingAttachmentCipher.newFileKey(), input = new byte[33]; var c = context(33); var a = new ByteArrayOutputStream(); var b = new ByteArrayOutputStream();
    StreamingAttachmentCipher.encrypt(new ByteArrayInputStream(input), a, c, key, () -> true); StreamingAttachmentCipher.encrypt(new ByteArrayInputStream(input), b, c, key, () -> true);
    assertFalse(Arrays.equals(a.toByteArray(), b.toByteArray()));
    assertThrows(IOException.class, () -> StreamingAttachmentCipher.encrypt(new ByteArrayInputStream(input), new ByteArrayOutputStream(), context(34), key, () -> true));
    assertThrows(IOException.class, () -> StreamingAttachmentCipher.encrypt(new ByteArrayInputStream(input), new ByteArrayOutputStream(), context(32), key, () -> true));
  }
  @Test void revocationStopsEncryptionAndDecryptionBeforePublication() throws Exception {
    var calls = new AtomicInteger(); byte[] key = StreamingAttachmentCipher.newFileKey();
    assertThrows(IOException.class, () -> StreamingAttachmentCipher.encrypt(new ByteArrayInputStream(new byte[1024 * 1024]), new ByteArrayOutputStream(), context(1024 * 1024), key, () -> calls.incrementAndGet() < 4));
    var value = encrypt(3 * 1024 * 1024); calls.set(0); Path target = directory.resolve("revoked");
    assertThrows(IOException.class, () -> StreamingAttachmentCipher.decryptToNewFile(new ByteArrayInputStream(value.ciphertext()), target, value.context(), value.key(), value.result().plaintextSha256(), value.result().ciphertextSha256(), () -> calls.incrementAndGet() < 7));
    assertFalse(Files.exists(target));
  }
  @Test void rejectsOversizeBadKeyAndTraversalIdentifier() {
    assertThrows(IllegalArgumentException.class, () -> context(StreamingAttachmentCipher.MAX_PLAINTEXT + 1));
    assertThrows(IllegalArgumentException.class, () -> new StreamingAttachmentCipher.Context("../bad", A, B, 1));
    assertThrows(Exception.class, () -> StreamingAttachmentCipher.encrypt(new ByteArrayInputStream(new byte[1]), new ByteArrayOutputStream(), context(1), new byte[31], () -> true));
  }
  @Test void existingDestinationAndParentSymlinkCannotBeOverwritten() throws Exception {
    var value = encrypt(33); Path target = directory.resolve("existing"); Files.writeString(target, "unchanged");
    assertThrows(IOException.class, () -> decrypt(value, value.ciphertext(), value.context(), target)); assertEquals("unchanged", Files.readString(target));
    Path link = directory.resolve("alias"); Files.createSymbolicLink(link, directory);
    assertThrows(IOException.class, () -> decrypt(value, value.ciphertext(), value.context(), link.resolve("not-created")));
  }
}
