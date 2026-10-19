package org.securemail.attachments;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.attachments600.StreamingAttachmentCipher;
import org.securemail.attachments.protocol.AttachmentProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Actual 500 MiB local encrypted store/restart/resume/read/decrypt test; NOT network/Tor. */
class LargeAttachmentStore600Test {
  @TempDir Path home;
  @Test void fiveHundredMiBEncryptedObjectResumesAcrossStoreRestartWithBoundedHeap() throws Exception {
    long start = System.nanoTime(), size = StreamingAttachmentCipher.MAX_PLAINTEXT; String a = "a".repeat(64), b = "b".repeat(64), id = UUID.randomUUID().toString();
    var context = new StreamingAttachmentCipher.Context(id, a, b, size); byte[] key = StreamingAttachmentCipher.newFileKey(); Path encrypted = home.resolve("ciphertext.spool"), downloaded = home.resolve("downloaded.spool"), restored = home.resolve("restored.bin"); StreamingAttachmentCipher.Result result;
    try (InputStream input = new Pattern(size); OutputStream out = Files.newOutputStream(encrypted, StandardOpenOption.CREATE_NEW)) { result = StreamingAttachmentCipher.encrypt(input, out, context, key, () -> true); }
    var manifest = new AttachmentStore.Manifest(id, a, b, result.ciphertextBytes(), result.ciphertextSha256(), AttachmentStore.MAX_PENDING_TTL);
    var sender = auth(a); var recipient = auth(b); AttachmentStore store = new AttachmentStore(home.resolve("server"), Clock.systemUTC(), AttachmentStore.Quotas.defaults()); byte[] chunk = new byte[AttachmentStore.CHUNK_BYTES];
    try {
      store.begin(sender, manifest);
      try (InputStream input = Files.newInputStream(encrypted)) {
        for (int index = 0; index < manifest.chunks(); index++) {
          int expected = manifest.chunkLength(index); int n = input.readNBytes(chunk, 0, expected); assertEquals(expected, n); MessageDigest digest = MessageDigest.getInstance("SHA-256"); digest.update(chunk, 0, n); String hash = HexFormat.of().formatHex(digest.digest());
          store.putChunk(sender, id, index, hash, new ByteArrayInputStream(chunk, 0, n));
          if (index == 1) { store.close(); store = new AttachmentStore(home.resolve("server"), Clock.systemUTC(), AttachmentStore.Quotas.defaults()); assertEquals(List.of(0, 1), store.status(sender, id).present()); }
        }
      }
      store.commit(sender, id); assertEquals(result.ciphertextBytes(), store.reservedBytes());
      try (OutputStream out = Files.newOutputStream(downloaded, StandardOpenOption.CREATE_NEW)) { for (int index = 0; index < manifest.chunks(); index++) store.writeChunk(recipient, id, index, out); }
      try (InputStream in = Files.newInputStream(downloaded)) { assertEquals(result, StreamingAttachmentCipher.decryptToNewFile(in, restored, context, key, result.plaintextSha256(), result.ciphertextSha256(), () -> true)); }
      assertEquals(size, Files.size(restored)); store.acknowledge(recipient, id); assertEquals(0, store.reservedBytes());
      System.out.println("{\"scope\":\"actual-local-500MiB-crypto-store-restart-resume-read-decrypt-not-Tor\",\"plaintextBytes\":" + size + ",\"ciphertextBytes\":" + result.ciphertextBytes() + ",\"chunks\":" + manifest.chunks() + ",\"heapMaxBytes\":" + Runtime.getRuntime().maxMemory() + ",\"durationMillis\":" + (System.nanoTime() - start) / 1_000_000 + "}");
    } finally { Arrays.fill(key, (byte) 0); Arrays.fill(chunk, (byte) 0); store.close(); }
  }
  private static AttachmentStore.Authorization auth(String id) throws Exception {
    long now = System.currentTimeMillis(); byte[] app = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();
    var cap = new IdentityProtocol.Capability("d".repeat(64), id, "e".repeat(64), IdentityProtocol.App.MAIL, 1, IdentityProtocol.nonce(), now, now + 3600_000, now, app, EnumSet.of(IdentityProtocol.Scope.MAIL_READ, IdentityProtocol.Scope.MAIL_SEND), new byte[64]);
    return new AttachmentStore.Authorization(new IdentityProtocol.VerifiedContext(cap), () -> {});
  }
  private static final class Pattern extends InputStream { long remaining, offset; Pattern(long bytes) { remaining = bytes; } @Override public int read() { if (remaining == 0) return -1; remaining--; return (int) ((offset++ * 37 + 19) & 255); } @Override public int read(byte[] b, int off, int len) { if (remaining == 0) return -1; int n = (int) Math.min(len, remaining); for (int i = 0; i < n; i++) b[off + i] = (byte) (offset++ * 37 + 19); remaining -= n; return n; } }
}
