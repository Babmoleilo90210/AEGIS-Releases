package org.securemail.attachments;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.attachments.protocol.AttachmentProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol;

class AttachmentStoreTest {
  @TempDir Path home;
  MutableClock clock = new MutableClock(); AttachmentStore store; AttachmentStore.Authorization sender, recipient, stranger;
  private static final String A = "a".repeat(64), B = "b".repeat(64), C = "c".repeat(64);
  @BeforeEach void open() throws Exception { store = new AttachmentStore(home.resolve("store"), clock, AttachmentStore.Quotas.defaults()); sender = auth(A, () -> {}); recipient = auth(B, () -> {}); stranger = auth(C, () -> {}); }
  @AfterEach void close() throws Exception { store.close(); }
  static AttachmentStore.Authorization auth(String account, AttachmentStore.FreshCheck check) throws Exception {
    byte[] key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();
    var cap = new IdentityProtocol.Capability("d".repeat(64), account, "e".repeat(64), IdentityProtocol.App.MAIL, 1, IdentityProtocol.nonce(), 1_799_999_000_000L, 1_800_001_000_000L, 1_799_999_000_000L, key, EnumSet.of(IdentityProtocol.Scope.MAIL_READ, IdentityProtocol.Scope.MAIL_SEND), new byte[64]);
    return new AttachmentStore.Authorization(new IdentityProtocol.VerifiedContext(cap), check);
  }
  AttachmentStore.Manifest manifest(byte[] bytes) { return new AttachmentStore.Manifest(UUID.randomUUID().toString(), A, B, bytes.length, AttachmentProtocol.sha256(bytes), AttachmentStore.MAX_PENDING_TTL); }
  void upload(AttachmentStore.Manifest m, byte[] bytes) throws Exception { store.begin(sender, m); for (int i = 0; i < m.chunks(); i++) { byte[] part = Arrays.copyOfRange(bytes, i * AttachmentStore.CHUNK_BYTES, i * AttachmentStore.CHUNK_BYTES + m.chunkLength(i)); store.putChunk(sender, m.id(), i, AttachmentProtocol.sha256(part), new ByteArrayInputStream(part)); } store.commit(sender, m.id()); }
  @Test void immutableResumableChunksSurviveRestartAndAckFreesQuota() throws Exception {
    byte[] bytes = new byte[2 * AttachmentStore.CHUNK_BYTES + 17]; new Random(3).nextBytes(bytes); var m = manifest(bytes); store.begin(sender, m);
    byte[] first = Arrays.copyOf(bytes, AttachmentStore.CHUNK_BYTES); store.putChunk(sender, m.id(), 0, AttachmentProtocol.sha256(first), new ByteArrayInputStream(first)); store.close(); store = new AttachmentStore(home.resolve("store"), clock, AttachmentStore.Quotas.defaults());
    assertEquals(List.of(0), store.status(sender, m.id()).present()); store.begin(sender, m); assertEquals(bytes.length, store.reservedBytes());
    store.putChunk(sender, m.id(), 0, AttachmentProtocol.sha256(first), new ByteArrayInputStream(first));
    for (int i = 1; i < m.chunks(); i++) { byte[] part = Arrays.copyOfRange(bytes, i * AttachmentStore.CHUNK_BYTES, i * AttachmentStore.CHUNK_BYTES + m.chunkLength(i)); store.putChunk(sender, m.id(), i, AttachmentProtocol.sha256(part), new ByteArrayInputStream(part)); }
    store.commit(sender, m.id()); var result = new ByteArrayOutputStream(); for (int i = 0; i < m.chunks(); i++) store.writeChunk(recipient, m.id(), i, result); assertArrayEquals(bytes, result.toByteArray());
    assertThrows(IOException.class, () -> store.acknowledge(sender, m.id())); store.acknowledge(recipient, m.id()); assertEquals(0, store.reservedBytes()); assertEquals(0, store.transferCount());
  }
  @Test void duplicateConflictAndChangedManifestCannotOverwrite() throws Exception {
    byte[] bytes = new byte[100]; var m = manifest(bytes); store.begin(sender, m); store.putChunk(sender, m.id(), 0, AttachmentProtocol.sha256(bytes), new ByteArrayInputStream(bytes));
    byte[] altered = bytes.clone(); altered[1] = 1; assertThrows(IOException.class, () -> store.putChunk(sender, m.id(), 0, AttachmentProtocol.sha256(altered), new ByteArrayInputStream(altered)));
    var changed = new AttachmentStore.Manifest(m.id(), A, C, m.ciphertextBytes(), m.ciphertextSha256(), m.ttlMillis()); assertThrows(IOException.class, () -> store.begin(sender, changed)); store.commit(sender, m.id());
  }
  @Test void oversizedUndersizedAndWrongDigestDoNotBecomeStoredChunks() throws Exception {
    byte[] bytes = new byte[100]; var m = manifest(bytes); store.begin(sender, m);
    assertThrows(IOException.class, () -> store.putChunk(sender, m.id(), 0, AttachmentProtocol.sha256(bytes), new ByteArrayInputStream(new byte[101])));
    assertThrows(IOException.class, () -> store.putChunk(sender, m.id(), 0, AttachmentProtocol.sha256(bytes), new ByteArrayInputStream(new byte[99])));
    assertThrows(IOException.class, () -> store.putChunk(sender, m.id(), 0, "0".repeat(64), new ByteArrayInputStream(bytes)));
    assertEquals(List.of(), store.status(sender, m.id()).present()); assertThrows(IOException.class, () -> store.commit(sender, m.id()));
  }
  @Test void noRecipientMetadataBeforeCommitAndNoForeignAccessOrWrite() throws Exception {
    byte[] bytes = new byte[100]; var m = manifest(bytes); store.begin(sender, m);
    assertThrows(IOException.class, () -> store.status(recipient, m.id())); assertThrows(IOException.class, () -> store.status(stranger, m.id())); assertThrows(IOException.class, () -> store.abort(stranger, m.id()));
    store.putChunk(sender, m.id(), 0, AttachmentProtocol.sha256(bytes), new ByteArrayInputStream(bytes)); store.commit(sender, m.id()); assertTrue(store.status(recipient, m.id()).committed()); assertThrows(IOException.class, () -> store.writeChunk(stranger, m.id(), 0, new ByteArrayOutputStream()));
  }
  @Test void expiryAndClockRollbackNeverExtendThirtyDayDeadline() throws Exception {
    byte[] bytes = new byte[100]; var m = manifest(bytes); upload(m, bytes); long initial = store.status(sender, m.id()).expiresAt(); assertEquals(created(m.id()) + AttachmentStore.MAX_PENDING_TTL, initial);
    clock.value = initial + 1; assertEquals(1, store.cleanup(1)); clock.value -= 10 * 86400_000L; assertThrows(IOException.class, () -> store.status(sender, m.id())); assertEquals(0, store.reservedBytes());
  }
  @Test void partialUploadsExpireWithinOneDayAndAbortIsBoundToSender() throws Exception {
    var m = manifest(new byte[100]); store.begin(sender, m); assertEquals(created(m.id()) + AttachmentStore.PARTIAL_TTL, store.status(sender, m.id()).expiresAt());
    assertThrows(IOException.class, () -> store.abort(recipient, m.id())); store.abort(sender, m.id()); assertEquals(0, store.reservedBytes());
  }
  @Test void quotasReserveFullDeclaredSizeAtomicallyAndCannotDoubleCountRetry() throws Exception {
    store.close(); store = new AttachmentStore(home.resolve("quota"), clock, new AttachmentStore.Quotas(AttachmentStore.MAX_CIPHERTEXT, AttachmentStore.MAX_CIPHERTEXT, 0, 2, 2));
    var one = new AttachmentStore.Manifest(UUID.randomUUID().toString(), A, B, AttachmentStore.MAX_CIPHERTEXT, "0".repeat(64), 60000); store.begin(sender, one); store.begin(sender, one); assertEquals(AttachmentStore.MAX_CIPHERTEXT, store.reservedBytes());
    assertThrows(IOException.class, () -> store.begin(sender, manifest(new byte[100]))); store.abort(sender, one.id()); assertEquals(0, store.reservedBytes());
  }
  @Test void committedFilesReleaseConcurrentSlotsWhileRetainedObjectsStayBounded() throws Exception {
    byte[] bytes=new byte[100];var first=manifest(bytes);var second=manifest(bytes);var third=manifest(bytes);store.begin(sender,first);store.begin(sender,second);
    assertThrows(IOException.class,()->store.begin(sender,third));store.putChunk(sender,first.id(),0,AttachmentProtocol.sha256(bytes),new ByteArrayInputStream(bytes));store.commit(sender,first.id());
    store.begin(sender,third);store.abort(sender,second.id());store.abort(sender,third.id());
    for(int i=1;i<128;i++)upload(manifest(bytes),bytes);
    assertEquals(128,store.transferCount());assertEquals(12800,store.reservedBytes());assertThrows(IOException.class,()->store.begin(sender,manifest(bytes)));
  }
  @Test void pathTraversalSymlinkAndTwoProcessOpenAreRejected() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> new AttachmentStore.Manifest("../outside", A, B, 100, "0".repeat(64), 60000));
    assertThrows(IOException.class, () -> new AttachmentStore(home.resolve("store"), clock, AttachmentStore.Quotas.defaults()));
    var m = manifest(new byte[100]); store.begin(sender, m); Path target = home.resolve("store/objects").resolve(m.id()).resolve("0000.chunk"); Path outside = home.resolve("outside"); Files.writeString(outside, "keep"); Files.createSymbolicLink(target, outside);
    assertThrows(IOException.class, () -> store.putChunk(sender, m.id(), 0, AttachmentProtocol.sha256(new byte[100]), new ByteArrayInputStream(new byte[100]))); assertEquals("keep", Files.readString(outside));
  }
  @Test void authorityIsRecheckedDuringWriteAndNoChunkPublishedAfterRevoke() throws Exception {
    var calls = new AtomicInteger(); var restricted = auth(A, () -> { if (calls.incrementAndGet() >= 8) throw new IOException("revoked"); }); byte[] bytes = new byte[AttachmentStore.CHUNK_BYTES]; var m = manifest(bytes); store.begin(sender, m);
    assertThrows(IOException.class, () -> store.putChunk(restricted, m.id(), 0, AttachmentProtocol.sha256(bytes), new ByteArrayInputStream(bytes))); assertEquals(List.of(), store.status(sender, m.id()).present());
  }
  @Test void modifiedOnDiskChunkAndIncompleteCommitAreRejected() throws Exception {
    byte[] bytes = new byte[100]; var m = manifest(bytes); upload(m, bytes); Path chunk = home.resolve("store/objects").resolve(m.id()).resolve("0000.chunk"); byte[] altered = bytes.clone(); altered[99] = 1; Files.write(chunk, altered); var out = new ByteArrayOutputStream(); assertThrows(IOException.class, () -> store.writeChunk(recipient, m.id(), 0, out)); assertEquals(0, out.size());
  }
  @Test void canonicalFrameRejectsTrailingBytesAndChangedOperationFields() throws Exception {
    var request = AttachmentProtocol.Request.create(UUID.randomUUID().toString(), B, 100, "0".repeat(64), 60000); assertEquals(request, AttachmentProtocol.decode(request.encode()));
    byte[] extra = Arrays.copyOf(request.encode(), request.encode().length + 1); assertThrows(IOException.class, () -> AttachmentProtocol.decode(extra));
    assertThrows(IllegalArgumentException.class, () -> AttachmentProtocol.Request.put(request.transferId(), 0, AttachmentStore.CHUNK_BYTES + 1, "0".repeat(64)));
  }
  private long created(String id) throws Exception { try (var db = java.sql.DriverManager.getConnection("jdbc:sqlite:" + home.resolve("store/attachments.sqlite")); var q = db.prepareStatement("SELECT created FROM transfers WHERE id=?")) { q.setString(1, id); try (var r = q.executeQuery()) { assertTrue(r.next()); return r.getLong(1); } } }
  static final class MutableClock extends Clock { long value = 1_800_000_000_000L; public ZoneId getZone() { return ZoneOffset.UTC; } public Clock withZone(ZoneId z) { return this; } public Instant instant() { return Instant.ofEpochMilli(value); } public long millis() { return value; } }
}
