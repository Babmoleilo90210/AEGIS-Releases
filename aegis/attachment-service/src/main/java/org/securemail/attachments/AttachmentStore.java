package org.securemail.attachments;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.sql.*;
import java.time.Clock;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Opaque immutable chunk store. No media parser, file key, decryption or legacy Relay mutation. */
public final class AttachmentStore implements AutoCloseable {
  public static final int CHUNK_BYTES = 1024 * 1024, BUFFER_BYTES = 64 * 1024;
  public static final long MAX_PLAINTEXT = 500L * 1024 * 1024, MAX_CIPHERTEXT = MAX_PLAINTEXT + CHUNK_BYTES;
  public static final long MAX_PENDING_TTL = 30L * 86400_000, PARTIAL_TTL = 86400_000;
  public record Quotas(long globalBytes, long perSenderBytes, long freeReserveBytes, int perSenderTransfers, int globalTransfers) {
    public Quotas { if (globalBytes < MAX_CIPHERTEXT || perSenderBytes < MAX_CIPHERTEXT || perSenderBytes > globalBytes || freeReserveBytes < 0 || perSenderTransfers < 1 || perSenderTransfers > 128 || globalTransfers < perSenderTransfers || globalTransfers > 4096) throw new IllegalArgumentException("Квоты вложений"); }
    public static Quotas defaults() { return new Quotas(8L << 30, 2L << 30, 64L << 20, 2, 4096); }
  }
  /** Initial request must already be signature/body-bound by Identity; recheck must check current generation online. */
  public record Authorization(IdentityProtocol.VerifiedContext context, FreshCheck fresh) {
    public Authorization { Objects.requireNonNull(context); Objects.requireNonNull(fresh); }
    public void check() throws IOException { fresh.check(); }
  }
  @FunctionalInterface public interface FreshCheck { void check() throws IOException; }
  public record Manifest(String id, String senderId, String recipientId, long ciphertextBytes, String ciphertextSha256, long ttlMillis) {
    public Manifest { uuid(id); AttachmentStore.id(senderId); AttachmentStore.id(recipientId); digest(ciphertextSha256); if (ciphertextBytes < 56 || ciphertextBytes > MAX_CIPHERTEXT || ttlMillis < 60_000 || ttlMillis > MAX_PENDING_TTL) throw new IllegalArgumentException("Манифест вложения"); }
    public int chunks() { return Math.toIntExact((ciphertextBytes + CHUNK_BYTES - 1) / CHUNK_BYTES); }
    public int chunkLength(int index) { if (index < 0 || index >= chunks()) throw new IllegalArgumentException("Номер части"); return Math.toIntExact(Math.min(CHUNK_BYTES, ciphertextBytes - (long) index * CHUNK_BYTES)); }
    public byte[] operationBytes(String operation) { return encode(out -> { out.writeUTF("AEGIS-ATTACHMENTS/v1"); out.writeUTF(operation); out.writeUTF(id); out.writeUTF(senderId); out.writeUTF(recipientId); out.writeLong(ciphertextBytes); out.writeUTF(ciphertextSha256); out.writeLong(ttlMillis); }); }
  }
  public record Status(Manifest manifest, boolean committed, long expiresAt, List<Integer> present) { public Status { present = List.copyOf(present); } }
  private record Row(Manifest manifest, long created, long expires, boolean committed) {}
  private final Path root, objects;
  private final Clock clock; private final Quotas quotas; private final Connection db;
  private final FileChannel lockChannel; private final FileLock lock;
  private final long startNanos = System.nanoTime(), startWall; private long floor;
  private boolean closed;

  public AttachmentStore(Path directory, Clock clock, Quotas quotas) throws IOException, SQLException {
    this.clock = Objects.requireNonNull(clock); this.quotas = Objects.requireNonNull(quotas);
    root = directory.toAbsolutePath().normalize(); privateDirectory(root); objects = root.resolve("objects"); privateDirectory(objects);
    Path lockPath = root.resolve("store.lock"), database = root.resolve("attachments.sqlite"); rejectLink(lockPath); rejectLink(database);
    lockChannel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS); privateFile(lockPath);
    FileLock acquired;
    try { acquired = lockChannel.tryLock(); } catch (OverlappingFileLockException busy) { lockChannel.close(); throw new IOException("Хранилище уже открыто", busy); }
    if (acquired == null) { lockChannel.close(); throw new IOException("Хранилище уже открыто"); } lock = acquired;
    Connection connection = null;
    try {
      connection = DriverManager.getConnection("jdbc:sqlite:" + database); db = connection; privateFile(database);
      try (Statement s = db.createStatement()) {
        s.execute("PRAGMA journal_mode=DELETE"); s.execute("PRAGMA synchronous=FULL"); s.execute("PRAGMA foreign_keys=ON"); s.execute("PRAGMA busy_timeout=5000");
        s.execute("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v INTEGER NOT NULL)");
        s.execute("CREATE TABLE IF NOT EXISTS transfers(id TEXT PRIMARY KEY,sender TEXT NOT NULL,recipient TEXT NOT NULL,bytes INTEGER NOT NULL,digest TEXT NOT NULL,ttl INTEGER NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,committed INTEGER NOT NULL DEFAULT 0)");
        s.execute("CREATE INDEX IF NOT EXISTS transfers_sender ON transfers(sender)"); s.execute("CREATE INDEX IF NOT EXISTS transfers_expiry ON transfers(expires)");
        s.execute("CREATE TABLE IF NOT EXISTS chunks(transfer_id TEXT NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,idx INTEGER NOT NULL,bytes INTEGER NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(transfer_id,idx))");
        s.execute("INSERT OR IGNORE INTO settings VALUES('wall_floor',0)");
      }
      floor = scalar("SELECT v FROM settings WHERE k='wall_floor'"); startWall = Math.max(clock.millis(), floor); cleanup(64); reconcileTemporaryFiles();
    } catch (IOException | SQLException | RuntimeException failure) {
      if (connection != null) try { connection.close(); } catch (SQLException suppressed) { failure.addSuppressed(suppressed); }
      lock.release(); lockChannel.close(); throw failure;
    }
  }

  public synchronized Status begin(Authorization authorization, Manifest manifest) throws IOException, SQLException {
    require(authorization, IdentityProtocol.Scope.MAIL_SEND); if (!actor(authorization).equals(manifest.senderId())) throw unavailable();
    long now = now(); cleanup(32); Row prior = row(manifest.id());
    if (prior != null) { if (!prior.manifest().equals(manifest) || !prior.manifest().senderId().equals(actor(authorization))) throw unavailable(); return status(prior); }
    db.setAutoCommit(false);
    try {
      long global = scalar("SELECT COALESCE(SUM(bytes),0) FROM transfers"), sender = senderScalar("SELECT COALESCE(SUM(bytes),0) FROM transfers WHERE sender=?", manifest.senderId());
      if (manifest.ciphertextBytes() > quotas.globalBytes() - global || manifest.ciphertextBytes() > quotas.perSenderBytes() - sender
          || scalar("SELECT COUNT(*) FROM transfers") >= quotas.globalTransfers()
          || senderScalar("SELECT COUNT(*) FROM transfers WHERE sender=? AND committed=0", manifest.senderId()) >= quotas.perSenderTransfers()
          || senderScalar("SELECT COUNT(*) FROM transfers WHERE sender=?", manifest.senderId()) >= 128
          || Files.getFileStore(root).getUsableSpace() < manifest.ciphertextBytes() + quotas.freeReserveBytes()) throw new IOException("Достигнута квота вложений");
      authorization.check(); Path directory = objectPath(manifest.id()); if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) throw unavailable(); privateDirectory(directory);
      try (PreparedStatement s = db.prepareStatement("INSERT INTO transfers VALUES(?,?,?,?,?,?,?,?,0)")) {
        s.setString(1, manifest.id()); s.setString(2, manifest.senderId()); s.setString(3, manifest.recipientId()); s.setLong(4, manifest.ciphertextBytes()); s.setString(5, manifest.ciphertextSha256()); s.setLong(6, manifest.ttlMillis()); s.setLong(7, now); s.setLong(8, Math.addExact(now, Math.min(manifest.ttlMillis(), PARTIAL_TTL))); s.executeUpdate();
      }
      db.commit(); return status(Objects.requireNonNull(row(manifest.id())));
    } catch (IOException | SQLException | RuntimeException failure) { db.rollback(); throw failure; }
    finally { db.setAutoCommit(true); }
  }

  public synchronized Status status(Authorization authorization, String transferId) throws IOException, SQLException {
    require(authorization, IdentityProtocol.Scope.MAIL_READ); Row row = readable(authorization, transferId); return status(row);
  }

  public synchronized void putChunk(Authorization authorization, String transferId, int index, String expectedSha256, InputStream source) throws IOException, SQLException {
    require(authorization, IdentityProtocol.Scope.MAIL_SEND); digest(expectedSha256); Objects.requireNonNull(source); Row row = owned(authorization, transferId); int expected = row.manifest().chunkLength(index);
    if (row.committed()) throw unavailable(); Path directory = checkedObjectPath(transferId), target = chunkPath(directory, index); rejectLink(target);
    try (PreparedStatement q = db.prepareStatement("SELECT bytes,digest FROM chunks WHERE transfer_id=? AND idx=?")) {
      q.setString(1, transferId); q.setInt(2, index); try (ResultSet r = q.executeQuery()) { if (r.next()) {
        if (r.getInt(1) != expected || !r.getString(2).equals(expectedSha256)) throw new IOException("Часть вложения неизменяема");
        String retryDigest = consumeExactly(source, expected, null, authorization); if (!retryDigest.equals(expectedSha256) || !hashFile(target, expected, authorization).equals(expectedSha256)) throw new IOException("Проверка части не пройдена"); return;
      } }
    }
    if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Хранилище требует проверки целостности");
    if (Files.getFileStore(root).getUsableSpace() < expected + quotas.freeReserveBytes()) throw new IOException("Недостаточно места для вложения");
    Path temporary = directory.resolve(".part-" + UUID.randomUUID()); boolean published = false;
    try {
      authorization.check(); createPrivateFile(temporary);
      try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
        String actual = consumeExactly(source, expected, channel, authorization); if (!actual.equals(expectedSha256)) throw new IOException("Проверка части не пройдена"); channel.force(true);
      }
      require(authorization, IdentityProtocol.Scope.MAIL_SEND); owned(authorization, transferId);
      Files.createLink(target, temporary); published = true; Files.delete(temporary);
      try (PreparedStatement s = db.prepareStatement("INSERT INTO chunks VALUES(?,?,?,?)")) { s.setString(1, transferId); s.setInt(2, index); s.setInt(3, expected); s.setString(4, expectedSha256); s.executeUpdate(); }
    } catch (IOException | SQLException | RuntimeException failure) { if (published) Files.deleteIfExists(target); throw failure; }
    finally { Files.deleteIfExists(temporary); }
  }

  public synchronized void commit(Authorization authorization, String transferId) throws IOException, SQLException {
    require(authorization, IdentityProtocol.Scope.MAIL_SEND); Row row = owned(authorization, transferId);
    if (row.committed()) return;
    Status current = status(row); if (current.present().size() != row.manifest().chunks()) throw new IOException("Вложение ещё не загружено");
    MessageDigest combined = sha256(); byte[] buffer = new byte[BUFFER_BYTES];
    try {
      for (int index = 0; index < row.manifest().chunks(); index++) {
        require(authorization, IdentityProtocol.Scope.MAIL_SEND); Path file = chunkPath(checkedObjectPath(transferId), index); int size = row.manifest().chunkLength(index); MessageDigest each = sha256();
        try (InputStream in = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
          int count, total = 0; while ((count = in.read(buffer)) != -1) { authorization.check(); total = Math.addExact(total, count); if (total > size) throw unavailable(); combined.update(buffer, 0, count); each.update(buffer, 0, count); } if (total != size) throw unavailable();
        }
        try (PreparedStatement q = db.prepareStatement("SELECT digest FROM chunks WHERE transfer_id=? AND idx=?")) { q.setString(1, transferId); q.setInt(2, index); try (ResultSet r = q.executeQuery()) { if (!r.next() || !r.getString(1).equals(hex(each.digest()))) throw unavailable(); } }
      }
      if (!row.manifest().ciphertextSha256().equals(hex(combined.digest()))) throw new IOException("Итоговая целостность вложения не подтверждена");
      require(authorization, IdentityProtocol.Scope.MAIL_SEND); long expiry = Math.addExact(row.created(), row.manifest().ttlMillis()); if (expiry <= now()) throw unavailable();
      try (PreparedStatement s = db.prepareStatement("UPDATE transfers SET committed=1,expires=? WHERE id=?")) { s.setLong(1, expiry); s.setString(2, transferId); s.executeUpdate(); }
    } finally { Arrays.fill(buffer, (byte) 0); }
  }

  public synchronized void writeChunk(Authorization authorization, String transferId, int index, OutputStream destination) throws IOException, SQLException {
    require(authorization, IdentityProtocol.Scope.MAIL_READ); Row row = readable(authorization, transferId); if (!row.committed()) throw unavailable(); int expected = row.manifest().chunkLength(index);
    Path file = chunkPath(checkedObjectPath(transferId), index); String expectedDigest;
    try (PreparedStatement q = db.prepareStatement("SELECT digest FROM chunks WHERE transfer_id=? AND idx=?")) { q.setString(1, transferId); q.setInt(2, index); try (ResultSet r = q.executeQuery()) { if (!r.next()) throw unavailable(); expectedDigest = r.getString(1); } }
    // Detect local corruption before starting the response. The private immutable file is then streamed.
    if (!hashFile(file, expected, authorization).equals(expectedDigest)) throw unavailable();
    byte[] buffer = new byte[BUFFER_BYTES]; int total = 0;
    try (InputStream in = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
      int count; while ((count = in.read(buffer)) != -1) { require(authorization, IdentityProtocol.Scope.MAIL_READ); total = Math.addExact(total, count); if (total > expected) throw unavailable(); destination.write(buffer, 0, count); } if (total != expected) throw unavailable();
    } finally { Arrays.fill(buffer, (byte) 0); }
  }

  public synchronized void acknowledge(Authorization authorization, String transferId) throws IOException, SQLException {
    require(authorization, IdentityProtocol.Scope.MAIL_READ); Row row = readable(authorization, transferId); if (!row.committed() || !actor(authorization).equals(row.manifest().recipientId())) throw unavailable(); remove(row.manifest().id());
  }
  public synchronized void abort(Authorization authorization, String transferId) throws IOException, SQLException { require(authorization, IdentityProtocol.Scope.MAIL_SEND); Row row = owned(authorization, transferId); authorization.check(); remove(row.manifest().id()); }

  /** Bounded retention work; does not follow symlinks and never extends TTL. */
  public synchronized int cleanup(int limit) throws IOException, SQLException {
    if (limit < 1 || limit > 128) throw new IllegalArgumentException("Лимит очистки"); long now = now(); List<String> expired = new ArrayList<>();
    try (PreparedStatement q = db.prepareStatement("SELECT id FROM transfers WHERE expires<=? ORDER BY expires,id LIMIT ?")) { q.setLong(1, now); q.setInt(2, limit); try (ResultSet r = q.executeQuery()) { while (r.next()) expired.add(r.getString(1)); } }
    for (String id : expired) remove(id); return expired.size();
  }
  public synchronized long reservedBytes() throws SQLException { return scalar("SELECT COALESCE(SUM(bytes),0) FROM transfers"); }
  public synchronized int transferCount() throws SQLException { return Math.toIntExact(scalar("SELECT COUNT(*) FROM transfers")); }

  private Row owned(Authorization auth, String transfer) throws IOException, SQLException { uuid(transfer); Row r = row(transfer); if (r == null || r.expires() <= now() || !r.manifest().senderId().equals(actor(auth))) throw unavailable(); return r; }
  private Row readable(Authorization auth, String transfer) throws IOException, SQLException { uuid(transfer); Row r = row(transfer); if (r == null || r.expires() <= now() || !(r.manifest().senderId().equals(actor(auth)) || r.committed() && r.manifest().recipientId().equals(actor(auth)))) throw unavailable(); return r; }
  private Status status(Row row) throws SQLException { List<Integer> indices = new ArrayList<>(); try (PreparedStatement q = db.prepareStatement("SELECT idx FROM chunks WHERE transfer_id=? ORDER BY idx")) { q.setString(1, row.manifest().id()); try (ResultSet r = q.executeQuery()) { while (r.next()) indices.add(r.getInt(1)); } } return new Status(row.manifest(), row.committed(), row.expires(), indices); }
  private Row row(String id) throws SQLException { try (PreparedStatement q = db.prepareStatement("SELECT * FROM transfers WHERE id=?")) { q.setString(1, id); try (ResultSet r = q.executeQuery()) { return r.next() ? new Row(new Manifest(r.getString("id"), r.getString("sender"), r.getString("recipient"), r.getLong("bytes"), r.getString("digest"), r.getLong("ttl")), r.getLong("created"), r.getLong("expires"), r.getInt("committed") == 1) : null; } } }
  private void remove(String id) throws IOException, SQLException { Path directory = objectPath(id); if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) { checkedObjectPath(id); try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) { for (Path file : stream) { String name = file.getFileName().toString(); if (!(name.matches("[0-9]{4}\\.chunk") || name.matches("\\.part-[a-f0-9-]{36}")) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Небезопасный объект хранилища"); Files.delete(file); } } Files.delete(directory); } try (PreparedStatement s = db.prepareStatement("DELETE FROM transfers WHERE id=?")) { s.setString(1, id); s.executeUpdate(); } }
  private void reconcileTemporaryFiles() throws IOException, SQLException {
    int inspected = 0; try (DirectoryStream<Path> dirs = Files.newDirectoryStream(objects)) { for (Path directory : dirs) { if (++inspected > quotas.globalTransfers() + 128) throw new IOException("Лимит объектов хранилища"); String transfer = directory.getFileName().toString(); uuid(transfer); checkedObjectPath(transfer); Row row = row(transfer);
      if (row == null) { remove(transfer); continue; }
      try (DirectoryStream<Path> files = Files.newDirectoryStream(directory)) { int n = 0; for (Path file : files) { if (++n > 1024 || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) throw unavailable(); String name = file.getFileName().toString(); if (name.matches("\\.part-[a-f0-9-]{36}")) { Files.delete(file); continue; } if (!name.matches("[0-9]{4}\\.chunk")) throw unavailable(); int idx = Integer.parseInt(name.substring(0, 4)); try (PreparedStatement q = db.prepareStatement("SELECT COUNT(*) FROM chunks WHERE transfer_id=? AND idx=?")) { q.setString(1, transfer); q.setInt(2, idx); try (ResultSet r = q.executeQuery()) { r.next(); if (r.getLong(1) == 0) Files.delete(file); } } } }
    } }
  }
  private void require(Authorization authorization, IdentityProtocol.Scope scope) throws IOException { if (closed || authorization == null) throw unavailable(); authorization.check(); var c = authorization.context(); if (c.appId != IdentityProtocol.App.MAIL || !c.capabilities.contains(scope) || c.generation < 1 || c.leaseUntil <= now()) throw unavailable(); }
  private static String actor(Authorization auth) { return IdentityProtocol.idValue(auth.context().accountId); }
  private long now() throws IOException { if (closed) throw unavailable(); long elapsed = Math.max(0, System.nanoTime() - startNanos) / 1_000_000; long value = Math.max(floor, Math.max(clock.millis(), startWall + elapsed)); floor = value; try (PreparedStatement s = db.prepareStatement("UPDATE settings SET v=? WHERE k='wall_floor'")) { s.setLong(1, value); s.executeUpdate(); } catch (SQLException e) { throw new IOException("Не удалось сохранить срок хранения", e); } return value; }
  private long scalar(String sql) throws SQLException { try (Statement s = db.createStatement(); ResultSet r = s.executeQuery(sql)) { r.next(); return r.getLong(1); } }
  private long senderScalar(String sql, String sender) throws SQLException { try (PreparedStatement s = db.prepareStatement(sql)) { s.setString(1, sender); try (ResultSet r = s.executeQuery()) { r.next(); return r.getLong(1); } } }
  private Path objectPath(String id) { uuid(id); return objects.resolve(id); }
  private Path checkedObjectPath(String id) throws IOException { Path p = objectPath(id); if (!Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS) || !p.toRealPath().equals(p)) throw unavailable(); return p; }
  private static Path chunkPath(Path directory, int index) { if (index < 0 || index > 1023) throw new IllegalArgumentException("Часть вложения"); return directory.resolve(String.format(Locale.ROOT, "%04d.chunk", index)); }
  private static String consumeExactly(InputStream source, int expected, FileChannel output, Authorization auth) throws IOException { MessageDigest digest = sha256(); byte[] buffer = new byte[BUFFER_BYTES]; int total = 0; try { while (total < expected) { auth.check(); int n = source.read(buffer, 0, Math.min(buffer.length, expected - total)); if (n < 0) throw new EOFException("Часть усечена"); if (n == 0) continue; if (output != null) { auth.check(); ByteBuffer b = ByteBuffer.wrap(buffer, 0, n); while (b.hasRemaining()) output.write(b); } digest.update(buffer, 0, n); total += n; } if (source.read() != -1) throw new IOException("Часть слишком велика"); return hex(digest.digest()); } finally { Arrays.fill(buffer, (byte) 0); } }
  private static String hashFile(Path path, int expected, Authorization auth) throws IOException { if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) != expected) throw unavailable(); try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { return consumeExactly(in, expected, null, auth); } }
  private static void privateDirectory(Path path) throws IOException { if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) { if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || !path.toRealPath().equals(path)) throw unavailable(); } else { Path parent = path.getParent(); if (parent == null || !parent.toRealPath().equals(parent)) throw unavailable(); Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))); } Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------")); }
  private static void createPrivateFile(Path p) throws IOException { Files.createFile(p, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); }
  private static void privateFile(Path p) throws IOException { Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------")); }
  private static void rejectLink(Path p) throws IOException { if (Files.exists(p, LinkOption.NOFOLLOW_LINKS) && !Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) throw unavailable(); }
  private static void uuid(String id) { if (id == null || !UUID.fromString(id).toString().equals(id)) throw new IllegalArgumentException("Идентификатор вложения"); }
  private static void id(String value) { IdentityProtocol.idValue(value); }
  private static void digest(String value) { if (value == null || !value.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Digest вложения"); }
  private static MessageDigest sha256() { try { return MessageDigest.getInstance("SHA-256"); } catch (GeneralSecurityException e) { throw new IllegalStateException(e); } }
  private static String hex(byte[] value) { return HexFormat.of().formatHex(value); }
  private static IOException unavailable() { return new IOException("Вложение недоступно"); }
  private interface Writer { void write(DataOutputStream out) throws IOException; }
  public static byte[] encode(Writer writer) { try { var bytes = new ByteArrayOutputStream(); try (var out = new DataOutputStream(bytes)) { writer.write(out); } return bytes.toByteArray(); } catch (IOException e) { throw new IllegalStateException(e); } }
  @Override public synchronized void close() throws IOException { if (closed) return; closed = true; try { db.close(); } catch (SQLException e) { throw new IOException("Не удалось закрыть хранилище", e); } finally { lock.release(); lockChannel.close(); } }
}
