package org.securemail.management;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.sql.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.securemail.attachments.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Privileged broker validates identities independently; public agent cannot assert isAdmin/approval. */
public final class ManagementService implements AutoCloseable {
  @FunctionalInterface public interface Authority { AttachmentStore.Authorization authorize(IdentityRemoteAuthority.Proof proof, String action, byte[] operation) throws IOException; }
  @FunctionalInterface public interface Runner { Result run(List<String> fixedArguments) throws IOException; }
  public record Result(int exitCode, String safeOutput) { public Result { if (safeOutput == null || safeOutput.length() > 8192) throw new IllegalArgumentException("Размер результата"); } }
  private final Connection db; private final byte[] auditKey; private final Authority authority; private final Runner runner; private final Clock clock;
  public ManagementService(Path database, byte[] auditKey, Authority authority, Runner runner, Clock clock) throws IOException, SQLException {
    this.authority = Objects.requireNonNull(authority); this.runner = Objects.requireNonNull(runner); this.clock = Objects.requireNonNull(clock);
    if (auditKey == null || auditKey.length != 32) throw new IllegalArgumentException("Ключ аудита"); this.auditKey = auditKey.clone(); database = database.toAbsolutePath().normalize();
    Path parent = database.getParent(); if (parent == null || !parent.toRealPath().equals(parent) || Files.exists(database, LinkOption.NOFOLLOW_LINKS) && !Files.isRegularFile(database, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Каталог аудита");
    db = DriverManager.getConnection("jdbc:sqlite:" + database); Files.setPosixFilePermissions(database, PosixFilePermissions.fromString("rw-------"));
    try (Statement s = db.createStatement()) { s.execute("PRAGMA journal_mode=DELETE"); s.execute("PRAGMA synchronous=FULL"); s.execute("PRAGMA busy_timeout=5000"); s.execute("CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,payload_hash TEXT NOT NULL,actor1 TEXT NOT NULL,actor2 TEXT NOT NULL,created INTEGER NOT NULL,state TEXT NOT NULL,exit_code INTEGER)"); s.execute("CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY,id TEXT NOT NULL,stage TEXT NOT NULL,payload_hash TEXT NOT NULL,at INTEGER NOT NULL,previous BLOB NOT NULL,mac BLOB NOT NULL)"); }
    if (!verifyAudit()) { db.close(); throw new IOException("Целостность административного журнала нарушена"); }
  }
  public synchronized Result execute(ManagementPolicy.Request request, List<IdentityRemoteAuthority.Proof> proofs) throws IOException, SQLException {
    Objects.requireNonNull(request); int expected = request.action().critical() ? 2 : 1; if (proofs == null || proofs.size() != expected) throw denied();
    byte[] payload = request.encode(); String hash = HexFormat.of().formatHex(IdentityProtocol.digest(payload)); List<AttachmentStore.Authorization> approvals = new ArrayList<>(); Set<String> actors = new HashSet<>();
    for (var proof : proofs) {
      var approval = authority.authorize(proof, request.action().permission(), payload); var c = approval.context();
      if (c.appId != IdentityProtocol.App.AEGIS || !c.capabilities.contains(IdentityProtocol.Scope.ADMIN) || c.leaseUntil <= clock.millis() || !actors.add(c.accountId)) throw denied(); approval.check(); approvals.add(approval);
    }
    // Approval proofs are short lived and bound to exactly the immutable command and request UUID.
    long now = clock.millis(); for (var p : proofs) if (p.time() < Math.max(0, now - 120_000) || p.time() > now + 30_000) throw denied();
    db.setAutoCommit(false);
    try {
      try (PreparedStatement q = db.prepareStatement("SELECT COUNT(*) FROM operations WHERE id=?")) { q.setString(1, request.id()); try (ResultSet r = q.executeQuery()) { r.next(); if (r.getInt(1) != 0) throw new IOException("Операция уже использована; повторное исполнение запрещено"); } }
      String first = approvals.getFirst().context().accountId, second = approvals.size() == 2 ? approvals.get(1).context().accountId : "";
      try (PreparedStatement s = db.prepareStatement("INSERT INTO operations VALUES(?,?,?,?,?,'STARTED',NULL)")) { s.setString(1, request.id()); s.setString(2, hash); s.setString(3, first); s.setString(4, second); s.setLong(5, now); s.executeUpdate(); }
      append(request.id(), "INTENT", hash, now); db.commit();
    } catch (IOException | SQLException failure) { db.rollback(); throw failure; } finally { db.setAutoCommit(true); }
    Result result;
    try { for (var approval : approvals) approval.check(); result = runner.run(ManagementPolicy.command(request)); }
    catch (IOException failure) { recordResult(request.id(), hash, -1, "FAILED"); throw new IOException("Серверная операция не выполнена", failure); }
    recordResult(request.id(), hash, result.exitCode(), result.exitCode() == 0 ? "FINISHED" : "FAILED"); return result;
  }
  private void recordResult(String id, String hash, int code, String state) throws SQLException, IOException {
    db.setAutoCommit(false); try { try (PreparedStatement s = db.prepareStatement("UPDATE operations SET state=?,exit_code=? WHERE id=?")) { s.setString(1, state); s.setInt(2, code); s.setString(3, id); s.executeUpdate(); } append(id, state, hash, clock.millis()); db.commit(); } catch (SQLException | IOException failure) { db.rollback(); throw failure; } finally { db.setAutoCommit(true); }
  }
  private void append(String id, String stage, String hash, long at) throws SQLException, IOException {
    byte[] previous = new byte[32]; long seq = 1; try (Statement s = db.createStatement(); ResultSet r = s.executeQuery("SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1")) { if (r.next()) { seq = r.getLong(1) + 1; previous = r.getBytes(2); } }
    byte[] mac = mac(seq, id, stage, hash, at, previous); try (PreparedStatement s = db.prepareStatement("INSERT INTO audit VALUES(?,?,?,?,?,?,?)")) { s.setLong(1, seq); s.setString(2, id); s.setString(3, stage); s.setString(4, hash); s.setLong(5, at); s.setBytes(6, previous); s.setBytes(7, mac); s.executeUpdate(); }
  }
  public synchronized boolean verifyAudit() throws SQLException, IOException {
    byte[] previous = new byte[32]; long seq = 0; try (Statement s = db.createStatement(); ResultSet r = s.executeQuery("SELECT * FROM audit ORDER BY seq")) { while (r.next()) { if (r.getLong("seq") != ++seq || !MessageDigest.isEqual(previous, r.getBytes("previous"))) return false; byte[] expected = mac(seq, r.getString("id"), r.getString("stage"), r.getString("payload_hash"), r.getLong("at"), previous); if (!MessageDigest.isEqual(expected, r.getBytes("mac"))) return false; previous = expected; } } return true;
  }
  private byte[] mac(long seq, String id, String stage, String hash, long at, byte[] previous) throws IOException {
    try { var bytes = new ByteArrayOutputStream(); try (var out = new DataOutputStream(bytes)) { out.writeUTF("AEGIS-MANAGEMENT-AUDIT/v1"); out.writeLong(seq); out.writeUTF(id); out.writeUTF(stage); out.writeUTF(hash); out.writeLong(at); out.write(previous); } Mac hmac = Mac.getInstance("HmacSHA256"); hmac.init(new SecretKeySpec(auditKey, "HmacSHA256")); return hmac.doFinal(bytes.toByteArray()); } catch (GeneralSecurityException e) { throw new IOException("Аудит недоступен", e); }
  }
  public static Result runFixedProcess(List<String> command) throws IOException {
    // Commands can only originate in ManagementPolicy. Reject even an internal accidental arbitrary command.
    if (!ManagementPolicy.allowsCommand(command)) throw denied();
    ProcessBuilder builder = new ProcessBuilder(command); builder.environment().clear(); builder.environment().put("PATH", "/usr/sbin:/usr/bin"); builder.environment().put("LANG", "C.UTF-8"); builder.redirectErrorStream(true); Process process = builder.start();
    ExecutorService reader = Executors.newSingleThreadExecutor(r -> { Thread t = new Thread(r, "aegis-management-output"); t.setDaemon(true); return t; }); Future<byte[]> output = reader.submit(() -> { try (InputStream in = process.getInputStream()) { ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[1024]; int n; while ((n = in.read(buffer)) != -1) { if (bytes.size() + n > 8192) { process.destroyForcibly(); throw new IOException("Размер вывода превышен"); } bytes.write(buffer, 0, n); } return bytes.toByteArray(); } });
    try {
      if (!process.waitFor(45, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IOException("Срок операции истёк"); }
      byte[] bytes = output.get(3, TimeUnit.SECONDS); String raw = new String(bytes, StandardCharsets.UTF_8); Arrays.fill(bytes, (byte) 0);
      // status is a strict property allowlist; other command stderr can contain private filesystem details.
      String safe = command.contains("show") ? raw.lines().filter(line -> line.matches("(?:ActiveState|SubState)=[a-z-]{0,40}|(?:MainPID|MemoryCurrent|TasksCurrent)=[0-9]{1,20}|(?:MemoryCurrent|TasksCurrent)=\\[not set\\]")).limit(5).reduce("", (a, b) -> a + b + "\n") : command.contains("--no-block") ? "Системное задание поставлено в очередь; результат проверьте отдельно" : "Операция завершена с кодом " + process.exitValue();
      return new Result(process.exitValue(), safe);
    } catch (InterruptedException e) { Thread.currentThread().interrupt(); process.destroyForcibly(); throw new IOException("Операция прервана", e); }
      catch (ExecutionException | TimeoutException e) { process.destroyForcibly(); throw new IOException("Результат операции недоступен", e); }
    finally { reader.shutdownNow(); process.destroy(); }
  }
  private static IOException denied() { return new IOException("Серверная операция не разрешена"); }
  @Override public synchronized void close() throws SQLException { Arrays.fill(auditKey, (byte) 0); db.close(); }
}
