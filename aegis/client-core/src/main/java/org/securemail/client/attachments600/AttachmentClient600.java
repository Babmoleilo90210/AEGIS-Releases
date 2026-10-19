package org.securemail.client.attachments600;

import com.google.gson.*;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;
import org.securemail.attachments.protocol.AttachmentProtocol;
import org.securemail.client.community.CommunityJson;
import org.securemail.client.net.TorTransport;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.protocol.Limits;

/** Actual onion-only bounded-chunk client; no direct socket, DNS, URL or plaintext upload API. */
public final class AttachmentClient600 implements AutoCloseable {
  @FunctionalInterface public interface Progress { void measured(long completedBytes, long totalBytes) throws IOException; }
  public record RemoteFile(String transferId, String recipientId, long ciphertextBytes, String ciphertextSha256, long ttlMillis) {
    public RemoteFile { AttachmentProtocol.Request.create(transferId, recipientId, ciphertextBytes, ciphertextSha256, ttlMillis); }
    public int chunks() { return Math.toIntExact((ciphertextBytes + AttachmentProtocol.CHUNK_BYTES - 1) / AttachmentProtocol.CHUNK_BYTES); }
    public int chunkLength(int index) { if (index < 0 || index >= chunks()) throw new IllegalArgumentException("Часть вложения"); return (int) Math.min(AttachmentProtocol.CHUNK_BYTES, ciphertextBytes - (long) index * AttachmentProtocol.CHUNK_BYTES); }
  }
  public record Response(JsonObject data, byte[] payload) { public Response { payload = payload.clone(); } @Override public byte[] payload() { return payload.clone(); } }
  private final TorTransport tor; private final String onion, capability; private final int port; private final byte[] servicePublic; private final PrivateKey appProof;
  private final IdentityProtocol.Capability grant; private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
  private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(r -> { Thread t = new Thread(r, "aegis-attachments-deadline"); t.setDaemon(true); return t; });
  private final Semaphore slots = new Semaphore(2); private volatile boolean closed;
  public AttachmentClient600(TorTransport tor, String onion, int port, byte[] servicePublicKey, byte[] identityPublicKey, String capability, PrivateKey appProof) throws IOException {
    this.tor = Objects.requireNonNull(tor); this.onion = Limits.onion(onion); if (port < 1 || port > 65535) throw new IllegalArgumentException("Порт вложений"); this.port = port; IdentityProtocol.publicKey(servicePublicKey); servicePublic = servicePublicKey.clone(); grant = IdentityProtocol.decodeCapability(capability);
    if (!IdentityProtocol.verifyCapability(grant, identityPublicKey, System.currentTimeMillis()) || grant.appId != IdentityProtocol.App.MAIL || !grant.capabilities.containsAll(EnumSet.of(IdentityProtocol.Scope.MAIL_READ, IdentityProtocol.Scope.MAIL_SEND))) throw new IOException("Разрешение Почты недействительно");
    this.capability = capability; this.appProof = Objects.requireNonNull(appProof); byte[] challenge = "AEGIS attachment app proof consistency".getBytes(StandardCharsets.US_ASCII); if (!IdentityProtocol.verify(grant.proofKey, challenge, IdentityProtocol.sign(appProof, challenge))) throw new IOException("Ключ приложения не совпадает с разрешением");
  }
  public void upload(Path ciphertextSpool, RemoteFile file, BooleanSupplier active, Progress progress) throws IOException {
    Objects.requireNonNull(active); Objects.requireNonNull(progress); ciphertextSpool = checkedFile(ciphertextSpool); if (Files.size(ciphertextSpool) != file.ciphertextBytes() || !hash(ciphertextSpool, active).equals(file.ciphertextSha256())) throw new IOException("Зашифрованная очередь повреждена");
    exchange(AttachmentProtocol.Request.create(file.transferId(), file.recipientId(), file.ciphertextBytes(), file.ciphertextSha256(), file.ttlMillis()), new byte[0]);
    JsonObject status = exchange(AttachmentProtocol.Request.control(AttachmentProtocol.Command.STATUS, file.transferId()), new byte[0]).data(); verifyStatus(file, status); Set<Integer> present = present(status, file.chunks());
    if (booleanValue(status, "committed")) { progress.measured(file.ciphertextBytes(), file.ciphertextBytes()); return; }
    long done = present.stream().mapToLong(file::chunkLength).sum(); progress.measured(done, file.ciphertextBytes()); byte[] chunk = new byte[AttachmentProtocol.CHUNK_BYTES];
    try (FileChannel in = FileChannel.open(ciphertextSpool, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
      for (int index = 0; index < file.chunks(); index++) {
        check(active); if (present.contains(index)) continue; int length = file.chunkLength(index); ByteBuffer b = ByteBuffer.wrap(chunk, 0, length); in.position((long) index * AttachmentProtocol.CHUNK_BYTES); while (b.hasRemaining()) if (in.read(b) < 0) throw new EOFException("Очередь усечена");
        byte[] payload = Arrays.copyOf(chunk, length); try { exchange(AttachmentProtocol.Request.put(file.transferId(), index, length, AttachmentProtocol.sha256(payload)), payload); } finally { Arrays.fill(payload, (byte) 0); }
        done += length; progress.measured(done, file.ciphertextBytes());
      }
      check(active); exchange(AttachmentProtocol.Request.control(AttachmentProtocol.Command.COMMIT, file.transferId()), new byte[0]);
    } finally { Arrays.fill(chunk, (byte) 0); }
  }
  /** Download writes encrypted bytes only. Final plaintext publication is performed by StreamingAttachmentCipher. */
  public void download(RemoteFile file, Path encryptedPartial, BooleanSupplier active, Progress progress) throws IOException {
    Objects.requireNonNull(active); Objects.requireNonNull(progress); encryptedPartial = encryptedPartial.toAbsolutePath().normalize(); Path parent = encryptedPartial.getParent(); if (parent == null || !parent.toRealPath().equals(parent)) throw new IOException("Каталог очереди вложений");
    JsonObject status = exchange(AttachmentProtocol.Request.control(AttachmentProtocol.Command.STATUS, file.transferId()), new byte[0]).data(); verifyStatus(file, status); if (!booleanValue(status, "committed")) throw new IOException("Вложение ещё не доставлено");
    if (!Files.exists(encryptedPartial, LinkOption.NOFOLLOW_LINKS)) createPrivate(encryptedPartial); checkedFile(encryptedPartial); long length = Files.size(encryptedPartial); if (length > file.ciphertextBytes()) throw new IOException("Очередь повреждена");
    // A partial final chunk was never acknowledged locally; replace only that encrypted tail.
    long offset = length == file.ciphertextBytes() ? length : length / AttachmentProtocol.CHUNK_BYTES * AttachmentProtocol.CHUNK_BYTES;
    if (offset == file.ciphertextBytes()) { if (hash(encryptedPartial, active).equals(file.ciphertextSha256())) { progress.measured(offset, offset); return; } throw new IOException("Очередь повреждена"); }
    try (FileChannel out = FileChannel.open(encryptedPartial, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
      out.truncate(offset); out.position(offset); progress.measured(offset, file.ciphertextBytes());
      for (int index = Math.toIntExact(offset / AttachmentProtocol.CHUNK_BYTES); index < file.chunks(); index++) {
        check(active); Response response = exchange(AttachmentProtocol.Request.get(file.transferId(), index), new byte[0]); byte[] payload = response.payload();
        try { if (payload.length != file.chunkLength(index) || !AttachmentProtocol.sha256(payload).equals(text(response.data(), "chunkSha256"))) throw new IOException("Часть вложения повреждена"); ByteBuffer bytes = ByteBuffer.wrap(payload); while (bytes.hasRemaining()) { check(active); out.write(bytes); } out.force(false); offset += payload.length; progress.measured(offset, file.ciphertextBytes()); }
        finally { Arrays.fill(payload, (byte) 0); }
      }
    }
    if (!hash(encryptedPartial, active).equals(file.ciphertextSha256())) throw new IOException("Итоговая целостность вложения нарушена");
  }
  public void acknowledge(String transferId) throws IOException { exchange(AttachmentProtocol.Request.control(AttachmentProtocol.Command.ACK, transferId), new byte[0]); }
  public void abort(String transferId) throws IOException { exchange(AttachmentProtocol.Request.control(AttachmentProtocol.Command.ABORT, transferId), new byte[0]); }
  public Response exchange(AttachmentProtocol.Request request, byte[] payload) throws IOException {
    if (closed || System.currentTimeMillis() >= grant.expiresAt || payload.length != request.payloadBytes()) throw new IOException("Сеанс Почты недействителен");
    byte[] metadata = request.encode(); long time = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] signature = IdentityProtocol.sign(appProof, IdentityProtocol.requestDigest(grant, request.command().action(), IdentityProtocol.digest(metadata), time, nonce));
    if (!slots.tryAcquire()) throw new IOException("Дождитесь завершения передачи вложений"); Socket[] observed = {null}; ScheduledFuture<?>[] deadline = {null};
    try (Socket socket = tor.connectPeer(onion, port, opened -> {
      if (closed) throw new IOException("Сеанс закрыт"); observed[0] = opened; sockets.add(opened); deadline[0] = timer.schedule(() -> { try { opened.close(); } catch (IOException ignored) {} }, 60, TimeUnit.SECONDS);
    })) {
      if (closed) throw new IOException("Сеанс закрыт"); socket.setSoTimeout(45000); OutputStream out = socket.getOutputStream(); int contentLength = 4 + metadata.length + payload.length;
      String headers = "POST /attachments/v1 HTTP/1.1\r\nHost: " + onion + "\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: " + contentLength + "\r\nAEGIS-Capability: " + capability + "\r\nAEGIS-Time: " + time + "\r\nAEGIS-Nonce: " + nonce + "\r\nAEGIS-Proof: " + IdentityProtocol.b64(signature) + "\r\n\r\n";
      out.write(headers.getBytes(StandardCharsets.US_ASCII)); var data = new DataOutputStream(out); data.writeInt(metadata.length); data.write(metadata); data.write(payload); data.flush(); var in = new DataInputStream(socket.getInputStream()); String status = line(in, 1024); if (!status.matches("HTTP/1\\.[01] [1-5][0-9]{2}(?: [\\x20-\\x7e]*)?")) throw new IOException("Ответ сервера вложений");
      Map<String, String> responseHeaders = new HashMap<>(); boolean complete = false; int headerBytes = 0;
      for (int i = 0; i < 24; i++) { String h = line(in, 4096); headerBytes += h.length(); if (headerBytes > 8192) throw new IOException("Заголовки превышены"); if (h.isEmpty()) { complete = true; break; } int colon = h.indexOf(':'); if (colon < 1 || !h.substring(0, colon).matches("[A-Za-z0-9-]+") || responseHeaders.putIfAbsent(h.substring(0, colon).toLowerCase(Locale.ROOT), h.substring(colon + 1).strip()) != null) throw new IOException("Заголовки ответа неверны"); }
      String sizeText = responseHeaders.getOrDefault("content-length", ""); if (!complete || responseHeaders.containsKey("transfer-encoding") || responseHeaders.containsKey("content-encoding") || !sizeText.matches("[0-9]{1,8}")) throw new IOException("Кодирование ответа запрещено"); int size = Integer.parseInt(sizeText); if (size < 6 || size > AttachmentProtocol.CHUNK_BYTES + AttachmentProtocol.MAX_REPLY_METADATA + 4) throw new IOException("Размер ответа превышен"); byte[] response = in.readNBytes(size);
      if (response.length != size || !IdentityProtocol.verify(servicePublic, AttachmentProtocol.responseSigningBytes(metadata, nonce, response), IdentityProtocol.unb64(responseHeaders.getOrDefault("aegis-signature", ""), 64))) throw new IOException("Подпись сервиса вложений не подтверждена");
      try (var reply = new DataInputStream(new ByteArrayInputStream(response))) { int n = reply.readInt(); if (n < 2 || n > AttachmentProtocol.MAX_REPLY_METADATA || n > response.length - 4) throw new IOException("Формат ответа вложений"); JsonObject object = CommunityJson.parse(reply.readNBytes(n)); if (!booleanValue(object, "ok") || !status.matches("HTTP/1\\.[01] 200(?: .*)?")) throw new IOException("Вложение недоступно"); JsonElement result = object.get("data"); if (result == null || !result.isJsonObject()) throw new IOException("Формат ответа вложений"); if (closed) throw new IOException("Сеанс закрыт"); return new Response(result.getAsJsonObject(), reply.readAllBytes()); }
    } catch (RuntimeException failure) { throw new IOException("Передача вложения не выполнена", failure); }
    finally { slots.release(); if (deadline[0] != null) deadline[0].cancel(false); if (observed[0] != null) { sockets.remove(observed[0]); try { observed[0].close(); } catch (IOException ignored) {} } }
  }
  private static void verifyStatus(RemoteFile file, JsonObject status) throws IOException { if (!file.transferId().equals(text(status, "transferId")) || !file.ciphertextSha256().equals(text(status, "ciphertextSha256")) || number(status, "ciphertextBytes") != file.ciphertextBytes() || number(status, "chunks") != file.chunks()) throw new IOException("Дескриптор вложения не совпадает"); }
  private static Set<Integer> present(JsonObject status, int chunks) throws IOException { JsonElement e = status.get("present"); if (e == null || !e.isJsonArray() || e.getAsJsonArray().size() > 1024) throw new IOException("Состояние передачи"); Set<Integer> result = new HashSet<>(); for (JsonElement value : e.getAsJsonArray()) { int index; try { index = value.getAsBigDecimal().intValueExact(); } catch (RuntimeException invalid) { throw new IOException("Номер части", invalid); } if (index < 0 || index >= chunks || !result.add(index)) throw new IOException("Номер части"); } return result; }
  private void check(BooleanSupplier active) throws IOException { if (closed || !active.getAsBoolean() || System.currentTimeMillis() >= grant.expiresAt) throw new IOException("Передача отменена или сеанс отозван"); }
  private static Path checkedFile(Path file) throws IOException { file = file.toAbsolutePath().normalize(); if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || file.getParent() == null || !file.getParent().toRealPath().equals(file.getParent())) throw new IOException("Небезопасный файл очереди"); return file; }
  private static void createPrivate(Path file) throws IOException { try { Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); } catch (UnsupportedOperationException windows) { Files.createFile(file); var view = Files.getFileAttributeView(file, java.nio.file.attribute.AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS); if (view == null) { Files.deleteIfExists(file); throw new IOException("Защита очереди недоступна"); } var owner = Files.getOwner(file); view.setAcl(List.of(java.nio.file.attribute.AclEntry.newBuilder().setType(java.nio.file.attribute.AclEntryType.ALLOW).setPrincipal(owner).setPermissions(EnumSet.allOf(java.nio.file.attribute.AclEntryPermission.class)).build())); } }
  private static String hash(Path file, BooleanSupplier active) throws IOException { MessageDigest hash; try { hash = MessageDigest.getInstance("SHA-256"); } catch (GeneralSecurityException impossible) { throw new IllegalStateException(impossible); } byte[] buffer = new byte[65536]; try (InputStream in = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) { int n; long count = 0; while ((n = in.read(buffer)) != -1) { if (!active.getAsBoolean()) throw new IOException("Передача отменена"); count += n; if (count > AttachmentProtocol.MAX_CIPHERTEXT) throw new IOException("Размер очереди превышен"); hash.update(buffer, 0, n); } return HexFormat.of().formatHex(hash.digest()); } finally { Arrays.fill(buffer, (byte) 0); } }
  private static String text(JsonObject object, String key) throws IOException { JsonElement e = object.get(key); if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) throw new IOException("Данные вложения"); return e.getAsString(); }
  private static boolean booleanValue(JsonObject object, String key) throws IOException { JsonElement e = object.get(key); if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isBoolean()) throw new IOException("Состояние вложения"); return e.getAsBoolean(); }
  private static long number(JsonObject object, String key) throws IOException { try { JsonElement e = object.get(key); if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isNumber()) throw new IOException("Размер вложения"); return e.getAsBigDecimal().longValueExact(); } catch (RuntimeException failure) { throw new IOException("Размер вложения", failure); } }
  private static String line(DataInputStream in, int limit) throws IOException { var bytes = new ByteArrayOutputStream(); for (int i = 0; i < limit; i++) { int c = in.read(); if (c < 0) throw new EOFException(); if (c == '\r') { if (in.read() != '\n') throw new IOException("HTTP framing"); return bytes.toString(StandardCharsets.US_ASCII); } if (c < 32 || c > 126) throw new IOException("HTTP framing"); bytes.write(c); } throw new IOException("HTTP line too long"); }
  @Override public void close() { closed = true; for (Socket socket : sockets) try { socket.close(); } catch (IOException ignored) {} sockets.clear(); timer.shutdownNow(); }
}
