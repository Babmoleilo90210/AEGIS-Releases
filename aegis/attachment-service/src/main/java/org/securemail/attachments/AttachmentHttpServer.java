package org.securemail.attachments;

import com.google.gson.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.attachments.protocol.AttachmentProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Bounded binary chunk RPC origin, exposed to clients only through an operator-owned onion service. */
public final class AttachmentHttpServer implements AutoCloseable {
  @FunctionalInterface public interface Authorizer { AttachmentStore.Authorization authorize(IdentityRemoteAuthority.Proof proof, String action, byte[] actualMetadata) throws IOException; }
  private final HttpServer server; private final AttachmentStore store; private final Authorizer authority; private final KeyPair key;
  private final ThreadPoolExecutor workers = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(8), r -> { Thread t = new Thread(r, "aegis-attachment-http"); t.setDaemon(true); return t; }, new ThreadPoolExecutor.AbortPolicy());
  private final ScheduledThreadPoolExecutor timer = new ScheduledThreadPoolExecutor(1, r -> { Thread t = new Thread(r, "aegis-attachment-deadlines"); t.setDaemon(true); return t; });
  private long window = System.nanoTime(); private int requests;
  public AttachmentHttpServer(InetSocketAddress bind, AttachmentStore store, Authorizer authority, KeyPair serviceKey) throws IOException {
    if (bind.isUnresolved() || !bind.getAddress().isLoopbackAddress()) throw new IOException("Вложения доступны только через loopback за onion service");
    this.store = Objects.requireNonNull(store); this.authority = Objects.requireNonNull(authority); key = Objects.requireNonNull(serviceKey); IdentityProtocol.publicKey(key.getPublic().getEncoded());
    byte[] test = "AEGIS attachment service key consistency".getBytes(StandardCharsets.US_ASCII);
    if (!IdentityProtocol.verify(key.getPublic().getEncoded(), test, IdentityProtocol.sign(key.getPrivate(), test))) throw new IOException("Несогласованные ключи сервиса");
    System.setProperty("jdk.httpserver.maxConnections", "32"); System.setProperty("sun.net.httpserver.maxReqHeaders", "16"); System.setProperty("sun.net.httpserver.maxReqTime", "45"); System.setProperty("sun.net.httpserver.maxRspTime", "45");
    server = HttpServer.create(bind, 16); server.setExecutor(workers); server.createContext("/", this::handle); timer.setRemoveOnCancelPolicy(true);
    timer.scheduleWithFixedDelay(() -> { try { store.cleanup(32); } catch (Exception ignored) { /* Details may contain paths; never log request data. */ } }, 30, 30, TimeUnit.SECONDS);
  }
  public void start() { server.start(); }
  public int port() { return server.getAddress().getPort(); }
  private synchronized boolean rate() { long now = System.nanoTime(); if (now - window > 60_000_000_000L) { window = now; requests = 0; } return ++requests <= 1200; }
  private void handle(HttpExchange exchange) {
    byte[] metadata = new byte[0]; String nonce = IdentityProtocol.nonce(); var deadline = timer.schedule(exchange::close, 45, TimeUnit.SECONDS);
    try {
      if (!exchange.getRequestMethod().equals("POST") || !exchange.getRequestURI().getRawPath().equals("/attachments/v1") || exchange.getRequestURI().getRawQuery() != null || !rate()) throw new IOException("Недоступно");
      Headers headers = exchange.getRequestHeaders(); String lengthText = single(headers, "Content-Length");
      if (headers.containsKey("Transfer-Encoding") || headers.containsKey("Content-Encoding") || lengthText == null || !lengthText.matches("[0-9]{1,8}") || !"application/octet-stream".equals(single(headers, "Content-Type"))) throw new IOException("Формат запроса");
      int length = Integer.parseInt(lengthText); if (length < 5 || length > AttachmentProtocol.CHUNK_BYTES + AttachmentProtocol.MAX_METADATA + 4) throw new IOException("Размер запроса");
      var in = new DataInputStream(exchange.getRequestBody()); int n = in.readInt(); if (n < 1 || n > AttachmentProtocol.MAX_METADATA || n > length - 4) throw new IOException("Метаданные запроса");
      metadata = in.readNBytes(n); if (metadata.length != n) throw new EOFException(); var request = AttachmentProtocol.decode(metadata);
      if (length != 4 + n + request.payloadBytes()) throw new IOException("Размер части не совпадает");
      nonce = IdentityProtocol.nonceValue(single(headers, "AEGIS-Nonce")); String time = single(headers, "AEGIS-Time"); if (time == null || !time.matches("[0-9]{1,17}")) throw new IOException("Подтверждение времени");
      var proof = new IdentityRemoteAuthority.Proof(single(headers, "AEGIS-Capability"), Long.parseLong(time), nonce, IdentityProtocol.unb64(single(headers, "AEGIS-Proof"), 64));
      // Body-bound application proof is verified online before any store mutation or read.
      var authorization = authority.authorize(proof, request.command().action(), metadata);
      JsonObject result = new JsonObject(); byte[] payload = new byte[0];
      switch (request.command()) {
        case CREATE -> { var manifest = new AttachmentStore.Manifest(request.transferId(), authorization.context().accountId, request.recipientId(), request.ciphertextBytes(), request.ciphertextSha256(), request.ttlMillis()); result = status(store.begin(authorization, manifest)); }
        case STATUS -> result = status(store.status(authorization, request.transferId()));
        case PUT -> { store.putChunk(authorization, request.transferId(), request.chunkIndex(), request.payloadSha256(), new ExactInput(in, request.payloadBytes())); result.addProperty("stored", true); }
        case COMMIT -> { store.commit(authorization, request.transferId()); result.addProperty("committed", true); }
        case GET -> { var bytes = new ByteArrayOutputStream(AttachmentProtocol.CHUNK_BYTES); store.writeChunk(authorization, request.transferId(), request.chunkIndex(), bytes); payload = bytes.toByteArray(); result.addProperty("chunkBytes", payload.length); result.addProperty("chunkSha256", AttachmentProtocol.sha256(payload)); }
        case ACK -> { store.acknowledge(authorization, request.transferId()); result.addProperty("acknowledged", true); }
        case ABORT -> { store.abort(authorization, request.transferId()); result.addProperty("aborted", true); }
      }
      if (in.read() != -1) throw new IOException("Лишние данные запроса");
      respond(exchange, 200, metadata, nonce, result, payload);
    } catch (Exception failure) {
      // Identical externally visible error for inaccessible/nonexistent objects. No user paths, names, keys or token values.
      try { JsonObject error = new JsonObject(); error.addProperty("error", "Вложение недоступно"); respond(exchange, 403, metadata, nonce, error, new byte[0]); } catch (Exception ignored) { }
    } finally { Arrays.fill(metadata, (byte) 0); deadline.cancel(false); exchange.close(); }
  }
  private void respond(HttpExchange exchange, int status, byte[] request, String nonce, JsonObject result, byte[] payload) throws IOException {
    JsonObject json = new JsonObject(); json.addProperty("ok", status == 200); json.add("data", result); byte[] metadata = json.toString().getBytes(StandardCharsets.UTF_8); byte[] body = AttachmentProtocol.frame(metadata, payload);
    Headers headers = exchange.getResponseHeaders(); headers.set("Content-Type", "application/octet-stream"); headers.set("Connection", "close"); headers.set("Cache-Control", "no-store"); headers.set("X-Content-Type-Options", "nosniff");
    headers.set("AEGIS-Signature", IdentityProtocol.b64(IdentityProtocol.sign(key.getPrivate(), AttachmentProtocol.responseSigningBytes(request, nonce, body))));
    exchange.sendResponseHeaders(status, body.length); exchange.getResponseBody().write(body);
  }
  private static JsonObject status(AttachmentStore.Status status) { var m = status.manifest(); JsonObject result = new JsonObject(); result.addProperty("transferId", m.id()); result.addProperty("ciphertextBytes", m.ciphertextBytes()); result.addProperty("ciphertextSha256", m.ciphertextSha256()); result.addProperty("chunks", m.chunks()); result.addProperty("committed", status.committed()); result.addProperty("expiresAt", status.expiresAt()); JsonArray indices = new JsonArray(); status.present().forEach(indices::add); result.add("present", indices); return result; }
  private static String single(Headers headers, String key) { List<String> values = headers.get(key); return values != null && values.size() == 1 ? values.getFirst() : null; }
  private static final class ExactInput extends FilterInputStream { private int remaining; ExactInput(InputStream in, int remaining) { super(in); this.remaining = remaining; } @Override public int read() throws IOException { if (remaining == 0) return -1; int value = in.read(); if (value < 0) throw new EOFException(); remaining--; return value; } @Override public int read(byte[] bytes, int offset, int length) throws IOException { if (remaining == 0) return -1; int n = in.read(bytes, offset, Math.min(length, remaining)); if (n < 0) throw new EOFException(); remaining -= n; return n; } }
  @Override public void close() { server.stop(0); timer.shutdownNow(); workers.shutdownNow(); }
}
