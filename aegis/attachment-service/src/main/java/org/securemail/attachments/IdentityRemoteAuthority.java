package org.securemail.attachments;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.*;
import java.net.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Server-to-server pinned loopback Identity RPC. Never reads a user's proof private key. */
public final class IdentityRemoteAuthority {
  public record Proof(String capability, long time, String nonce, byte[] signature) {
    public Proof { IdentityProtocol.decodeCapability(capability); IdentityProtocol.nonceValue(nonce); if (time < 0 || signature == null || signature.length != 64) throw new IllegalArgumentException("Подтверждение запроса"); signature = signature.clone(); }
    @Override public byte[] signature() { return signature.clone(); }
  }
  private final URI endpoint; private final byte[] publicKey; private final String audience;
  public IdentityRemoteAuthority(URI endpoint, byte[] pinnedKey) {
    Objects.requireNonNull(endpoint); IdentityProtocol.publicKey(pinnedKey);
    // Fixed literal loopback, no DNS, proxy, redirect, userinfo or arbitrary destination.
    if (!"http".equals(endpoint.getScheme()) || !"127.0.0.1".equals(endpoint.getHost()) || !"/identity/v1".equals(endpoint.getPath()) || endpoint.getPort() < 1 || endpoint.getPort() > 65535 || endpoint.getUserInfo() != null || endpoint.getQuery() != null || endpoint.getFragment() != null) throw new IllegalArgumentException("Локальный адрес Identity");
    this.endpoint = endpoint; publicKey = pinnedKey.clone(); audience = IdentityProtocol.id(publicKey);
  }
  public static byte[] readPinnedKey(Path path) throws IOException {
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 128) throw denied(); byte[] bytes = Files.readAllBytes(path);
    try { if (bytes.length == 44) { IdentityProtocol.publicKey(bytes); return bytes; } String value = new String(bytes, StandardCharsets.US_ASCII).strip(); byte[] key; try { key = Base64.getUrlDecoder().decode(value); } catch (IllegalArgumentException ignored) { key = Base64.getDecoder().decode(value); } IdentityProtocol.publicKey(key); return key; }
    catch (RuntimeException failure) { throw denied(); }
  }
  public AttachmentStore.Authorization authorize(Proof proof, String action, byte[] actualOperationBytes) throws IOException {
    var capability = IdentityProtocol.decodeCapability(proof.capability());
    if (!IdentityProtocol.verifyCapability(capability, publicKey, System.currentTimeMillis())) throw denied();
    JsonObject data = new JsonObject(); data.addProperty("capability", proof.capability()); data.addProperty("action", action); data.addProperty("bodySha256", IdentityProtocol.b64(IdentityProtocol.digest(actualOperationBytes))); data.addProperty("time", proof.time()); data.addProperty("nonce", proof.nonce()); data.addProperty("proof", IdentityProtocol.b64(proof.signature()));
    JsonObject context = rpc("authorizeDigest", data);
    if (!text(context, "accountId").equals(capability.accountId) || !text(context, "deviceId").equals(capability.deviceId) || !text(context, "appId").equals(capability.appId.name()) || exactLong(context, "generation") != capability.generation || exactLong(context, "leaseUntil") != capability.expiresAt) throw denied();
    JsonArray scopes = context.getAsJsonArray("capabilities"); Set<String> actual = new HashSet<>(); if (scopes == null || scopes.size() > IdentityProtocol.Scope.values().length) throw denied(); for (JsonElement item : scopes) if (!item.isJsonPrimitive() || !item.getAsJsonPrimitive().isString() || !actual.add(item.getAsString())) throw denied();
    if (!actual.equals(new HashSet<>(capability.capabilities.stream().map(Enum::name).toList()))) throw denied();
    // Initial proof is freshly verified above. During one bounded RPC, reuse a
    // successful ONLINE recheck for at most 250 ms measured by a monotonic clock.
    // No offline continuation after an error; this is an explicit revocation bound.
    return new AttachmentStore.Authorization(new IdentityProtocol.VerifiedContext(capability), new AttachmentStore.FreshCheck() {
      private long checkedAt = System.nanoTime();
      @Override public synchronized void check() throws IOException {
        if (System.currentTimeMillis() >= capability.expiresAt) throw denied();
        long now = System.nanoTime(); if (now - checkedAt >= 250_000_000L) { if (!isActive(proof.capability())) throw denied(); checkedAt = System.nanoTime(); }
      }
    });
  }
  public boolean isActive(String capability) throws IOException { JsonObject data = new JsonObject(); data.addProperty("capability", capability); JsonObject result = rpc("isActive", data); JsonElement active = result.get("active"); if (active == null || !active.isJsonPrimitive() || !active.getAsJsonPrimitive().isBoolean()) throw denied(); return active.getAsBoolean(); }
  public JsonObject rpc(String operation, JsonObject data) throws IOException {
    String nonce = IdentityProtocol.nonce(); JsonObject request = new JsonObject(); request.addProperty("operation", operation); request.addProperty("nonce", nonce); request.add("data", data);
    byte[] body = request.toString().getBytes(StandardCharsets.UTF_8); if (body.length > IdentityProtocol.MAX_BODY) throw denied(); HttpURLConnection connection = (HttpURLConnection) endpoint.toURL().openConnection(Proxy.NO_PROXY);
    try {
      connection.setInstanceFollowRedirects(false); connection.setConnectTimeout(2000); connection.setReadTimeout(3000); connection.setRequestMethod("POST"); connection.setDoOutput(true); connection.setFixedLengthStreamingMode(body.length); connection.setRequestProperty("Content-Type", "application/json"); connection.setRequestProperty("Connection", "close");
      try (OutputStream out = connection.getOutputStream()) { out.write(body); }
      int status = connection.getResponseCode(); if (status >= 300 && status < 400 || connection.getHeaderField("Content-Encoding") != null || connection.getHeaderField("Transfer-Encoding") != null) throw denied();
      long length = connection.getContentLengthLong(); if (length < 2 || length > IdentityProtocol.MAX_BODY) throw denied();
      byte[] response; try (InputStream in = status < 400 ? connection.getInputStream() : connection.getErrorStream()) { if (in == null) throw denied(); response = in.readNBytes((int) length + 1); }
      if (response.length != length) throw denied(); List<String> signatures = connection.getHeaderFields().entrySet().stream().filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase("AEGIS-Signature")).flatMap(e -> e.getValue().stream()).toList();
      if (signatures.size() != 1 || !IdentityProtocol.verify(publicKey, IdentityProtocol.response(audience, nonce, body, response), IdentityProtocol.unb64(signatures.getFirst(), 64))) throw denied();
      JsonObject parsed = parseStrict(response); JsonElement ok = parsed.get("ok"); if (status != 200 || ok == null || !ok.isJsonPrimitive() || !ok.getAsJsonPrimitive().isBoolean() || !ok.getAsBoolean() || !parsed.has("data") || !parsed.get("data").isJsonObject()) throw denied(); return parsed.getAsJsonObject("data");
    } catch (RuntimeException failure) { throw denied(); }
    finally { Arrays.fill(body, (byte) 0); connection.disconnect(); }
  }
  public static JsonObject parseStrict(byte[] bytes) throws IOException {
    try {
      CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
      try (JsonReader reader = new JsonReader(new StringReader(decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()))) { reader.setStrictness(Strictness.STRICT); int[] count = {0}; JsonElement element = parseValue(reader, 0, count); if (!element.isJsonObject() || reader.peek() != JsonToken.END_DOCUMENT) throw denied(); return element.getAsJsonObject(); }
    } catch (RuntimeException failure) { throw denied(); }
  }
  private static JsonElement parseValue(JsonReader r, int depth, int[] nodes) throws IOException {
    if (depth > 12 || ++nodes[0] > 4096) throw denied();
    return switch (r.peek()) {
      case BEGIN_OBJECT -> { JsonObject object = new JsonObject(); r.beginObject(); while (r.hasNext()) { String name = r.nextName(); if (name.length() > 100 || object.has(name)) throw denied(); object.add(name, parseValue(r, depth + 1, nodes)); } r.endObject(); yield object; }
      case BEGIN_ARRAY -> { JsonArray array = new JsonArray(); r.beginArray(); while (r.hasNext()) array.add(parseValue(r, depth + 1, nodes)); r.endArray(); yield array; }
      case STRING -> { String value = r.nextString(); if (value.length() > 8192) throw denied(); yield new JsonPrimitive(value); }
      case NUMBER -> { String value = r.nextString(); if (!value.matches("0|[1-9][0-9]{0,18}")) throw denied(); yield new JsonPrimitive(new java.math.BigDecimal(value)); }
      case BOOLEAN -> new JsonPrimitive(r.nextBoolean());
      case NULL -> { r.nextNull(); yield JsonNull.INSTANCE; }
      default -> throw denied();
    };
  }
  private static String text(JsonObject object, String key) throws IOException { JsonElement e = object.get(key); if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) throw denied(); return e.getAsString(); }
  private static long exactLong(JsonObject object, String key) throws IOException { try { JsonElement e = object.get(key); if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isNumber()) throw denied(); return e.getAsBigDecimal().longValueExact(); } catch (ArithmeticException e) { throw denied(); } }
  private static IOException denied() { return new IOException("Проверка действующей сессии не пройдена"); }
}
