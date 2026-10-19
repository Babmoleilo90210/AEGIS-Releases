package org.securemail.attachments;

import static org.junit.jupiter.api.Assertions.*;
import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.attachments.protocol.AttachmentProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import org.securemail.identity.*;
import org.securemail.client.attachments600.*;
import org.securemail.client.net.TorTransport;

/** Real production HTTP+SQLite+Ed25519+Identity generation checks; explicitly NOT Tor/native. */
class AttachmentHttpIntegrationTest {
  @TempDir Path home;
  IdentityStore identity; IdentityHttpServer identityHttp; AttachmentStore objects; AttachmentHttpServer attachmentHttp; IdentityRemoteAuthority authority;
  KeyPair identityKey, attachmentKey; Account sender, recipient;
  record Account(KeyPair root, KeyPair device, KeyPair recovery, KeyPair app, IdentityStore.Session session, Capability capability) {}
  record Reply(int status, JsonObject metadata, byte[] payload) {}
  static KeyPair pair() throws Exception { return KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); }
  @BeforeEach void setup() throws Exception {
    identityKey = pair(); attachmentKey = pair(); byte[] audit = new byte[32]; new SecureRandom().nextBytes(audit); identity = new IdentityStore(home.resolve("identity.sqlite"), identityKey, audit, Clock.systemUTC());
    sender = account(); recipient = account(); identityHttp = new IdentityHttpServer(new InetSocketAddress("127.0.0.1", 0), identity, identityKey); identityHttp.start();
    authority = new IdentityRemoteAuthority(URI.create("http://127.0.0.1:" + identityHttp.port() + "/identity/v1"), identityKey.getPublic().getEncoded()); objects = new AttachmentStore(home.resolve("objects"), Clock.systemUTC(), AttachmentStore.Quotas.defaults());
    attachmentHttp = new AttachmentHttpServer(new InetSocketAddress("127.0.0.1", 0), objects, authority::authorize, attachmentKey); attachmentHttp.start();
  }
  @AfterEach void close() throws Exception { if (attachmentHttp != null) attachmentHttp.close(); if (objects != null) objects.close(); if (identityHttp != null) identityHttp.close(); if (identity != null) identity.close(); }
  Account account() throws Exception {
    KeyPair root = pair(), device = pair(), recovery = pair(), app = pair(); long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] registration = IdentityProtocol.registration(identity.audience(), root.getPublic().getEncoded(), device.getPublic().getEncoded(), recovery.getPublic().getEncoded(), "Тест", now, nonce);
    var session = identity.register(root.getPublic().getEncoded(), device.getPublic().getEncoded(), recovery.getPublic().getEncoded(), "Тест", now, nonce, IdentityProtocol.sign(root.getPrivate(), registration), IdentityProtocol.sign(device.getPrivate(), registration));
    Set<Scope> scopes = EnumSet.of(Scope.MAIL_READ, Scope.MAIL_SEND); now = System.currentTimeMillis(); nonce = IdentityProtocol.nonce(); byte[] request = IdentityProtocol.capabilityRequest(identity.audience(), session.accountId(), session.deviceId(), session.generation(), App.MAIL, app.getPublic().getEncoded(), scopes, 600000, now, nonce);
    Capability cap = identity.issueCapability(session.accountId(), session.deviceId(), session.generation(), App.MAIL, app.getPublic().getEncoded(), scopes, 600000, now, nonce, IdentityProtocol.sign(device.getPrivate(), request), IdentityProtocol.sign(app.getPrivate(), request)); return new Account(root, device, recovery, app, session, cap);
  }
  IdentityRemoteAuthority.Proof proof(Account account, AttachmentProtocol.Request request) { long time = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] signature = IdentityProtocol.sign(account.app().getPrivate(), IdentityProtocol.requestDigest(account.capability(), request.command().action(), IdentityProtocol.digest(request.encode()), time, nonce)); return new IdentityRemoteAuthority.Proof(IdentityProtocol.encodeCapability(account.capability()), time, nonce, signature); }
  Reply request(Account account, AttachmentProtocol.Request request, byte[] payload) throws Exception { return request(request, payload, proof(account, request)); }
  Reply request(AttachmentProtocol.Request request, byte[] payload, IdentityRemoteAuthority.Proof proof) throws Exception {
    byte[] metadata = request.encode(), body = AttachmentProtocol.frame(metadata, payload); HttpURLConnection http = (HttpURLConnection) new URL("http://127.0.0.1:" + attachmentHttp.port() + "/attachments/v1").openConnection(Proxy.NO_PROXY); http.setRequestMethod("POST"); http.setDoOutput(true); http.setConnectTimeout(2000); http.setReadTimeout(5000); http.setFixedLengthStreamingMode(body.length); http.setRequestProperty("Content-Type", "application/octet-stream"); http.setRequestProperty("AEGIS-Capability", proof.capability()); http.setRequestProperty("AEGIS-Time", Long.toString(proof.time())); http.setRequestProperty("AEGIS-Nonce", proof.nonce()); http.setRequestProperty("AEGIS-Proof", IdentityProtocol.b64(proof.signature()));
    try { try (OutputStream out = http.getOutputStream()) { out.write(body); } int status = http.getResponseCode(); byte[] response; try (InputStream in = status < 400 ? http.getInputStream() : http.getErrorStream()) { response = in.readNBytes(AttachmentProtocol.CHUNK_BYTES + AttachmentProtocol.MAX_REPLY_METADATA + 5); }
      assertTrue(IdentityProtocol.verify(attachmentKey.getPublic().getEncoded(), AttachmentProtocol.responseSigningBytes(metadata, proof.nonce(), response), IdentityProtocol.unb64(http.getHeaderField("AEGIS-Signature"), 64)));
      try (var in = new DataInputStream(new ByteArrayInputStream(response))) { int n = in.readInt(); assertTrue(n <= AttachmentProtocol.MAX_REPLY_METADATA); JsonObject meta = IdentityRemoteAuthority.parseStrict(in.readNBytes(n)); return new Reply(status, meta, in.readAllBytes()); }
    } finally { http.disconnect(); }
  }
  @Test void actualRemoteIdentityAndChunkHttpRoundTripThenRecipientAck() throws Exception {
    byte[] bytes = new byte[2 * AttachmentProtocol.CHUNK_BYTES + 7]; new Random(8).nextBytes(bytes); String id = UUID.randomUUID().toString(); var create = AttachmentProtocol.Request.create(id, recipient.session().accountId(), bytes.length, AttachmentProtocol.sha256(bytes), 60000);
    assertEquals(200, request(sender, create, new byte[0]).status()); assertEquals(403, request(recipient, AttachmentProtocol.Request.control(AttachmentProtocol.Command.STATUS, id), new byte[0]).status());
    for (int i = 0; i < 3; i++) { byte[] chunk = Arrays.copyOfRange(bytes, i * AttachmentProtocol.CHUNK_BYTES, Math.min(bytes.length, (i + 1) * AttachmentProtocol.CHUNK_BYTES)); assertEquals(200, request(sender, AttachmentProtocol.Request.put(id, i, chunk.length, AttachmentProtocol.sha256(chunk)), chunk).status()); }
    assertEquals(200, request(sender, AttachmentProtocol.Request.control(AttachmentProtocol.Command.COMMIT, id), new byte[0]).status()); var restored = new ByteArrayOutputStream();
    for (int i = 0; i < 3; i++) { Reply reply = request(recipient, AttachmentProtocol.Request.get(id, i), new byte[0]); assertEquals(200, reply.status()); restored.write(reply.payload()); } assertArrayEquals(bytes, restored.toByteArray());
    assertEquals(200, request(recipient, AttachmentProtocol.Request.control(AttachmentProtocol.Command.ACK, id), new byte[0]).status()); assertEquals(0, objects.reservedBytes());
  }
  @Test void tamperedOperationReplayAndCipherChunkMismatchRejectedByRealServers() throws Exception {
    byte[] bytes = new byte[100]; String id = UUID.randomUUID().toString(); var create = AttachmentProtocol.Request.create(id, recipient.session().accountId(), bytes.length, AttachmentProtocol.sha256(bytes), 60000); var initial = proof(sender, create);
    var changed = AttachmentProtocol.Request.create(id, sender.session().accountId(), bytes.length, AttachmentProtocol.sha256(bytes), 60000); assertEquals(403, request(changed, new byte[0], initial).status());
    assertEquals(200, request(create, new byte[0], initial).status()); assertEquals(403, request(create, new byte[0], initial).status());
    var put = AttachmentProtocol.Request.put(id, 0, bytes.length, "0".repeat(64)); assertEquals(403, request(sender, put, bytes).status());
    assertEquals(0, objects.status(new AttachmentStore.Authorization(new VerifiedContext(sender.capability()), () -> identity.validateCurrent(sender.capability())), id).present().size());
  }
  @Test void newGenerationRevokesRemoteAuthorityAndOldUploadCapability() throws Exception {
    var request = AttachmentProtocol.Request.create(UUID.randomUUID().toString(), recipient.session().accountId(), 100, "0".repeat(64), 60000); var bound = authority.authorize(proof(sender, request), request.command().action(), request.encode());
    long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] login = IdentityProtocol.login(identity.audience(), sender.session().accountId(), sender.session().deviceId(), now, nonce); identity.login(sender.session().accountId(), sender.session().deviceId(), now, nonce, IdentityProtocol.sign(sender.device().getPrivate(), login));
    Thread.sleep(275); assertThrows(IOException.class, bound::check); assertEquals(403, request(sender, request, new byte[0]).status()); assertEquals(0, objects.transferCount());
  }
  @Test void servicePinAndPublicListenAreRejected() throws Exception {
    var wrong = new IdentityRemoteAuthority(URI.create("http://127.0.0.1:" + identityHttp.port() + "/identity/v1"), pair().getPublic().getEncoded()); var request = AttachmentProtocol.Request.create(UUID.randomUUID().toString(), recipient.session().accountId(), 100, "0".repeat(64), 60000);
    assertThrows(IOException.class, () -> wrong.authorize(proof(sender, request), request.command().action(), request.encode()));
    assertThrows(IOException.class, () -> new AttachmentHttpServer(new InetSocketAddress("0.0.0.0", 0), objects, authority::authorize, attachmentKey)); assertThrows(IllegalArgumentException.class, () -> new IdentityRemoteAuthority(URI.create("http://example.com/identity/v1"), identityKey.getPublic().getEncoded()));
  }
  @Test void actualOnionOnlyClientFiveHundredMiBHttpUploadResumeRestartDownloadRevoke() throws Exception {
    long started = System.nanoTime(); String onion = "a".repeat(56) + ".onion", id = UUID.randomUUID().toString(); long size = StreamingAttachmentCipher.MAX_PLAINTEXT;
    Path spool = home.resolve("cipher.spool"), partial = home.resolve("received.spool"), restored = home.resolve("restored.bin"); byte[] key = StreamingAttachmentCipher.newFileKey(); var context = new StreamingAttachmentCipher.Context(id, sender.session().accountId(), recipient.session().accountId(), size); StreamingAttachmentCipher.Result encrypted;
    try (InputStream source = new PatternInput(size); OutputStream out = Files.newOutputStream(spool, StandardOpenOption.CREATE_NEW)) { encrypted = StreamingAttachmentCipher.encrypt(source, out, context, key, () -> true); }
    var remote = new AttachmentClient600.RemoteFile(id, recipient.session().accountId(), encrypted.ciphertextBytes(), encrypted.ciphertextSha256(), AttachmentStore.MAX_PENDING_TTL);
    int originPort = attachmentHttp.port();
    try (SocksFixture socks = new SocksFixture(onion, () -> attachmentHttp.port());
         AttachmentClient600 outgoing = new AttachmentClient600(new TorTransport("127.0.0.1", socks.port()), onion, 80, attachmentKey.getPublic().getEncoded(), identityKey.getPublic().getEncoded(), IdentityProtocol.encodeCapability(sender.capability()), sender.app().getPrivate());
         AttachmentClient600 incoming = new AttachmentClient600(new TorTransport("127.0.0.1", socks.port()), onion, 80, attachmentKey.getPublic().getEncoded(), identityKey.getPublic().getEncoded(), IdentityProtocol.encodeCapability(recipient.capability()), recipient.app().getPrivate())) {
      // Stop after two actual HTTP chunks; only the encrypted spool survives.
      assertThrows(IOException.class, () -> outgoing.upload(spool, remote, () -> true, (done, total) -> { if (done >= 2L * AttachmentProtocol.CHUNK_BYTES) throw new IOException("planned interruption"); }));
      attachmentHttp.close(); objects.close(); objects = new AttachmentStore(home.resolve("objects"), Clock.systemUTC(), AttachmentStore.Quotas.defaults()); attachmentHttp = new AttachmentHttpServer(new InetSocketAddress("127.0.0.1", 0), objects, authority::authorize, attachmentKey); attachmentHttp.start();
      // Production Identity rate budgets are retained. The fixture paces requests instead of disabling security checks.
      outgoing.upload(spool, remote, () -> true, (done, total) -> pace());
      assertThrows(IOException.class, () -> incoming.download(remote, partial, () -> true, (done, total) -> { if (done >= 3L * AttachmentProtocol.CHUNK_BYTES) throw new IOException("planned interruption"); }));
      incoming.download(remote, partial, () -> true, (done, total) -> pace());
      try (InputStream in = Files.newInputStream(partial)) { assertEquals(encrypted, StreamingAttachmentCipher.decryptToNewFile(in, restored, context, key, encrypted.plaintextSha256(), encrypted.ciphertextSha256(), () -> true)); }
      assertEquals(size, Files.size(restored)); incoming.acknowledge(id); assertEquals(0, objects.reservedBytes());
      long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] login = IdentityProtocol.login(identity.audience(), sender.session().accountId(), sender.session().deviceId(), now, nonce); identity.login(sender.session().accountId(), sender.session().deviceId(), now, nonce, IdentityProtocol.sign(sender.device().getPrivate(), login));
      assertThrows(IOException.class, () -> outgoing.exchange(AttachmentProtocol.Request.create(UUID.randomUUID().toString(), remote.recipientId(), 100, "0".repeat(64), 60000), new byte[0]));
      System.out.println("{\"scope\":\"actual-500MiB-production-client-SOCKS-fixture-HTTP-Identity-crypto-not-public-Tor\",\"plaintextBytes\":" + size + ",\"ciphertextBytes\":" + encrypted.ciphertextBytes() + ",\"chunks\":" + remote.chunks() + ",\"heapMaxBytes\":" + Runtime.getRuntime().maxMemory() + ",\"durationMillis\":" + ((System.nanoTime() - started) / 1_000_000) + "}");
    } finally { Arrays.fill(key, (byte) 0); }
  }
  private static void pace() throws IOException { try { Thread.sleep(160); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); } }
  private static final class PatternInput extends InputStream { long remaining, offset; PatternInput(long size) { remaining = size; } @Override public int read() { if (remaining == 0) return -1; remaining--; return (int) ((offset++ * 17 + 3) & 255); } @Override public int read(byte[] b, int off, int len) { if (remaining == 0) return -1; int n = (int) Math.min(remaining, len); for (int i = 0; i < n; i++) b[off + i] = (byte) (offset++ * 17 + 3); remaining -= n; return n; } }
  /** Local SOCKS5 test fixture only. It validates the production client sent an onion name, never DNS/IP. */
  private static final class SocksFixture implements AutoCloseable {
    final ServerSocket listener = new ServerSocket(0, 8, InetAddress.getByAddress(new byte[]{127,0,0,1})); final ExecutorService pool = Executors.newFixedThreadPool(8); final Set<Socket> active = ConcurrentHashMap.newKeySet(); final Thread accept; final String onion; final java.util.function.IntSupplier origin; volatile boolean closed;
    SocksFixture(String onion, java.util.function.IntSupplier origin) throws IOException { this.onion = onion; this.origin = origin; accept = new Thread(() -> { while (!closed) try { Socket socket = listener.accept(); active.add(socket); pool.execute(() -> relay(socket)); } catch (IOException | RejectedExecutionException e) { if (!closed) throw new IllegalStateException(e); } }, "attachment-test-socks"); accept.setDaemon(true); accept.start(); }
    int port() { return listener.getLocalPort(); }
    void relay(Socket client) {
      Socket backend = null;
      try { client.setSoTimeout(60000); var in = new DataInputStream(client.getInputStream()); OutputStream out = client.getOutputStream(); if (in.readUnsignedByte() != 5 || in.readUnsignedByte() != 1 || in.readUnsignedByte() != 0) throw new IOException(); out.write(new byte[]{5,0}); out.flush(); if (in.readUnsignedByte() != 5 || in.readUnsignedByte() != 1 || in.readUnsignedByte() != 0 || in.readUnsignedByte() != 3) throw new IOException(); int n = in.readUnsignedByte(); String host = new String(in.readNBytes(n), StandardCharsets.US_ASCII); int port = in.readUnsignedShort(); if (!host.equals(onion) || port != 80) throw new IOException(); backend = new Socket(InetAddress.getByAddress(new byte[]{127,0,0,1}), origin.getAsInt()); active.add(backend); out.write(new byte[]{5,0,0,1,127,0,0,1,0,0}); out.flush(); Socket target = backend;
        pool.execute(() -> { try { target.getInputStream().transferTo(client.getOutputStream()); } catch (IOException ignored) {} finally { try { target.close(); client.close(); } catch (IOException ignored) {} active.remove(target); active.remove(client); } }); in.transferTo(backend.getOutputStream());
      } catch (IOException ignored) { try { client.close(); if (backend != null) backend.close(); } catch (IOException ignored2) {} }
    }
    @Override public void close() throws Exception { closed = true; listener.close(); for (Socket socket : active) socket.close(); pool.shutdownNow(); accept.join(1000); }
  }
}
