package org.securemail.management;

import com.google.gson.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.security.spec.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.attachments.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Public non-root agent and separately invoked fixed privileged broker. No arbitrary root shell. */
public final class ManagementMain {
  private static final int MAX_REQUEST = 16384;
  private ManagementMain() {}
  public static void main(String[] args) {
    try {
      if (args.length == 1 && args[0].equals("broker")) { broker(); return; }
      if (args.length == 1 && args[0].equals("broker-serve")) { brokerServe(); return; }
      if (args.length == 1 && args[0].equals("broker-init")) { initializeBroker(); return; }
      if (args.length == 2 && args[0].equals("init")) { initialize(Path.of(args[1])); return; }
      if (args.length == 3 && args[0].equals("serve") && !root()) { serve(Path.of(args[1]), Integer.parseInt(args[2])); return; }
      throw new IOException("Аргументы управления");
    } catch (Exception failure) { System.err.println("Операция управления АЕГИС не выполнена. Проверьте серверные полномочия, изоляцию, параметры и журнал безопасности."); System.exit(1); }
  }
  private static void broker() throws Exception {
    byte[] requestBytes = System.in.readNBytes(MAX_REQUEST + 1); if (requestBytes.length > MAX_REQUEST) throw new IOException("Размер запроса управления");
    try (ManagementService service = brokerService()) { System.out.println(processBroker(service, requestBytes)); }
    finally { Arrays.fill(requestBytes, (byte) 0); }
  }
  private static ManagementService brokerService() throws Exception {
    if (!root()) throw new IOException("Нужен защищённый системный broker"); Path configuration = Path.of("/etc/aegis600/management-broker.properties"); rootOwned(configuration);
    Properties p = new Properties(); try (InputStream in = Files.newInputStream(configuration, LinkOption.NOFOLLOW_LINKS)) { p.load(in); }
    if (!p.stringPropertyNames().equals(Set.of("identityEndpoint", "identityPublicKey", "stateDirectory"))) throw new IOException("Настройки broker");
    Path publicPath = Path.of(p.getProperty("identityPublicKey")).toAbsolutePath().normalize(), state = Path.of(p.getProperty("stateDirectory")).toAbsolutePath().normalize(); rootOwned(publicPath);
    if (!state.equals(Path.of("/var/lib/aegis600/management-broker")) || !Files.isDirectory(state, LinkOption.NOFOLLOW_LINKS) || !state.toRealPath().equals(state)) throw new IOException("Каталог broker"); rootOwned(state);
    byte[] publicKey = IdentityRemoteAuthority.readPinnedKey(publicPath), auditKey = privateBytes(state.resolve("audit.key"), 32); var authority = new IdentityRemoteAuthority(URI.create(p.getProperty("identityEndpoint")), publicKey);
    try { return new ManagementService(state.resolve("management.sqlite"), auditKey, authority::authorize, ManagementService::runFixedProcess, Clock.systemUTC()); }
    finally { Arrays.fill(auditKey, (byte) 0); }
  }
  private static JsonObject processBroker(ManagementService service, byte[] bytes) throws Exception {
    Envelope envelope = decode(bytes); var result = service.execute(envelope.request(), envelope.proofs()); JsonObject output = new JsonObject(); output.addProperty("exitCode", result.exitCode()); output.addProperty("output", result.safeOutput()); return output;
  }
  private static void brokerServe() throws Exception {
    if (!root()) throw new IOException("Нужен системный broker"); Path socket = Path.of("/run/aegis600-management/broker.sock");
    rootOwned(socket.getParent());
    if (!socket.getParent().toRealPath().equals(socket.getParent()) || Files.exists(socket, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Каталог broker socket");
    var timer = new ScheduledThreadPoolExecutor(1); timer.setRemoveOnCancelPolicy(true);
    var workers = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(4), r -> new Thread(r, "aegis-root-broker"), new ThreadPoolExecutor.AbortPolicy());
    try (ManagementService service = brokerService(); ServerSocketChannel listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
      listener.bind(UnixDomainSocketAddress.of(socket)); Files.setPosixFilePermissions(socket, PosixFilePermissions.fromString("rw-rw----")); Files.getFileAttributeView(socket, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).setGroup(FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByGroupName("aegis600-management"));
      Runtime.getRuntime().addShutdownHook(new Thread(() -> { try { listener.close(); } catch (IOException ignored) {} workers.shutdownNow(); timer.shutdownNow(); }, "aegis-root-broker-stop"));
      while (listener.isOpen()) {
        SocketChannel channel = listener.accept();
        var peer = channel.getOption(jdk.net.ExtendedSocketOptions.SO_PEERCRED);
        if (!peer.user().getName().equals("aegis600-management")) { channel.close(); continue; }
        try { workers.execute(() -> {
          var deadline = timer.schedule(() -> { try { channel.close(); } catch (IOException ignored) {} }, 50, TimeUnit.SECONDS);
          try (channel; var in = new DataInputStream(Channels.newInputStream(channel)); var out = new DataOutputStream(Channels.newOutputStream(channel))) {
            int length = in.readInt(); if (length < 2 || length > MAX_REQUEST) throw new IOException("Размер broker request"); byte[] request = in.readNBytes(length); if (request.length != length) throw new EOFException();
            try { byte[] reply = processBroker(service, request).toString().getBytes(StandardCharsets.UTF_8); if (reply.length > 12288) throw new IOException("Размер broker reply"); out.writeInt(reply.length); out.write(reply); out.flush(); }
            finally { Arrays.fill(request, (byte) 0); }
          } catch (Exception ignored) { /* No raw request/secret or filesystem exception is logged. */ } finally { deadline.cancel(false); }
        }); } catch (RejectedExecutionException full) { channel.close(); }
      }
    } finally { workers.shutdownNow(); timer.shutdownNow(); Files.deleteIfExists(socket); }
  }
  private static void serve(Path state, int port) throws Exception {
    if (port < 1 || port > 65535) throw new IOException("Порт управления"); state = state.toAbsolutePath().normalize(); if (!state.toRealPath().equals(state)) throw new IOException("Каталог управления");
    byte[] secret = privateBytes(state.resolve("service-private.pkcs8"), 48), pub = privateBytes(state.resolve("service-public.x509"), 44); KeyFactory f = KeyFactory.getInstance("Ed25519"); KeyPair key;
    try { key = new KeyPair(f.generatePublic(new X509EncodedKeySpec(pub)), f.generatePrivate(new PKCS8EncodedKeySpec(secret))); } finally { Arrays.fill(secret, (byte) 0); }
    try (var server = new ManagementHttpServer600(new InetSocketAddress("127.0.0.1", port), key, ManagementMain::invokeBroker)) {
      CountDownLatch stop = new CountDownLatch(1); Runtime.getRuntime().addShutdownHook(new Thread(stop::countDown, "aegis-management-stop")); server.start(); System.out.println("Управление АЕГИС доступно только через loopback; системные операции ограничены broker."); stop.await();
    }
  }
  private static JsonObject invokeBroker(byte[] body) throws Exception {
    Path path = Path.of("/run/aegis600-management/broker.sock"); rootOwned(path.getParent()); if (!Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).getName().equals("root") || Files.isSymbolicLink(path)) throw new IOException("Недоверенный broker socket");
    try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
      channel.connect(UnixDomainSocketAddress.of(path)); var peer = channel.getOption(jdk.net.ExtendedSocketOptions.SO_PEERCRED); if (!peer.user().getName().equals("root")) throw new IOException("Недоверенный broker");
      var executor = Executors.newSingleThreadScheduledExecutor(r -> { Thread t = new Thread(r, "aegis-broker-deadline"); t.setDaemon(true); return t; }); var deadline = executor.schedule(() -> { try { channel.close(); } catch (IOException ignored) {} }, 50, TimeUnit.SECONDS);
      try { var out = new DataOutputStream(Channels.newOutputStream(channel)); var in = new DataInputStream(Channels.newInputStream(channel)); out.writeInt(body.length); out.write(body); out.flush(); int length = in.readInt(); if (length < 2 || length > 12288) throw new IOException("Размер broker reply"); byte[] response = in.readNBytes(length); if (response.length != length) throw new EOFException(); return IdentityRemoteAuthority.parseStrict(response); }
      finally { deadline.cancel(false); executor.shutdownNow(); }
    }
  }
  public record Envelope(ManagementPolicy.Request request, List<IdentityRemoteAuthority.Proof> proofs) { public Envelope { proofs = List.copyOf(proofs); } }
  public static Envelope decode(byte[] body) throws IOException {
    if (body.length > MAX_REQUEST) throw new IOException("Размер запроса управления"); JsonObject object = IdentityRemoteAuthority.parseStrict(body);
    if (!object.keySet().equals(Set.of("metadata", "proofs")) || !object.get("metadata").isJsonPrimitive() || !object.getAsJsonPrimitive("metadata").isString() || !object.get("proofs").isJsonArray()) throw new IOException("Формат управления");
    var request = ManagementPolicy.decode(IdentityProtocol.unb64(object.get("metadata").getAsString(), 1024)); JsonArray proofs = object.getAsJsonArray("proofs"); if (proofs.size() != (request.action().critical() ? 2 : 1)) throw new IOException("Подтверждения операции"); List<IdentityRemoteAuthority.Proof> values = new ArrayList<>();
    try { for (JsonElement e : proofs) { if (!e.isJsonObject()) throw new IOException("Подтверждение"); var p = e.getAsJsonObject(); if (!p.keySet().equals(Set.of("capability", "time", "nonce", "proof"))) throw new IOException("Подтверждение"); values.add(new IdentityRemoteAuthority.Proof(p.get("capability").getAsString(), p.get("time").getAsBigDecimal().longValueExact(), p.get("nonce").getAsString(), IdentityProtocol.unb64(p.get("proof").getAsString(), 64))); } }
    catch (RuntimeException failure) { throw new IOException("Подтверждение операции", failure); } return new Envelope(request, values);
  }
  private static void initialize(Path path) throws Exception {
    path = path.toAbsolutePath().normalize(); if (Files.exists(path, LinkOption.NOFOLLOW_LINKS) || path.getParent() == null || !path.getParent().toRealPath().equals(path.getParent())) throw new IOException("Нужен новый каталог управления"); Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); byte[] audit = new byte[32], secret = pair.getPrivate().getEncoded(); new SecureRandom().nextBytes(audit);
    try { write(path.resolve("audit.key"), audit); write(path.resolve("service-private.pkcs8"), secret); write(path.resolve("service-public.x509"), pair.getPublic().getEncoded()); } finally { Arrays.fill(audit, (byte) 0); Arrays.fill(secret, (byte) 0); }
    System.out.println("Подготовлен отдельный каталог управления без production-изменений.");
  }
  private static void initializeBroker() throws Exception {
    if (!root()) throw new IOException("Нужна локальная настройка системного broker");
    Path state = Path.of("/var/lib/aegis600/management-broker"); rootOwned(state);
    if (!Files.isDirectory(state, LinkOption.NOFOLLOW_LINKS) || Files.getPosixFilePermissions(state).stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))) throw new IOException("Приватный каталог broker");
    try (var entries = Files.list(state)) { if (entries.findAny().isPresent()) throw new IOException("Повторная инициализация broker запрещена"); }
    byte[] audit = new byte[32]; new SecureRandom().nextBytes(audit);
    try { write(state.resolve("audit.key"), audit); } finally { Arrays.fill(audit, (byte) 0); }
    System.out.println("Создан отдельный ключ аудита broker без ключей аккаунтов и релиза.");
  }
  private static boolean root() { return System.getProperty("os.name").equals("Linux") && new com.sun.security.auth.module.UnixSystem().getUid() == 0; }
  private static void rootOwned(Path path) throws IOException { if (!path.toAbsolutePath().normalize().equals(path.toRealPath()) || Files.isSymbolicLink(path) || !Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).getName().equals("root") || Files.getPosixFilePermissions(path).contains(PosixFilePermission.GROUP_WRITE) || Files.getPosixFilePermissions(path).contains(PosixFilePermission.OTHERS_WRITE)) throw new IOException("Доверенный файл broker"); }
  private static byte[] privateBytes(Path path, int size) throws IOException { if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) != size || Files.getPosixFilePermissions(path).stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))) throw new IOException("Защищённый файл управления"); return Files.readAllBytes(path); }
  private static void write(Path path, byte[] data) throws IOException { Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); Files.write(path, data); }
}
