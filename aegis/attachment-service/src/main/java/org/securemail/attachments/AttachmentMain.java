package org.securemail.attachments;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.CountDownLatch;

/** Explicit operator CLI. Does not configure Tor, change Relay or deploy anything. */
public final class AttachmentMain {
  private AttachmentMain() {}
  public static void main(String[] args) {
    try {
      if (args.length == 2 && args[0].equals("init")) { initialize(Path.of(args[1])); return; }
      if (args.length != 6 || !args[0].equals("serve")) throw new IOException("Аргументы");
      Path state = Path.of(args[1]).toAbsolutePath().normalize(); int port = Integer.parseInt(args[2]); if (port < 1 || port > 65535) throw new IOException("Порт");
      byte[] privateBytes = secret(state.resolve("service-private.pkcs8"), 48), publicBytes = secret(state.resolve("service-public.x509"), 44), identityPublic = IdentityRemoteAuthority.readPinnedKey(Path.of(args[5]));
      KeyPair key; try { KeyFactory factory = KeyFactory.getInstance("Ed25519"); key = new KeyPair(factory.generatePublic(new X509EncodedKeySpec(publicBytes)), factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes))); } finally { Arrays.fill(privateBytes, (byte) 0); }
      if (!args[3].equals("--identity")) throw new IOException("Identity"); var authority = new IdentityRemoteAuthority(URI.create(args[4]), identityPublic);
      try (var store = new AttachmentStore(state.resolve("store"), Clock.systemUTC(), AttachmentStore.Quotas.defaults()); var server = new AttachmentHttpServer(new InetSocketAddress("127.0.0.1", port), store, authority::authorize, key)) {
        var stop = new CountDownLatch(1); Runtime.getRuntime().addShutdownHook(new Thread(stop::countDown, "aegis-attachment-stop")); server.start(); System.out.println("Сервис вложений слушает только loopback; требуется отдельный onion service."); stop.await();
      }
    } catch (Exception failure) { System.err.println("Сервис вложений не запущен: проверьте защищённый каталог, параметры, ключ Identity и доступность его проверки. Прямой обход авторизации отключён."); System.exit(1); }
  }
  private static void initialize(Path path) throws Exception {
    path = path.toAbsolutePath().normalize(); Path parent = path.getParent(); if (parent == null || !parent.toRealPath().equals(parent) || Files.exists(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Нужен новый каталог");
    Path temporary = parent.resolve(".attachment-setup-" + UUID.randomUUID()); Files.createDirectory(temporary, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    KeyPair key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); byte[] privateBytes = key.getPrivate().getEncoded();
    try { write(temporary.resolve("service-private.pkcs8"), privateBytes); write(temporary.resolve("service-public.x509"), key.getPublic().getEncoded()); Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE); System.out.println("Подготовлен отдельный сервис вложений. Публичный ключ: " + Base64.getEncoder().encodeToString(key.getPublic().getEncoded())); }
    finally { Arrays.fill(privateBytes, (byte) 0); }
  }
  private static void write(Path path, byte[] bytes) throws IOException { Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); Files.write(path, bytes); }
  private static byte[] secret(Path path, int size) throws IOException { if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) != size || Files.getPosixFilePermissions(path).stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))) throw new IOException("Ключ сервиса"); return Files.readAllBytes(path); }
}
