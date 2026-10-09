package org.securemail.client;

import java.io.*;
import java.nio.file.*;
import java.util.Properties;
import org.securemail.protocol.Limits;

public record ClientConfig(
    String torSocksAddress,
    int torSocksPort,
    int torControlPort,
    int torUpdateSocksPort,
    Path torCookiePath,
    int localServicePort,
    long defaultTTL,
    String relayOnionAddress,
    int relayPort,
    Path storagePath,
    int maxFileSize,
    long maxLocalStorage,
    long deliveryTTL) {
  public ClientConfig {
    if (!torSocksAddress.equals("127.0.0.1")
        || torSocksPort < 1
        || torSocksPort > 65535
        || torControlPort < 1
        || torControlPort > 65535
        || torUpdateSocksPort < 1
        || torUpdateSocksPort > 65535
        || torUpdateSocksPort == torSocksPort
        || torUpdateSocksPort == torControlPort
        || torSocksPort == torControlPort
        || localServicePort < 1
        || localServicePort > 65535
        || relayPort < 1
        || relayPort > 65535
        || defaultTTL < 1
        || defaultTTL > Limits.MAX_TTL_SECONDS
        || maxFileSize < 1024
        || maxFileSize > Limits.HARD_FILE_BYTES
        || maxLocalStorage < maxFileSize
        || deliveryTTL < 60_000
        || deliveryTTL > Limits.MAX_DELIVERY_MILLIS)
      throw new IllegalArgumentException("Некорректная конфигурация");
    if (!relayOnionAddress.isEmpty()) Limits.onion(relayOnionAddress);
  }

  /** Existing protocol-1 clients and saved configurations retain their constructor. */
  public ClientConfig(String torSocksAddress,int torSocksPort,int torControlPort,
      Path torCookiePath,int localServicePort,long defaultTTL,String relayOnionAddress,
      int relayPort,Path storagePath,int maxFileSize,long maxLocalStorage,long deliveryTTL) {
    this(torSocksAddress,torSocksPort,torControlPort,19052,torCookiePath,localServicePort,
        defaultTTL,relayOnionAddress,relayPort,storagePath,maxFileSize,maxLocalStorage,deliveryTTL);
  }

  public static ClientConfig load(Path file) throws IOException {
    Properties p = new Properties();
    if (Files.exists(file))
      try (var in = Files.newInputStream(file)) {
        p.load(in);
      }
    return new ClientConfig(
        p.getProperty("torSocksAddress", "127.0.0.1"),
        n(p, "torSocksPort", 19050),
        n(p, "torControlPort", 19051),
        n(p, "torUpdateSocksPort", 19052),
        path(p.getProperty("torCookiePath", AppPaths.root().resolve("tor/control_auth_cookie").toString())),
        n(p, "localServicePort", 19120),
        n(p, "defaultTTL", 1800),
        p.getProperty("relayOnionAddress", ""),
        n(p, "relayPort", 80),
        path(p.getProperty("storagePath", AppPaths.windows() || System.getProperty("aegis.profile")!=null ? AppPaths.root().resolve("data").toString() : "~/.local/share/aegis")),
        n(p, "maxFileSize", Limits.DEFAULT_FILE_BYTES),
        Long.parseLong(p.getProperty("maxLocalStorage", "268435456")),
        Long.parseLong(p.getProperty("deliveryTTL", "604800000")));
  }

  private static int n(Properties p, String k, int d) {
    return Integer.parseInt(p.getProperty(k, "" + d));
  }

  public static Path path(String s) {
    return Path.of(s.startsWith("~/") ? System.getProperty("user.home") + s.substring(1) : s)
        .toAbsolutePath();
  }

  public ClientConfig withRelay(String onion) { return new ClientConfig(torSocksAddress,torSocksPort,torControlPort,torUpdateSocksPort,torCookiePath,localServicePort,defaultTTL,onion,relayPort,storagePath,maxFileSize,maxLocalStorage,deliveryTTL); }
  public ClientConfig withStorage(Path path) { return new ClientConfig(torSocksAddress,torSocksPort,torControlPort,torUpdateSocksPort,torCookiePath,localServicePort,defaultTTL,relayOnionAddress,relayPort,path,maxFileSize,maxLocalStorage,deliveryTTL); }
  public int maxCiphertext() {
    return maxFileSize + Limits.PAYLOAD_OVERHEAD;
  }

  public void save(Path file) throws IOException {
    Properties p = new Properties();
    p.setProperty("torSocksAddress", torSocksAddress);
    p.setProperty("torSocksPort", "" + torSocksPort);
    p.setProperty("torControlPort", "" + torControlPort);
    p.setProperty("torUpdateSocksPort", "" + torUpdateSocksPort);
    p.setProperty("torCookiePath", torCookiePath.toString());
    p.setProperty("localServicePort", "" + localServicePort);
    p.setProperty("defaultTTL", "" + defaultTTL);
    p.setProperty("relayOnionAddress", relayOnionAddress);
    p.setProperty("relayPort", "" + relayPort);
    p.setProperty("storagePath", storagePath.toString());
    p.setProperty("maxFileSize", "" + maxFileSize);
    p.setProperty("maxLocalStorage", "" + maxLocalStorage);
    p.setProperty("deliveryTTL", "" + deliveryTTL);
    org.securemail.client.storage.AtomicFiles.directory(file.toAbsolutePath().getParent());
    var b = new ByteArrayOutputStream();
    p.store(b, "AEGIS settings. No secrets.");
    org.securemail.client.storage.AtomicFiles.write(file.toAbsolutePath(), b.toByteArray());
  }
}
