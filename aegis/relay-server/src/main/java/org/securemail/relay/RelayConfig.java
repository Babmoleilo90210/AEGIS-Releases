package org.securemail.relay;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.securemail.protocol.Limits;

public record RelayConfig(
    Path databasePath,
    String listenAddress,
    int listenPort,
    long maxMessageAge,
    int maxFileSize,
    long maxPendingStoragePerUser,
    int maxPendingPackets,
    int maxUsers,
    boolean allowRegistration,
    Set<String> allowedNicknames) {
  public RelayConfig {
    if (!listenAddress.equals("127.0.0.1")
        || listenPort < 0
        || listenPort > 65535
        || maxMessageAge < 60_000
        || maxMessageAge > Limits.MAX_DELIVERY_MILLIS
        || maxFileSize < 1024
        || maxFileSize > Limits.HARD_FILE_BYTES
        || maxPendingStoragePerUser < maxFileSize
        || maxPendingPackets < 1
        || maxPendingPackets > 1024
        || maxUsers < 1
        || maxUsers > 32) throw new IllegalArgumentException("Invalid relay config: loopback only");
    allowedNicknames = Set.copyOf(allowedNicknames);
  }

  public static RelayConfig load(Path path) throws IOException {
    Properties p = new Properties();
    try (var in = Files.newInputStream(path)) {
      p.load(in);
    }
    var names = new HashSet<String>();
    for (String n : p.getProperty("allowedNicknames", "").split(","))
      if (!n.isBlank()) names.add(Limits.nickname(n.strip()));
    String mode=p.getProperty("registrationMode", "legacy");
    if(!Set.of("legacy","open","closed").contains(mode))throw new IOException("registrationMode must be open or closed");
    if(mode.equals("open"))names.clear();
    return new RelayConfig(
        Path.of(p.getProperty("databasePath", "data/relay.db")),
        p.getProperty("listenAddress", "127.0.0.1"),
        Integer.parseInt(p.getProperty("listenPort", "19110")),
        Long.parseLong(p.getProperty("maxMessageAge", "604800000")),
        Integer.parseInt(p.getProperty("maxFileSize", "16777216")),
        Long.parseLong(p.getProperty("maxPendingStoragePerUser", "268435456")),
        Integer.parseInt(p.getProperty("maxPendingPackets", "256")),
        Integer.parseInt(p.getProperty("maxUsers", "32")),
        mode.equals("open") || (mode.equals("legacy") && Boolean.parseBoolean(p.getProperty("allowRegistration", "false"))),
        names);
  }

  public int maxCiphertext() {
    return maxFileSize + Limits.PAYLOAD_OVERHEAD;
  }
}
