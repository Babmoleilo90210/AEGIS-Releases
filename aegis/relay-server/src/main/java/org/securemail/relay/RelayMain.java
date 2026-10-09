package org.securemail.relay;

import java.nio.file.*;
import java.time.Clock;
import java.util.concurrent.*;

public final class RelayMain {
  private RelayMain() {}

  public static void main(String[] args) {
    try {
      run(args);
    } catch (Exception e) {
      System.err.println("{\"event\":\"relay_error\",\"detail\":\"operation_failed\"}");
      System.exit(1);
    }
  }

  private static void run(String[] args) throws Exception {
    String command = args.length > 0 ? args[0] : "serve";
    Path file = Path.of(args.length > 1 ? args[1] : "config/relay.properties");
    RelayConfig config = RelayConfig.load(file);
    if (command.equals("version")) {
      System.out.println("AEGIS relay 0.3.0 / protocol 1");
      return;
    }
    Path health = config.databasePath().toAbsolutePath().resolveSibling("relay-health.json");
    if (command.equals("health")) {
      if (!Files.exists(health)
          || System.currentTimeMillis() - Files.getLastModifiedTime(health).toMillis() > 60_000)
        throw new IllegalStateException();
      System.out.println(Files.readString(health));
      return;
    }
    try (var store = new RelayStore(config, Clock.systemUTC())) {
      if (command.equals("cleanup")) {
        store.cleanup();
        System.out.println("{\"event\":\"cleanup_complete\"}");
        return;
      }
      if (command.equals("stats")) {
        System.out.println(stats(store, config, 0, 0));
        return;
      }
      if (!command.equals("serve")) throw new IllegalArgumentException();
      try (var server = new RelayServer(config, store, Clock.systemUTC())) {
        server.start();
        var stop = new CountDownLatch(1);
        var timer = Executors.newSingleThreadScheduledExecutor();
        var stopped = new CountDownLatch(1);
        Runtime.getRuntime()
            .addShutdownHook(
                new Thread(
                    () -> {
                      stop.countDown();
                      try {
                        stopped.await(10, TimeUnit.SECONDS);
                      } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                      }
                    },
                    "relay-shutdown"));
        timer.scheduleAtFixedRate(
            () -> {
              try {
                String s = stats(store, config, server.uptimeSeconds(), server.rejectedRequests());
                Path t = health.resolveSibling("relay-health.tmp");
                Files.writeString(t, s);
                Files.move(
                    t, health, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
              } catch (Exception ignored) {
                System.err.println("{\"event\":\"maintenance_failed\"}");
              }
            },
            0,
            30,
            TimeUnit.SECONDS);
        System.out.println("{\"event\":\"relay_started\",\"version\":\"0.3.0\"}");
        try {
          stop.await();
        } finally {
          timer.shutdownNow();
          try {
            timer.awaitTermination(5, TimeUnit.SECONDS);
            Files.deleteIfExists(health);
          } finally {
            stopped.countDown();
          }
        }
      }
    }
  }

  private static String stats(RelayStore s, RelayConfig c, long uptime, long rejects)
      throws Exception {
    return String.format(
        java.util.Locale.ROOT,
        "{\"version\":\"0.3.0\",\"users\":%d,\"pending_packets\":%d,\"pending_bytes\":%d,\"database_bytes\":%d,\"uptime_seconds\":%d,\"rejected_requests\":%d}",
        s.userCount(),
        s.packetCount(),
        s.pendingBytes(),
        Files.size(c.databasePath()),
        uptime,
        rejects);
  }
}
