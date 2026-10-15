package org.securemail.integration;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** TEST ONLY. Synthetic onion routing, never packaged in production applications. */
final class SocksHarness implements AutoCloseable {
  static final String RELAY = "a".repeat(56) + ".onion", PEER = "b".repeat(56) + ".onion";
  final ServerSocket server = new ServerSocket(0, 16, InetAddress.getLoopbackAddress());
  final Map<String, Integer> destinations = new ConcurrentHashMap<>();
  final List<String> hosts = new CopyOnWriteArrayList<>();
  final AtomicBoolean dropNextPeerReply = new AtomicBoolean();
  final ByteArrayOutputStream relayBytes = new ByteArrayOutputStream();
  final ExecutorService work = Executors.newVirtualThreadPerTaskExecutor();
  final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
  volatile boolean closed;

  SocksHarness() throws IOException {
    work.submit(
        () -> {
          while (!closed)
            try {
              Socket s = server.accept();
              sockets.add(s);
              work.submit(() -> handle(s));
            } catch (IOException e) {
              if (closed) return;
            }
        });
  }

  int port() {
    return server.getLocalPort();
  }

  void handle(Socket client) {
    try (client) {
      client.setSoTimeout(10_000);
      var in = new DataInputStream(client.getInputStream());
      var out = client.getOutputStream();
      if (in.readUnsignedByte() != 5) return;
      in.readNBytes(in.readUnsignedByte());
      out.write(new byte[] {5, 0});
      out.flush();
      if (in.readUnsignedByte() != 5
          || in.readUnsignedByte() != 1
          || in.readUnsignedByte() != 0
          || in.readUnsignedByte() != 3) return;
      String host =
          new String(
              in.readNBytes(in.readUnsignedByte()), java.nio.charset.StandardCharsets.US_ASCII);
      in.readUnsignedShort();
      hosts.add(host);
      Integer port = destinations.get(host);
      if (port == null) {
        out.write(new byte[] {5, 4, 0, 1, 0, 0, 0, 0, 0, 0});
        out.flush();
        return;
      }
      try (Socket upstream = new Socket(InetAddress.getLoopbackAddress(), port)) {
        sockets.add(upstream);
        upstream.setSoTimeout(10_000);
        out.write(new byte[] {5, 0, 0, 1, 127, 0, 0, 1, 0, 0});
        out.flush();
        work.submit(
            () -> {
              try {
                byte[] b = new byte[4096];
                int n;
                while ((n = in.read(b)) != -1) {
                  if (host.equals(RELAY))
                    synchronized (relayBytes) {
                      relayBytes.write(b, 0, n);
                    }
                  upstream.getOutputStream().write(b, 0, n);
                  upstream.getOutputStream().flush();
                }
              } catch (IOException ignored) {
              }
            });
        if (host.equals(PEER) && dropNextPeerReply.compareAndSet(true, false)) {
          upstream.getInputStream().read();
          return;
        }
        upstream.getInputStream().transferTo(out);
        out.flush();
        sockets.remove(upstream);
      }
    } catch (IOException ignored) {
    } finally {
      sockets.remove(client);
    }
  }

  @Override
  public void close() throws IOException {
    closed = true;
    server.close();
    for (Socket s : sockets)
      try {
        s.close();
      } catch (IOException ignored) {
      }
    work.shutdownNow();
  }
}
