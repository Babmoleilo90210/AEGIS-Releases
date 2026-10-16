package org.securemail.client.net;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import org.securemail.protocol.Limits;

/** Only outbound data connector: loopback SOCKS5; onion names are never resolved locally. */
public final class TorTransport {
  private final int socksPort;
  private static volatile java.util.function.BooleanSupplier available=()->true;
  public static void requireAvailability(java.util.function.BooleanSupplier guard){available=java.util.Objects.requireNonNull(guard);}

  public TorTransport(String address, int port) {
    if (!address.equals("127.0.0.1") || port < 1 || port > 65535)
      throw new IllegalArgumentException("SOCKS must use 127.0.0.1");
    socksPort = port;
  }

  public Socket connect(String onion, int port) throws IOException {
    Limits.onion(onion);
    return connectHost(onion,port);
  }

  /** Bounded optional peer capability probe. Still onion-only and loopback SOCKS only. */
  public Socket connectPeer(String onion,int port)throws IOException {Limits.onion(onion);return connectHost(onion,port,20_000);}

  /** Separate authenticated community RPC, observed before even the SOCKS handshake. */
  public Socket connectPeer(String onion,int port,SocketObserver observer)throws IOException {Limits.onion(onion);return connectHost(onion,port,20_000,java.util.Objects.requireNonNull(observer));}

  /** Explicit update-only destinations. DNS resolution is performed by Tor, never by this JVM. */
  public Socket connectUpdate(String host) throws IOException {
    if(!java.util.Set.of("github.com","raw.githubusercontent.com","release-assets.githubusercontent.com","objects.githubusercontent.com").contains(host))throw new IOException("Update destination rejected");
    return connectHost(host,443,20_000);
  }

  /** Official browser distribution only, using the HTTPS-capable SOCKS context.
   * The hostname is sent in the SOCKS5 request, never resolved by the local JVM. */
  public Socket connectTorBrowserDownload(String host) throws IOException {
    return connectTorBrowserDownload(host, socket -> { });
  }

  @FunctionalInterface public interface SocketObserver { void opened(Socket socket) throws IOException; }
  public Socket connectTorBrowserDownload(String host, SocketObserver observer) throws IOException {
    if (!java.util.Set.of("aus1.torproject.org", "dist.torproject.org").contains(host))
      throw new IOException("Tor Browser download destination rejected");
    return connectHost(host, 443, 20_000, java.util.Objects.requireNonNull(observer));
  }

  private Socket connectHost(String onion,int port) throws IOException {
    return connectHost(onion,port,120_000);
  }
  private Socket connectHost(String onion,int port,int timeout) throws IOException {
    return connectHost(onion,port,timeout,socket -> { });
  }
  private Socket connectHost(String onion,int port,int timeout,SocketObserver observer) throws IOException {
    if(!available.getAsBoolean())throw new IOException("Tor ещё подключается. Прямое подключение отключено.");
    if (port < 1 || port > 65535) throw new IOException("Bad port");
    Socket socket = new Socket(Proxy.NO_PROXY);
    try {
      observer.opened(socket);
      socket.connect(
          new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), socksPort),
          5000);
      socket.setSoTimeout(timeout);
      var in = new DataInputStream(socket.getInputStream());
      var out = socket.getOutputStream();
      out.write(new byte[] {5, 1, 0});
      out.flush();
      if (in.readUnsignedByte() != 5 || in.readUnsignedByte() != 0)
        throw new IOException("Tor SOCKS unavailable");
      byte[] host = onion.getBytes(StandardCharsets.US_ASCII);
      out.write(new byte[] {5, 1, 0, 3, (byte) host.length});
      out.write(host);
      out.write(port >>> 8);
      out.write(port & 255);
      out.flush();
      int version = in.readUnsignedByte(),
          status = in.readUnsignedByte(),
          reserved = in.readUnsignedByte(),
          type = in.readUnsignedByte();
      if (version != 5 || status != 0 || reserved != 0)
        throw new IOException("Tor connection unavailable");
      int n =
          switch (type) {
            case 1 -> 4;
            case 3 -> in.readUnsignedByte();
            case 4 -> 16;
            default -> throw new IOException("Bad SOCKS response");
          };
      byte[] discard = new byte[n + 2];
      in.readFully(discard);
      return socket;
    } catch (IOException | RuntimeException e) {
      try {
        socket.close();
      } catch (IOException ignored) {
      }
      throw e;
    }
  }
}
