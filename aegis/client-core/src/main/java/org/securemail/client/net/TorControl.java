package org.securemail.client.net;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.securemail.client.crypto.Secrets;
import org.securemail.protocol.Limits;

/** SAFECOOKIE controller, non-detached ephemeral onion. No private onion key is returned. */
public final class TorControl implements AutoCloseable {
  private final Socket socket;
  private final InputStream in;
  private final OutputStream out;

  public TorControl(int port, Path cookieFile) throws IOException, GeneralSecurityException {
    if (port < 1
        || port > 65535
        || Files.isSymbolicLink(cookieFile)
        || Files.size(cookieFile) != 32) throw new IOException("Invalid Tor cookie or port");
    byte[] cookie = Files.readAllBytes(cookieFile), clientNonce = Secrets.random(32);
    socket = new Socket(Proxy.NO_PROXY);
    try {
      socket.connect(
          new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), port), 5000);
      socket.setSoTimeout(5000);
      in = socket.getInputStream();
      out = socket.getOutputStream();
      var reply = command("AUTHCHALLENGE SAFECOOKIE " + HexFormat.of().formatHex(clientNonce));
      String line =
          reply.stream()
              .filter(s -> s.contains("SERVERHASH="))
              .findFirst()
              .orElseThrow(() -> new IOException("SAFECOOKIE unavailable"));
      byte[] hash = field(line, "SERVERHASH"),
          serverNonce = field(line, "SERVERNONCE"),
          data = new byte[96];
      System.arraycopy(cookie, 0, data, 0, 32);
      System.arraycopy(clientNonce, 0, data, 32, 32);
      System.arraycopy(serverNonce, 0, data, 64, 32);
      if (!MessageDigest.isEqual(
          hash, hmac("Tor safe cookie authentication server-to-controller hash", data)))
        throw new GeneralSecurityException("Tor authentication failed");
      command(
          "AUTHENTICATE "
              + HexFormat.of()
                  .formatHex(
                      hmac("Tor safe cookie authentication controller-to-server hash", data)));
      Arrays.fill(data, (byte) 0);
    } catch (IOException | GeneralSecurityException | RuntimeException e) {
      socket.close();
      throw e;
    } finally {
      Arrays.fill(cookie, (byte) 0);
      Arrays.fill(clientNonce, (byte) 0);
    }
  }

  private static byte[] field(String line, String name) throws IOException {
    for (String part : line.split(" "))
      if (part.startsWith(name + "="))
        try {
          byte[] b = HexFormat.of().parseHex(part.substring(name.length() + 1));
          if (b.length == 32) return b;
        } catch (IllegalArgumentException ignored) {
        }
    throw new IOException("Bad Tor authentication reply");
  }

  private static byte[] hmac(String key, byte[] data) throws GeneralSecurityException {
    Mac m = Mac.getInstance("HmacSHA256");
    m.init(new SecretKeySpec(key.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
    return m.doFinal(data);
  }

  public synchronized String publish(int localPort) throws IOException {
    if (localPort < 1 || localPort > 65535) throw new IOException("Bad port");
    var lines =
        command(
            "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK MaxStreams=4 Port=80,127.0.0.1:" + localPort + " Port=81,127.0.0.1:" + localPort);
    for (String line : lines)
      if (line.startsWith("250-ServiceID=")) return Limits.onion(line.substring(14) + ".onion");
    throw new IOException("Onion creation failed");
  }

  public synchronized int bootstrapProgress() throws IOException {
    for(String line:command("GETINFO status/bootstrap-phase")) {
      var m=java.util.regex.Pattern.compile("(?:^| )PROGRESS=([0-9]{1,3})(?: |$)").matcher(line);
      if(m.find())return Math.min(100,Integer.parseInt(m.group(1)));
    }
    return 0;
  }

  public synchronized boolean bootstrapped() throws IOException {
    return command("GETINFO status/bootstrap-phase").stream()
        .anyMatch(s -> s.contains("PROGRESS=100"));
  }

  private List<String> command(String text) throws IOException {
    out.write((text + "\r\n").getBytes(StandardCharsets.US_ASCII));
    out.flush();
    var lines = new ArrayList<String>();
    for (int n = 0; n < 64; n++) {
      var b = new ByteArrayOutputStream();
      int c;
      while ((c = in.read()) != -1 && c != '\n') {
        if (b.size() >= 4096) throw new IOException("Tor reply too large");
        if (c != '\r') b.write(c);
      }
      if (c == -1) throw new EOFException("Tor control closed");
      String line = b.toString(StandardCharsets.US_ASCII);
      if (!line.startsWith("250")) throw new IOException("Tor command rejected");
      lines.add(line);
      if (line.startsWith("250 ")) return lines;
      if (!line.startsWith("250-")) throw new IOException("Unsupported Tor reply");
    }
    throw new IOException("Tor reply too long");
  }

  @Override
  public void close() throws IOException {
    socket.close();
  }
}
