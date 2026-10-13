package org.securemail.client;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.Secrets;
import org.securemail.client.net.TorControl;

class TorControlTest {
  @TempDir Path temp;

  static byte[] hmac(String key, byte[] data) throws Exception {
    var m = Mac.getInstance("HmacSHA256");
    m.init(new SecretKeySpec(key.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
    return m.doFinal(data);
  }

  @Test
  void safeCookieAuthenticatedBeforeAddOnion() throws Exception {
    byte[] cookie = Secrets.random(32);
    Path file = temp.resolve("cookie");
    Files.write(file, cookie);
    try (var server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        var executor = Executors.newVirtualThreadPerTaskExecutor()) {
      Future<Boolean> checked =
          executor.submit(
              () -> {
                try (var socket = server.accept();
                    var r =
                        new BufferedReader(
                            new InputStreamReader(
                                socket.getInputStream(), StandardCharsets.US_ASCII));
                    var w =
                        new PrintWriter(
                            socket.getOutputStream(), true, StandardCharsets.US_ASCII)) {
                  socket.setSoTimeout(5000);
                  String challenge = r.readLine();
                  assertTrue(challenge.startsWith("AUTHCHALLENGE SAFECOOKIE "));
                  byte[] client = HexFormat.of().parseHex(challenge.split(" ")[2]),
                      nonce = Secrets.random(32),
                      data = new byte[96];
                  System.arraycopy(cookie, 0, data, 0, 32);
                  System.arraycopy(client, 0, data, 32, 32);
                  System.arraycopy(nonce, 0, data, 64, 32);
                  w.print(
                      "250 AUTHCHALLENGE SERVERHASH="
                          + HexFormat.of()
                              .formatHex(
                                  hmac(
                                      "Tor safe cookie authentication server-to-controller hash",
                                      data))
                          + " SERVERNONCE="
                          + HexFormat.of().formatHex(nonce)
                          + "\r\n");
                  w.flush();
                  assertEquals(
                      "AUTHENTICATE "
                          + HexFormat.of()
                              .formatHex(
                                  hmac(
                                      "Tor safe cookie authentication controller-to-server hash",
                                      data)),
                      r.readLine());
                  w.print("250 OK\r\n");
                  w.flush();
                  assertEquals(
                      "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK MaxStreams=4"
                          + " Port=80,127.0.0.1:19120 Port=81,127.0.0.1:19120",
                      r.readLine());
                  w.print("250-ServiceID=" + "b".repeat(56) + "\r\n250 OK\r\n");
                  w.flush();
                  assertEquals("GETINFO status/bootstrap-phase", r.readLine());
                  w.print(
                      "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done"
                          + " SUMMARY=Done\r\n"
                          + "250 OK\r\n");
                  w.flush();
                  return true;
                }
              });
      try (var control = new TorControl(server.getLocalPort(), file)) {
        assertEquals("b".repeat(56) + ".onion", control.publish(19120));
        assertTrue(control.bootstrapped());
      }
      assertTrue(checked.get(5, TimeUnit.SECONDS));
    }
  }

  @Test
  void refusesImpersonatedTorController() throws Exception {
    Path file = temp.resolve("cookie");
    Files.write(file, Secrets.random(32));
    try (var server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        var executor = Executors.newVirtualThreadPerTaskExecutor()) {
      var f =
          executor.submit(
              () -> {
                try (var s = server.accept();
                    var r = new BufferedReader(new InputStreamReader(s.getInputStream()));
                    var w = new PrintWriter(s.getOutputStream(), true)) {
                  s.setSoTimeout(5000);
                  r.readLine();
                  w.print(
                      "250 AUTHCHALLENGE SERVERHASH="
                          + "0".repeat(64)
                          + " SERVERNONCE="
                          + "1".repeat(64)
                          + "\r\n");
                  w.flush();
                  assertNull(r.readLine());
                  return true;
                }
              });
      assertThrows(
          java.security.GeneralSecurityException.class,
          () -> new TorControl(server.getLocalPort(), file));
      assertTrue(f.get(5, TimeUnit.SECONDS));
    }
  }
}
