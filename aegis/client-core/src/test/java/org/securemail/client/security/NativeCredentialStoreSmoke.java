package org.securemail.client.security;

import java.io.IOException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.crypto.Secrets;

/** Explicit native acceptance probe. Never invoked by the ordinary unit-test task. */
public final class NativeCredentialStoreSmoke {
  private static void require(boolean value, String message) {
    if (!value) throw new AssertionError(message);
  }
  private static final class TestClock extends Clock {
    long now = System.currentTimeMillis();
    public ZoneId getZone() { return ZoneOffset.UTC; }
    public Clock withZone(ZoneId zone) { return this; }
    public Instant instant() { return Instant.ofEpochMilli(now); }
  }
  public static void main(String[] args) throws Exception {
    if (!Boolean.getBoolean("aegis.secret.test.isolated"))
      throw new IllegalStateException("Run only through the isolated native acceptance harness");
    Path profile = Path.of(args[0]).toAbsolutePath();
    String mode = args.length > 1 ? args[1] : "roundtrip";
    SystemSecrets os = SystemSecrets.current(profile);
    require(os instanceof SystemSecrets.SecretService || os instanceof SystemSecrets.Dpapi, "Native system provider required");
    if (mode.equals("load-child")) {
      byte[] expected = System.in.readNBytes(32), actual = os.load();
      try { require(expected.length == 32 && actual != null && MessageDigest.isEqual(expected, actual), "Secret did not survive JVM restart"); }
      finally { Arrays.fill(expected, (byte)0); if (actual != null) Arrays.fill(actual, (byte)0); }
      System.out.println("PASS native credential store: independent JVM load");
      return;
    }
    if (mode.equals("unavailable")) {
      RememberedLogin saved = new RememberedLogin(profile, os, Clock.systemUTC());
      byte[] vault = Secrets.random(32);
      boolean rejected = false;
      try { saved.save("raven", "a".repeat(56) + ".onion", "b".repeat(64), vault); }
      catch (IOException expected) { rejected = true; }
      finally { Arrays.fill(vault, (byte)0); }
      require(rejected, "Unavailable provider was accepted");
      require(!Files.exists(profile.resolve("session/resume.enc")), "Plaintext or unprotected fallback created");
      System.out.println("PASS native credential store: missing bus fails closed without saved session");
      return;
    }
    byte[] first = Secrets.random(32), second = Secrets.random(32), vault = Secrets.random(32);
    try {
      os.clear();
      require(os.load() == null, "Fresh isolated profile contained a device secret");
      os.store(first);
      byte[] loaded = os.load();
      try { require(loaded != null && MessageDigest.isEqual(first, loaded), "Native store/load mismatch"); }
      finally { if (loaded != null) Arrays.fill(loaded, (byte)0); }
      SystemSecrets other = SystemSecrets.current(profile.resolveSibling(profile.getFileName() + "-other"));
      require(other.load() == null, "Native profile attributes are not isolated");
      System.out.println("PASS native credential store: store/load and profile isolation");
      os.store(second);
      loaded = os.load();
      try { require(loaded != null && MessageDigest.isEqual(second, loaded), "Native replacement mismatch"); }
      finally { if (loaded != null) Arrays.fill(loaded, (byte)0); }
      Process child = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
          "-Daegis.secret.test.isolated=true", "-cp", System.getProperty("java.class.path"),
          NativeCredentialStoreSmoke.class.getName(), profile.toString(), "load-child")
          .redirectOutput(ProcessBuilder.Redirect.INHERIT).redirectError(ProcessBuilder.Redirect.INHERIT).start();
      try {
        try (var input = child.getOutputStream()) { input.write(second); }
        require(child.waitFor(30, TimeUnit.SECONDS) && child.exitValue() == 0, "Native child-process load failed");
      } finally { if (child.isAlive()) { child.destroy(); if (!child.waitFor(5, TimeUnit.SECONDS)) child.destroyForcibly(); } }
      os.clear(); require(os.load() == null, "Native secret was not cleared");
      System.out.println("PASS native credential store: replace/clear");
      TestClock clock = new TestClock();
      RememberedLogin saved = new RememberedLogin(profile, os, clock);
      String relay = "a".repeat(56) + ".onion", token = "b".repeat(64);
      saved.save("raven", relay, token, vault);
      byte[] sealed = Files.readAllBytes(profile.resolve("session/resume.enc"));
      require(!new String(sealed, java.nio.charset.StandardCharsets.ISO_8859_1).contains(token), "Bearer stored as plaintext");
      clock.now += 13 * 3600_000L;
      try (var resume = saved.load(relay).orElseThrow()) {
        require(MessageDigest.isEqual(vault, resume.vaultKey()), "Native remembered vault key mismatch");
        require(!resume.relayValid(clock.millis()), "Expired relay bearer accepted");
      }
      clock.now += 7 * 86400_000L;
      require(saved.load(relay).isEmpty() && os.load() == null, "Expired local session retained its system secret");
      require(!Files.exists(profile.resolve("session/resume.enc")), "Expired resume file remains");
      System.out.println("PASS native credential store: encrypted resume, simulated 7-day local expiry and 12-hour relay expiry");
      saved.save("raven", relay, token, vault);
      Path file = profile.resolve("session/resume.enc");
      byte[] tampered = Files.readAllBytes(file); tampered[30] ^= 1; Files.write(file, tampered);
      boolean rejected = false;
      try { saved.load(relay); } catch (javax.crypto.AEADBadTagException expected) { rejected = true; }
      require(rejected && os.load() == null && !Files.exists(file), "Tampered session not removed");
      System.out.println("PASS native credential store: AEAD tamper removes session and native secret");
    } finally {
      Arrays.fill(first, (byte)0); Arrays.fill(second, (byte)0); Arrays.fill(vault, (byte)0);
      os.clear();
    }
  }
}
