package org.securemail.client;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.time.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

class StorageTest {
  @TempDir Path temp;
  static final char[] VAULT = "an independent vault password".toCharArray(),
      SECRET = "a different message password".toCharArray();

  static class MutableClock extends Clock {
    long now = 1_800_000_000_000L;

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId z) {
      return this;
    }

    @Override
    public Instant instant() {
      return Instant.ofEpochMilli(now);
    }

    @Override
    public long millis() {
      return now;
    }
  }

  @Test
  void durableAckDedupTtlAcrossRestartAndNoPlaintextFiles() throws Exception {
    var time = new MutableClock();
    var sender = Identity.create();
    EncryptedPacket p;
    long received;
    try (var local = new LocalStore(temp, VAULT, time, 200_000, 1_000_000)) {
      local.trust(new UserInfo(sender.userId(), "raven", sender.publicKey(), null));
      try (var text = PlainMessage.text("DO-NOT-PERSIST-THIS-CONTENT-91837")) {
        p =
            new EncryptionService(time)
                .encrypt(
                    text,
                    SECRET,
                    Algorithm.AES_256_GCM,
                    60,
                    86400_000,
                    sender,
                    "raven",
                    local.identity().userId());
      }
      received = local.accept(p).deliveredAt();
      time.now += 20_000;
      assertEquals(received, local.accept(p).deliveredAt());
      assertEquals(1, local.inbox().size());
      assertEquals(received + 60_000, local.inbox().getFirst().expiresAt());
      try (var files = Files.walk(temp)) {
        for (Path file : files.filter(Files::isRegularFile).toList())
          assertFalse(
              new String(Files.readAllBytes(file), java.nio.charset.StandardCharsets.ISO_8859_1)
                  .contains("DO-NOT-PERSIST-THIS-CONTENT-91837"));
      }
    }
    time.now += 45_000;
    try (var local = new LocalStore(temp, VAULT, time, 200_000, 1_000_000)) {
      assertTrue(local.inbox().isEmpty());
      assertEquals(received, local.accept(p).deliveredAt());
      assertTrue(local.inbox().isEmpty());
    }
  }

  @Test
  void incorrectVaultPasswordAndExclusiveLock() throws Exception {
    var time = new MutableClock();
    try (var local = new LocalStore(temp, VAULT, time, 200_000, 1_000_000)) {
      assertThrows(
          java.io.IOException.class, () -> new LocalStore(temp, VAULT, time, 200_000, 1_000_000));
    }
    assertThrows(
        java.security.GeneralSecurityException.class,
        () ->
            new LocalStore(
                temp, "an incorrect vault password".toCharArray(), time, 200_000, 1_000_000));
  }

  @Test
  void clockRollbackPreservesMailWithoutExtendingItsDeadline() throws Exception {
    var time = new MutableClock();
    var sender = Identity.create();long expiry;
    try (var local = new LocalStore(temp, VAULT, time, 200_000, 1_000_000)) {
      local.trust(new UserInfo(sender.userId(), "raven", sender.publicKey(), null));
      try (var m = PlainMessage.text("expires")) {
        local.accept(
            new EncryptionService(time)
                .encrypt(
                    m,
                    SECRET,
                    Algorithm.AES_256_GCM,
                    60,
                    86400_000,
                    sender,
                    "raven",
                    local.identity().userId()));
      }
      assertEquals(1, local.inbox().size());expiry=local.inbox().getFirst().expiresAt();
    }
    long original=time.now;
    time.now -= 100_000;
    try (var local = new LocalStore(temp, VAULT, time, 200_000, 1_000_000)) {
      assertEquals(1,local.inbox().size(),"Rolling the clock back must not destroy unrelated mail");
      assertTrue(local.now()>=original,"Persisted high-water time is retained");
      assertEquals(expiry,local.inbox().getFirst().expiresAt());
      time.now=original+61_000;assertTrue(local.inbox().isEmpty(),"The signed TTL is not extended");
    }
  }

  @Test
  void maintenanceDeletesWithoutVaultPassword() throws Exception {
    var time = new MutableClock();
    var sender = Identity.create();
    try (var local = new LocalStore(temp, VAULT, time, 200_000, 1_000_000)) {
      local.trust(new UserInfo(sender.userId(), "raven", sender.publicKey(), null));
      try (var m = PlainMessage.text("expires")) {
        local.accept(
            new EncryptionService(time)
                .encrypt(
                    m,
                    SECRET,
                    Algorithm.AES_256_GCM,
                    60,
                    86400_000,
                    sender,
                    "raven",
                    local.identity().userId()));
      }
    }
    LocalStore.cleanupLockedFiles(temp, time.now + 61_000);
    try (var f = Files.list(temp.resolve("mail"))) {
      assertEquals(0, f.count());
    }
  }
}
