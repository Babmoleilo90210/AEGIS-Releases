package org.securemail.client.storage;

import static org.junit.jupiter.api.Assertions.*;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.util.Arrays;
import java.util.zip.CRC32;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.Identity;
import org.securemail.protocol.PublicProfile;
import org.securemail.protocol.UserInfo;

/** Local signed-profile transport/cache tests. These do not claim a live Relay test. */
class PublicProfileCacheTest {
  private static final char[] PASSWORD = "local-profile-test-passphrase".toCharArray();
  @TempDir Path root;

  private LocalStore open(Path path, String nickname) throws Exception {
    LocalStore store = new LocalStore(path, PASSWORD, Clock.systemUTC(), 1_000_000, 8_000_000);
    store.bindNickname(nickname);
    return store;
  }

  private static UserInfo user(Identity identity, String nickname) {
    return new UserInfo(identity.userId(), nickname, identity.publicKey(), null);
  }

  private static byte[] image(String format, int width, int height, int color) throws IOException {
    BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
    try {
      for (int y = 0; y < height; y++)
        for (int x = 0; x < width; x++) image.setRGB(x, y, color);
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      assertTrue(ImageIO.write(image, format, output));
      return output.toByteArray();
    } finally {
      image.flush();
    }
  }

  private static byte[] avatar(int color) throws IOException {
    return AvatarCodec.normalize(image("png", 24, 20, color));
  }

  private static void assertAvatar(byte[] actual, int color) throws IOException {
    assertNotNull(actual);
    BufferedImage decoded = ImageIO.read(new ByteArrayInputStream(actual));
    assertNotNull(decoded);
    try {
      assertEquals(AvatarCodec.SIZE, decoded.getWidth());
      assertEquals(AvatarCodec.SIZE, decoded.getHeight());
      assertEquals(color | 0xff000000, decoded.getRGB(128, 128));
    } finally {
      decoded.flush();
    }
  }

  @Test void twoIdentitiesReceiveChangedAvatarAndRetainItAfterOfflineRestart() throws Exception {
    Path alicePath = root.resolve("alice"), bobPath = root.resolve("bob");
    byte[] alicePublicKey, bobPublicKey;
    try (LocalStore alice = open(alicePath, "alice"); LocalStore bob = open(bobPath, "bob")) {
      alicePublicKey = alice.identity().publicKey();
      bobPublicKey = bob.identity().publicKey();
      assertFalse(Arrays.equals(alicePublicKey, bobPublicKey));
      bob.trust(user(alice.identity(), "alice"));
      alice.avatar("alice", avatar(0x337799));
      bob.cacheProfile(alice.identity().profile("alice", 1, true, "First profile", alice.avatar("alice")));
      assertAvatar(bob.avatar("alice"), 0x337799);
      assertNull(bob.avatar("bob"), "Remote avatar must not replace Bob's own avatar");

      alice.avatar("alice", avatar(0xbb4422));
      bob.cacheProfile(alice.identity().profile("alice", 2, true, "Updated profile", alice.avatar("alice")));
      assertAvatar(bob.avatar("alice"), 0xbb4422);
      assertEquals("Updated profile", bob.cachedProfile("alice").about());
    }
    // No network service is involved in reopening the receiver's encrypted cache.
    try (LocalStore alice = open(alicePath, "alice"); LocalStore bob = open(bobPath, "bob")) {
      assertArrayEquals(alicePublicKey, alice.identity().publicKey());
      assertArrayEquals(bobPublicKey, bob.identity().publicKey());
      assertEquals(2, bob.cachedProfile("alice").revision());
      assertAvatar(bob.avatar("alice"), 0xbb4422);
    }
  }

  @Test void hidingProfileRemovesPreviouslyVisibleContentAndPersistsTheRestriction() throws Exception {
    Identity alice = Identity.create();
    Path bobPath = root.resolve("bob");
    try (LocalStore bob = open(bobPath, "bob")) {
      bob.trust(user(alice, "alice"));
      bob.cacheProfile(alice.profile("alice", 1, true, "Private after revocation", avatar(0x447722)));
      PublicProfile hidden = alice.profile("alice", 2, false, "Must not be published", avatar(0x554499));
      assertTrue(hidden.about().isEmpty());
      assertEquals(0, hidden.avatar().length);
      bob.cacheProfile(hidden);
      assertFalse(bob.cachedProfile("alice").visible());
      assertTrue(bob.cachedProfile("alice").about().isEmpty());
      assertNull(bob.avatar("alice"));
    }
    try (LocalStore bob = open(bobPath, "bob")) {
      assertFalse(bob.cachedProfile("alice").visible());
      assertNull(bob.avatar("alice"));
    }
  }

  @Test void absentProfileAndExplicitAvatarRemovalDoNotReturnAnOldImage() throws Exception {
    Identity alice = Identity.create();
    try (LocalStore bob = open(root.resolve("bob"), "bob")) {
      bob.trust(user(alice, "alice"));
      assertNull(bob.cachedProfile("alice"));
      assertNull(bob.avatar("alice"));
      assertNull(bob.cachedProfile("unknown"));
      bob.cacheProfile(alice.profile("alice", 1, true, "With avatar", avatar(0x446688)));
      bob.cacheProfile(alice.profile("alice", 2, true, "No avatar", new byte[0]));
      assertTrue(bob.cachedProfile("alice").visible());
      assertEquals("No avatar", bob.cachedProfile("alice").about());
      assertNull(bob.avatar("alice"));
    }
  }

  @Test void identicalRevisionIsIdempotentWhileReplayAndConflictsPreserveTheCurrentProfile() throws Exception {
    Identity alice = Identity.create();
    try (LocalStore bob = open(root.resolve("bob"), "bob")) {
      bob.trust(user(alice, "alice"));
      PublicProfile current = alice.profile("alice", 5, true, "Current", avatar(0x226688));
      bob.cacheProfile(current);
      long revision = bob.avatarRevision();
      bob.cacheProfile(current);
      assertEquals(revision, bob.avatarRevision(), "An identical cached revision must not invalidate the avatar");
      assertThrows(GeneralSecurityException.class,
          () -> bob.cacheProfile(alice.profile("alice", 4, true, "Old", avatar(0x998833))));
      assertThrows(GeneralSecurityException.class,
          () -> bob.cacheProfile(alice.profile("alice", 5, true, "Conflicting", avatar(0x998833))));
      assertEquals("Current", bob.cachedProfile("alice").about());
      assertAvatar(bob.avatar("alice"), 0x226688);
      assertEquals(revision, bob.avatarRevision());
    }
  }

  @Test void unverifiedAndForgedProfilesCannotOverwriteAPinnedContact() throws Exception {
    Identity alice = Identity.create(), attacker = Identity.create();
    try (LocalStore bob = open(root.resolve("bob"), "bob")) {
      PublicProfile genuine = alice.profile("alice", 1, true, "Genuine", avatar(0x223355));
      assertThrows(IOException.class, () -> bob.cacheProfile(genuine));
      bob.trust(user(alice, "alice"));
      bob.cacheProfile(genuine);
      assertThrows(GeneralSecurityException.class,
          () -> bob.cacheProfile(attacker.profile("alice", 2, true, "Impersonation", new byte[0])));
      PublicProfile tampered = new PublicProfile(genuine.userId(), genuine.nickname(), 2, true,
          "Tampered", genuine.avatar(), genuine.publicKey(), genuine.signature());
      assertThrows(GeneralSecurityException.class, () -> bob.cacheProfile(tampered));
      assertEquals("Genuine", bob.cachedProfile("alice").about());
      assertAvatar(bob.avatar("alice"), 0x223355);
    }
  }

  @Test void signedMalformedAndExcessiveDimensionAvatarsAreRejectedBeforeCacheReplacement() throws Exception {
    Identity alice = Identity.create();
    try (LocalStore bob = open(root.resolve("bob"), "bob")) {
      bob.trust(user(alice, "alice"));
      bob.cacheProfile(alice.profile("alice", 1, true, "Good", avatar(0x449933)));
      byte[][] hostile = {
          "Not an image, even if its owner has signed it".getBytes(StandardCharsets.UTF_8),
          image("png", AvatarCodec.MAX_DIMENSION + 1, 1, 0),
          Arrays.copyOf(image("png", 24, 24, 0), 40),
          image("gif", 24, 24, 0)
      };
      for (byte[] payload : hostile) {
        assertThrows(IOException.class,
            () -> bob.cacheProfile(alice.profile("alice", 2, true, "Hostile", payload)));
        assertEquals(1, bob.cachedProfile("alice").revision());
        assertAvatar(bob.avatar("alice"), 0x449933);
      }
      assertThrows(IllegalArgumentException.class,
          () -> alice.profile("alice", 3, true, "Oversize", new byte[PublicProfile.MAX_AVATAR + 1]));
    }
  }

  @Test void sanitizingPixelsBeforeSigningRemovesEmbeddedImageMetadata() throws Exception {
    String metadata = "GPS-location-never-publish-55.7558-37.6173";
    byte[] original = pngWithText(image("png", 24, 24, 0x884433), metadata);
    assertTrue(new String(original, StandardCharsets.ISO_8859_1).contains(metadata));
    byte[] sanitized = AvatarCodec.normalize(original);
    assertFalse(new String(sanitized, StandardCharsets.ISO_8859_1).contains(metadata));
    assertAvatar(sanitized, 0x884433);
    PublicProfile published = Identity.create().profile("alice", 1, true, "", sanitized);
    assertFalse(new String(published.avatar(), StandardCharsets.ISO_8859_1).contains(metadata));
    try (LocalStore alice = open(root.resolve("alice"), "alice")) {
      alice.avatar("alice", original);
      byte[] stored = alice.avatar("alice");
      assertFalse(new String(stored, StandardCharsets.ISO_8859_1).contains(metadata));
      assertAvatar(stored, 0x884433);
      assertThrows(IOException.class, () -> alice.avatar("alice", "not an image".getBytes(StandardCharsets.UTF_8)));
      assertAvatar(alice.avatar("alice"), 0x884433);
    }
  }

  @Test void remoteProfileAndAvatarAreEncryptedOnDisk() throws Exception {
    Identity alice = Identity.create();
    String about = "Public profile content is still encrypted in Bob's local vault";
    byte[] avatar = avatar(0xaa3377);
    try (LocalStore bob = open(root.resolve("bob"), "bob")) {
      bob.trust(user(alice, "alice"));
      bob.cacheProfile(alice.profile("alice", 1, true, about, avatar));
      Path cache = bob.root().resolve("profiles").resolve(alice.userId() + ".enc");
      byte[] encrypted = Files.readAllBytes(cache);
      assertFalse(new String(encrypted, StandardCharsets.ISO_8859_1).contains(about));
      assertFalse(Arrays.equals(avatar, encrypted));
      assertAvatar(bob.avatar("alice"), 0xaa3377);
    }
  }

  /** Valid PNG tEXt chunk: the metadata-bearing input must remain a decodable image. */
  private static byte[] pngWithText(byte[] png, String text) throws IOException {
    byte[] type = "tEXt".getBytes(StandardCharsets.US_ASCII);
    byte[] data = ("Comment\0" + text).getBytes(StandardCharsets.ISO_8859_1);
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (DataOutputStream output = new DataOutputStream(bytes)) {
      output.write(png, 0, png.length - 12); // Insert immediately before IEND.
      output.writeInt(data.length);
      output.write(type);
      output.write(data);
      CRC32 crc = new CRC32();
      crc.update(type);
      crc.update(data);
      output.writeInt((int) crc.getValue());
      output.write(png, png.length - 12, 12);
    }
    return bytes.toByteArray();
  }
}
