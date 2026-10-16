package org.securemail.client.storage;

import static org.junit.jupiter.api.Assertions.*;
import static org.securemail.client.appearance.Appearance.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.AppPaths;
import org.securemail.client.ClientConfig;
import org.securemail.client.appearance.AppearanceStore;
import org.securemail.client.archive.EncryptedArchive;
import org.securemail.client.crypto.AutomaticEncryption;
import org.securemail.client.crypto.Identity;
import org.securemail.client.crypto.PlainMessage;
import org.securemail.client.update.JsonData;
import org.securemail.protocol.EncryptedPacket;
import org.securemail.protocol.UserInfo;

/** Synthetic 1.5 data using real vault/archive formats, without installation or live networking. */
class NavigationMigration200Test {
  @TempDir Path root;

  @Test void sixSectionCustomOrderSurvivesLoadSaveExportAndRepeatedImport() throws Exception {
    List<String> oldOrder = List.of("settings", "letters", "archive", "contacts", "search", "profile");
    List<String> expected = List.of("letters", "archive", "contacts", "search", "profile", "safeweb", "glas", "organizations", "news", "library", "settings");
    Path profile = root.resolve("profile");
    AppearanceStore initial = new AppearanceStore(profile);
    initial.saveLayout("Рабочий макет", initial.current().layout().panels(18, 35).below(true));
    Path settings = initial.root().resolve("settings.json");
    JsonObject legacy = JsonData.object(Files.readAllBytes(settings), MAX_JSON);
    JsonArray six = new JsonArray();
    oldOrder.forEach(six::add);
    legacy.getAsJsonObject("current").getAsJsonObject("layout").add("order", six.deepCopy());
    legacy.getAsJsonArray("layouts").get(0).getAsJsonObject().getAsJsonObject("layout").add("order", six.deepCopy());
    Files.write(settings, JsonData.encode(legacy));
    byte[] original = Files.readAllBytes(settings);

    AppearanceStore migrated = new AppearanceStore(profile);
    assertEquals("", migrated.recovery());
    assertEquals(expected, migrated.current().layout().order());
    assertEquals(expected, migrated.layouts().get("Рабочий макет").order());
    assertTrue(migrated.layouts().get("Рабочий макет").previewBelow());
    assertArrayEquals(original, Files.readAllBytes(settings), "Reading must retain the original file for backup");
    migrated.apply(migrated.current());
    AppearanceStore reopened = new AppearanceStore(profile);
    assertEquals(expected, reopened.current().layout().order());
    assertEquals(1, reopened.current().layout().order().stream().filter("safeweb"::equals).count());

    Path exchange = root.resolve("layout.json");
    reopened.exportLayout("Рабочий макет", exchange);
    AppearanceStore receiver = new AppearanceStore(root.resolve("receiver"));
    receiver.importLayout(exchange);
    receiver.importLayout(exchange);
    assertEquals(1, receiver.layouts().size());
    assertEquals(reopened.layouts().get("Рабочий макет"), receiver.layouts().get("Рабочий макет"));
    assertEquals(expected, Layout.parse(receiver.layouts().get("Рабочий макет").json()).order());
    for(var block:NAVIGATION_BLOCKS)assertEquals(oldOrder.stream().filter(block::contains).toList(),expected.stream().filter(oldOrder::contains).filter(block::contains).toList());
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(strings={"2.0.0","2.5.0","5.0.0"})
  void beforeVersionOpenSnapshotsRealKeysMailArchiveAndAppearanceWithoutRewritingSources(String nextVersion) throws Exception {
    String previous = System.getProperty("aegis.profile");
    System.setProperty("aegis.profile", root.toString());
    char[] password = "migration-200-account-passphrase".toCharArray();
    char[] archivePassword = "independent-archive-200-passphrase".toCharArray();
    try {
      ClientConfig config = ClientConfig.load(AppPaths.config());
      config.save(AppPaths.config());
      byte[] publicKey, privateKey;
      String identityId, archiveItem;
      EncryptedPacket incoming;
      try (LocalStore store = new LocalStore(config.storagePath(), password, Clock.systemUTC(), 200_000, 4_000_000)) {
        store.bindNickname("alice");
        identityId = store.identity().userId();
        publicKey = store.identity().publicKey();
        privateKey = store.identity().privateKey();
        Identity peer = Identity.create();
        UserInfo remote = new UserInfo(peer.userId(), "bob", peer.publicKey(), null);
        UserInfo local = new UserInfo(identityId, "alice", publicKey, null);
        store.trust(remote);
        try (PlainMessage body = PlainMessage.text("Incoming preserved across 1.5 to 2.0")) {
          incoming = new AutomaticEncryption(Clock.systemUTC()).encrypt(body, 86400, 604800000, peer, "bob", local);
        }
        store.accept(incoming);
        try (PlainMessage body = PlainMessage.text("Sent preserved across 1.5 to 2.0")) {
          var sent = new AutomaticEncryption(Clock.systemUTC()).encrypt(body, 86400, 604800000, store.identity(), "alice", remote);
          store.saveSent(sent, "bob", System.currentTimeMillis());
        }
        store.writeArchivePreferences("archive-preferences-fixture".getBytes(StandardCharsets.UTF_8));
      }
      AppearanceStore appearance = new AppearanceStore(root);
      appearance.apply(appearance.current().manual("forest-green"));
      appearance.saveLayout("Мой макет", appearance.current().layout().panels(18, 35).below(true));
      Path history = root.resolve("updates/events/history-fixture.json");
      Files.createDirectories(history.getParent());
      Files.writeString(history, "{\"version\":\"1.5.0\",\"event\":\"previous-release\"}");
      Path archive = config.storagePath().resolveSibling(config.storagePath().getFileName() + ".personal-archive");
      Path guards = root.resolve("archive-guards");
      try (EncryptedArchive container = EncryptedArchive.create(archive, guards, archivePassword, false, Clock.systemUTC()).archive()) {
        archiveItem = container.importBytes("keep.txt", "text", "Actual encrypted archive content".getBytes(StandardCharsets.UTF_8),
            "", false, EncryptedArchive.QUIET, () -> false).id();
      }
      Map<String, byte[]> vaultBefore = files(config.storagePath()), archiveBefore = files(archive), appearanceBefore = files(root.resolve("appearance"));
      byte[] historyBefore = Files.readAllBytes(history), configBefore = Files.readAllBytes(AppPaths.config());
      Path backup = ClientUpgrade.beforeVersionOpen(nextVersion, config, root.resolve("backups"));
      assertNotNull(backup);
      ProfileSnapshot.verify(backup, config);
      assertEquals(backup, ClientUpgrade.beforeVersionOpen(nextVersion, config, root.resolve("backups")));
      assertFilesEqual(vaultBefore, files(config.storagePath()));
      assertFilesEqual(archiveBefore, files(archive));
      assertFilesEqual(appearanceBefore, files(root.resolve("appearance")));
      assertArrayEquals(historyBefore, Files.readAllBytes(history));
      assertArrayEquals(configBefore, Files.readAllBytes(AppPaths.config()));
      assertFilesEqual(vaultBefore, files(backup.resolve("vault")));
      assertFilesEqual(archiveBefore, files(backup.resolve("personal-archives/main")));
      assertFilesEqual(appearanceBefore, files(backup.resolve("app/appearance")));
      assertArrayEquals(historyBefore, Files.readAllBytes(backup.resolve("app/updates/events/history-fixture.json")));
      try (LocalStore store = new LocalStore(config.storagePath(), password, Clock.systemUTC(), 200_000, 4_000_000)) {
        assertEquals(identityId, store.identity().userId());
        assertArrayEquals(publicKey, store.identity().publicKey());
        assertArrayEquals(privateKey, store.identity().privateKey());
        assertEquals(1, store.contacts().size());
        assertEquals(1, store.inbox().size());
        assertEquals(1, store.mailboxIndex(true).size());
        assertArrayEquals(Identity.digest(incoming), Identity.digest(store.load(incoming.messageId())));
      }
      try (EncryptedArchive container = EncryptedArchive.open(archive, guards, archivePassword, false, Clock.systemUTC())) {
        assertEquals("Actual encrypted archive content", new String(container.previewBytes(archiveItem, 1024), StandardCharsets.UTF_8));
      }
      AppearanceStore reopened = new AppearanceStore(root);
      assertEquals(appearance.current(), reopened.current());
      assertEquals(appearance.layouts(), reopened.layouts());
      ProfileSnapshot.verify(backup, config);
    } finally {
      if (previous == null) System.clearProperty("aegis.profile"); else System.setProperty("aegis.profile", previous);
    }
  }

  private static Map<String, byte[]> files(Path folder) throws Exception {
    Map<String, byte[]> result = new LinkedHashMap<>();
    try (var paths = Files.walk(folder)) {
      for (Path file : paths.filter(Files::isRegularFile).sorted().toList())
        if (!file.getFileName().toString().endsWith(".lock"))
          result.put(folder.relativize(file).toString(), Files.readAllBytes(file));
    }
    return result;
  }

  private static void assertFilesEqual(Map<String, byte[]> expected, Map<String, byte[]> actual) {
    assertEquals(expected.keySet(), actual.keySet());
    expected.forEach((name, bytes) -> assertArrayEquals(bytes, actual.get(name), name));
  }
}
