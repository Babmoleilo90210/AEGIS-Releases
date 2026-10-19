package org.securemail.client.storage;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.*;

class ProfileSnapshot600Test {
  @TempDir Path root;
  private String previous;
  @BeforeEach void profile(){previous=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.toString());}
  @AfterEach void reset(){if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);}
  private void file(String name,String value)throws IOException{Path p=root.resolve(name);Files.createDirectories(p.getParent());Files.writeString(p,value);}
  @Test void persistentCoreVoiceAndMigrationMetadataRestoreWithoutCacheCookiesOrBackupRecursion()throws Exception{
    ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());
    for(String p:List.of("core600/device.vault","core600/navigation.json","core600/notification-preferences.json","core600/identity.properties","core600/relay600.properties","core600/obsidian-control/linux-distribution.json","glas600/account/state.enc","mail600/migrated-profile6/migration.properties","mail600/migrated-profile6/migration.mac"))file(p,"ciphertext-or-public-setting:"+p);
    for(String p:List.of("core600/core.lock","core600/tor/control_auth_cookie","core600/library-cache/account/known.enc","core600/not-approved.key","core600/obsidian-control/personal-manager/requests/current.json","mail600/encrypted-migration-backups/old.aeb6"))file(p,"must-not-copy");
    Path snapshot=ProfileSnapshot.create(config,root.resolve("backups"));ProfileSnapshot.verify(snapshot,config);
    assertEquals("ciphertext-or-public-setting:core600/device.vault",Files.readString(snapshot.resolve("app/core600/device.vault")));assertTrue(Files.exists(snapshot.resolve("app/glas600/account/state.enc")));assertTrue(Files.exists(snapshot.resolve("app/mail600/migrated-profile6/migration.properties")));
    assertFalse(Files.exists(snapshot.resolve("app/core600/core.lock")));assertFalse(Files.exists(snapshot.resolve("app/core600/tor")));assertFalse(Files.exists(snapshot.resolve("app/core600/library-cache")));assertTrue(Files.exists(snapshot.resolve("app/core600/obsidian-control/linux-distribution.json")));assertFalse(Files.exists(snapshot.resolve("app/core600/obsidian-control/personal-manager")));assertFalse(Files.exists(snapshot.resolve("app/core600/not-approved.key")));assertFalse(Files.exists(snapshot.resolve("app/mail600/encrypted-migration-backups")));
    file("core600/device.vault","changed");file("glas600/account/state.enc","changed");ProfileSnapshot.restore(snapshot,config);assertEquals("ciphertext-or-public-setting:core600/device.vault",Files.readString(root.resolve("core600/device.vault")));assertEquals("ciphertext-or-public-setting:core600/notification-preferences.json",Files.readString(root.resolve("core600/notification-preferences.json")));assertEquals("ciphertext-or-public-setting:glas600/account/state.enc",Files.readString(root.resolve("glas600/account/state.enc")));
    assertEquals("must-not-copy",Files.readString(root.resolve("core600/not-approved.key")));
  }
  @Test void mailMigrationSnapshotNeverIncludesCoreGlasOrMigrationReceiptSources()throws Exception{
    ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());file("core600/device.vault","Core-only-ciphertext");file("glas600/account/state.enc","Glas-only-ciphertext");file("mail600/migrated-profile6/migration.properties","migration metadata");file("ui-preferences.json","legacy-theme");
    Path snapshot=ProfileSnapshot.createMailMigration600(config,root.resolve("migration-work"));ProfileSnapshot.verify(snapshot,config);assertFalse(Files.exists(snapshot.resolve("app/core600")));assertFalse(Files.exists(snapshot.resolve("app/glas600")));assertFalse(Files.exists(snapshot.resolve("app/mail600")));assertEquals("legacy-theme",Files.readString(snapshot.resolve("app/ui-preferences.json")));
  }
  @Test void absentUnownedMigrationTargetsDoNotCreateAnIncompleteMigrationDirectory()throws Exception{
    ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());Path snapshot=ProfileSnapshot.create(config,root.resolve("backups"));ProfileSnapshot.restore(snapshot,config);assertFalse(Files.exists(root.resolve("mail600/migrated-profile6")));assertFalse(Files.exists(root.resolve("core600")));assertFalse(Files.exists(root.resolve("glas600")));
  }
  @Test void pre6SnapshotWithoutCoreOwnershipNeverRemovesLaterPairedDevice()throws Exception{
    ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());Path snapshot=ProfileSnapshot.create(config,root.resolve("backups"));
    Properties p=new Properties();try(var in=Files.newInputStream(snapshot.resolve("snapshot.properties"))){p.load(in);}p.keySet().removeIf(key->key.toString().startsWith("managed/"));try(var out=Files.newOutputStream(snapshot.resolve("snapshot.properties"))){p.store(out,"schema1 pre-6 compatible fixture");}
    file("core600/device.vault","new-paired-ciphertext");file("glas600/account/state.enc","new-voice-ciphertext");ProfileSnapshot.verify(snapshot,config);ProfileSnapshot.restore(snapshot,config);assertEquals("new-paired-ciphertext",Files.readString(root.resolve("core600/device.vault")));assertEquals("new-voice-ciphertext",Files.readString(root.resolve("glas600/account/state.enc")));
  }
}
