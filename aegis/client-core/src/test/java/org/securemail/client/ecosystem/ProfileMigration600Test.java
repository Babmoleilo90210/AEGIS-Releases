package org.securemail.client.ecosystem;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.storage.*;
import org.securemail.protocol.UserInfo;

class ProfileMigration600Test {
  @TempDir Path root;
  private String prior;private ClientConfig config;private byte[] key;
  @BeforeEach void oldProfile()throws Exception {
    prior=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.resolve("old-app").toString());
    config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());key=LocalIpc.random(32);
    AtomicFiles.directory(config.storagePath());Files.write(config.storagePath().resolve("state.vault"),LocalIpc.random(128));Files.write(config.storagePath().resolve("salt"),LocalIpc.random(16));
    Path archive=config.storagePath().resolveSibling(config.storagePath().getFileName()+".personal-archive");AtomicFiles.directory(archive);Files.write(archive.resolve("catalog.enc"),LocalIpc.random(1024));
    for(String path:List.of("theme.txt","ui-preferences.json","appearance/custom.json","tor-mode.txt","session/resume.enc")) {
      Path file=AppPaths.root().resolve(path);AtomicFiles.directory(file.getParent());Files.writeString(file,"fixture-"+path);
    }
  }
  @AfterEach void restore(){Arrays.fill(key,(byte)0);if(prior==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",prior);}
  private ProfileMigration600.SemanticVerifier fixtureVerifier(){return (snapshot,mail)->{
    assertArrayEquals(Files.readAllBytes(snapshot.resolve("vault/state.vault")),Files.readAllBytes(mail.resolve("profile/state.vault")));
    assertArrayEquals(Files.readAllBytes(snapshot.resolve("personal-archives/main/catalog.enc")),Files.readAllBytes(mail.resolve("profile.personal-archive/catalog.enc")));
    return new ProfileMigration600.Verification("existing-account",EnumSet.allOf(ProfileMigration600.Check.class));
  };}
  private ProfileMigration600.Result migrate(ProfileMigration600.SemanticVerifier verifier)throws Exception{return ProfileMigration600.migrate(config,root.resolve("ecosystem6"),root.resolve("encrypted-backups"),key,verifier,()->false);}
  @Test void copyVerifyAtomicPublishKeepsOldDataAndOnlyMailOwnsLegacySecrets()throws Exception {
    String old=treeHash(AppPaths.root());var result=migrate(fixtureVerifier());assertFalse(result.alreadyMigrated());assertEquals(old,treeHash(AppPaths.root()));
    assertEquals("fixture-theme.txt",Files.readString(result.profile().resolve("core/settings/theme.txt")));
    assertTrue(Files.exists(result.profile().resolve("mail/legacy-app/session/resume.enc")));assertFalse(Files.exists(result.profile().resolve("core/settings/session")));
    assertArrayEquals(Files.readAllBytes(config.storagePath().resolve("state.vault")),Files.readAllBytes(result.profile().resolve("mail/profile/state.vault")));
    assertEquals(result.sourceDigest(),ProfileMigration600.verifyBackup(result.encryptedBackup(),key,()->false));
    Path restored=ProfileMigration600.restoreBackup(result.encryptedBackup(),root.resolve("restored-snapshot"),key,()->false);ProfileSnapshot.verify(restored,config);
    assertArrayEquals(Files.readAllBytes(config.storagePath().resolve("state.vault")),Files.readAllBytes(restored.resolve("vault/state.vault")));
    assertThrows(IOException.class,()->ProfileMigration600.restoreBackup(result.encryptedBackup(),restored,key,()->false));
    assertFalse(new String(Files.readAllBytes(result.encryptedBackup()),java.nio.charset.StandardCharsets.ISO_8859_1).contains("fixture-theme.txt"));
    var second=migrate((a,b)->{fail("Idempotent restart must not reopen or rewrite an accepted profile");return null;});assertTrue(second.alreadyMigrated());assertEquals(result.encryptedBackup(),second.encryptedBackup());
  }
  @Test void semanticFailureDoesNotPublishOrDeleteTheOldProfile()throws Exception {
    String before=treeHash(AppPaths.root());assertThrows(IOException.class,()->migrate((snapshot,mail)->{throw new IOException("identity mismatch");}));
    assertFalse(Files.exists(root.resolve("ecosystem6")));assertEquals(before,treeHash(AppPaths.root()));
    try(var list=Files.list(root.resolve("encrypted-backups"))){Path backup=list.findFirst().orElseThrow();ProfileMigration600.verifyBackup(backup,key,()->false);}
  }
  @Test void incompleteSemanticChecksCannotPublishAProfile()throws Exception {
    assertThrows(IOException.class,()->migrate((a,b)->new ProfileMigration600.Verification("existing-account",Set.of(ProfileMigration600.Check.IDENTITY))));assertFalse(Files.exists(root.resolve("ecosystem6")));
  }
  @Test void encryptedBackupAndReceiptRejectModificationOrWrongKey()throws Exception {
    var result=migrate(fixtureVerifier());byte[] bad=key.clone();bad[0]^=1;assertThrows(IOException.class,()->ProfileMigration600.verifyBackup(result.encryptedBackup(),bad,()->false));
    byte[] encrypted=Files.readAllBytes(result.encryptedBackup());encrypted[encrypted.length-1]^=1;Files.write(result.encryptedBackup(),encrypted);
    assertThrows(IOException.class,()->ProfileMigration600.verifyBackup(result.encryptedBackup(),key,()->false));assertThrows(IOException.class,()->migrate(fixtureVerifier()));
    assertThrows(IOException.class,()->ProfileMigration600.restoreBackup(result.encryptedBackup(),root.resolve("must-not-publish"),key,()->false));assertFalse(Files.exists(root.resolve("must-not-publish")));
    assertTrue(Files.exists(config.storagePath().resolve("state.vault")));
  }
  @Test void cancelledMigrationAndSymlinkNeverReplaceTheOldState()throws Exception {
    String before=treeHash(AppPaths.root());assertThrows(InterruptedIOException.class,()->ProfileMigration600.migrate(config,root.resolve("ecosystem6"),root.resolve("encrypted-backups"),key,fixtureVerifier(),()->true));assertFalse(Files.exists(root.resolve("ecosystem6")));assertEquals(before,treeHash(AppPaths.root()));
    Path outside=root.resolve("outside");Files.writeString(outside,"must not read");Files.createSymbolicLink(config.storagePath().resolve("linked"),outside);
    assertThrows(IOException.class,()->migrate(fixtureVerifier()));assertEquals("must not read",Files.readString(outside));assertFalse(Files.exists(root.resolve("ecosystem6")));
  }
  @Test void realEncryptedIdentityContactAndIndependentArchiveRemainReadable()throws Exception {
    Files.delete(config.storagePath().resolve("state.vault"));Files.delete(config.storagePath().resolve("salt"));
    char[] password="migration fixture strong mail password".toCharArray();String id;byte[] publicKey;Identity peer=Identity.create();
    try(var store=new LocalStore(config.storagePath(),password,Clock.systemUTC(),100000,2000000)) {
      store.bindNickname("raven");store.trust(new UserInfo(peer.userId(),"heron",peer.publicKey(),null));id=store.identity().userId();publicKey=store.identity().publicKey();
    }
    Path oldArchive=config.storagePath().resolveSibling(config.storagePath().getFileName()+".personal-archive");
    Files.delete(oldArchive.resolve("catalog.enc"));Files.delete(oldArchive);
    char[] archivePassword="independent archive recovery fixture".toCharArray();String item;
    try(var archive=org.securemail.client.archive.EncryptedArchive.create(oldArchive,root.resolve("archive-guards"),archivePassword,false,Clock.systemUTC()).archive()) {
      item=archive.importBytes("preserved.txt","text","archive semantic proof".getBytes(java.nio.charset.StandardCharsets.UTF_8),"",false,org.securemail.client.archive.EncryptedArchive.QUIET,()->false).id();
    }
    byte[] before=Files.readAllBytes(config.storagePath().resolve("state.vault"));
    var result=migrate((snapshot,mail)-> {
      try(var store=new LocalStore(mail.resolve("profile"),password,Clock.systemUTC(),100000,2000000);
          var archive=org.securemail.client.archive.EncryptedArchive.open(mail.resolve("profile.personal-archive"),root.resolve("verify-archive-guards"),archivePassword,true,Clock.systemUTC())) {
        assertEquals(id,store.identity().userId());assertArrayEquals(publicKey,store.identity().publicKey());assertEquals(peer.userId(),store.contact("heron").userId());
        assertEquals("archive semantic proof",new String(archive.previewBytes(item,1024),java.nio.charset.StandardCharsets.UTF_8));
        return new ProfileMigration600.Verification(id,EnumSet.allOf(ProfileMigration600.Check.class));
      }catch(java.security.GeneralSecurityException e){throw new IOException(e);}
    });
    assertEquals(id,result.accountId());assertArrayEquals(before,Files.readAllBytes(config.storagePath().resolve("state.vault")));assertArrayEquals(before,Files.readAllBytes(result.profile().resolve("mail/profile/state.vault")));
  }
  private static String treeHash(Path directory)throws Exception {
    var digest=java.security.MessageDigest.getInstance("SHA-256");try(var walk=Files.walk(directory)){for(Path path:walk.sorted().toList())if(Files.isRegularFile(path)){digest.update(directory.relativize(path).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update(Files.readAllBytes(path));}}return HexFormat.of().formatHex(digest.digest());
  }
}
