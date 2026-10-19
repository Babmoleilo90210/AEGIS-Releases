package org.securemail.client.ecosystem;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.file.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.*;
import org.securemail.client.safeweb600.VzorState600;

class MailFilesystemBoundary600Test {
  @TempDir Path root;
  private String previousProfile;
  @BeforeEach void setup(){previousProfile=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.resolve("app").toString());}
  @AfterEach void restore(){if(previousProfile==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previousProfile);}
  private ClientConfig config()throws IOException{return ClientConfig.load(AppPaths.config());}
  private Path browserRoot(){return VzorState600.defaultRoot().resolveSibling(AppPaths.windows()?"AEGIS-SafeWeb":"aegis-safeweb");}
  @Test void ordinaryMissingPrivateStorageIsAcceptedWithoutCreatingAnything()throws Exception {
    Path data=root.resolve("private-mail/missing/profile");MailFilesystemBoundary600.require(config().withStorage(data));MailFilesystemBoundary600.requireArchive(root.resolve("separate-archive"));assertFalse(Files.exists(data));assertFalse(Files.exists(AppPaths.root()));
  }
  @Test void systemBindCannotBecomeMailStorageEvenWhenDestinationDoesNotExist()throws Exception {
    Assumptions.assumeTrue(System.getProperty("os.name").equals("Linux"));
    for(String path:new String[]{"/usr/aegis-private-synthetic/missing","/lib/aegis-private-synthetic/missing","/etc/fonts/aegis-private-synthetic"})assertThrows(IOException.class,()->MailFilesystemBoundary600.require(config().withStorage(Path.of(path))));
  }
  @Test void symlinkAliasIntoBrowserVisibleSystemBindIsRejected()throws Exception {
    Assumptions.assumeTrue(System.getProperty("os.name").equals("Linux"));Path alias=root.resolve("alias");Files.createSymbolicLink(alias,Path.of("/usr"));assertThrows(IOException.class,()->MailFilesystemBoundary600.require(config().withStorage(alias.resolve("private/missing"))));assertTrue(Files.isSymbolicLink(alias));
  }
  @Test void browserProfileOrDownloadsCannotContainMailArchive()throws Exception {
    Path browser=browserRoot();assertThrows(IOException.class,()->MailFilesystemBoundary600.require(config().withStorage(browser.resolve("persistent/profile"))));assertThrows(IOException.class,()->MailFilesystemBoundary600.requireArchive(browser.resolve("downloads/archive")));
  }
  @Test void managerStateAndParentOfBrowserCannotContainPrivateData()throws Exception {
    Path manager=VzorState600.defaultRoot();assertThrows(IOException.class,()->MailFilesystemBoundary600.require(config().withStorage(manager.resolve("profile"))));assertThrows(IOException.class,()->MailFilesystemBoundary600.requireArchive(browserRoot().getParent()));
  }
  @Test void migrationRejectsExposedStorageBeforeBackupOrMutation()throws Exception {
    Assumptions.assumeTrue(System.getProperty("os.name").equals("Linux"));ClientConfig unsafe=config().withStorage(Path.of("/usr/aegis-private-synthetic/missing"));assertThrows(IOException.class,()->MailProfileMigration600.beforeOpen(unsafe,"synthetic password".toCharArray(),new char[0],()->false));assertFalse(Files.exists(AppPaths.root()));
  }
  @Test void recoveryRejectsExposedStorageBeforeReadingBackup()throws Exception {
    Assumptions.assumeTrue(System.getProperty("os.name").equals("Linux"));ClientConfig unsafe=config().withStorage(Path.of("/usr/aegis-private-synthetic/missing"));assertThrows(IOException.class,()->MailRecoveryIdentity600.openExisting(unsafe,new char[0],"a".repeat(64),()->false));assertThrows(IOException.class,()->MailRecoveryIdentity600.restoreBackup(unsafe,root.resolve("not-read"),new char[0],"a".repeat(64),()->false));assertFalse(Files.exists(AppPaths.root()));
  }
  @Test void coreProfileInsideBrowserIsRejectedBeforeFilesAreCreated()throws Exception {
    System.setProperty("aegis.profile",browserRoot().resolve("private-profile-synthetic").toString());assertThrows(IOException.class,()->MailFilesystemBoundary600.require(config()));
  }
}
