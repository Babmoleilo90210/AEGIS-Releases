package org.securemail.client.safeweb600;
import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;import java.nio.file.*;import java.util.*;
import org.junit.jupiter.api.*;import org.junit.jupiter.api.io.TempDir;

/** Actual canonical filesystem tests only; no native sandbox acceptance claim. */
class VzorStoragePaths600Test {
 @TempDir Path home;
 private List<Path> browser(){return List.of(home.resolve("manager"),home.resolve("browser"));}
 @Test void readOnlyPreflightAcceptsSeparateMissingPrivateDirectoriesWithoutCreatingThem()throws Exception{
  Path privateData=home.resolve("account/private/vault");VzorLaunch600.checkHiddenData(List.of(privateData),browser(),false);assertFalse(Files.exists(privateData));assertFalse(Files.exists(browser().getFirst()));VzorLaunch600.requireHiddenData(List.of(privateData));assertFalse(Files.exists(privateData));
 }
 @Test void browserRootChildrenAndAncestorsAreNeverAllowedForSensitiveState(){
  for(Path path:List.of(home,home.resolve("manager"),home.resolve("manager/identity.key"),home.resolve("browser/archive")))assertThrows(IOException.class,()->VzorLaunch600.checkHiddenData(List.of(path),browser(),false));
 }
 @Test void existingSymlinkAndMissingSuffixAreResolvedBeforeComparison()throws Exception{
  Path browser=home.resolve("browser"),alias=home.resolve("public-looking-alias");Files.createDirectories(browser);
  try{Files.createSymbolicLink(alias,browser);}catch(UnsupportedOperationException|FileSystemException unavailable){Assumptions.abort("Host cannot create symlinks");}
  assertThrows(IOException.class,()->VzorLaunch600.checkHiddenData(List.of(alias.resolve("new-private-state")),browser(),false));assertFalse(Files.exists(browser.resolve("new-private-state")));
 }
 @Test void symlinkedBrowserRootCannotHideOverlapWithPrivateDirectory()throws Exception{
  Path privateData=home.resolve("account"),alias=home.resolve("browser-alias");Files.createDirectories(privateData);
  try{Files.createSymbolicLink(alias,privateData);}catch(UnsupportedOperationException|FileSystemException unavailable){Assumptions.abort("Host cannot create symlinks");}
  assertThrows(IOException.class,()->VzorLaunch600.checkHiddenData(List.of(privateData.resolve("vault")),List.of(home.resolve("manager"),alias),false));
 }
 @Test void linuxSystemBindRootsAreRejectedWithoutReadingOrCreatingSecrets(){
  Assumptions.assumeTrue(System.getProperty("os.name").equals("Linux"));
  for(Path path:List.of(Path.of("/usr/aegis-private-never-create"),Path.of("/etc/fonts/aegis-private-never-create"),Path.of("/lib/aegis-private-never-create")))assertThrows(IOException.class,()->VzorLaunch600.requireHiddenData(List.of(path)));
 }
 @Test void ambiguousRelativeNullAndOversizedInputFailClosed(){
  assertThrows(IOException.class,()->VzorLaunch600.checkHiddenData(List.of(Path.of("relative-private")),browser(),false));assertThrows(IOException.class,()->VzorLaunch600.checkHiddenData(Collections.singletonList(null),browser(),false));assertThrows(IOException.class,()->VzorLaunch600.checkHiddenData(Collections.nCopies(65,home.resolve("data")),browser(),false));assertThrows(IOException.class,()->VzorLaunch600.requireHiddenData(List.of()));
 }
 @Test void diagnosticsNeverContainPrivatePathOrAccountText(){
  String marker="PRIVATE_ACCOUNT_MARKER";IOException error=assertThrows(IOException.class,()->VzorLaunch600.checkHiddenData(List.of(home.resolve("browser/"+marker)),browser(),false));assertFalse(error.getMessage().contains(marker));assertFalse(error.getMessage().contains(home.toString()));assertTrue(error.getMessage().contains("Небезопасное расположение"));
 }
}
