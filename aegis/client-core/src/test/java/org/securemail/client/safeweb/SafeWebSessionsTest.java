package org.securemail.client.safeweb;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SafeWebSessionsTest {
  @TempDir Path root;
  Path install(SafeWebSessions store,String marker)throws Exception{
    Path p=store.newInstallationPath();Files.createDirectories(p.resolve("Browser/TorBrowser/Data/Browser/profile.default"));Files.writeString(p.resolve("Browser/start-tor-browser"),"signed fixture "+marker);Files.writeString(p.resolve("Browser/firefox"),"fixture browser");return p;
  }
  @Test void persistentProfileAndTemporaryCleanupAreSeparate()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));store.registerVerifiedBundle(install(store,"one"),"a".repeat(64));
    var first=store.prepare(SafeWebSessions.Mode.PERSISTENT);Path prefs=first.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default/prefs.js");Files.writeString(prefs,"synthetic bookmark/prefs");store.complete(first);
    var reopened=new SafeWebSessions(root.resolve("browser")).prepare(SafeWebSessions.Mode.PERSISTENT);assertEquals(first.bundle(),reopened.bundle());assertEquals("synthetic bookmark/prefs",Files.readString(prefs));
    var ephemeral=store.prepare(SafeWebSessions.Mode.TEMPORARY);assertNotEquals(reopened.bundle(),ephemeral.bundle());assertFalse(Files.exists(ephemeral.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default/prefs.js")));store.complete(ephemeral);assertFalse(Files.exists(ephemeral.bundle()));assertTrue(Files.exists(reopened.bundle()));
  }
  @Test void browserCannotResealItsModifiedExecutables()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));store.registerVerifiedBundle(install(store,"one"),"a".repeat(64));var session=store.prepare(SafeWebSessions.Mode.PERSISTENT);
    Files.writeString(session.bundle().resolve("Browser/firefox"),"tampered fixture");Files.writeString(session.bundle().resolve("aegis-verified.sha256"),"untrusted self hashes");
    assertThrows(java.io.IOException.class,()->store.prepare(SafeWebSessions.Mode.PERSISTENT));assertFalse(session.control().startsWith(session.bundle()));assertFalse(store.root().resolve("control").startsWith(session.bundle()));
  }
  @Test void cleanupNeverFollowsAnExternalSymlink()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));store.registerVerifiedBundle(install(store,"one"),"a".repeat(64));var session=store.prepare(SafeWebSessions.Mode.TEMPORARY);
    Path outside=root.resolve("outside");Files.createDirectory(outside);Files.writeString(outside.resolve("keep"),"synthetic sentinel");Files.createSymbolicLink(session.bundle().resolve("external"),outside);store.complete(session);assertEquals("synthetic sentinel",Files.readString(outside.resolve("keep")));
  }
  @Test void authenticatedTemplateUpgradeKeepsOnlyBrowserData()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));store.registerVerifiedBundle(install(store,"one"),"a".repeat(64));var old=store.prepare(SafeWebSessions.Mode.PERSISTENT);Files.writeString(old.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default/prefs.js"),"bookmark");store.complete(old);
    store.registerVerifiedBundle(install(store,"two"),"b".repeat(64));var updated=store.prepare(SafeWebSessions.Mode.PERSISTENT);assertNotEquals(old.bundle(),updated.bundle());assertEquals("signed fixture two",Files.readString(updated.bundle().resolve("Browser/start-tor-browser")));assertEquals("bookmark",Files.readString(updated.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default/prefs.js")));
  }
  @Test void arbitraryForeignSessionCannotBeDeleted()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));Path outside=root.resolve("keep");Files.createDirectory(outside);assertThrows(java.io.IOException.class,()->store.complete(new SafeWebSessions.Session("foreign",outside,outside,SafeWebSessions.Mode.TEMPORARY)));assertTrue(Files.exists(outside));
  }
  @Test void failedTemplateCopyNeverPublishesPartialTemplate()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));store.registerVerifiedBundle(install(store,"one"),"a".repeat(64));
    Path next=install(store,"two"),outside=Files.writeString(root.resolve("outside"),"synthetic sentinel");
    Files.createSymbolicLink(next.resolve("Browser/TorBrowser/Data/bad"),outside);
    assertThrows(java.io.IOException.class,()->store.registerVerifiedBundle(next,"b".repeat(64)));
    assertFalse(Files.exists(store.root().resolve("templates/template-"+"b".repeat(64))));assertEquals("a".repeat(64),store.installedFingerprint());
    try(var paths=Files.list(store.root().resolve("templates"))){assertFalse(paths.anyMatch(p->p.getFileName().toString().startsWith(".template-stage-")));}
  }
  @Test void failedProfileUpgradePreservesPreviousAndCanBeRetried()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));store.registerVerifiedBundle(install(store,"one"),"a".repeat(64));var old=store.prepare(SafeWebSessions.Mode.PERSISTENT);
    Path prefs=old.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default/prefs.js");Files.writeString(prefs,"old bookmark");
    Path bad=old.bundle().resolve("Browser/TorBrowser/Data/bad"),outside=Files.writeString(root.resolve("outside"),"outside");Files.createSymbolicLink(bad,outside);
    store.registerVerifiedBundle(install(store,"two"),"b".repeat(64));assertThrows(java.io.IOException.class,()->store.prepare(SafeWebSessions.Mode.PERSISTENT));
    assertFalse(Files.exists(store.root().resolve("bundles/normal-"+"b".repeat(16))));assertEquals("old bookmark",Files.readString(prefs));
    Files.delete(bad);var retried=store.prepare(SafeWebSessions.Mode.PERSISTENT);assertEquals("old bookmark",Files.readString(retried.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default/prefs.js")));
  }
  @Test void downloadsSurviveNormalCloseAndAuthenticatedUpgrade()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));store.registerVerifiedBundle(install(store,"one"),"a".repeat(64));var old=store.prepare(SafeWebSessions.Mode.PERSISTENT);
    Path download=old.bundle().resolve("aegis-downloads/keep.txt");Files.createDirectory(download.getParent());Files.writeString(download,"download");store.complete(old);assertEquals("download",Files.readString(download));
    SafeWebSessions restarted=new SafeWebSessions(store.root());var existing=restarted.persistentSession().orElseThrow();assertFalse(Files.exists(existing.control()));assertEquals(List.of(download),restarted.downloads(existing));
    store.registerVerifiedBundle(install(store,"two"),"b".repeat(64));var updated=store.prepare(SafeWebSessions.Mode.PERSISTENT);assertEquals("download",Files.readString(updated.bundle().resolve("aegis-downloads/keep.txt")));
  }
  @Test void staleCleanupRequiresExclusiveLockAndPreservesNormalSession()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));store.registerVerifiedBundle(install(store,"one"),"a".repeat(64));var normal=store.prepare(SafeWebSessions.Mode.PERSISTENT);var stale=store.prepare(SafeWebSessions.Mode.TEMPORARY);
    assertThrows(java.io.IOException.class,()->store.cleanupStaleTemporarySessions(null));
    try(var channel=java.nio.channels.FileChannel.open(store.root().resolve("control/manager.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);var lock=channel.lock()){
      assertTrue(store.cleanupStaleTemporarySessions(lock)>=1);
    }
    assertFalse(Files.exists(stale.bundle()));assertFalse(Files.exists(stale.control()));assertTrue(Files.exists(normal.bundle()));
    assertThrows(java.io.IOException.class,()->store.complete(new SafeWebSessions.Session(normal.id(),normal.bundle(),normal.control(),SafeWebSessions.Mode.TEMPORARY)));assertTrue(Files.exists(normal.bundle()));
  }
  @Test void mutableRootsCannotEscapeAndOnlyRootDesktopLauncherMayChange()throws Exception{
    SafeWebSessions store=new SafeWebSessions(root.resolve("browser"));Path source=install(store,"one");Files.writeString(source.resolve("Browser/start-tor-browser.desktop"),"canonical signed launcher");store.registerVerifiedBundle(source,"a".repeat(64));var session=store.prepare(SafeWebSessions.Mode.PERSISTENT);
    Files.writeString(session.bundle().resolve("start-tor-browser.desktop"),"generated session launcher");assertDoesNotThrow(()->store.prepare(SafeWebSessions.Mode.PERSISTENT));
    Files.writeString(session.bundle().resolve("Browser/start-tor-browser.desktop"),"tampered canonical launcher");assertThrows(java.io.IOException.class,()->store.prepare(SafeWebSessions.Mode.PERSISTENT));
    Path outside=Files.createDirectory(root.resolve("outside"));Files.createSymbolicLink(session.bundle().resolve("aegis-downloads"),outside);assertThrows(java.io.IOException.class,()->SafeWebSessions.snapshot(session.bundle()));
  }
  @Test void messengerRootAliasCannotOverlapBrowserStorage()throws Exception{
    Path browser=Files.createDirectory(root.resolve("browser")),alias=root.resolve("messenger-link");Files.createSymbolicLink(alias,browser);
    String previous=System.getProperty("aegis.profile");
    try{System.setProperty("aegis.profile",alias.toString());assertThrows(java.io.IOException.class,()->new SafeWebSessions(browser));}
    finally{if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);}
  }
}
