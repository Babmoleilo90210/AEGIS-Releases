package org.securemail.client.safeweb;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class TorBrowserDiscoveryTest {
    @TempDir Path root;
    static byte[] elf(int machine){byte[] bytes=new byte[64];bytes[0]=0x7f;bytes[1]='E';bytes[2]='L';bytes[3]='F';bytes[4]=2;bytes[5]=1;bytes[18]=(byte)machine;bytes[19]=(byte)(machine>>8);return bytes;}
    Path bundle(Path path,String name,int machine)throws Exception {
        Files.createDirectories(path.resolve("Browser/TorBrowser/Tor"));Files.write(path.resolve("Browser/firefox"),elf(machine));Files.write(path.resolve("Browser/TorBrowser/Tor/tor"),elf(machine));Files.writeString(path.resolve("Browser/start-tor-browser"),"#!/bin/sh\ntouch NEVER_EXECUTE");Files.writeString(path.resolve("Browser/application.ini"),"[App]\nName="+name+"\nVersion=140.4.0\n");Files.write(path.resolve("Browser/tbb_version.json"),TorBrowserDownloadServiceTest.version("15.0.25","linux-x86_64"));return path;
    }
    @Test void discoversKnownInstallationWithoutExecutingOrReadingOrCopyingProfile()throws Exception {
        Path home=root.resolve("home"),browser=bundle(home.resolve("Downloads/tor-browser"),"Tor Browser",62);Path secret=browser.resolve("Browser/TorBrowser/Data/Browser/profile.default/cookies.sqlite");Files.createDirectories(secret.getParent());Files.writeString(secret,"sentinel profile data");var before=Files.getLastModifiedTime(secret);
        var candidates=TorBrowserDiscovery.discover(home,Map.of(),"Linux");assertEquals(1,candidates.size());assertEquals(browser.toRealPath(),candidates.getFirst().bundle());assertTrue(candidates.getFirst().versionLabel().contains("15.0.25"));assertTrue(candidates.getFirst().status().contains("не проверена"));assertEquals("sentinel profile data",Files.readString(secret));assertEquals(before,Files.getLastModifiedTime(secret));assertFalse(Files.exists(root.resolve("NEVER_EXECUTE")));assertEquals(1,Files.list(home.resolve("Downloads")).count());
    }
    @Test void findsStandardAndExplicitXdgUserDataInstallationWithoutHomeScan()throws Exception {
        Path home=root.resolve("home");Path standard=bundle(home.resolve(".local/share/tor-browser"),"TorBrowser",62);assertTrue(TorBrowserDiscovery.discover(home,Map.of(),"Linux").stream().anyMatch(candidate->candidate.bundle().equals(standard)));
        Path data=root.resolve("xdg");Path custom=bundle(data.resolve("tor-browser"),"TorBrowser",62);assertTrue(TorBrowserDiscovery.discover(home,Map.of("XDG_DATA_HOME",data.toString()),"Linux").stream().anyMatch(candidate->candidate.bundle().equals(custom)));assertFalse(TorBrowserDiscovery.discover(home,Map.of("XDG_DATA_HOME",data.toString()),"Linux").stream().anyMatch(candidate->candidate.bundle().equals(standard)));
    }
    @Test void ordinaryFirefoxAndEscapingExecutableLinksAreNotBrowserCandidates()throws Exception {
        Path firefox=bundle(root.resolve("firefox"),"Firefox",62);assertTrue(TorBrowserDiscovery.inspectDirectory(firefox).isEmpty());
        Path browser=bundle(root.resolve("browser"),"TorBrowser",62),outside=Files.write(root.resolve("outside"),elf(62));Files.delete(browser.resolve("Browser/firefox"));Files.createSymbolicLink(browser.resolve("Browser/firefox"),outside);assertTrue(TorBrowserDiscovery.inspectDirectory(browser).isEmpty());
    }
    @Test void allowsInternalExecutableLinkAndManualBrowserDirectorySelection()throws Exception {
        Path browser=bundle(root.resolve("browser"),"TorBrowser",62);Files.move(browser.resolve("Browser/firefox"),browser.resolve("Browser/firefox.real"));Files.createSymbolicLink(browser.resolve("Browser/firefox"),Path.of("firefox.real"));assertEquals(browser.toRealPath(),TorBrowserDiscovery.inspectDirectory(browser.resolve("Browser")).orElseThrow().bundle());
    }
    @Test void unknownWrongAndTruncatedArchitecturesStayIncompatible()throws Exception {
        Path browser=bundle(root.resolve("browser"),"TorBrowser",183);assertFalse(TorBrowserDiscovery.inspectDirectory(browser).orElseThrow().compatible());assertEquals("aarch64",TorBrowserDiscovery.architecture(browser.resolve("Browser/firefox")));Files.write(browser.resolve("Browser/firefox"),new byte[]{0x7f,'E','L','F'});assertEquals("unknown",TorBrowserDiscovery.architecture(browser.resolve("Browser/firefox")));
        byte[] pe=new byte[140];pe[0]='M';pe[1]='Z';ByteBuffer.wrap(pe,60,4).order(ByteOrder.LITTLE_ENDIAN).putInt(128);pe[128]='P';pe[129]='E';pe[132]=0x64;pe[133]=(byte)0x86;Path executable=Files.write(root.resolve("portable.exe"),pe);assertEquals("x86_64",TorBrowserDiscovery.architecture(executable));
    }
    @Test void boundsIniAndRejectsLinkedParentWithoutChangingFiles()throws Exception {
        Path browser=bundle(root.resolve("browser"),"TorBrowser",62);Files.writeString(browser.resolve("Browser/application.ini"),"[App]\nName=TorBrowser\n"+"x".repeat(33000));assertTrue(TorBrowserDiscovery.inspectDirectory(browser).isEmpty());Files.createSymbolicLink(root.resolve("link"),browser);assertTrue(TorBrowserDiscovery.inspectDirectory(root.resolve("link")).isEmpty());
    }
    @Test void signedVersionMetadataMustMatchPlatformChannelAndFilename()throws Exception {
        var version=TorBrowserPackageMetadata.parse(TorBrowserDownloadServiceTest.version("15.0.25","linux-x86_64"));TorBrowserPackageMetadata.require(version,"15.0.25",false);assertThrows(IOException.class,()->TorBrowserPackageMetadata.require(version,"15.0.24",false));assertThrows(IOException.class,()->TorBrowserPackageMetadata.require(version,"15.0.25",true));assertThrows(IOException.class,()->TorBrowserPackageMetadata.parse("{\"version\":\"15.0.25\",\"architecture\":\"linux-x86_64\",\"channel\":\"alpha\"}".getBytes()));assertThrows(IOException.class,()->TorBrowserPackageMetadata.parse("{\"version\":\"15.0.25\",\"version\":\"15.0.25\",\"architecture\":\"linux-x86_64\",\"channel\":\"release\"}".getBytes()));
    }
    @Test void cancelledImportCreatesNothingAndCancelledExtractionStopsBeforeOutput()throws Exception {
        Path archive=Files.write(root.resolve("fixture.tar.xz"),new byte[]{1});Path signature=Files.writeString(root.resolve("fixture.asc"),"invalid");Path dest=root.resolve("destination");assertThrows(InterruptedIOException.class,()->TorBrowserInstaller.install(archive,signature,dest,()->true));assertFalse(Files.exists(dest));assertThrows(InterruptedIOException.class,()->TorBrowserInstaller.extractLinux(archive,root.resolve("unpack"),()->true));assertFalse(Files.exists(root.resolve("unpack")));
    }
    @Test void trustedImportVersionFloorSurvivesRestartAndLostFloorKeepsSelectedVersion()throws Exception {
        SafeWebSessions sessions=new SafeWebSessions(root.resolve("browser-state"));Path old=bundle(sessions.newInstallationPath(),"TorBrowser",62);sessions.registerVerifiedBundle(new TorBrowserInstaller.Installed(old,"a".repeat(64),TorBrowserSignature.PRIMARY_FINGERPRINT,"fixture","15.0.25","linux-x86_64"));
        Path older=bundle(sessions.newInstallationPath(),"TorBrowser",62);Files.write(older.resolve("Browser/tbb_version.json"),TorBrowserDownloadServiceTest.version("15.0.24","linux-x86_64"));var downgrade=new TorBrowserInstaller.Installed(older,"b".repeat(64),TorBrowserSignature.PRIMARY_FINGERPRINT,"fixture","15.0.24","linux-x86_64");assertThrows(IOException.class,()->new SafeWebSessions(sessions.root()).registerVerifiedBundle(downgrade));assertEquals("a".repeat(64),sessions.installedFingerprint());Files.delete(sessions.root().resolve("control/minimum-installed-linux-x86_64.txt"));assertThrows(IOException.class,()->sessions.registerVerifiedBundle(downgrade));assertEquals("a".repeat(64),sessions.installedFingerprint());
    }
    private TorBrowserInstaller.Installed authenticatedFixture(SafeWebSessions sessions,String hash)throws Exception {
        Path source=bundle(sessions.newInstallationPath(),"TorBrowser",62);return new TorBrowserInstaller.Installed(source,hash,TorBrowserSignature.PRIMARY_FINGERPRINT,"authenticated fixture boundary","15.0.25","linux-x86_64");
    }
    @Test void preflightAndFreshAuthenticatedSameVersionRepairPreserveBookmarksAndDownloads()throws Exception {
        Path state=root.resolve("state");SafeWebSessions sessions=new SafeWebSessions(state);SafeWebProcess process=new SafeWebProcess(state);assertFalse(process.authenticatedPreflight());sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64)));assertTrue(process.authenticatedPreflight());
        var normal=sessions.prepare(SafeWebSessions.Mode.PERSISTENT);Path prefs=normal.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default/prefs.js");Files.createDirectories(prefs.getParent());Files.writeString(prefs,"synthetic bookmark");Path download=normal.bundle().resolve("aegis-downloads/keep.txt");Files.createDirectory(download.getParent());Files.writeString(download,"synthetic download");sessions.complete(normal);Files.writeString(normal.bundle().resolve("Browser/firefox"),"changed executable");assertFalse(process.authenticatedPreflight());
        sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64)));assertTrue(process.authenticatedPreflight());assertEquals("synthetic bookmark",Files.readString(prefs));assertEquals("synthetic download",Files.readString(download));assertArrayEquals(elf(62),Files.readAllBytes(normal.bundle().resolve("Browser/firefox")));process.close();
    }
    @Test void corruptTemplateAndManifestRequireFreshAuthenticatedRepair()throws Exception {
        Path state=root.resolve("state");SafeWebSessions sessions=new SafeWebSessions(state);sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64)));Path template=state.resolve("templates/template-"+"a".repeat(64));Files.writeString(template.resolve("Browser/firefox"),"changed template");Files.writeString(state.resolve("control/template-"+"a".repeat(64)+".json"),"{broken");
        SafeWebProcess process=new SafeWebProcess(state);assertFalse(process.authenticatedPreflight());sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64)));assertTrue(process.authenticatedPreflight());assertArrayEquals(elf(62),Files.readAllBytes(template.resolve("Browser/firefox")));process.close();
    }
    @Test void failedRepairPreservesCurrentBrowserDataAndCanBeRetried()throws Exception {
        Path state=root.resolve("state");SafeWebSessions sessions=new SafeWebSessions(state);sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64)));var normal=sessions.prepare(SafeWebSessions.Mode.PERSISTENT);Path data=normal.bundle().resolve("Browser/TorBrowser/Data");Files.createDirectories(data);Files.writeString(data.resolve("keep"),"bookmark");Path outside=Files.writeString(root.resolve("outside"),"unrelated sentinel");Files.createSymbolicLink(data.resolve("bad"),outside);Files.writeString(normal.bundle().resolve("Browser/firefox"),"changed executable");
        assertThrows(IOException.class,()->sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64))));assertEquals("bookmark",Files.readString(data.resolve("keep")));assertEquals("unrelated sentinel",Files.readString(outside));assertEquals("a".repeat(64),sessions.installedFingerprint());Files.delete(data.resolve("bad"));sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64)));assertEquals("bookmark",Files.readString(data.resolve("keep")));
    }
    @Test void managerRecoversRepairCrashBackupBeforeRemovingStaging()throws Exception {
        Path state=root.resolve("state");SafeWebSessions sessions=new SafeWebSessions(state);sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64)));var normal=sessions.prepare(SafeWebSessions.Mode.PERSISTENT);Path keep=normal.bundle().resolve("Browser/TorBrowser/Data/keep");Files.createDirectories(keep.getParent());Files.writeString(keep,"bookmark before repair");Path backup=normal.bundle().resolveSibling(".repair-backup-"+normal.bundle().getFileName());Files.move(normal.bundle(),backup,StandardCopyOption.ATOMIC_MOVE);Path partial=normal.bundle().resolveSibling(".session-stage-"+UUID.randomUUID());Files.createDirectory(partial);Files.writeString(partial.resolve("partial"),"incomplete staging");
        try(SafeWebProcess process=new SafeWebProcess(state)){assertTrue(process.authenticatedPreflight());assertEquals("bookmark before repair",Files.readString(keep));assertFalse(Files.exists(backup));assertFalse(Files.exists(partial));}
    }

    @Test void authenticatedUpgradeOmitsOnlyStaleStockMozillaMutexLeavesWithoutTouchingSource()throws Exception {
        SafeWebSessions sessions=new SafeWebSessions(root.resolve("state"));sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64)));var old=sessions.prepare(SafeWebSessions.Mode.PERSISTENT);Path profile=old.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default");Files.createDirectories(profile);Files.writeString(profile.resolve("prefs.js"),"synthetic bookmark");Files.createSymbolicLink(profile.resolve("lock"),Path.of("127.0.0.1:+999999"));Files.writeString(profile.resolve(".parentlock"),"stale mutex");Files.writeString(profile.resolve("parent.lock"),"stale mutex");Path download=old.bundle().resolve("aegis-downloads/keep.txt");Files.createDirectory(download.getParent());Files.writeString(download,"download");sessions.complete(old);
        sessions.registerVerifiedBundle(authenticatedFixture(sessions,"b".repeat(64)));var upgraded=sessions.prepare(SafeWebSessions.Mode.PERSISTENT);Path next=upgraded.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default");assertEquals("synthetic bookmark",Files.readString(next.resolve("prefs.js")));assertEquals("download",Files.readString(upgraded.bundle().resolve("aegis-downloads/keep.txt")));for(String name:List.of("lock",".parentlock","parent.lock"))assertFalse(Files.exists(next.resolve(name),LinkOption.NOFOLLOW_LINKS));assertEquals(Path.of("127.0.0.1:+999999"),Files.readSymbolicLink(profile.resolve("lock")));assertEquals("stale mutex",Files.readString(profile.resolve(".parentlock")));
    }
    @Test void nonMutexProfileSymlinkStillBlocksUpgradeAndPreservesBrowserData()throws Exception {
        SafeWebSessions sessions=new SafeWebSessions(root.resolve("state"));sessions.registerVerifiedBundle(authenticatedFixture(sessions,"a".repeat(64)));var old=sessions.prepare(SafeWebSessions.Mode.PERSISTENT);Path profile=old.bundle().resolve("Browser/TorBrowser/Data/Browser/profile.default");Files.createDirectories(profile);Files.writeString(profile.resolve("prefs.js"),"synthetic bookmark");Path outside=Files.writeString(root.resolve("outside"),"unrelated sentinel");Files.createSymbolicLink(profile.resolve("not-a-lock"),outside);sessions.complete(old);sessions.registerVerifiedBundle(authenticatedFixture(sessions,"b".repeat(64)));assertThrows(IOException.class,()->sessions.prepare(SafeWebSessions.Mode.PERSISTENT));assertEquals("synthetic bookmark",Files.readString(profile.resolve("prefs.js")));assertEquals("unrelated sentinel",Files.readString(outside));assertFalse(Files.exists(sessions.root().resolve("bundles/normal-"+"b".repeat(16))));
    }

    @Test void legacyAuthenticatedTemplateVersionPreventsDowngradeEvenWhenSessionNeedsRepair()throws Exception {
        SafeWebSessions sessions=new SafeWebSessions(root.resolve("legacy-state"));var current=authenticatedFixture(sessions,"a".repeat(64));sessions.registerVerifiedBundle(current.bundle(),current.archiveSha256());var old=sessions.prepare(SafeWebSessions.Mode.PERSISTENT);Files.writeString(old.bundle().resolve("Browser/firefox"),"changed session");assertFalse(Files.exists(sessions.root().resolve("control/minimum-installed-linux-x86_64.txt")));
        var offered=authenticatedFixture(sessions,"b".repeat(64));Files.write(offered.bundle().resolve("Browser/tbb_version.json"),TorBrowserDownloadServiceTest.version("15.0.24","linux-x86_64"));var downgrade=new TorBrowserInstaller.Installed(offered.bundle(),offered.archiveSha256(),offered.fingerprint(),"older fixture","15.0.24","linux-x86_64");assertThrows(IOException.class,()->sessions.registerVerifiedBundle(downgrade));assertEquals("a".repeat(64),sessions.installedFingerprint());
    }

}
