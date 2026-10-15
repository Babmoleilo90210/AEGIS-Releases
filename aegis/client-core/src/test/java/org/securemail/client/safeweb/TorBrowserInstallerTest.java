package org.securemail.client.safeweb;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import org.apache.commons.compress.archivers.tar.*;
import org.tukaani.xz.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Generated TAR fixtures exercise extraction boundaries; they are not a Tor Browser build. */
class TorBrowserInstallerTest {
    @TempDir Path root;
    record Item(String name, byte[] data, byte kind, String link) { }
    private static Item file(String name) { return new Item(name, ("TEST FIXTURE " + name).getBytes(java.nio.charset.StandardCharsets.UTF_8), TarConstants.LF_NORMAL, ""); }
    private static Item link(String name, String target, boolean hard) { return new Item(name, new byte[0], hard ? TarConstants.LF_LINK : TarConstants.LF_SYMLINK, target); }

    private Path archive(Item... additional) throws Exception {
        List<Item> items = new ArrayList<>(List.of(
                file("tor-browser/Browser/firefox"), file("tor-browser/Browser/start-tor-browser"),
                file("tor-browser/Browser/application.ini"), file("tor-browser/Browser/TorBrowser/Tor/tor"),
                file("tor-browser/Browser/TorBrowser/Data/Browser/profile.default/prefs.js")));
        items.addAll(List.of(additional));
        Path output = root.resolve("tor-browser-linux-x86_64-15.0.25.tar.xz");
        try (var file = Files.newOutputStream(output); var xz = new XZOutputStream(file, new LZMA2Options());
             var tar = new TarArchiveOutputStream(xz)) {
            tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
            tar.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);
            for (Item item : items) {
                var entry = new TarArchiveEntry(item.name(), item.kind()); entry.setMode(06755);
                entry.setSize(item.data().length); entry.setLinkName(item.link());
                tar.putArchiveEntry(entry); tar.write(item.data()); tar.closeArchiveEntry();
            }
        }
        return output;
    }

    @Test void extractsBoundedXzTarWithoutChangingFileBytesOrKeepingSetuidBits() throws Exception {
        Path bundle = TorBrowserInstaller.extractLinux(archive(), root.resolve("unpack"));
        assertArrayEquals(file("tor-browser/Browser/firefox").data(), Files.readAllBytes(bundle.resolve("Browser/firefox")));
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(bundle.resolve("Browser/firefox")));
        assertFalse(Files.exists(root.resolve("outside")));
    }

    @Test void supportsPaxLongNamesAndInternalSymlinks() throws Exception {
        String longName = "tor-browser/Browser/" + "x".repeat(180);
        Path bundle = TorBrowserInstaller.extractLinux(archive(file(longName), link("tor-browser/Browser/alias", "firefox", false)), root.resolve("unpack"));
        assertTrue(Files.exists(bundle.resolve("Browser/" + "x".repeat(180))));
        assertEquals(Path.of("firefox"), Files.readSymbolicLink(bundle.resolve("Browser/alias")));
    }

    @Test void supportsInternalDirectorySymlink() throws Exception {
        Path bundle = TorBrowserInstaller.extractLinux(archive(link("tor-browser/Browser/tor-alias", "TorBrowser/Tor", false)), root.resolve("unpack"));
        assertEquals(bundle.resolve("Browser/TorBrowser/Tor").toRealPath(), bundle.resolve("Browser/tor-alias").toRealPath());
    }

    @Test void supportsForwardHardlinkChains() throws Exception {
        Path bundle = TorBrowserInstaller.extractLinux(archive(
                link("tor-browser/Browser/hard-first", "tor-browser/Browser/hard-second", true),
                link("tor-browser/Browser/hard-second", "tor-browser/Browser/firefox", true)), root.resolve("unpack"));
        assertTrue(Files.isSameFile(bundle.resolve("Browser/hard-first"), bundle.resolve("Browser/firefox")));
    }

    @Test void refusesEscapingLinkAndDoesNotWriteOutsideExtraction() throws Exception {
        Path input = archive(link("tor-browser/Browser/link", "../../../outside", false));
        assertThrows(IOException.class, () -> TorBrowserInstaller.extractLinux(input, root.resolve("unpack")));
        assertFalse(Files.exists(root.resolve("outside")));
    }

    @Test void refusesAbsolutePathAndTraversalBeforeOpeningFile() throws Exception {
        for (String name : List.of("../outside", "tor-browser/../../outside", "/tmp/aegis-installer-outside", "C:/outside", "tor-browser/Browser\\outside", "tor-browser/line\nbreak")) {
            Path input = archive(file(name));
            assertThrows(IOException.class, () -> TorBrowserInstaller.extractLinux(input, root.resolve("unpack-" + UUID.randomUUID())));
        }
        assertFalse(Files.exists(root.resolve("outside")));
    }

    @Test void refusesCyclicAndDanglingLinks() throws Exception {
        Path cycle = archive(link("tor-browser/Browser/a", "b", false), link("tor-browser/Browser/b", "a", false));
        assertThrows(IOException.class, () -> TorBrowserInstaller.extractLinux(cycle, root.resolve("cycle")));
        Path dangling = archive(link("tor-browser/Browser/a", "missing", false));
        assertThrows(IOException.class, () -> TorBrowserInstaller.extractLinux(dangling, root.resolve("dangling")));
    }

    @Test void refusesSpecialFilesDuplicateMembersAndMultipleRoots() throws Exception {
        for (Item malicious : List.of(new Item("tor-browser/pipe", new byte[0], TarConstants.LF_FIFO, ""),
                file("tor-browser/Browser/firefox"), file("other-root/file"))) {
            Path input = archive(malicious);
            assertThrows(IOException.class, () -> TorBrowserInstaller.extractLinux(input, root.resolve("bad-" + UUID.randomUUID())));
        }
    }

    @Test void refusesMembersUnderSymlinkEvenWhenTargetIsInternal() throws Exception {
        Path input = archive(link("tor-browser/Browser/a", "TorBrowser", false), file("tor-browser/Browser/a/payload"));
        assertThrows(IOException.class, () -> TorBrowserInstaller.extractLinux(input, root.resolve("unpack")));
    }

    @Test void malformedSignatureRefusedBeforeExtractionAndExistingDataPreserved() throws Exception {
        Path input = archive(); Path asc = Files.writeString(root.resolve("fixture.asc"), "NOT AN OPENPGP SIGNATURE");
        Path destination = root.resolve("new-bundle");
        assertThrows(IOException.class, () -> TorBrowserInstaller.install(input, asc, destination));
        assertFalse(Files.exists(destination));
        assertTrue(Files.list(root).noneMatch(path -> path.getFileName().toString().startsWith(".aegis-tor-import-")));
        Files.createDirectory(destination); Path keep = Files.writeString(destination.resolve("KEEP"), "unchanged");
        assertThrows(IOException.class, () -> TorBrowserInstaller.install(input, asc, destination));
        assertEquals("unchanged", Files.readString(keep));
    }
}
