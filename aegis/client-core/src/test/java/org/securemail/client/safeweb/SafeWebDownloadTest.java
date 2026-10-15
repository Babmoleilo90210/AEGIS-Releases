package org.securemail.client.safeweb;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class SafeWebDownloadTest {
    @TempDir Path root;
    Path downloads, staging;
    @BeforeEach void directories() throws Exception {
        downloads = Files.createDirectory(root.resolve("browser-downloads"));
        staging = Files.createDirectory(root.resolve("messenger-private"));
    }

    @Test void capturesPrivateIndependentCopyAndPreservesOriginalBasename() throws Exception {
        Path original = Files.writeString(downloads.resolve("Отчёт.pdf"), "downloaded contents");
        try (var snapshot = SafeWebDownload.capture(downloads, original, staging)) {
            assertEquals("Отчёт.pdf", snapshot.path().getFileName().toString());
            assertTrue(snapshot.path().startsWith(staging));
            assertFalse(snapshot.path().startsWith(downloads));
            Files.writeString(original, "browser changed original");
            assertEquals("downloaded contents", Files.readString(snapshot.path()));
            if (snapshot.path().getFileSystem().supportedFileAttributeViews().contains("posix")) {
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(snapshot.path()));
                assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(snapshot.path().getParent()));
            }
        }
        assertEquals("browser changed original", Files.readString(original));
    }

    @Test void closeDeletesOnlyOwnSnapshotAndIsIdempotent() throws Exception {
        Path original = Files.writeString(downloads.resolve("file.txt"), "file");
        Path sibling = Files.writeString(staging.resolve("keep.txt"), "keep");
        var snapshot = SafeWebDownload.capture(downloads, original, staging);
        Path own = snapshot.path().getParent();
        snapshot.close(); snapshot.close();
        assertFalse(Files.exists(own));
        assertTrue(Files.isDirectory(staging));
        assertEquals("keep", Files.readString(sibling));
        assertTrue(Files.exists(original));
        assertThrows(IllegalStateException.class, snapshot::path);
    }

    @Test void emptyCompletedDownloadIsHandledWithoutExecution() throws Exception {
        Path empty = Files.createFile(downloads.resolve("empty.bin"));
        try (var snapshot = SafeWebDownload.capture(downloads, empty, staging)) { assertEquals(0, Files.size(snapshot.path())); }
    }

    @Test void rejectsSourceSymlinkWithoutFollowingSecret() throws Exception {
        Path privateFile = Files.writeString(root.resolve("secret.txt"), "private");
        Path link = Files.createSymbolicLink(downloads.resolve("link.txt"), privateFile);
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, link, staging));
        assertEquals("private", Files.readString(privateFile));
        assertStagingEmpty();
    }

    @Test void rejectsSymlinkInDownloadAncestors() throws Exception {
        Path original = Files.writeString(downloads.resolve("file.txt"), "file");
        Path alias = Files.createSymbolicLink(root.resolve("browser-alias"), downloads);
        assertThrows(IOException.class, () -> SafeWebDownload.capture(alias, alias.resolve(original.getFileName()), staging));
        assertStagingEmpty();
    }

    @Test void rejectsOutsideAndNestedSelections() throws Exception {
        Path outside = Files.writeString(root.resolve("outside.txt"), "outside");
        Path nested = Files.createDirectories(downloads.resolve("nested")).resolve("nested.txt");
        Files.writeString(nested, "nested");
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, outside, staging));
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, nested, staging));
        assertStagingEmpty();
    }

    @Test void rejectsSourceDirectoriesAndHardLinks() throws Exception {
        Path directory = Files.createDirectory(downloads.resolve("directory"));
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, directory, staging));
        Path privateFile = Files.writeString(root.resolve("secret.txt"), "private");
        Path hardLink = Files.createLink(downloads.resolve("hardlink.txt"), privateFile);
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, hardLink, staging));
        assertStagingEmpty();
    }

    @Test void stagingMustBeDisjointAndCannotUseParentSymlinks() throws Exception {
        Path original = Files.writeString(downloads.resolve("file.txt"), "file");
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, original, downloads.resolve("private")));
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, original, root));
        Path alias = Files.createSymbolicLink(root.resolve("staging-alias"), staging);
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, original, alias));
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, original, alias.resolve("nested")));
        assertStagingEmpty();
    }

    @Test void rejectsOversizedFileBeforeCopyingAndCleansNothingUnrelated() throws Exception {
        Path huge = downloads.resolve("huge.bin");
        try (var file = new RandomAccessFile(huge.toFile(), "rw")) { file.setLength(SafeWebDownload.MAX_BYTES + 1); }
        assertThrows(IOException.class, () -> SafeWebDownload.capture(downloads, huge, staging));
        assertStagingEmpty();
    }

    @Test void detectsActualMutationDuringStreamingAndRemovesPartialSnapshot() throws Exception {
        byte[] bytes = new byte[160_000]; Arrays.fill(bytes, (byte)'A');
        Path original = Files.write(downloads.resolve("mutating.bin"), bytes);
        var mutate = new AtomicBoolean();
        assertThrows(IOException.class, () -> SafeWebDownload.captureObserved(downloads, original, staging, copied -> {
            if (mutate.compareAndSet(false, true)) Files.writeString(original, "changed by browser", StandardOpenOption.TRUNCATE_EXISTING);
        }));
        assertTrue(mutate.get());
        assertStagingEmpty();
    }

    @Test void detectsReplacedFilenameDuringStreamingAndRemovesPartialSnapshot() throws Exception {
        byte[] bytes = new byte[160_000]; Arrays.fill(bytes, (byte)'A');
        Path original = Files.write(downloads.resolve("replaced.bin"), bytes);
        var replace = new AtomicBoolean();
        assertThrows(IOException.class, () -> SafeWebDownload.captureObserved(downloads, original, staging, copied -> {
            if (replace.compareAndSet(false, true)) {
                Files.move(original, downloads.resolve("old.bin"));
                Files.write(original, bytes);
            }
        }));
        assertTrue(replace.get());
        assertStagingEmpty();
    }

    @Test void heldDirectoryPreventsParentSymlinkSwapFromReadingOutsideDownload() throws Exception {
        byte[] bytes = new byte[160_000]; Arrays.fill(bytes, (byte)'A');
        Path original = Files.write(downloads.resolve("file.bin"), bytes);
        Path secrets = Files.createDirectory(root.resolve("secrets"));
        Files.writeString(secrets.resolve("file.bin"), "secret");
        var replace = new AtomicBoolean();
        assertThrows(IOException.class, () -> SafeWebDownload.captureObserved(downloads, original, staging, copied -> {
            if (replace.compareAndSet(false, true)) {
                Files.move(downloads, root.resolve("moved-downloads"));
                Files.createSymbolicLink(downloads, secrets);
            }
        }));
        assertEquals("secret", Files.readString(secrets.resolve("file.bin")));
        assertStagingEmpty();
    }

    @Test void closeRefusesReplacedDirectoryInsteadOfDeletingAnotherTree() throws Exception {
        Path original = Files.writeString(downloads.resolve("file.txt"), "file");
        var snapshot = SafeWebDownload.capture(downloads, original, staging);
        Path old = snapshot.path().getParent(), moved = staging.resolve("original-snapshot");
        Files.move(old, moved);
        Files.createDirectory(old);
        Path unrelated = Files.writeString(old.resolve("keep.txt"), "keep");
        assertThrows(IOException.class, snapshot::close);
        assertEquals("keep", Files.readString(unrelated));
        assertEquals("file", Files.readString(moved.resolve("file.txt")));
    }

    @Test void closeUnlinksSubstitutedSymlinkAndPreservesItsTarget() throws Exception {
        Path original = Files.writeString(downloads.resolve("file.txt"), "file");
        var snapshot = SafeWebDownload.capture(downloads, original, staging);
        Path file = snapshot.path(), target = Files.writeString(root.resolve("keep.txt"), "keep");
        Files.delete(file);
        Files.createSymbolicLink(file, target);
        snapshot.close();
        assertEquals("keep", Files.readString(target));
        assertStagingEmpty();
    }

    private void assertStagingEmpty() throws IOException {
        try (var children = Files.list(staging)) { assertEquals(0, children.count()); }
    }
}
