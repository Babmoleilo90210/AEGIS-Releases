package org.securemail.client.safeweb;

import org.securemail.client.storage.AtomicFiles;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

/** Explicit browser-download handoff into a private, bounded plaintext snapshot.
 * The staging root must be inside the messenger's private storage and outside every
 * browser-visible filesystem mount. This API never sends a path or key to the browser.
 * Callers must close the snapshot after the existing archive encryption import completes.
 */
public final class SafeWebDownload {
    public static final long MAX_BYTES = 1024L * 1024 * 1024;
    private SafeWebDownload() { }

    /** Keep runtime-directory ancestors pinned while a sandbox can modify its mapped tree.
     * Package-private lifecycle guard for the native Safe Web wrapper; creates/deletes nothing. */
    static java.io.Closeable guardDirectory(Path directory) throws IOException {
        DirectoryAccess access = DirectoryAccess.openDirectory(absolute(directory));
        return access::close;
    }

    public static Snapshot capture(Path downloadsDirectory, Path selected, Path privateStagingRoot) throws IOException {
        return captureObserved(downloadsDirectory, selected, privateStagingRoot, bytes -> { });
    }

    @FunctionalInterface interface CopyObserver { void copied(long bytes) throws IOException; }

    // Deterministic mutation tests; no production runtime switches or global hooks.
    static Snapshot captureObserved(Path downloadsDirectory, Path selected, Path privateStagingRoot,
                                    CopyObserver observer) throws IOException {
        Path downloads = absolute(downloadsDirectory), source = absolute(selected), staging = absolute(privateStagingRoot);
        if (!downloads.equals(source.getParent())) throw failure("Выберите файл непосредственно из каталога загрузок Safe Web");
        if (staging.startsWith(downloads) || downloads.startsWith(staging))
            throw failure("Каталог импорта должен быть отделён от загрузок браузера");
        Path name = source.getFileName();
        if (name == null || name.toString().isBlank() || name.toString().chars().anyMatch(c -> c < 32 || c == 127)
                || name.toString().contains(":") || name.toString().contains("\\"))
            throw failure("Недопустимое имя загруженного файла");
        rejectParentLinks(staging);
        AtomicFiles.directory(staging);
        rejectParentLinks(staging);
        Snapshot snapshot = null;
        try (DirectoryAccess access = DirectoryAccess.openDirectory(downloads)) {
            BasicFileAttributes before = regular(access.attributes(name));
            rejectHardLinks(source);
            BasicFileAttributes directoryBefore = access.directoryAttributes();
            // A held directory handle resolves the basename, rather than following a mutable
            // browser-controlled parent pathname. NOFOLLOW is also applied to the final file.
            try (FileChannel input = access.open(name)) {
                if (input.size() != before.size()) throw failure("Загрузка изменилась перед импортом");
                Path ownDirectory = createPrivateDirectory(staging);
                snapshot = new Snapshot(ownDirectory, ownDirectory.resolve(name));
                try (FileChannel output = FileChannel.open(snapshot.path(),
                        Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW, LinkOption.NOFOLLOW_LINKS),
                        AtomicFiles.attributes(ownDirectory))) {
                    ByteBuffer buffer = ByteBuffer.allocate(64 * 1024);
                    long copied = 0;
                    while (input.read(buffer) != -1) {
                        buffer.flip();
                        int count = buffer.remaining();
                        copied += count;
                        if (copied > MAX_BYTES || copied > before.size()) throw failure("Загрузка превышает лимит или изменилась");
                        while (buffer.hasRemaining()) output.write(buffer);
                        buffer.clear();
                        observer.copied(copied);
                    }
                    BasicFileAttributes after = regular(access.attributes(name));
                    rejectHardLinks(source);
                    if (copied != before.size() || input.size() != before.size() || !sameFile(before, after)
                            || !sameIdentity(directoryBefore, access.directoryAttributes()))
                        throw failure("Загрузка изменилась во время импорта. Повторите выбор файла");
                    output.force(true);
                }
                // The source name must still identify the same held directory, not a new path
                // planted after a rename. A copy from an unlinked directory is also refused.
                rejectParentLinks(downloads);
                BasicFileAttributes namedDirectory = Files.readAttributes(downloads, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!sameIdentity(directoryBefore, namedDirectory)) throw failure("Каталог загрузок изменился во время импорта");
                return snapshot;
            }
        } catch (IOException | RuntimeException failure) {
            if (snapshot != null) try { snapshot.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    public static final class Snapshot implements AutoCloseable {
        private final Path directory, file;
        private final BasicFileAttributes identity;
        private boolean closed;

        private Snapshot(Path directory, Path file) throws IOException {
            this.directory = directory;
            this.file = file;
            identity = Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        }

        /** Preserve the downloaded basename for the existing encrypted archive import API. */
        public synchronized Path path() {
            if (closed) throw new IllegalStateException("Снимок загрузки уже очищен");
            return file;
        }

        /** Removes only this snapshot; never walks recursively or deletes a caller-owned root. */
        @Override public synchronized void close() throws IOException {
            if (closed) return;
            rejectParentLinks(directory.getParent());
            if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) { closed = true; return; }
            BasicFileAttributes current = Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!current.isDirectory() || current.isSymbolicLink() || !sameIdentity(identity, current))
                throw failure("Каталог снимка заменён; автоматическая очистка остановлена");
            // delete() unlinks a substituted symlink without touching its target. An unexpected
            // directory or extra entries cause failure instead of recursive deletion.
            if (Files.isDirectory(file, LinkOption.NOFOLLOW_LINKS))
                throw failure("Файл снимка заменён каталогом; автоматическая очистка остановлена");
            Files.deleteIfExists(file);
            Files.delete(directory);
            closed = true;
        }
    }

    private interface DirectoryAccess extends AutoCloseable {
        FileChannel open(Path name) throws IOException;
        BasicFileAttributes attributes(Path name) throws IOException;
        BasicFileAttributes directoryAttributes() throws IOException;
        @Override void close() throws IOException;

        static DirectoryAccess openDirectory(Path directory) throws IOException {
            if (System.getProperty("os.name").startsWith("Windows")) return new WindowsDirectory(directory);
            return new SecureDirectory(directory);
        }
    }

    /** Descriptor-relative path walk from the filesystem root: no parent symlink traversal. */
    private static final class SecureDirectory implements DirectoryAccess {
        private final List<SecureDirectoryStream<Path>> held = new ArrayList<>();
        private final SecureDirectoryStream<Path> directory;

        @SuppressWarnings("unchecked")
        SecureDirectory(Path path) throws IOException {
            try {
                DirectoryStream<Path> root = Files.newDirectoryStream(path.getRoot());
                if (!(root instanceof SecureDirectoryStream<?>)) {
                    root.close();
                    throw failure("Файловая система не предоставляет безопасный доступ к загрузкам");
                }
                SecureDirectoryStream<Path> current = (SecureDirectoryStream<Path>) root;
                held.add(current);
                for (Path component : path) {
                    current = current.newDirectoryStream(component, LinkOption.NOFOLLOW_LINKS);
                    held.add(current);
                }
                directory = current;
            } catch (IOException | RuntimeException failure) {
                try { close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
                throw failure;
            }
        }

        public FileChannel open(Path name) throws IOException {
            SeekableByteChannel channel = directory.newByteChannel(name, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
            if (channel instanceof FileChannel file) return file;
            channel.close();
            throw failure("Файловая система не предоставляет безопасный файловый канал");
        }
        public BasicFileAttributes attributes(Path name) throws IOException {
            return directory.getFileAttributeView(name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
        }
        public BasicFileAttributes directoryAttributes() throws IOException {
            return directory.getFileAttributeView(BasicFileAttributeView.class).readAttributes();
        }
        public void close() throws IOException {
            IOException failure = null;
            for (int i = held.size() - 1; i >= 0; i--) try { held.get(i).close(); } catch (IOException error) { failure = error; }
            held.clear();
            if (failure != null) throw failure;
        }
    }

    /** Existing JNA dependency; loaded only on Windows. Ancestors are held without SHARE_DELETE
     * so they cannot be renamed/replaced while the final Java FileChannel is opened/copied. */
    private static final class WindowsDirectory implements DirectoryAccess {
        private final List<com.sun.jna.platform.win32.WinNT.HANDLE> held = new ArrayList<>();
        private final Path directory;
        WindowsDirectory(Path path) throws IOException {
            directory = path;
            if (path.getRoot() == null || !path.getRoot().toString().matches("[A-Za-z]:\\\\"))
                throw failure("Загрузки Safe Web требуют локальный диск Windows");
            try {
                Path cursor = path.getRoot();
                hold(cursor);
                for (Path component : path) { cursor = cursor.resolve(component); hold(cursor); }
            } catch (IOException | RuntimeException failure) {
                try { close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
                throw failure;
            }
        }
        private void hold(Path path) throws IOException {
            var api = com.sun.jna.platform.win32.Kernel32.INSTANCE;
            var handle = api.CreateFile(path.toString(), com.sun.jna.platform.win32.WinNT.FILE_READ_ATTRIBUTES,
                    com.sun.jna.platform.win32.WinNT.FILE_SHARE_READ | com.sun.jna.platform.win32.WinNT.FILE_SHARE_WRITE,
                    null, com.sun.jna.platform.win32.WinNT.OPEN_EXISTING,
                    com.sun.jna.platform.win32.WinNT.FILE_FLAG_BACKUP_SEMANTICS
                            | com.sun.jna.platform.win32.WinNT.FILE_FLAG_OPEN_REPARSE_POINT, null);
            if (com.sun.jna.platform.win32.WinBase.INVALID_HANDLE_VALUE.equals(handle))
                throw failure("Не удалось закрепить каталог загрузок Windows");
            held.add(handle);
            var info = new com.sun.jna.platform.win32.WinBase.FILE_ATTRIBUTE_TAG_INFO();
            if (!api.GetFileInformationByHandleEx(handle, com.sun.jna.platform.win32.WinBase.FileAttributeTagInfo,
                    info.getPointer(), new com.sun.jna.platform.win32.WinDef.DWORD(info.size())))
                throw failure("Не удалось проверить каталог загрузок Windows");
            info.read();
            if ((info.FileAttributes & com.sun.jna.platform.win32.WinNT.FILE_ATTRIBUTE_REPARSE_POINT) != 0
                    || (info.FileAttributes & com.sun.jna.platform.win32.WinNT.FILE_ATTRIBUTE_DIRECTORY) == 0)
                throw failure("Ссылки и reparse points в пути загрузок запрещены");
        }
        public FileChannel open(Path name) throws IOException {
            Path file = directory.resolve(name);
            var api = com.sun.jna.platform.win32.Kernel32.INSTANCE;
            // Deny both writes and renames/deletes until the Java copy is closed.
            var handle = api.CreateFile(file.toString(), com.sun.jna.platform.win32.WinNT.FILE_READ_ATTRIBUTES,
                    com.sun.jna.platform.win32.WinNT.FILE_SHARE_READ, null,
                    com.sun.jna.platform.win32.WinNT.OPEN_EXISTING,
                    com.sun.jna.platform.win32.WinNT.FILE_FLAG_OPEN_REPARSE_POINT, null);
            if (com.sun.jna.platform.win32.WinBase.INVALID_HANDLE_VALUE.equals(handle))
                throw failure("Загрузка ещё используется или не может быть безопасно открыта");
            held.add(handle);
            var tag = new com.sun.jna.platform.win32.WinBase.FILE_ATTRIBUTE_TAG_INFO();
            // FILE_STANDARD_INFO has two 8-byte LARGE_INTEGERs, DWORD link count and
            // two one-byte BOOLEANs (not the four-byte BOOL used by Java booleans).
            try (var standard = new com.sun.jna.Memory(24)) {
                standard.clear();
                if (!api.GetFileInformationByHandleEx(handle, com.sun.jna.platform.win32.WinBase.FileAttributeTagInfo,
                        tag.getPointer(), new com.sun.jna.platform.win32.WinDef.DWORD(tag.size()))
                        || !api.GetFileInformationByHandleEx(handle, com.sun.jna.platform.win32.WinBase.FileStandardInfo,
                        standard, new com.sun.jna.platform.win32.WinDef.DWORD(24)))
                    throw failure("Не удалось проверить файл загрузки Windows");
                tag.read();
                if ((tag.FileAttributes & com.sun.jna.platform.win32.WinNT.FILE_ATTRIBUTE_REPARSE_POINT) != 0
                        || standard.getByte(21) != 0 || standard.getByte(20) != 0 || standard.getInt(16) != 1
                        || standard.getLong(8) < 0 || standard.getLong(8) > MAX_BYTES)
                    throw failure("Ссылки, особые и слишком большие загрузки запрещены");
            }
            return FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        }
        public BasicFileAttributes attributes(Path name) throws IOException {
            return Files.readAttributes(directory.resolve(name), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        }
        public BasicFileAttributes directoryAttributes() throws IOException {
            return Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        }
        public void close() throws IOException {
            boolean failed = false;
            for (int i = held.size() - 1; i >= 0; i--) failed |= !com.sun.jna.platform.win32.Kernel32.INSTANCE.CloseHandle(held.get(i));
            held.clear();
            if (failed) throw failure("Не удалось закрыть дескриптор каталога Windows");
        }
    }

    private static Path createPrivateDirectory(Path root) throws IOException {
        Path own;
        if (Files.getFileStore(root).supportsFileAttributeView("posix"))
            own = Files.createTempDirectory(root, "download-import-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        else {
            own = Files.createTempDirectory(root, "download-import-");
            try { AtomicFiles.directory(own); } catch (IOException error) { Files.deleteIfExists(own); throw error; }
        }
        return own;
    }
    private static BasicFileAttributes regular(BasicFileAttributes attributes) throws IOException {
        if (!attributes.isRegularFile() || attributes.isSymbolicLink() || attributes.size() < 0 || attributes.size() > MAX_BYTES)
            throw failure("Выберите обычную загрузку размером не более 1 ГБ");
        return attributes;
    }
    private static void rejectHardLinks(Path file) throws IOException {
        // Capability lookup does not resolve a browser-controlled pathname.
        if (file.getFileSystem().supportedFileAttributeViews().contains("unix")) {
            Object links = Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
            if (!(links instanceof Number count) || count.longValue() != 1)
                throw failure("Жёсткие ссылки не принимаются в качестве загрузок");
        }
    }
    private static boolean sameFile(BasicFileAttributes a, BasicFileAttributes b) {
        return sameIdentity(a, b) && a.size() == b.size() && a.lastModifiedTime().equals(b.lastModifiedTime());
    }
    private static boolean sameIdentity(BasicFileAttributes a, BasicFileAttributes b) {
        return a.fileKey() != null && b.fileKey() != null ? a.fileKey().equals(b.fileKey()) : a.creationTime().equals(b.creationTime());
    }
    private static Path absolute(Path path) { return Objects.requireNonNull(path).toAbsolutePath().normalize(); }
    private static void rejectParentLinks(Path path) throws IOException {
        for (Path current = path; current != null; current = current.getParent())
            if (Files.isSymbolicLink(current)) throw failure("Ссылки в пути импорта запрещены");
    }
    private static IOException failure(String message) { return new IOException(message); }
}
