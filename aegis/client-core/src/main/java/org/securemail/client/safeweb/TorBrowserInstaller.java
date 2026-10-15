package org.securemail.client.safeweb;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.regex.Pattern;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarConstants;
import org.tukaani.xz.XZInputStream;

/** Offline authenticated import of official Tor Browser, without Python or GnuPG.
 * This installs a dedicated bundle; process/network containment is the caller's job.
 * No AEGIS identity, profile, archive, credential or release key is read here.
 */
public final class TorBrowserInstaller {
    private TorBrowserInstaller() { }
    public record Installed(Path bundle, String archiveSha256, String fingerprint, String label) { }
    private record Member(String name, boolean directory, boolean symbolic, boolean hard, String target) { }
    private static final long MAX_PACKAGE = 1_000_000_000L;
    private static final long MAX_EXPANDED = 3_000_000_000L;
    private static final int MAX_ENTRIES = 20_000;
    private static final Pattern PACKAGE = Pattern.compile("tor-browser-(linux-x86_64|windows-x86_64-portable)-([0-9]+(?:\\.[0-9]+){1,3})\\.(tar\\.xz|exe)");

    public static Installed install(Path archive, Path signature, Path destination) throws IOException {
        return install(archive, signature, destination, null);
    }

    /** Optional public key input is still checked against the fixed Tor Developers pin. */
    public static Installed install(Path archive, Path signature, Path destination, InputStream publicKey) throws IOException {
        Objects.requireNonNull(archive); Objects.requireNonNull(signature); Objects.requireNonNull(destination);
        Path target = destination.toAbsolutePath().normalize();
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Каталог Tor Browser уже существует; его данные не будут перезаписаны");
        Path parent = target.getParent();
        if (parent == null) throw new IOException("Нужен отдельный каталог Tor Browser");
        Files.createDirectories(parent);
        rejectLinkAncestors(parent);
        Path scratch = Files.createTempDirectory(parent, ".aegis-tor-import-"); privateDirectory(scratch);
        boolean destinationCreated = false;
        try {
            Path packageCopy = scratch.resolve("official-package.bin"), signatureCopy = scratch.resolve("official-package.asc");
            snapshot(archive, packageCopy, MAX_PACKAGE); snapshot(signature, signatureCopy, 100_000);
            // Authentication happens before archive parsing, decompression or executing an EXE.
            var verified = publicKey == null ? TorBrowserSignature.verify(packageCopy, signatureCopy)
                    : TorBrowserSignature.verify(packageCopy, signatureCopy, publicKey);
            var match = PACKAGE.matcher(archive.getFileName().toString());
            if (!match.matches()) throw new IOException("Нужен официальный стабильный Tor Browser Linux x86_64 или Windows portable x86_64");
            boolean windows = match.group(1).startsWith("windows");
            if ((windows && !match.group(3).equals("exe")) || (!windows && !match.group(3).equals("tar.xz")))
                throw new IOException("Расширение пакета Tor Browser не соответствует платформе");
            Path bundle;
            if (windows) {
                if (!System.getProperty("os.name", "").startsWith("Windows"))
                    throw new IOException("Установка официального portable EXE требует Windows; файл проверен, но не запущен");
                Path executable = scratch.resolve("tor-browser-portable.exe");
                Files.move(packageCopy, executable);
                bundle = scratch.resolve("windows-bundle");
                installWindows(executable, bundle);
            } else {
                if (!System.getProperty("os.name", "").equals("Linux"))
                    throw new IOException("Установка Linux Tor Browser требует Linux");
                bundle = extractLinux(packageCopy, scratch.resolve("unpack"));
            }
            validateLayout(bundle, windows);
            // Exclusive creation prevents overwriting an existing browser/profile, even after a race.
            Files.createDirectory(target); destinationCreated = true; privateDirectory(target);
            copyBundle(bundle, target);
            validateLayout(target, windows);
            // Detached signatures authenticate bytes, not the caller-supplied filename.
            // Never promote a renamed package label into an authenticated browser version.
            return new Installed(target, verified.sha256(), verified.primaryFingerprint(), "Пакет " + archive.getFileName());
        } catch (IOException | RuntimeException failure) {
            if (destinationCreated) deleteTree(target);
            throw failure;
        } finally {
            deleteTree(scratch);
        }
    }

    private static void snapshot(Path source, Path copy, long maximum) throws IOException {
        if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(source))
            throw new IOException("Нужен обычный файл пакета/подписи");
        long size = Files.size(source);
        if (size <= 0 || size > maximum) throw new IOException("Неверный размер пакета/подписи");
        try (InputStream in = Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS);
             OutputStream out = Files.newOutputStream(copy, StandardOpenOption.CREATE_NEW)) {
            byte[] buffer = new byte[65536]; long count = 0;
            for (int read; (read = in.read(buffer)) != -1;) {
                count += read; if (count > maximum) throw new IOException("Превышен размер пакета/подписи");
                out.write(buffer, 0, read);
            }
        }
        privateFile(copy, false);
    }

    /** Commons Compress handles USTAR, PAX and GNU long names; no shell/tar parser. */
    static Path extractLinux(Path archive, Path output) throws IOException {
        Files.createDirectory(output); privateDirectory(output);
        Map<String, Member> members = new LinkedHashMap<>(); Set<String> roots = new HashSet<>();
        long expanded = 0;
        // Bound XZ dictionary memory to 128 MiB and total uncompressed stream to 3 GiB.
        try (InputStream file = Files.newInputStream(archive);
             InputStream xz = new XZInputStream(file, 131072);
             InputStream bounded = new LimitedInput(xz, MAX_EXPANDED);
             TarArchiveInputStream tar = new TarArchiveInputStream(bounded)) {
            for (TarArchiveEntry entry; (entry = tar.getNextEntry()) != null;) {
                String name = safeName(entry.getName());
                boolean symbolic = entry.isSymbolicLink(), hard = entry.isLink(), directory = entry.isDirectory();
                boolean regular = entry.getLinkFlag() == TarConstants.LF_NORMAL || entry.getLinkFlag() == TarConstants.LF_OLDNORM;
                if (!(regular || directory || symbolic || hard) || entry.isSparse())
                    throw new IOException("Неподдерживаемый тип записи Tor Browser");
                if (entry.getSize() < 0 || entry.getSize() > MAX_EXPANDED - expanded || members.size() >= MAX_ENTRIES)
                    throw new IOException("Распакованный Tor Browser превышает лимиты");
                expanded += entry.getSize();
                Member member = new Member(name, directory, symbolic, hard, (symbolic || hard) ? entry.getLinkName() : "");
                if (members.putIfAbsent(name, member) != null) throw new IOException("Повтор пути в архиве Tor Browser");
                roots.add(name.split("/", 2)[0]);
                Path path = output.resolve(name);
                // Links are never created until ALL regular data has been extracted/checked.
                if (symbolic || hard) continue;
                Files.createDirectories(path.getParent());
                if (directory) { Files.createDirectories(path); privateDirectory(path); }
                else {
                    try (OutputStream stream = Files.newOutputStream(path, StandardOpenOption.CREATE_NEW)) {
                        byte[] buffer = new byte[65536]; long written = 0;
                        for (int read; (read = tar.read(buffer)) != -1;) {
                            if ((written += read) > entry.getSize()) throw new IOException("Неверный размер записи Tor Browser");
                            stream.write(buffer, 0, read);
                        }
                        if (written != entry.getSize()) throw new IOException("Обрезанная запись Tor Browser");
                    }
                    privateFile(path, (entry.getMode() & 0111) != 0);
                }
            }
        }
        if (roots.size() != 1) throw new IOException("Нужен единый корневой каталог официального Tor Browser");
        for (Member member : members.values()) {
            Path parent = Path.of(member.name()).getParent();
            while (parent != null) {
                Member ancestor = members.get(parent.toString().replace('\\', '/'));
                if (ancestor != null && !ancestor.directory()) throw new IOException("Запись внутри ссылки/файла архива");
                parent = parent.getParent();
            }
            if (member.symbolic() || member.hard()) resolveLink(member, members);
        }
        for (Member member : members.values()) if (member.hard()) {
            String resolved = resolveLink(member, members);
            Member target = members.get(resolved);
            if (target == null || target.directory()) throw new IOException("Hardlink должен указывать на обычный файл");
            Path path = output.resolve(member.name()); Files.createDirectories(path.getParent());
            Files.createLink(path, output.resolve(resolved));
        }
        for (Member member : members.values()) if (member.symbolic()) {
            Path path = output.resolve(member.name()); Files.createDirectories(path.getParent());
            Files.createSymbolicLink(path, Path.of(member.target()));
        }
        Path bundle = output.resolve(roots.iterator().next()); validateLayout(bundle, false); return bundle;
    }

    private static String safeName(String raw) throws IOException {
        if (raw == null || raw.isEmpty() || raw.startsWith("/") || raw.contains("\\") || raw.contains(":"))
            throw new IOException("Небезопасный путь архива");
        for (char value : raw.toCharArray()) if (value < 32 || value == 127) throw new IOException("Управляющий символ в пути архива");
        for (String part : raw.split("/")) if (part.equals("..")) throw new IOException("Выход из каталога архива");
        String result = Path.of(raw).normalize().toString().replace('\\', '/');
        if (result.isEmpty() || result.equals(".")) throw new IOException("Пустой путь архива");
        return result;
    }

    private static String resolveLink(Member start, Map<String, Member> members) throws IOException {
        Set<String> seen = new HashSet<>(); Member current = start;
        String root = start.name().split("/", 2)[0];
        while (current.symbolic() || current.hard()) {
            if (!seen.add(current.name())) throw new IOException("Циклическая ссылка архива");
            String link = current.target();
            if (link == null || link.isEmpty() || link.startsWith("/") || link.contains("\\") || link.contains(":"))
                throw new IOException("Небезопасная ссылка архива");
            for (char value : link.toCharArray()) if (value < 32 || value == 127) throw new IOException("Управляющий символ в ссылке архива");
            Path linkParent = Path.of(current.name()).getParent();
            if (linkParent == null && !current.hard()) throw new IOException("Корневой каталог архива не может быть ссылкой");
            Path path = current.hard() ? Path.of(link).normalize() : linkParent.resolve(link).normalize();
            String name = path.toString().replace('\\', '/');
            if (!(name.equals(root) || name.startsWith(root + "/"))) throw new IOException("Ссылка выходит из каталога Tor Browser");
            Member next = members.get(name);
            if (next == null) {
                if (!start.hard() && members.keySet().stream().anyMatch(key -> key.startsWith(name + "/"))) return name;
                throw new IOException("Ссылка на отсутствующую запись архива");
            }
            current = next;
        }
        return current.name();
    }

    private static void installWindows(Path executable, Path destination) throws IOException {
        String path = destination.toAbsolutePath().toString();
        if (path.indexOf('"') >= 0 || path.chars().anyMatch(value -> value < 32)) throw new IOException("Небезопасный каталог Windows");
        // NSIS requires its final /D= argument unquoted, including directory spaces.
        // CreateProcessW avoids ProcessBuilder's automatic argument quoting. No shell,
        // inherited handles or account secrets are passed to the authenticated installer.
        WindowsPortable.install(executable, destination);
    }

    private static final class WindowsPortable {
        static void install(Path executable, Path destination) throws IOException {
            var kernel = com.sun.jna.platform.win32.Kernel32.INSTANCE;
            var startup = new com.sun.jna.platform.win32.WinBase.STARTUPINFO();
            startup.cb = new com.sun.jna.platform.win32.WinDef.DWORD(startup.size());
            var process = new com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION();
            String exe = executable.toAbsolutePath().toString();
            String command = "\"" + exe + "\" /S /D=" + destination.toAbsolutePath();
            char[] mutable = com.sun.jna.Native.toCharArray(command);
            if (!kernel.CreateProcessW(exe, mutable, null, null, false,
                    new com.sun.jna.platform.win32.WinDef.DWORD(0x08000000), null,
                    executable.getParent().toString(), startup, process))
                throw new IOException("Не удалось запустить официальный installer Tor Browser: " + kernel.GetLastError());
            try {
                int result = kernel.WaitForSingleObject(process.hProcess, 600000);
                if (result != 0) {
                    kernel.TerminateProcess(process.hProcess, 1);
                    kernel.WaitForSingleObject(process.hProcess, 5000);
                    throw new IOException("Официальный installer Tor Browser не завершился вовремя");
                }
                var status = new com.sun.jna.ptr.IntByReference();
                if (!kernel.GetExitCodeProcess(process.hProcess, status) || status.getValue() != 0)
                    throw new IOException("Официальный installer Tor Browser завершился с ошибкой");
            } finally {
                kernel.CloseHandle(process.hThread); kernel.CloseHandle(process.hProcess);
            }
        }
    }

    private static void validateLayout(Path bundle, boolean windows) throws IOException {
        for (String required : windows
                ? List.of("Browser/firefox.exe", "Browser/application.ini", "Browser/TorBrowser/Tor/tor.exe")
                : List.of("Browser/firefox", "Browser/start-tor-browser", "Browser/application.ini", "Browser/TorBrowser/Tor/tor")) {
            Path file = bundle.resolve(required);
            if (!Files.isRegularFile(file) || !file.toRealPath().startsWith(bundle.toRealPath()))
                throw new IOException("Не найден обязательный компонент официального Tor Browser: " + required);
        }
    }

    private static void copyBundle(Path source, Path target) throws IOException {
        try (var paths = Files.walk(source)) {
            for (Path file : paths.toList()) {
                if (file.equals(source)) continue;
                Path out = target.resolve(source.relativize(file));
                if (Files.isSymbolicLink(file)) Files.createSymbolicLink(out, Files.readSymbolicLink(file));
                else if (Files.isDirectory(file, LinkOption.NOFOLLOW_LINKS)) { Files.createDirectories(out); privateDirectory(out); }
                else { Files.copy(file, out, LinkOption.NOFOLLOW_LINKS); privateFile(out, Files.isExecutable(file)); }
            }
        }
    }

    private static void rejectLinkAncestors(Path path) throws IOException {
        for (Path current = path; current != null; current = current.getParent())
            if (Files.isSymbolicLink(current)) throw new IOException("Ссылка в каталоге установки Tor Browser");
    }
    private static void privateDirectory(Path path) throws IOException {
        if (path.getFileSystem().supportedFileAttributeViews().contains("posix"))
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
    }
    private static void privateFile(Path path, boolean executable) throws IOException {
        if (path.getFileSystem().supportedFileAttributeViews().contains("posix"))
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(executable ? "rwx------" : "rw-------"));
    }
    private static void deleteTree(Path path) throws IOException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return;
        try (var paths = Files.walk(path)) {
            for (Path entry : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(entry);
        }
    }
    private static final class LimitedInput extends FilterInputStream {
        private long left;
        LimitedInput(InputStream input, long limit) { super(input); left = limit; }
        private void count(long read) throws IOException { if (read > 0 && (left -= read) < 0) throw new IOException("Превышен лимит распаковки Tor Browser"); }
        @Override public int read() throws IOException { int value = in.read(); count(value < 0 ? 0 : 1); return value; }
        @Override public int read(byte[] buffer, int offset, int length) throws IOException { int read = in.read(buffer, offset, (int) Math.min(length, Math.max(1, left + 1))); count(read); return read; }
        @Override public long skip(long amount) throws IOException { long skipped = in.skip(Math.min(amount, Math.max(1, left + 1))); count(skipped); return skipped; }
    }
}
