package org.securemail.client.voice;

import com.google.gson.JsonParser;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/** Compiled-in digest trust, never a checksum sidecar next to a writable DLL. */
final class GlasAudioLibraries {
    private static final int MAX_LIBRARY_BYTES = 16 * 1024 * 1024;
    private static final Map<String, Loaded<?>> LOADED = new HashMap<>();
    private record Loaded<T>(T api, AutoCloseable guard) {}
    static synchronized <T extends Library> T load(String home, String filename, Class<T> api) throws IOException {
        String platform = platform();
        Path file = Path.of(home, "native", filename).toAbsolutePath().normalize();
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Не найдена комплектная аудиобиблиотека: " + filename);
        AutoCloseable guard = null;
        try {
            if (platform.startsWith("windows")) guard = new WindowsGuard(file);
            byte[] bytes = verified(file, filename, platform);
            String key = platform + '/' + filename;
            Loaded<?> existing = LOADED.get(key);
            if (existing != null) { Arrays.fill(bytes, (byte) 0); if (guard != null) guard.close(); return api.cast(existing.api); }
            String loadPath = file.toString();
            if (platform.startsWith("linux")) {
                LinuxImage image = new LinuxImage(bytes); guard = image; loadPath = image.path();
            }
            Arrays.fill(bytes, (byte) 0);
            T loaded = platform.startsWith("windows")
                    ? Native.load(loadPath, api, Map.of(Library.OPTION_OPEN_FLAGS, 0x800)) // dependency lookup: SYSTEM32 only
                    : Native.load(loadPath, api);
            // Two immutable mappings and their guards live for this JVM. Never recycle a memfd
            // pathname while dlopen/JNA can cache it, and never release Windows rename guards.
            LOADED.put(key, new Loaded<>(loaded, guard)); guard = null;
            return loaded;
        } catch (IOException e) { throw e; }
        catch (Exception | LinkageError e) { throw new IOException("Не удалось проверить или загрузить аудиобиблиотеку", e); }
        finally { if (guard != null) try { guard.close(); } catch (Exception ignored) {} }
    }
    static byte[] verified(Path file, String filename, String platform) throws IOException {
        String expected;
        try (var input = GlasAudioLibraries.class.getResourceAsStream("/org/securemail/client/voice/voice-runtime.json")) {
            if (input == null) throw new IOException("Отсутствует доверенный список аудиобиблиотек");
            byte[] registry = input.readNBytes(16385);
            if (registry.length > 16384) throw new IOException("Неверный список аудиобиблиотек");
            var json = JsonParser.parseString(new String(registry, StandardCharsets.UTF_8)).getAsJsonObject();
            expected = json.getAsJsonObject("libraries").getAsJsonObject(platform).get(filename).getAsString();
            if (!expected.matches("[0-9a-f]{64}")) throw new IOException("Неверная подпись комплекта аудио");
        } catch (IOException e) { throw e; }
        catch (RuntimeException e) { throw new IOException("Неверный доверенный список аудиобиблиотек", e); }
        try (FileChannel input = FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            long size = input.size();
            if (size <= 0 || size > MAX_LIBRARY_BYTES) throw new IOException("Недопустимый размер аудиобиблиотеки");
            byte[] bytes = new byte[(int) size]; ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) if (input.read(buffer) < 0) throw new IOException("Аудиобиблиотека изменилась");
            if (input.read(ByteBuffer.allocate(1)) != -1 || input.size() != size ||
                    !MessageDigest.isEqual(HexFormat.of().parseHex(expected), MessageDigest.getInstance("SHA-256").digest(bytes))) {
                Arrays.fill(bytes, (byte) 0); throw new IOException("Проверка подлинности аудиобиблиотеки не пройдена");
            }
            return bytes;
        } catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }
    private static String platform() throws IOException {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (!arch.equals("amd64") && !arch.equals("x86_64")) throw new IOException("Архитектура аудиобиблиотек не поддерживается");
        String os = System.getProperty("os.name", "");
        if (os.startsWith("Windows")) return "windows-x86_64";
        if (os.equals("Linux")) return "linux-x86_64";
        throw new IOException("Платформа аудиобиблиотек не поддерживается");
    }
    /** Verified bytes become immutable before dlopen, avoiding writable-path hash/load races. */
    private static final class LinuxImage implements AutoCloseable {
        private final NativeLibrary process = NativeLibrary.getProcess();
        private int fd = -1;
        LinuxImage(byte[] bytes) throws IOException {
            try {
                // MFD_EXEC is explicit on recent kernels; old kernels reject it with EINVAL.
                fd = process.getFunction("memfd_create").invokeInt(new Object[]{"aegis-verified-voice", 1 | 2 | 16});
                if (fd < 0 && Native.getLastError() == 22)
                    fd = process.getFunction("memfd_create").invokeInt(new Object[]{"aegis-verified-voice", 1 | 2});
                if (fd < 0) throw new IOException("Не удалось создать неизменяемый образ аудиокодека");
                try (Memory memory = new Memory(bytes.length)) {
                    memory.write(0, bytes, 0, bytes.length); long offset = 0;
                    while (offset < bytes.length) {
                        long n = process.getFunction("write").invokeLong(new Object[]{fd, memory.share(offset), (long) bytes.length - offset});
                        if (n <= 0) throw new IOException("Не удалось заполнить образ аудиокодека"); offset += n;
                    }
                }
                // F_ADD_SEALS/F_GET_SEALS: SEAL|SHRINK|GROW|WRITE. No writeable mappings exist.
                int seals = 1 | 2 | 4 | 8;
                if (process.getFunction("fcntl").invokeInt(new Object[]{fd, 1033, seals}) < 0 ||
                        (process.getFunction("fcntl").invokeInt(new Object[]{fd, 1034}) & seals) != seals)
                    throw new IOException("Не удалось закрепить неизменяемый аудиокодек");
            } catch (IOException | RuntimeException | LinkageError e) { close(); throw e; }
        }
        String path() { return "/proc/self/fd/" + fd; }
        public void close() { if (fd >= 0) { process.getFunction("close").invokeInt(new Object[]{fd}); fd = -1; } }
    }
    private static final class WindowsGuard implements AutoCloseable {
        private final List<com.sun.jna.platform.win32.WinNT.HANDLE> held = new ArrayList<>();
        WindowsGuard(Path file) throws IOException {
            Path root = file.getRoot();
            if (root == null || !root.toString().matches("[A-Za-z]:\\\\")) throw new IOException("Аудиобиблиотеки требуют локальный диск Windows");
            try {
                Path cursor = root; hold(cursor, true);
                for (Path part : file.getParent()) { cursor = cursor.resolve(part); hold(cursor, true); }
                hold(file, false);
            } catch (IOException | RuntimeException e) { close(); throw e; }
        }
        private void hold(Path file, boolean directory) throws IOException {
            var api = com.sun.jna.platform.win32.Kernel32.INSTANCE;
            var handle = api.CreateFile(file.toString(), com.sun.jna.platform.win32.WinNT.FILE_READ_ATTRIBUTES,
                    com.sun.jna.platform.win32.WinNT.FILE_SHARE_READ | (directory ? com.sun.jna.platform.win32.WinNT.FILE_SHARE_WRITE : 0),
                    null, com.sun.jna.platform.win32.WinNT.OPEN_EXISTING,
                    com.sun.jna.platform.win32.WinNT.FILE_FLAG_OPEN_REPARSE_POINT |
                            (directory ? com.sun.jna.platform.win32.WinNT.FILE_FLAG_BACKUP_SEMANTICS : 0), null);
            if (com.sun.jna.platform.win32.WinBase.INVALID_HANDLE_VALUE.equals(handle)) throw new IOException("Не удалось закрепить комплектную аудиобиблиотеку");
            held.add(handle);
            var info = new com.sun.jna.platform.win32.WinBase.FILE_ATTRIBUTE_TAG_INFO();
            if (!api.GetFileInformationByHandleEx(handle, com.sun.jna.platform.win32.WinBase.FileAttributeTagInfo,
                    info.getPointer(), new com.sun.jna.platform.win32.WinDef.DWORD(info.size()))) throw new IOException("Не удалось проверить путь аудиобиблиотеки");
            info.read();
            boolean actualDirectory = (info.FileAttributes & com.sun.jna.platform.win32.WinNT.FILE_ATTRIBUTE_DIRECTORY) != 0;
            if ((info.FileAttributes & com.sun.jna.platform.win32.WinNT.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || actualDirectory != directory)
                throw new IOException("Ссылки и reparse points в пути аудиобиблиотек запрещены");
        }
        public void close() {
            for (int i = held.size() - 1; i >= 0; i--) com.sun.jna.platform.win32.Kernel32.INSTANCE.CloseHandle(held.get(i));
            held.clear();
        }
    }
}
