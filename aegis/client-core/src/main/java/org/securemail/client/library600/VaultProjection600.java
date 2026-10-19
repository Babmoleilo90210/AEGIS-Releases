package org.securemail.client.library600;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

/** Bounded plaintext projection of explicitly exportable material, separate from the private archive.
 * Directory permissions are NOT a same-UID sandbox. The protected launcher must supply OS isolation.
 * Construction clears this connector's prior projection: no offline permit survives process restart. */
public final class VaultProjection600 implements AutoCloseable {
    public record Context(String accountId, String deviceId, long generation, long aclEpoch) { }
    private static final String MARKER = ".aegis-projection-v1";
    private static final int MAX_NOTE = 1024 * 1024, MAX_FILES = 512;
    private static final long MAX_TOTAL = 64L * 1024 * 1024;
    private final Path root;
    private final Map<UUID, Entry> entries = new HashMap<>();
    private boolean closed;
    private record Entry(long revision, long bytes, LibraryLease600 lease, Context context, String sha256) { }

    public VaultProjection600(Path directory) throws IOException {
        root = directory.toAbsolutePath().normalize();
        Path parent = root.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || !parent.toRealPath().equals(parent)) throw new IOException("Небезопасный каталог проекции");
        boolean existed = Files.exists(root, LinkOption.NOFOLLOW_LINKS);
        if (!existed) Files.createDirectory(root);
        checkRoot(); privateMode(root, true);
        Path marker = root.resolve(MARKER);
        if (existed && (!Files.isRegularFile(marker, LinkOption.NOFOLLOW_LINKS)
                || !Files.readString(marker).equals("AEGIS-LIBRARY-PROJECTION-v1\n")))
            throw new IOException("Каталог не принадлежит коннектору библиотеки");
        if (!existed) { Files.writeString(marker, "AEGIS-LIBRARY-PROJECTION-v1\n", StandardOpenOption.CREATE_NEW); privateMode(marker, false); }
        // Never interpret or remove arbitrary user files, .obsidian directories, or nested vaults.
        try (var paths = Files.list(root)) {
            for (Path path : paths.toList()) {
                if (path.getFileName().toString().equals(MARKER)) continue;
                if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                        || !path.getFileName().toString().matches("[a-f0-9-]{36}\\.md"))
                    throw new IOException("В проекции обнаружены посторонние файлы");
                parseId(path.getFileName().toString().substring(0, 36));
                Files.delete(path);
            }
        }
    }

    public synchronized Path publish(String materialId, long revision, String markdown,
                                      LibraryLease600 lease, Context context) throws IOException {
        check(); UUID id = parseId(materialId); Objects.requireNonNull(context); Objects.requireNonNull(lease);
        if (revision < 1 || markdown == null) throw new IOException("Некорректная версия материала");
        lease.require(context.accountId(), context.deviceId(), context.generation(), context.aclEpoch());
        // Bounded text-only projection: embeds/raw active tags need a separately authorised attachment pipeline.
        // This does not sanitize the entire Obsidian renderer; the protected OS/network boundary is mandatory.
        if (markdown.indexOf('\0') >= 0 || unsafeEmbed(markdown))
            throw new IOException("Активные внешние вложения запрещены в проекции");
        for (int i=0;i<markdown.length();i++) if(Character.isSurrogate(markdown.charAt(i))) {
            if (!Character.isHighSurrogate(markdown.charAt(i)) || i+1>=markdown.length() || !Character.isLowSurrogate(markdown.charAt(++i)))
                throw new IOException("Некорректный текст Unicode");
        }
        byte[] bytes = markdown.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_NOTE) throw new IOException("Материал превышает лимит проекции");
        Entry previous = entries.get(id);
        String digest;
        try { digest=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch(java.security.NoSuchAlgorithmException impossible){throw new AssertionError(impossible);}
        if (previous != null && (revision < previous.revision() || revision == previous.revision() && !previous.sha256().equals(digest)))
            throw new IOException("Устаревшая или противоречивая версия проекции");
        long total = entries.values().stream().mapToLong(Entry::bytes).sum() - (previous == null ? 0 : previous.bytes()) + bytes.length;
        if (total > MAX_TOTAL || previous == null && entries.size() >= MAX_FILES) throw new IOException("Лимит проекции библиотеки");
        Path target = root.resolve(id + ".md");
        if (Files.isSymbolicLink(target)) throw new IOException("Символическая ссылка запрещена");
        Path temporary = Files.createTempFile(root, ".aegis-", ".tmp");
        try {
            privateMode(temporary, false);
            try (var channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer data = ByteBuffer.wrap(bytes); while (data.hasRemaining()) channel.write(data); channel.force(true);
            }
            checkRoot(); lease.require(context.accountId(), context.deviceId(), context.generation(), context.aclEpoch());
            // No non-atomic fallback: on unsupported filesystems the previous revision remains intact.
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            entries.put(id, new Entry(revision, bytes.length, lease, context, digest));
            return target;
        } finally { Arrays.fill(bytes, (byte)0); Files.deleteIfExists(temporary); }
    }
    public synchronized void prune() throws IOException {
        check();
        for (var iterator = entries.entrySet().iterator(); iterator.hasNext();) {
            var item = iterator.next(); Entry e = item.getValue();
            try { e.lease().require(e.context().accountId(), e.context().deviceId(), e.context().generation(), e.context().aclEpoch()); }
            catch (IOException expired) { Files.deleteIfExists(root.resolve(item.getKey()+".md")); iterator.remove(); }
        }
    }
    public synchronized void revokeAll() throws IOException {
        checkRoot(); IOException failure = null;
        for (var item : entries.entrySet()) {
            item.getValue().lease().revoke();
            try { Files.deleteIfExists(root.resolve(item.getKey()+".md")); } catch (IOException e) { failure = e; }
        }
        entries.clear(); if (failure != null) throw failure;
    }
    @Override public synchronized void close() throws IOException {
        if (!closed) { try { revokeAll(); } finally { closed = true; } }
    }
    private static boolean unsafeEmbed(String markdown) {
        // Linear scan, deliberately conservative. No unbounded regex over attacker-controlled Markdown.
        if(markdown.contains("!["))return true;
        String lower=markdown.toLowerCase(java.util.Locale.ROOT);
        for(String tag:java.util.List.of("<img","<iframe","<script","<object","<embed","<link","<video","<audio","<source","<svg","<style","<base","<form","<meta"))
            if(lower.contains(tag))return true;
        return false;
    }
    private void check() throws IOException { if (closed) throw new IOException("Проекция заблокирована"); checkRoot(); }
    private void checkRoot() throws IOException {
        if (Files.isSymbolicLink(root) || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || !root.toRealPath().equals(root))
            throw new IOException("Каталог проекции изменён");
    }
    private static UUID parseId(String value) throws IOException {
        try { UUID id = UUID.fromString(value); if (!id.toString().equals(value)) throw new IllegalArgumentException(); return id; }
        catch (RuntimeException e) { throw new IOException("Недопустимый идентификатор материала"); }
    }
    private static void privateMode(Path path, boolean directory) throws IOException {
        try { Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------")); }
        catch (UnsupportedOperationException ignored) { /* Windows boundary is mandatory at the launcher, not inferred here. */ }
    }
}
