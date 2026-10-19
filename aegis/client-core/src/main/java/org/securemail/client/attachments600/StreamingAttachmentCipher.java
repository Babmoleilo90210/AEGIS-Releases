package org.securemail.client.attachments600;

import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;
import java.util.function.BooleanSupplier;

/** Standard Tink streaming AEAD. Never assembles a whole attachment in JVM memory. */
public final class StreamingAttachmentCipher {
  public static final long MAX_PLAINTEXT = 500L * 1024 * 1024;
  public static final int SEGMENT_BYTES = 1024 * 1024, COPY_BUFFER_BYTES = 64 * 1024;
  private static final String SUITE = "TINK-AES256-GCM-HKDF-SHA256-1MB/v1";
  private StreamingAttachmentCipher() {}

  public record Context(String transferId, String senderId, String recipientId, long plaintextBytes) {
    public Context {
      canonicalUuid(transferId);
      if (senderId == null || !senderId.matches("[a-f0-9]{64}")
          || recipientId == null || !recipientId.matches("[a-f0-9]{64}")
          || plaintextBytes < 0 || plaintextBytes > MAX_PLAINTEXT)
        throw new IllegalArgumentException("Некорректный контекст вложения");
    }
    public byte[] associatedData() {
      try {
        var bytes = new ByteArrayOutputStream(256);
        try (var out = new DataOutputStream(bytes)) {
          out.writeUTF("AEGIS-ATTACHMENT/v1"); out.writeUTF(SUITE); out.writeUTF(transferId);
          out.writeUTF(senderId); out.writeUTF(recipientId); out.writeLong(plaintextBytes);
        }
        return bytes.toByteArray();
      } catch (IOException impossible) { throw new IllegalStateException(impossible); }
    }
  }

  public record Result(long plaintextBytes, long ciphertextBytes, String plaintextSha256, String ciphertextSha256) {}

  public static byte[] newFileKey() { byte[] key = new byte[32]; new SecureRandom().nextBytes(key); return key; }

  public static long ciphertextSize(long plaintextBytes) throws GeneralSecurityException {
    if (plaintextBytes < 0 || plaintextBytes > MAX_PLAINTEXT) throw new GeneralSecurityException("Размер вложения превышен");
    byte[] dummy = new byte[32];
    try { return primitive(dummy).expectedCiphertextSize(plaintextBytes); }
    finally { Arrays.fill(dummy, (byte) 0); }
  }

  /** Both caller streams stay open. A failed ciphertext must be discarded in its entirety. */
  public static Result encrypt(InputStream source, OutputStream ciphertext, Context context, byte[] key,
                               BooleanSupplier authorized) throws IOException, GeneralSecurityException {
    Objects.requireNonNull(source); Objects.requireNonNull(ciphertext); Objects.requireNonNull(context);
    requireAuthority(authorized); byte[] owned = checkedKey(key), buffer = new byte[COPY_BUFFER_BYTES];
    MessageDigest plainHash = sha256(), cipherHash = sha256();
    var counter = new CountingOutput(new DigestOutputStream(new NonClosingOutput(ciphertext), cipherHash));
    long plainBytes = 0;
    try (OutputStream encrypted = primitive(owned).newEncryptingStream(counter, context.associatedData())) {
      int count;
      while ((count = source.read(buffer)) != -1) {
        requireAuthority(authorized);
        if (count == 0) continue;
        if (count > context.plaintextBytes() - plainBytes) throw new IOException("Размер вложения изменился");
        plainHash.update(buffer, 0, count); encrypted.write(buffer, 0, count); plainBytes += count;
      }
      requireAuthority(authorized);
      if (plainBytes != context.plaintextBytes()) throw new IOException("Вложение усечено");
    } finally { Arrays.fill(owned, (byte) 0); Arrays.fill(buffer, (byte) 0); }
    if (counter.count != ciphertextSize(context.plaintextBytes())) throw new IOException("Размер шифротекста неверен");
    return new Result(plainBytes, counter.count, hex(plainHash.digest()), hex(cipherHash.digest()));
  }

  /** Creates only a new destination, exposing no partial plaintext when EOF authentication fails. */
  public static Result decryptToNewFile(InputStream ciphertext, Path destination, Context context,
                                        byte[] key, String expectedPlainSha256, String expectedCipherSha256,
                                        BooleanSupplier authorized) throws IOException, GeneralSecurityException {
    Objects.requireNonNull(ciphertext); Objects.requireNonNull(context); requireDigest(expectedPlainSha256); requireDigest(expectedCipherSha256);
    requireAuthority(authorized); destination = destination.toAbsolutePath().normalize();
    Path parent = destination.getParent();
    if (parent == null || !parent.toRealPath().equals(parent) || Files.exists(destination, LinkOption.NOFOLLOW_LINKS))
      throw new IOException("Нужен новый файл в существующем защищённом каталоге");
    Path temporary = parent.resolve(".aegis-attachment-" + UUID.randomUUID());
    byte[] owned = checkedKey(key), buffer = new byte[COPY_BUFFER_BYTES];
    MessageDigest plainHash = sha256(), cipherHash = sha256(); long plainBytes = 0;
    var counted = new CountingInput(new DigestInputStream(new NonClosingInput(ciphertext), cipherHash));
    boolean moved = false;
    try {
      createPrivate(temporary);
      try (var file = FileChannel.open(temporary, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
           InputStream decrypted = primitive(owned).newDecryptingStream(counted, context.associatedData())) {
        int count;
        while ((count = decrypted.read(buffer)) != -1) {
          requireAuthority(authorized);
          if (count == 0) continue;
          if (count > context.plaintextBytes() - plainBytes) throw new IOException("Размер вложения превышен");
          plainHash.update(buffer, 0, count);
          ByteBuffer bytes = ByteBuffer.wrap(buffer, 0, count); while (bytes.hasRemaining()) file.write(bytes);
          plainBytes += count;
        }
        requireAuthority(authorized);
        if (plainBytes != context.plaintextBytes() || counted.count != ciphertextSize(context.plaintextBytes()))
          throw new IOException("Размер вложения неверен");
        String plainDigest = hex(plainHash.digest()), cipherDigest = hex(cipherHash.digest());
        if (!sameDigest(expectedPlainSha256, plainDigest) || !sameDigest(expectedCipherSha256, cipherDigest))
          throw new IOException("Проверка целостности вложения не пройдена");
        file.force(true); requireAuthority(authorized);
        // createLink is atomic CREATE_NEW publication. ATOMIC_MOVE alone may overwrite
        // an existing destination on Unix even without REPLACE_EXISTING.
        Files.createLink(destination, temporary); moved = true; Files.delete(temporary);
        return new Result(plainBytes, counted.count, plainDigest, cipherDigest);
      }
    } finally {
      Arrays.fill(owned, (byte) 0); Arrays.fill(buffer, (byte) 0);
      if (!moved) Files.deleteIfExists(temporary);
    }
  }

  private static AesGcmHkdfStreaming primitive(byte[] key) throws GeneralSecurityException {
    return new AesGcmHkdfStreaming(key, "HmacSha256", 32, SEGMENT_BYTES, 0);
  }
  private static byte[] checkedKey(byte[] key) throws GeneralSecurityException {
    if (key == null || key.length != 32) throw new GeneralSecurityException("Некорректный ключ вложения"); return key.clone();
  }
  private static void canonicalUuid(String value) {
    if (value == null || !UUID.fromString(value).toString().equals(value)) throw new IllegalArgumentException("Некорректный идентификатор вложения");
  }
  private static void requireDigest(String value) { if (value == null || !value.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Некорректный digest"); }
  private static boolean sameDigest(String expected, String actual) { return MessageDigest.isEqual(HexFormat.of().parseHex(expected), HexFormat.of().parseHex(actual)); }
  private static String hex(byte[] bytes) { return HexFormat.of().formatHex(bytes); }
  private static MessageDigest sha256() { try { return MessageDigest.getInstance("SHA-256"); } catch (GeneralSecurityException impossible) { throw new IllegalStateException(impossible); } }
  private static void requireAuthority(BooleanSupplier authorized) throws IOException {
    if (authorized == null || !authorized.getAsBoolean()) throw new IOException("Доступ к вложению отозван");
  }
  private static void createPrivate(Path file) throws IOException {
    try { Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); }
    catch (UnsupportedOperationException unavailable) {
      Files.createFile(file); AclFileAttributeView view = Files.getFileAttributeView(file, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
      if (view == null) { Files.deleteIfExists(file); throw new IOException("Защита файла недоступна"); }
      UserPrincipal owner = Files.getOwner(file, LinkOption.NOFOLLOW_LINKS);
      view.setAcl(List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build()));
    }
  }
  private static final class NonClosingOutput extends FilterOutputStream {
    NonClosingOutput(OutputStream out) { super(out); }
    @Override public void write(int value) throws IOException { out.write(value); }
    @Override public void write(byte[] bytes, int offset, int length) throws IOException { out.write(bytes, offset, length); }
    @Override public void close() throws IOException { flush(); }
  }
  private static final class NonClosingInput extends FilterInputStream { NonClosingInput(InputStream in) { super(in); } @Override public void close() {} }
  private static final class CountingOutput extends FilterOutputStream {
    long count; CountingOutput(OutputStream out) { super(out); }
    @Override public void write(int value) throws IOException { out.write(value); count++; }
    @Override public void write(byte[] bytes, int offset, int length) throws IOException { out.write(bytes, offset, length); count += length; }
  }
  private static final class CountingInput extends FilterInputStream {
    long count; CountingInput(InputStream in) { super(in); }
    @Override public int read() throws IOException { int value = in.read(); if (value != -1) count++; return value; }
    @Override public int read(byte[] bytes, int offset, int length) throws IOException { int value = in.read(bytes, offset, length); if (value > 0) count += value; return value; }
  }
}
