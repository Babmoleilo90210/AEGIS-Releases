package org.securemail.attachments.protocol;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** New capability-negotiated attachment endpoint; does not modify legacy protocol 1. */
public final class AttachmentProtocol {
  public static final int CHUNK_BYTES = 1024 * 1024, MAX_METADATA = 4096, MAX_REPLY_METADATA = 16384;
  public static final long MAX_PLAINTEXT = 500L * 1024 * 1024, MAX_CIPHERTEXT = MAX_PLAINTEXT + CHUNK_BYTES;
  private AttachmentProtocol() {}
  public enum Command {
    CREATE("attachments.create"), STATUS("attachments.status"), PUT("attachments.write"), COMMIT("attachments.write"), GET("attachments.read"), ACK("attachments.read"), ABORT("attachments.delete");
    private final String action; Command(String action) { this.action = action; } public String action() { return action; }
  }
  public record Request(Command command, String transferId, String recipientId, long ciphertextBytes,
                        String ciphertextSha256, long ttlMillis, int chunkIndex, int payloadBytes, String payloadSha256) {
    public Request {
      Objects.requireNonNull(command); uuid(transferId);
      recipientId = recipientId == null ? "" : recipientId; ciphertextSha256 = ciphertextSha256 == null ? "" : ciphertextSha256; payloadSha256 = payloadSha256 == null ? "" : payloadSha256;
      if (command == Command.CREATE) {
        IdentityProtocol.idValue(recipientId); digest(ciphertextSha256);
        if (ciphertextBytes < 56 || ciphertextBytes > MAX_CIPHERTEXT || ttlMillis < 60000 || ttlMillis > 30L * 86400_000) throw invalid();
      } else if (!recipientId.isEmpty() || ciphertextBytes != 0 || !ciphertextSha256.isEmpty() || ttlMillis != 0) throw invalid();
      if (command == Command.PUT) { if (chunkIndex < 0 || chunkIndex > 1023 || payloadBytes < 1 || payloadBytes > CHUNK_BYTES) throw invalid(); digest(payloadSha256); }
      else if (command == Command.GET) { if (chunkIndex < 0 || chunkIndex > 1023 || payloadBytes != 0 || !payloadSha256.isEmpty()) throw invalid(); }
      else if (chunkIndex != 0 || payloadBytes != 0 || !payloadSha256.isEmpty()) throw invalid();
    }
    public byte[] encode() {
      try { var bytes = new ByteArrayOutputStream(); try (var out = new DataOutputStream(bytes)) {
        out.writeUTF("AEGIS-ATTACHMENT-REQUEST/v1"); out.writeUTF(command.name()); out.writeUTF(transferId); out.writeUTF(recipientId); out.writeLong(ciphertextBytes); out.writeUTF(ciphertextSha256); out.writeLong(ttlMillis); out.writeInt(chunkIndex); out.writeInt(payloadBytes); out.writeUTF(payloadSha256);
      } return bytes.toByteArray(); } catch (IOException impossible) { throw new IllegalStateException(impossible); }
    }
    public static Request create(String id, String recipient, long length, String sha256, long ttl) { return new Request(Command.CREATE, id, recipient, length, sha256, ttl, 0, 0, ""); }
    public static Request put(String id, int index, int length, String digest) { return new Request(Command.PUT, id, "", 0, "", 0, index, length, digest); }
    public static Request control(Command command, String id) { return new Request(command, id, "", 0, "", 0, 0, 0, ""); }
    public static Request get(String id, int index) { return new Request(Command.GET, id, "", 0, "", 0, index, 0, ""); }
  }
  public static Request decode(byte[] metadata) throws IOException {
    if (metadata.length < 1 || metadata.length > MAX_METADATA) throw new IOException("Размер запроса превышен");
    try (var in = new DataInputStream(new ByteArrayInputStream(metadata))) {
      if (!in.readUTF().equals("AEGIS-ATTACHMENT-REQUEST/v1")) throw new IOException("Неверный протокол вложений");
      var request = new Request(Command.valueOf(in.readUTF()), in.readUTF(), in.readUTF(), in.readLong(), in.readUTF(), in.readLong(), in.readInt(), in.readInt(), in.readUTF());
      if (in.read() != -1 || !MessageDigest.isEqual(metadata, request.encode())) throw new IOException("Неканонический запрос вложения"); return request;
    } catch (IllegalArgumentException failure) { throw new IOException("Некорректный запрос вложения", failure); }
  }
  public static byte[] responseSigningBytes(byte[] metadata, String nonce, byte[] reply) {
    IdentityProtocol.nonceValue(nonce);
    if (metadata.length > MAX_METADATA || reply.length > CHUNK_BYTES + MAX_REPLY_METADATA + 4) throw invalid();
    try { var bytes = new ByteArrayOutputStream(); try (var out = new DataOutputStream(bytes)) { out.writeUTF("AEGIS-ATTACHMENT-RESPONSE/v1"); out.writeUTF(nonce); out.write(IdentityProtocol.digest(metadata)); out.writeInt(reply.length); out.write(IdentityProtocol.digest(reply)); } return bytes.toByteArray(); }
    catch (IOException impossible) { throw new IllegalStateException(impossible); }
  }
  public static byte[] frame(byte[] metadata, byte[] payload) {
    if (metadata.length > MAX_REPLY_METADATA || payload.length > CHUNK_BYTES) throw invalid();
    try { var bytes = new ByteArrayOutputStream(4 + metadata.length + payload.length); try (var out = new DataOutputStream(bytes)) { out.writeInt(metadata.length); out.write(metadata); out.write(payload); } return bytes.toByteArray(); }
    catch (IOException impossible) { throw new IllegalStateException(impossible); }
  }
  public static String sha256(byte[] bytes) { return HexFormat.of().formatHex(IdentityProtocol.digest(bytes)); }
  private static void uuid(String s) { if (s == null || !UUID.fromString(s).toString().equals(s)) throw invalid(); }
  private static void digest(String s) { if (s == null || !s.matches("[a-f0-9]{64}")) throw invalid(); }
  private static IllegalArgumentException invalid() { return new IllegalArgumentException("Некорректный запрос вложения"); }
}
