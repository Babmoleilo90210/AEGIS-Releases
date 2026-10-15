package org.securemail.protocol;

/** Transport metadata and ciphertext only. AEAD tag is appended to ciphertext. */
public record EncryptedPacket(
    String messageId,
    String senderId,
    String senderNickname,
    String recipientId,
    long createdAt,
    long deliveryDeadline,
    long ttlAfterDelivery,
    Algorithm algorithm,
    byte[] salt,
    byte[] nonce,
    byte[] ciphertext,
    byte[] senderPublicKey,
    byte[] signature) {
  public EncryptedPacket {
    Limits.messageId(messageId);
    Limits.userId(senderId);
    Limits.userId(recipientId);
    if (!Limits.nickname(senderNickname).equals(senderNickname))
      throw new IllegalArgumentException("Noncanonical nickname");
    if (createdAt <= 0
        || deliveryDeadline <= createdAt
        || deliveryDeadline - createdAt > Limits.MAX_DELIVERY_MILLIS
        || ttlAfterDelivery < 1
        || ttlAfterDelivery > Limits.MAX_TTL_SECONDS)
      throw new IllegalArgumentException("Invalid lifetime");
    if (algorithm == null
        || salt.length != (algorithm == Algorithm.ENIGMA ? 0 : 16)
        || nonce.length != algorithm.nonceLength
        || ciphertext.length < (algorithm == Algorithm.ENIGMA ? 1 : 16)
        || ciphertext.length > Limits.HARD_FILE_BYTES + Limits.PAYLOAD_OVERHEAD
        || senderPublicKey.length != 44
        || (signature.length != 0 && signature.length != 64))
      throw new IllegalArgumentException("Invalid packet");
    salt = salt.clone();
    nonce = nonce.clone();
    ciphertext = ciphertext.clone();
    senderPublicKey = senderPublicKey.clone();
    signature = signature.clone();
  }

  @Override
  public byte[] salt() {
    return salt.clone();
  }

  @Override
  public byte[] nonce() {
    return nonce.clone();
  }

  @Override
  public byte[] ciphertext() {
    return ciphertext.clone();
  }

  @Override
  public byte[] senderPublicKey() {
    return senderPublicKey.clone();
  }

  @Override
  public byte[] signature() {
    return signature.clone();
  }

  @Override
  public String toString() {
    return "EncryptedPacket[redacted]";
  }
}
