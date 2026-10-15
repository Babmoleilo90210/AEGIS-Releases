package org.securemail.protocol;

public enum Algorithm {
  AES_256_GCM(1, 12, "AES-256-GCM · рекомендуется"),
  XCHACHA20_POLY1305(2, 24, "XChaCha20-Poly1305 · рекомендуется"),
  CHACHA20_POLY1305(3, 12, "ChaCha20-Poly1305"),
  CAMELLIA_256_GCM(4, 12, "Camellia-256-GCM"),
  ENIGMA(5, 0, "Enigma · НЕ для секретов");
  public static final String ENIGMA_WARNING =
      "Исторический шифр. Не предназначен для конфиденциальных данных.";
  public final int code, nonceLength;
  private final String label;

  Algorithm(int code, int nonceLength, String label) {
    this.code = code;
    this.nonceLength = nonceLength;
    this.label = label;
  }

  public static Algorithm fromCode(int code) {
    for (var a : values()) if (a.code == code) return a;
    throw new IllegalArgumentException("Unknown algorithm");
  }

  @Override
  public String toString() {
    return label;
  }
}
