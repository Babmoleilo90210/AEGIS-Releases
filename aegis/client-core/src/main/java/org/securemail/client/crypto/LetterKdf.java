package org.securemail.client.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/** Letter-only KDF. Account passwords and vault format are unchanged. */
final class LetterKdf {
  private LetterKdf() {}
  static byte[] derive(char[] secret, byte[] salt, boolean inner) {
    if (secret.length > 1024 || salt.length != 16) throw new IllegalArgumentException("Недопустимые параметры письма");
    byte[] input = Secrets.utf8(secret), key = new byte[32];
    var params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
        .withMemoryAsKB(65536).withIterations(3).withParallelism(1).withSalt(salt)
        .withAdditional((inner ? "AEGIS/letter-v3/FF1" : "AEGIS/letter-v3/AES-GCM").getBytes(StandardCharsets.US_ASCII))
        .build();
    try {
      var generator = new Argon2BytesGenerator();
      generator.init(params);
      generator.generateBytes(input, key);
      return key;
    } finally {
      Arrays.fill(input, (byte) 0);
      params.clear();
    }
  }
}

