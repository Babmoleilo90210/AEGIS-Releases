package org.securemail.relay;

import com.password4j.Argon2Function;
import com.password4j.types.Argon2;
import java.security.SecureRandom;

/** Hashing only; no message decryption library in relay runtime. */
final class Authentication {
  private static final Argon2Function KDF =
      Argon2Function.getInstance(65536, 3, 1, 32, Argon2.ID, 19);
  private static final SecureRandom RANDOM = new SecureRandom();

  private Authentication() {}

  static byte[] salt() {
    byte[] b = new byte[16];
    RANDOM.nextBytes(b);
    return b;
  }

  static byte[] hash(byte[] password, byte[] salt) {
    if (password.length < 12 || password.length > 4096)
      throw new IllegalArgumentException("Bad password length");
    return KDF.hash(password, salt).getBytes();
  }
}
