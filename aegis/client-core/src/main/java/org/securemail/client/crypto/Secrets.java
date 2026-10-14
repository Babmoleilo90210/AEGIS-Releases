package org.securemail.client.crypto;

import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public final class Secrets {
  private static final SecureRandom RANDOM = new SecureRandom();

  private Secrets() {}

  public static byte[] random(int n) {
    byte[] b = new byte[n];
    RANDOM.nextBytes(b);
    return b;
  }

  public static byte[] utf8(char[] chars) {
    ByteBuffer b = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
    byte[] r = new byte[b.remaining()];
    b.get(r);
    if (b.hasArray()) Arrays.fill(b.array(), (byte) 0);
    return r;
  }

  /** Fixed protocol parameters: Argon2id v19, m=64 MiB, t=3, p=1. */
  public static synchronized byte[] derive(char[] password, byte[] salt) {
    return derive(password,salt,null);
  }

  /** Account wire material stays unchanged; the local vault has a distinct context. */
  public static byte[] deriveVault(char[] password,byte[] salt){return derive(password,salt,"AEGIS-VAULT-v1");}
  /** Independent archive password domain; existing account/vault derivations are unchanged. */
  public static byte[] deriveArchive(char[] password,byte[] salt){return derive(password,salt,"AEGIS-ARCHIVE-v1");}
  private static synchronized byte[] derive(char[] password,byte[] salt,String context) {
    if (password.length < 12 || password.length > 1024 || salt.length != 16)
      throw new IllegalArgumentException("Пароль: от 12 до 1024 символов");
    byte[] input = utf8(password), key = new byte[32];
    var builder =
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(65536)
            .withIterations(3)
            .withParallelism(1)
            .withSalt(salt);
    if(context!=null)builder.withAdditional(context.getBytes(StandardCharsets.US_ASCII));
    var params=builder.build();
    try {
      var g = new Argon2BytesGenerator();
      g.init(params);
      g.generateBytes(input, key);
      return key;
    } finally {
      Arrays.fill(input, (byte) 0);
      params.clear();
    }
  }
}
