package org.securemail.client.crypto;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.security.GeneralSecurityException;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.*;
import org.securemail.protocol.*;

/** Standard FF1 (radix 16) inside authenticated AES-GCM, inside existing E2EE.
 * The inner layer deliberately has no correctness oracle or authentication tag.
 * Changing its code always computes a candidate; it never validates the code.
 */
public final class LetterEnvelope {
  public static final int MAX_BYTES = Limits.TEXT_BYTES + 256;
  private static final int MAGIC = 0x41474c33, VERSION = 3;
  private static final byte[] AAD = "AEGIS/letter-envelope/3/AES-256-GCM/Argon2id-19-65536-3-1".getBytes(StandardCharsets.US_ASCII);
  private LetterEnvelope() {}

  public static byte[] seal(String text, char[] password, char[] code) throws IOException, GeneralSecurityException {
    if (password.length < 8 || password.length > 1024)
      throw new IllegalArgumentException("Пароль письма: от 8 до 1024 символов");
    if (code.length == 0 || code.length > 1024)
      throw new IllegalArgumentException("Введите код второго слоя");
    byte[] plain = text.getBytes(StandardCharsets.UTF_8);
    if (plain.length > Limits.TEXT_BYTES) { wipe(plain); throw new IllegalArgumentException("Письмо слишком большое"); }
    byte[] outerSalt=Secrets.random(16), nonce=Secrets.random(12), innerSalt=Secrets.random(16), tweak=Secrets.random(16);
    byte[] codeKey=null, key=null, padded=null, packed=null, inner=null;
    try {
      codeKey=LetterKdf.derive(code, innerSalt, true);
      padded=Arrays.copyOf(plain, Math.max(3,plain.length)); // 16^6 domain >= 1,000,000, even for one character
      packed=ff1(padded,codeKey,tweak,true);
      final byte[] encryptedDigits=packed;
      inner=Binary.encode(out -> {
        out.writeInt(1); Binary.bytes(out,innerSalt); Binary.bytes(out,tweak);
        out.writeInt(plain.length); Binary.bytes(out,encryptedDigits);
      });
      key=LetterKdf.derive(password,outerSalt,false);
      Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
      cipher.updateAAD(AAD); cipher.updateAAD(outerSalt); cipher.updateAAD(nonce);
      byte[] ciphertext=cipher.doFinal(inner);
      return Binary.encode(out -> {
        out.writeInt(MAGIC); out.writeInt(VERSION);
        Binary.bytes(out,outerSalt); Binary.bytes(out,nonce); Binary.bytes(out,ciphertext);
      });
    } finally { wipe(plain,codeKey,key,padded,packed,inner); }
  }

  public static Opened open(byte[] envelope, char[] password) throws IOException, GeneralSecurityException {
    if (envelope.length > MAX_BYTES) throw new IOException("Повреждённое письмо");
    byte[] key=null, inner=null;
    try (var in=new DataInputStream(new ByteArrayInputStream(envelope))) {
      if(in.readInt()!=MAGIC || in.readInt()!=VERSION) throw new IOException("Версия письма не поддерживается");
      byte[] salt=Binary.bytes(in,16), nonce=Binary.bytes(in,12), ciphertext=Binary.bytes(in,MAX_BYTES);
      Binary.end(in);
      if(salt.length!=16 || nonce.length!=12 || ciphertext.length<16) throw new IOException("Повреждённое письмо");
      key=LetterKdf.derive(password,salt,false);
      Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
      cipher.updateAAD(AAD); cipher.updateAAD(salt); cipher.updateAAD(nonce);
      inner=cipher.doFinal(ciphertext); // Authenticate BEFORE rendering or parsing inner data.
      try (var decoded=new DataInputStream(new ByteArrayInputStream(inner))) {
        if(decoded.readInt()!=1) throw new IOException("Версия слоя не поддерживается");
        byte[] innerSalt=Binary.bytes(decoded,16), tweak=Binary.bytes(decoded,16);
        int length=decoded.readInt(); byte[] packed=Binary.bytes(decoded,Limits.TEXT_BYTES);
        Binary.end(decoded);
        if(innerSalt.length!=16 || tweak.length!=16 || length<0 || length>Limits.TEXT_BYTES || packed.length!=Math.max(3,length))
          throw new IOException("Повреждённое письмо");
        return new Opened(innerSalt,tweak,packed,length);
      }
    } finally { wipe(key,inner); }
  }

  static byte[] ff1(byte[] packed,byte[] key,byte[] tweak,boolean encrypt) {
    byte[] digits=new byte[packed.length*2], output=new byte[digits.length];
    var keyParameter=new KeyParameter(key);
    try {
      for(int i=0;i<packed.length;i++) { digits[2*i]=(byte)((packed[i]>>>4)&15); digits[2*i+1]=(byte)(packed[i]&15); }
      var engine=new FPEFF1Engine();
      engine.init(encrypt,new FPEParameters(keyParameter,16,tweak));
      engine.processBlock(digits,0,digits.length,output,0);
      byte[] result=new byte[packed.length];
      for(int i=0;i<result.length;i++) result[i]=(byte)((output[2*i]<<4)|output[2*i+1]);
      return result;
    } finally { wipe(digits,output,keyParameter.getKey()); }
  }
  private static void wipe(byte[]... arrays) { for(byte[] a:arrays) if(a!=null) Arrays.fill(a,(byte)0); }

  public static final class Opened implements AutoCloseable {
    private final byte[] salt,tweak,ciphertext;
    private final int length;
    private boolean closed;
    private Opened(byte[] salt,byte[] tweak,byte[] ciphertext,int length) {
      this.salt=salt; this.tweak=tweak; this.ciphertext=ciphertext; this.length=length;
    }
    public synchronized String ciphertext() {
      if(closed) throw new IllegalStateException("Письмо закрыто");
      return HexFormat.of().withUpperCase().formatHex(ciphertext);
    }
    public String candidate(char[] code) {
      byte[] localSalt,localTweak,localCipher,key=null,plain=null;
      synchronized(this) {
        if(closed) throw new IllegalStateException("Письмо закрыто");
        localSalt=salt.clone(); localTweak=tweak.clone(); localCipher=ciphertext.clone();
      }
      try {
        key=LetterKdf.derive(code,localSalt,true);
        plain=ff1(localCipher,key,localTweak,false);
        try {
          return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(plain,0,length)).toString();
        } catch(CharacterCodingException e) {
          // Display encoding only. This is not a code verifier: random bytes are shown as hex.
          return HexFormat.of().withUpperCase().formatHex(plain,0,length);
        }
      } finally { wipe(localSalt,localTweak,localCipher,key,plain); }
    }
    @Override public synchronized void close() { closed=true; wipe(salt,tweak,ciphertext); }
    @Override public String toString() { return "OpenedLetter[redacted]"; }
  }
}

