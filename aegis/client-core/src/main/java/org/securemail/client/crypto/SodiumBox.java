package org.securemail.client.crypto;
import com.sun.jna.*;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
/** Thin bindings to official libsodium. No algorithm implementation in application code. */
final class SodiumBox {
  interface API extends Library {
    int sodium_init();
    int crypto_sign_ed25519_pk_to_curve25519(byte[] x,byte[] ed);
    int crypto_sign_ed25519_sk_to_curve25519(byte[] x,byte[] ed);
    int crypto_box_seal(byte[] out,byte[] plain,long length,byte[] publicKey);
    int crypto_box_seal_open(byte[] out,byte[] cipher,long length,byte[] publicKey,byte[] secretKey);
  }
  private static API load(){
    String home=System.getProperty("aegis.home");
    if(home==null)home=System.getProperty("aegis.native.root");
    if(home==null)throw new IllegalStateException("Bundled crypto directory is not configured");
    Path file=Path.of(home,"native",System.getProperty("os.name").startsWith("Windows")?"libsodium.dll":"libsodium.so").toAbsolutePath();
    if(!Files.isRegularFile(file))throw new IllegalStateException("Bundled libsodium is missing");
    API api=Native.load(file.toString(),API.class);if(api.sodium_init()<0)throw new IllegalStateException("Crypto initialization failed");return api;
  }
  private static final class Holder { static final API API=load(); }
  static byte[] publicKey(byte[] der) throws GeneralSecurityException {
    if(der.length!=44||!Arrays.equals(Arrays.copyOf(der,12),HexFormat.of().parseHex("302a300506032b6570032100")))throw new GeneralSecurityException("Invalid Ed25519 public key");
    byte[] x=new byte[32];if(Holder.API.crypto_sign_ed25519_pk_to_curve25519(x,Arrays.copyOfRange(der,12,44))!=0)throw new GeneralSecurityException("Invalid public point");return x;
  }
  static byte[] seal(byte[] key,byte[] der) throws GeneralSecurityException {byte[] out=new byte[key.length+48];if(Holder.API.crypto_box_seal(out,key,key.length,publicKey(der))!=0)throw new GeneralSecurityException("Key wrapping failed");return out;}
  static byte[] open(byte[] sealed,Identity identity) throws GeneralSecurityException {
    if(sealed.length!=80)throw new GeneralSecurityException("Bad wrapped key");
    byte[] encoded=identity.privateKey(),seed=null,ed=new byte[64],x=new byte[32],out=new byte[32];
    try{
      var privateKey=(EdECPrivateKey)KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
      seed=privateKey.getBytes().orElseThrow(()->new GeneralSecurityException("Key unavailable"));
      System.arraycopy(seed,0,ed,0,32);System.arraycopy(identity.publicKey(),12,ed,32,32);
      if(Holder.API.crypto_sign_ed25519_sk_to_curve25519(x,ed)!=0||Holder.API.crypto_box_seal_open(out,sealed,sealed.length,publicKey(identity.publicKey()),x)!=0)throw new GeneralSecurityException("Не удалось открыть сообщение");return out;
    }finally{Arrays.fill(encoded,(byte)0);Arrays.fill(ed,(byte)0);Arrays.fill(x,(byte)0);if(seed!=null)Arrays.fill(seed,(byte)0);}
  }
}
