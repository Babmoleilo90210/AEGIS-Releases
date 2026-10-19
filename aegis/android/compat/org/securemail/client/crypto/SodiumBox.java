package org.securemail.client.crypto;
import java.security.*;
import java.util.*;
/** Android JNI adapter to the same official libsodium sealed-box functions as desktop. */
final class SodiumBox {
 private static final byte[] PUB={0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00};
 private static final byte[] SECRET={0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20};
 static {System.loadLibrary("aegis_sodium");if(initialize()<0)throw new ExceptionInInitializerError("libsodium initialization failed");}
 private static native int initialize();
 private static native byte[] nativeSeal(byte[] key,byte[] rawPublic)throws GeneralSecurityException;
 private static native byte[] nativeOpen(byte[] sealed,byte[] rawPublic,byte[] seed)throws GeneralSecurityException;
 private static byte[] rawPublic(byte[] der)throws GeneralSecurityException{if(der.length!=44||!MessageDigest.isEqual(Arrays.copyOf(der,12),PUB))throw new GeneralSecurityException("Invalid Ed25519 public key");return Arrays.copyOfRange(der,12,44);}
 static byte[] seal(byte[] key,byte[] der)throws GeneralSecurityException{if(key.length!=32)throw new GeneralSecurityException("Only 32-byte message keys");return nativeSeal(key,rawPublic(der));}
 static byte[] open(byte[] sealed,Identity identity)throws GeneralSecurityException{if(sealed.length!=80)throw new GeneralSecurityException("Bad wrapped key");byte[] encoded=identity.privateKey(),seed=null;try{if(encoded.length!=48||!MessageDigest.isEqual(Arrays.copyOf(encoded,16),SECRET))throw new GeneralSecurityException("Unsupported Ed25519 private-key encoding");seed=Arrays.copyOfRange(encoded,16,48);return nativeOpen(sealed,rawPublic(identity.publicKey()),seed);}finally{Arrays.fill(encoded,(byte)0);if(seed!=null)Arrays.fill(seed,(byte)0);}}
}
