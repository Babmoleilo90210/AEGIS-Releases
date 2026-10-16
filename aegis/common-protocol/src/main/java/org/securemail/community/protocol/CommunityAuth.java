package org.securemail.community.protocol;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/** Typed application message signatures using JCA Ed25519/SHA-256.
 * This does not replace Tor or define a new cipher. Exact HTTP body bytes are bound
 * to one service identity and request nonce before JSON is interpreted.
 */
public final class CommunityAuth {
  public static final int MAX_BODY=8*1024*1024;
  private CommunityAuth(){}
  public static String id(byte[] encoded){return HexFormat.of().formatHex(digest(encoded));}
  public static byte[] digest(byte[] bytes){try{return MessageDigest.getInstance("SHA-256").digest(bytes);}catch(GeneralSecurityException e){throw new IllegalStateException(e);}}
  public static PublicKey publicKey(byte[] bytes)throws GeneralSecurityException{
    if(bytes.length!=44)throw new GeneralSecurityException("Identity key length");
    PublicKey key=KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(bytes));
    if(!MessageDigest.isEqual(key.getEncoded(),bytes))throw new GeneralSecurityException("Noncanonical identity key");return key;
  }
  public static byte[] sign(PrivateKey key,byte[] bytes)throws GeneralSecurityException{
    Signature s=Signature.getInstance("Ed25519");s.initSign(key);s.update(bytes);return s.sign();
  }
  public static boolean verify(byte[] key,byte[] bytes,byte[] signature){
    try{if(signature.length!=64)return false;Signature s=Signature.getInstance("Ed25519");s.initVerify(publicKey(key));s.update(bytes);return s.verify(signature);}catch(GeneralSecurityException|RuntimeException e){return false;}
  }
  public static byte[] requestBytes(String audience,long time,String nonce,byte[] body)throws IOException{
    return encode("AEGIS-COMMUNITY-REQUEST/v1",audience,nonce,time,body);
  }
  public static byte[] responseBytes(String audience,String nonce,byte[] body)throws IOException{
    return encode("AEGIS-COMMUNITY-RESPONSE/v1",audience,nonce,0,body);
  }
  private static byte[] encode(String domain,String audience,String nonce,long time,byte[] body)throws IOException{
    if(audience==null||!audience.matches("[a-f0-9]{64}")||nonce==null||!nonce.matches("[A-Za-z0-9_-]{22,86}")||time<0||body.length>MAX_BODY)throw new IOException("Invalid signed envelope");
    var bytes=new ByteArrayOutputStream();try(var out=new DataOutputStream(bytes)){
      out.writeUTF(domain);out.writeUTF("POST /api/v1");out.writeUTF(audience);out.writeUTF(nonce);out.writeLong(time);out.writeInt(body.length);out.write(digest(body));
    }return bytes.toByteArray();
  }
  public static String nonce(){byte[] n=new byte[32];new SecureRandom().nextBytes(n);return Base64.getUrlEncoder().withoutPadding().encodeToString(n);}
}
