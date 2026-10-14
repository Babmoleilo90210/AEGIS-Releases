package org.securemail.client.archive;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import org.securemail.client.crypto.Secrets;
import org.securemail.protocol.Binary;

/** Standard BC Argon2id, JCA AES-GCM and Tink streaming AEAD. No bespoke cipher. */
final class ArchiveCrypto {
  static final int HEADER_MAGIC=0x41454741,VERSION=1;
  private ArchiveCrypto(){}
  static byte[] aad(String purpose){return ("AEGIS-ARCHIVE/v1/"+purpose).getBytes(StandardCharsets.UTF_8);}
  static byte[] seal(byte[] key,byte[] clear,String purpose)throws GeneralSecurityException {
    byte[] nonce=Secrets.random(12);Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad(purpose));
    byte[] encrypted=c.doFinal(clear),result=new byte[12+encrypted.length];System.arraycopy(nonce,0,result,0,12);System.arraycopy(encrypted,0,result,12,encrypted.length);return result;
  }
  static byte[] open(byte[] key,byte[] sealed,String purpose)throws GeneralSecurityException {
    if(sealed.length<28)throw new GeneralSecurityException("Повреждён архив");Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,sealed,0,12));c.updateAAD(aad(purpose));return c.doFinal(sealed,12,sealed.length-12);
  }
  static StreamingAead stream(byte[] key)throws GeneralSecurityException {return new AesGcmHkdfStreaming(key,"HmacSha256",32,1024*1024,0);}
  record Header(String id,byte[] salt,byte[] passwordWrap,byte[] recoveryWrap){
    byte[] encode()throws IOException {return Binary.encode(o->{o.writeInt(HEADER_MAGIC);o.writeInt(VERSION);Binary.text(o,id);Binary.bytes(o,salt);Binary.bytes(o,passwordWrap);Binary.bytes(o,recoveryWrap);});}
    @Override public String toString(){return "ArchiveHeader[redacted]";}
  }
  static Header header(String id,byte[] key,char[] password,byte[] recovery)throws GeneralSecurityException {
    byte[] salt=Secrets.random(16),derived=Secrets.deriveArchive(password,salt);
    try{return new Header(id,salt,seal(derived,key,id+"/password"),recovery==null?new byte[0]:seal(recovery,key,id+"/recovery"));}finally{Arrays.fill(derived,(byte)0);}
  }
  static Header parse(byte[] encoded)throws IOException {
    if(encoded.length>4096)throw new IOException("Повреждён заголовок архива");
    try(var i=new DataInputStream(new ByteArrayInputStream(encoded))){if(i.readInt()!=HEADER_MAGIC||i.readInt()!=VERSION)throw new IOException("Неподдерживаемый формат архива");String id=Binary.text(i,36);UUID.fromString(id);byte[] salt=Binary.bytes(i,16),pw=Binary.bytes(i,60),recovery=Binary.bytes(i,60);Binary.end(i);if(salt.length!=16||pw.length!=60||recovery.length!=0&&recovery.length!=60)throw new IOException("Повреждён заголовок архива");return new Header(id,salt,pw,recovery);}catch(IllegalArgumentException bad){throw new IOException("Повреждён заголовок архива",bad);}
  }
  static byte[] unlock(Header h,char[] password)throws GeneralSecurityException {byte[] k=Secrets.deriveArchive(password,h.salt());try{return open(k,h.passwordWrap(),h.id()+"/password");}finally{Arrays.fill(k,(byte)0);}}
  static byte[] recover(Header h,char[] encoded)throws GeneralSecurityException {
    if(h.recoveryWrap().length==0)throw new GeneralSecurityException("Восстановление для этого архива не включено");byte[] key=null;
    try{key=Base64.getUrlDecoder().decode(new String(encoded).replace(" ","").replace("\n","").strip());if(key.length!=32)throw new GeneralSecurityException("Некорректный ключ восстановления");return open(key,h.recoveryWrap(),h.id()+"/recovery");}catch(IllegalArgumentException invalid){throw new GeneralSecurityException("Некорректный ключ восстановления",invalid);}finally{if(key!=null)Arrays.fill(key,(byte)0);}
  }
  static String digest(byte[] data)throws GeneralSecurityException {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));}
}
