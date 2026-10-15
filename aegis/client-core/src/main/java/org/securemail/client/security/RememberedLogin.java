package org.securemail.client.security;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.securemail.client.*;
import org.securemail.client.crypto.Secrets;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

/** Seven-day local unlock plus the relay's existing 12-hour bearer session. No password storage. */
public final class RememberedLogin {
  public static final long LOCAL_AGE=Duration.ofDays(7).toMillis(),RELAY_AGE=Duration.ofHours(12).toMillis();
  private final Path file;private final SystemSecrets secrets;private final Clock clock;
  public record Resume(String nickname,String relay,String token,long createdAt,long expiresAt,long relayExpiresAt,byte[] vaultKey) implements AutoCloseable {
    public Resume{vaultKey=vaultKey.clone();}public byte[] vaultKey(){return vaultKey.clone();}public void close(){Arrays.fill(vaultKey,(byte)0);}
    public boolean relayValid(long now){return !token.isEmpty()&&relayExpiresAt>now;}
  }
  public RememberedLogin(Path profile,SystemSecrets secrets,Clock clock)throws IOException{this.secrets=secrets;this.clock=clock;Path dir=profile.resolve("session");AtomicFiles.directory(dir);file=dir.resolve("resume.enc");}
  public void save(ClientSession session)throws Exception {
    byte[] vault=session.local().sessionUnlockKey();try{save(session.local().nickname(),session.config().relayOnionAddress(),session.network().sessionToken(),vault);}finally{Arrays.fill(vault,(byte)0);}
  }
  void save(String nickname,String relay,String token,byte[] vault)throws Exception {
    Limits.nickname(nickname);Limits.onion(relay);if(!token.matches("[a-f0-9]{64}")||vault.length!=32)throw new IOException("Invalid remembered session");
    long now=clock.millis();byte[] device=Secrets.random(32),nonce=Secrets.random(12);byte[] data=Binary.encode(o->{o.writeInt(0x41525331);Binary.text(o,nickname);Binary.text(o,relay);Binary.text(o,token);o.writeLong(now);o.writeLong(now+LOCAL_AGE);o.writeLong(now+RELAY_AGE);o.writeLong(now);Binary.bytes(o,vault);});
    try{secrets.store(device);AtomicFiles.write(file,encrypt(device,nonce,data));}catch(Exception failure){Files.deleteIfExists(file);try{secrets.clear();}catch(IOException ignored){}throw failure;}finally{Arrays.fill(device,(byte)0);Arrays.fill(data,(byte)0);}
  }
  public Optional<Resume> load(String expectedRelay)throws Exception {
    if(!Files.exists(file))return Optional.empty();byte[] device=secrets.load();if(device==null)return Optional.empty();byte[] data=null;
    try {
      byte[] cipher=AtomicFiles.read(file,4096);if(cipher.length<28)throw new IOException("Invalid remembered session");Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(device,"AES"),new GCMParameterSpec(128,Arrays.copyOf(cipher,12)));c.updateAAD("AEGIS-DEVICE-SESSION-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII));data=c.doFinal(cipher,12,cipher.length-12);
      try(var in=new DataInputStream(new ByteArrayInputStream(data))){if(in.readInt()!=0x41525331)throw new IOException("Invalid remembered session");String nick=Binary.text(in,32),relay=Binary.text(in,62),token=Binary.text(in,64);long created=in.readLong(),expires=in.readLong(),relayExpires=in.readLong(),last=in.readLong();byte[] vault=Binary.bytes(in,32);Binary.end(in);long now=clock.millis();
        try{if(now<last||now<created||now>=expires||expires-created!=LOCAL_AGE||relayExpires-created!=RELAY_AGE||!relay.equals(expectedRelay)||!token.matches("[a-f0-9]{64}")||vault.length!=32){clear();return Optional.empty();}Limits.nickname(nick);Limits.onion(relay);Resume resume=new Resume(nick,relay,token,created,expires,relayExpires,vault);
          byte[] updated=Binary.encode(o->{o.writeInt(0x41525331);Binary.text(o,nick);Binary.text(o,relay);Binary.text(o,token);o.writeLong(created);o.writeLong(expires);o.writeLong(relayExpires);o.writeLong(now);Binary.bytes(o,vault);});try{AtomicFiles.write(file,encrypt(device,Secrets.random(12),updated));}finally{Arrays.fill(updated,(byte)0);}return Optional.of(resume);
        }finally{Arrays.fill(vault,(byte)0);}
      }
    }catch(IOException|GeneralSecurityException|RuntimeException failure){clear();throw failure;}finally{Arrays.fill(device,(byte)0);if(data!=null)Arrays.fill(data,(byte)0);}
  }
  private static byte[] encrypt(byte[] device,byte[] nonce,byte[] plain)throws GeneralSecurityException {
    Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(device,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD("AEGIS-DEVICE-SESSION-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII));byte[] encrypted=c.doFinal(plain),out=new byte[nonce.length+encrypted.length];System.arraycopy(nonce,0,out,0,nonce.length);System.arraycopy(encrypted,0,out,nonce.length,encrypted.length);return out;
  }
  public void clear()throws IOException{Files.deleteIfExists(file);AtomicFiles.syncDirectory(file.getParent());secrets.clear();}
}
