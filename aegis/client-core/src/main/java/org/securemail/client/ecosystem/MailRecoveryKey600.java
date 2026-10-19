package org.securemail.client.ecosystem;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.securemail.client.crypto.Secrets;
import org.securemail.client.storage.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Independent recovery identity, stored only in the existing encrypted Mail vault. Core gets its public key only. */
public final class MailRecoveryKey600 implements AutoCloseable {
  private static final String EXTENSION="identity6-recovery-root-v1";
  private static final byte[] DOMAIN="AEGIS-IDENTITY-RECOVERY-EXPORT/v1".getBytes(StandardCharsets.US_ASCII);
  private final KeyPair key;private boolean closed;
  private MailRecoveryKey600(KeyPair key){this.key=key;}
  /** Recovery must never generate or replace an independent registered key. */
  public static Optional<MailRecoveryKey600> loadExisting(LocalStore mail)throws IOException,GeneralSecurityException {
    byte[] value=mail.readExtension(EXTENSION,1024);if(value==null)return Optional.empty();try{var existing=new MailRecoveryKey600(decode(value));if(IdentityProtocol.id(existing.publicKey()).equals(mail.identity().userId())){existing.close();throw new GeneralSecurityException("Ключ восстановления должен быть независимым");}return Optional.of(existing);}finally{Arrays.fill(value,(byte)0);}
  }
  public static MailRecoveryKey600 loadOrCreate(LocalStore mail)throws IOException,GeneralSecurityException {
    byte[] value=mail.readExtension(EXTENSION,1024);
    if(value!=null)try{return new MailRecoveryKey600(decode(value));}finally{Arrays.fill(value,(byte)0);}
    KeyPair pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    if(IdentityProtocol.id(pair.getPublic().getEncoded()).equals(mail.identity().userId()))throw new GeneralSecurityException("Ключи восстановления должны быть независимыми");
    byte[] encoded=encode(pair);try{mail.writeExtension(EXTENSION,encoded,1024);mail.checkpoint();}finally{Arrays.fill(encoded,(byte)0);}
    return new MailRecoveryKey600(pair);
  }
  public synchronized byte[] publicKey(){ensureOpen();return key.getPublic().getEncoded();}
  public synchronized void exportEncrypted(Path destination,char[] exportPassword,String accountId)throws IOException,GeneralSecurityException {
    ensureOpen();IdentityProtocol.idValue(accountId);if(exportPassword==null||exportPassword.length<12)throw new IllegalArgumentException("Пароль набора восстановления должен содержать не менее 12 символов");
    destination=destination.toAbsolutePath().normalize();for(Path p=destination;p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылки в пути набора восстановления запрещены");
    if(!Files.isDirectory(destination.getParent(),LinkOption.NOFOLLOW_LINKS))throw new IOException("Папка экспорта не найдена");byte[] salt=Secrets.random(16),nonce=Secrets.random(12),derived=Secrets.deriveArchive(exportPassword,salt),plain=encode(key);
    try {
      Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(derived,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(LocalIpc.combine(DOMAIN,accountId.getBytes(StandardCharsets.US_ASCII)));
      byte[] encrypted=cipher.doFinal(plain);var bytes=new ByteArrayOutputStream();var data=new DataOutputStream(bytes);data.writeInt(0x41455236);data.writeUTF(accountId);data.write(salt);data.write(nonce);data.writeInt(encrypted.length);data.write(encrypted);
      try(var file=FileChannel.open(destination,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.exportAttributes(destination.getParent()))){var buffer=java.nio.ByteBuffer.wrap(bytes.toByteArray());while(buffer.hasRemaining())file.write(buffer);file.force(true);}AtomicFiles.syncDirectory(destination.getParent());
    }finally{Arrays.fill(derived,(byte)0);Arrays.fill(plain,(byte)0);}
  }
  public static MailRecoveryKey600 importEncrypted(Path source,char[] password,String expectedAccount)throws IOException,GeneralSecurityException {
    IdentityProtocol.idValue(expectedAccount);for(Path p=source.toAbsolutePath();p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылки в пути набора восстановления запрещены");if(!Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS))throw new IOException("Набор восстановления не найден");byte[] bytes=AtomicFiles.read(source,2048),plain=null,derived=null;
    try(var data=new DataInputStream(new ByteArrayInputStream(bytes))){if(data.readInt()!=0x41455236||!data.readUTF().equals(expectedAccount))throw new IOException("Набор восстановления принадлежит другой учётной записи");byte[] salt=data.readNBytes(16),nonce=data.readNBytes(12);int length=data.readInt();if(salt.length!=16||nonce.length!=12||length<16||length>1024)throw new IOException("Некорректный набор восстановления");byte[] encrypted=data.readNBytes(length);if(encrypted.length!=length||data.read()!=-1)throw new IOException("Некорректный набор восстановления");derived=Secrets.deriveArchive(password,salt);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(derived,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(LocalIpc.combine(DOMAIN,expectedAccount.getBytes(StandardCharsets.US_ASCII)));plain=cipher.doFinal(encrypted);return new MailRecoveryKey600(decode(plain));}
    finally{Arrays.fill(bytes,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);if(derived!=null)Arrays.fill(derived,(byte)0);}
  }
  /** Fixed recovery domain only; never exposes a generic signing oracle or the private key. */
  public synchronized byte[] approveRecovery(String audience,String accountId,String challenge,byte[] newDevicePublic,long expiresAt){ensureOpen();return IdentityProtocol.sign(key.getPrivate(),IdentityProtocol.recovery(audience,accountId,challenge,newDevicePublic,expiresAt));}
  private static byte[] encode(KeyPair key)throws IOException {var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.writeUTF("AEGIS-MAIL-RECOVERY-KEY/v1");byte[] pub=key.getPublic().getEncoded(),privateKey=key.getPrivate().getEncoded();try{out.writeInt(pub.length);out.write(pub);out.writeInt(privateKey.length);out.write(privateKey);return bytes.toByteArray();}finally{Arrays.fill(privateKey,(byte)0);}}
  private static KeyPair decode(byte[] bytes)throws IOException,GeneralSecurityException {try(var in=new DataInputStream(new ByteArrayInputStream(bytes))){if(!in.readUTF().equals("AEGIS-MAIL-RECOVERY-KEY/v1")||in.readInt()!=44)throw new IOException("Некорректный ключ восстановления");byte[] pub=in.readNBytes(44);int size=in.readInt();if(pub.length!=44||size<48||size>256)throw new IOException("Некорректный ключ восстановления");byte[] encoded=in.readNBytes(size);try{if(encoded.length!=size||in.read()!=-1)throw new IOException("Некорректный ключ восстановления");PrivateKey secret=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));byte[] test="AEGIS-RECOVERY-KEY-CHECK/v1".getBytes(StandardCharsets.US_ASCII);if(!IdentityProtocol.verify(pub,test,IdentityProtocol.sign(secret,test)))throw new GeneralSecurityException("Ключи восстановления не совпадают");return new KeyPair(IdentityProtocol.publicKey(pub),secret);}finally{Arrays.fill(encoded,(byte)0);}}}
  private void ensureOpen(){if(closed)throw new IllegalStateException("Ключ восстановления закрыт");}
  @Override public synchronized void close(){if(closed)return;closed=true;try{key.getPrivate().destroy();}catch(javax.security.auth.DestroyFailedException ignored){/* Provider/JVM limitations: never promise complete memory erasure. */}}
  @Override public String toString(){return "MailRecoveryKey600[redacted]";}
}
