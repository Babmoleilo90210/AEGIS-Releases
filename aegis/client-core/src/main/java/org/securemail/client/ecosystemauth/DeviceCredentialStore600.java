package org.securemail.client.ecosystemauth;

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.securemail.client.crypto.Secrets;
import org.securemail.client.storage.AtomicFiles;

/** Password-protected Core device key. Never reads a Mail vault or stores an account root private key. */
public final class DeviceCredentialStore600 {
  private static final byte[] MAGIC="AEGIS-CORE-DEVICE-VAULT/1\n".getBytes(StandardCharsets.US_ASCII);
  private final Path file;
  public DeviceCredentialStore600(Path file){this.file=Objects.requireNonNull(file).toAbsolutePath().normalize();}
  public boolean exists(){return Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(file);}
  /** First enrollment never overwrites a previous device identity. */
  public synchronized void create(DeviceCredentials600 credentials,char[] password)throws IOException {
    if(Files.exists(file,LinkOption.NOFOLLOW_LINKS))throw new IOException("Устройство уже настроено");
    checkParents();AtomicFiles.directory(file.getParent());
    byte[] salt=Secrets.random(16),nonce=Secrets.random(12),key=null,plain=null,sealed=null;
    Path staged=file.resolveSibling(file.getFileName()+"."+UUID.randomUUID()+".pending");
    try {
      key=Secrets.deriveDevice(password,salt);plain=credentials.encode();
      Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(MAGIC);sealed=cipher.doFinal(plain);
      ByteBuffer output=ByteBuffer.allocate(MAGIC.length+16+12+sealed.length);output.put(MAGIC).put(salt).put(nonce).put(sealed);AtomicFiles.write(staged,output.array());
      // CREATE_NEW hard-link publication cannot silently replace a concurrently enrolled device.
      Files.createLink(file,staged);
      AtomicFiles.syncDirectory(file.getParent());
    }catch(GeneralSecurityException|IllegalArgumentException invalid){throw new IOException("Не удалось защитить ключ устройства",invalid);}
    finally{Files.deleteIfExists(staged);wipe(salt,nonce,key,plain,sealed);}
  }
  public DeviceCredentials600 unlock(char[] password)throws IOException {
    checkParents();byte[] encoded=AtomicFiles.read(file,1024),salt=null,nonce=null,key=null,plain=null;
    try {
      if(encoded.length<MAGIC.length+16+12+16||!Arrays.equals(Arrays.copyOf(encoded,MAGIC.length),MAGIC))throw new IOException("Повреждено хранилище устройства");
      ByteBuffer in=ByteBuffer.wrap(encoded);in.position(MAGIC.length);salt=new byte[16];nonce=new byte[12];in.get(salt).get(nonce);byte[] sealed=new byte[in.remaining()];in.get(sealed);
      try{key=Secrets.deriveDevice(password,salt);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(MAGIC);plain=cipher.doFinal(sealed);return DeviceCredentials600.decode(plain);}finally{Arrays.fill(sealed,(byte)0);}
    }catch(GeneralSecurityException|IllegalArgumentException invalid){throw new IOException("Пароль неверен или хранилище устройства повреждено",invalid);}
    finally{wipe(encoded,salt,nonce,key,plain);}
  }
  /** Correct PUBLIC recovery metadata only after the caller verified a successful pinned recovery receipt.
   * The account public key and exact device private key are preserved; the previous encrypted vault remains. */
  synchronized void updateRecoveryPublic(String expectedAccount,String expectedDevice,byte[] recoveryPublic,char[] password)throws IOException {
    checkParents();Path staged=file.resolveSibling(file.getFileName()+"."+UUID.randomUUID()+".recovery-pending"),backup=file.resolveSibling(file.getFileName()+"."+UUID.randomUUID()+".before-recovery.encrypted");boolean published=false;
    try(var current=unlock(password)){
      if(!current.accountId().equals(expectedAccount)||!current.deviceId().equals(expectedDevice))throw new IOException("Хранилище относится к другому устройству");
      if(Arrays.equals(current.recoveryPublic(),recoveryPublic))return;
      try(var updated=current.withRecoveryPublic(recoveryPublic)){
        var temporary=new DeviceCredentialStore600(staged);temporary.create(updated,password);
        try(var verified=temporary.unlock(password)){if(!verified.accountId().equals(expectedAccount)||!verified.deviceId().equals(expectedDevice)||!Arrays.equals(verified.recoveryPublic(),recoveryPublic))throw new IOException("Проверка публичных данных восстановления не пройдена");}
        Files.createLink(backup,file);AtomicFiles.syncDirectory(file.getParent());
        published=true;AtomicFiles.write(file,AtomicFiles.read(staged,1024));
        try(var verified=unlock(password)){if(!verified.accountId().equals(expectedAccount)||!verified.deviceId().equals(expectedDevice)||!Arrays.equals(verified.recoveryPublic(),recoveryPublic))throw new IOException("Проверка обновлённого хранилища не пройдена");}
      }catch(IOException|RuntimeException failure){if(published&&Files.isRegularFile(backup,LinkOption.NOFOLLOW_LINKS))try{AtomicFiles.write(file,AtomicFiles.read(backup,1024));}catch(IOException restore){failure.addSuppressed(restore);}throw failure;}
    }finally{Files.deleteIfExists(staged);}
  }
  private void checkParents()throws IOException {for(Path path=file;path!=null;path=path.getParent())if(Files.isSymbolicLink(path))throw new IOException("Ссылки в пути хранилища устройства запрещены");}
  private static void wipe(byte[]... values){for(byte[] value:values)if(value!=null)Arrays.fill(value,(byte)0);}
}
