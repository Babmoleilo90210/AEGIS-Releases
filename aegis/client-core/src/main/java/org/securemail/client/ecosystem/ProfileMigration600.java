package org.securemail.client.ecosystem;

import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.securemail.client.ClientConfig;
import org.securemail.client.storage.*;

/** Copy/verify/publish migration. Execute in authenticated Mail while every old profile writer is stopped. */
public final class ProfileMigration600 {
  private static final int MAX_FILES=100000,BUFFER=65536;
  private static final long MAX_BYTES=100L*1024*1024*1024;
  private static final byte[] DOMAIN="AEGIS-6-MIGRATION-BACKUP-v1\0".getBytes(StandardCharsets.US_ASCII);
  private ProfileMigration600() {}
  public enum Check { IDENTITY, KEYS, LETTERS, CONTACTS, ARCHIVE, THEMES, SETTINGS }
  public record Verification(String accountId,Set<Check> checked) {
    public Verification {if(accountId==null || accountId.isBlank() || accountId.length()>256 || accountId.codePoints().anyMatch(Character::isISOControl))throw new IllegalArgumentException("Некорректная учётная запись");checked=Set.copyOf(checked);}
  }
  @FunctionalInterface public interface SemanticVerifier {
    /** Open this private verification copy with existing Mail credentials; compare public account ID and expected data, never regenerate keys. Changes in this throwaway verification copy are not published. */
    Verification verify(Path verifiedV5Snapshot,Path candidateMailDirectory) throws IOException;
  }
  public record Result(Path profile,Path encryptedBackup,String accountId,String sourceDigest,boolean alreadyMigrated) {}
  private record Entry(String name,boolean directory,long size,String digest) {}
  /** key is a 32-byte key derived by the existing authenticated Mail KDF; no password or key is written into Core metadata. */
  public static Result migrate(ClientConfig oldConfig,Path destination,Path backupDirectory,byte[] key,SemanticVerifier verifier,BooleanSupplier cancelled) throws IOException {
    Objects.requireNonNull(verifier);Objects.requireNonNull(cancelled);checkKey(key);
    destination=destination.toAbsolutePath().normalize();backupDirectory=backupDirectory.toAbsolutePath().normalize();
    rejectLinks(destination);rejectLinks(backupDirectory);
    if(destination.startsWith(oldConfig.storagePath().toAbsolutePath().normalize()) || backupDirectory.startsWith(oldConfig.storagePath().toAbsolutePath().normalize()) || destination.startsWith(backupDirectory) || backupDirectory.startsWith(destination))throw new IOException("Каталоги миграции пересекаются с исходным хранилищем");
    AtomicFiles.directory(destination.getParent());AtomicFiles.directory(backupDirectory);
    if(Files.exists(destination,LinkOption.NOFOLLOW_LINKS))return existing(destination,key);
    Path work=destination.resolveSibling(".migration-working-"+UUID.randomUUID());AtomicFiles.directory(work);
    Path stage=destination.resolveSibling(".migration-candidate-"+UUID.randomUUID());AtomicFiles.directory(stage);
    byte[] owned=key.clone();Path encrypted=null;
    try {
      cancelled(cancelled);Path snapshot=ProfileSnapshot.createMailMigration600(oldConfig,work);ProfileSnapshot.verify(snapshot,oldConfig);
      List<Entry> entries=inventory(snapshot);String digest=digest(entries);
      encrypted=backupDirectory.resolve("aegis-5-to-6-"+UUID.randomUUID()+".aeb6");
      writeBackup(snapshot,entries,encrypted,owned,digest,cancelled);verifyBackup(encrypted,owned,cancelled);
      copy(snapshot.resolve("vault"),stage.resolve("mail/profile"),cancelled);
      Path archive=snapshot.resolve("personal-archives/main");if(Files.exists(archive,LinkOption.NOFOLLOW_LINKS))copy(archive,stage.resolve("mail/profile.personal-archive"),cancelled);
      Path archives=snapshot.resolve("personal-archives");
      if(Files.isDirectory(archives))try(var list=Files.list(archives)){for(Path file:list.toList())if(!file.getFileName().toString().equals("main"))copy(file,stage.resolve("mail/restored-archives").resolve(file.getFileName()),cancelled);}
      Path app=snapshot.resolve("app");if(Files.exists(app,LinkOption.NOFOLLOW_LINKS))copy(app,stage.resolve("mail/legacy-app"),cancelled);
      Path config=snapshot.resolve("client-config");if(Files.exists(config,LinkOption.NOFOLLOW_LINKS))copy(config,stage.resolve("mail/client-v5.properties"),cancelled);
      // Only this explicit non-secret appearance/settings allowlist is available to Core. All old session and vault material stays under Mail.
      for(String name:List.of("ui-preferences.json","theme.txt","appearance","update-preferences.json","tor-mode.txt","mail-mode.txt")) {
        Path source=app.resolve(name);if(Files.exists(source,LinkOption.NOFOLLOW_LINKS))copy(source,stage.resolve("core/settings").resolve(name),cancelled);
      }
      cancelled(cancelled);String copiedDigest=digest(inventory(stage));
      Path semanticCopy=work.resolve("semantic-mail");copy(stage.resolve("mail"),semanticCopy,cancelled);
      Verification verified=verifier.verify(snapshot,semanticCopy);
      if(!copiedDigest.equals(digest(inventory(stage))))throw new IOException("Проверка не должна изменять перенесённые данные");
      if(!verified.checked().containsAll(EnumSet.allOf(Check.class)))throw new IOException("Не завершена проверка идентичности и данных миграции");
      // Recheck the immutable snapshot after semantic callbacks; a verifier cannot silently change the source being published.
      if(!digest.equals(digest(inventory(snapshot))))throw new IOException("Исходный снимок изменился во время миграции");
      var properties=new Properties();properties.setProperty("schema","6");properties.setProperty("accountId",verified.accountId());properties.setProperty("sourceSha256",digest);
      properties.setProperty("backup",encrypted.toString());properties.setProperty("backupSha256",ComponentInstallation.sha256(encrypted));
      byte[] receipt=encode(properties);AtomicFiles.write(stage.resolve("migration.properties"),receipt);
      AtomicFiles.write(stage.resolve("migration.mac"),LocalIpc.hmac(owned,LocalIpc.combine(DOMAIN,receipt)));
      AtomicFiles.syncDirectory(stage);cancelled(cancelled);
      Files.move(stage,destination,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(destination.getParent());
      return new Result(destination,encrypted,verified.accountId(),digest,false);
    } catch(GeneralSecurityException e){throw new IOException("Не удалось зашифровать резервную копию",e);}
    finally {Arrays.fill(owned,(byte)0);deleteOwned(work);if(Files.exists(stage,LinkOption.NOFOLLOW_LINKS))deleteOwned(stage);}
  }
  private static Result existing(Path destination,byte[] key) throws IOException {
    if(!Files.isDirectory(destination,LinkOption.NOFOLLOW_LINKS))throw new IOException("Каталог назначения уже занят");
    byte[] receipt=AtomicFiles.read(destination.resolve("migration.properties"),16384),mac=AtomicFiles.read(destination.resolve("migration.mac"),32);
    if(mac.length!=32 || !MessageDigest.isEqual(mac,LocalIpc.hmac(key,LocalIpc.combine(DOMAIN,receipt))))throw new IOException("Метка миграции повреждена");
    Properties p=new Properties();p.load(new ByteArrayInputStream(receipt));
    if(!"6".equals(p.getProperty("schema")) || !p.getProperty("sourceSha256","").matches("[a-f0-9]{64}") || p.getProperty("accountId","").isBlank())throw new IOException("Некорректная метка миграции");
    Path backup=Path.of(p.getProperty("backup","")).toAbsolutePath().normalize();rejectLinks(backup);
    if(!p.getProperty("backupSha256","").equals(ComponentInstallation.sha256(backup)))throw new IOException("Резервная копия миграции повреждена");
    verifyBackup(backup,key,()->false);return new Result(destination,backup,p.getProperty("accountId"),p.getProperty("sourceSha256"),true);
  }
  private static void writeBackup(Path source,List<Entry> entries,Path file,byte[] key,String digest,BooleanSupplier cancel) throws IOException,GeneralSecurityException {
    Path tmp=file.resolveSibling(".migration-backup-"+UUID.randomUUID());
    try {
      try(var raw=FileChannel.open(tmp,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.attributes(file.getParent()));
          var stream=java.nio.channels.Channels.newOutputStream(raw)) {
        byte[] aad=LocalIpc.combine(DOMAIN,HexFormat.of().parseHex(digest));DataOutputStream header=new DataOutputStream(stream);header.writeInt(0x41454236);header.write(HexFormat.of().parseHex(digest));header.flush();
        try(var encrypted=new AesGcmHkdfStreaming(key,"HmacSha256",32,1024*1024,0).newEncryptingStream(stream,aad);var out=new DataOutputStream(encrypted)) {
          out.writeInt(entries.size());byte[] buffer=new byte[BUFFER];
          for(Entry entry:entries){cancelled(cancel);out.writeUTF(entry.name());out.writeBoolean(entry.directory());out.writeLong(entry.size());
            if(!entry.directory())try(var input=Files.newInputStream(source.resolve(entry.name()))){long remaining=entry.size();while(remaining>0){cancelled(cancel);int n=input.read(buffer,0,(int)Math.min(remaining,buffer.length));if(n<0)throw new EOFException("Файл снимка усечён");out.write(buffer,0,n);remaining-=n;}if(input.read()!=-1)throw new IOException("Файл снимка вырос");}
          }
        }
      }
      try(var channel=FileChannel.open(tmp,StandardOpenOption.WRITE)){channel.force(true);}Files.move(tmp,file,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(file.getParent());
    } finally {Files.deleteIfExists(tmp);}
  }
  public static String verifyBackup(Path backup,byte[] key,BooleanSupplier cancel) throws IOException {
    return scanBackup(backup,key,cancel,null);
  }
  /** Restore into a new private snapshot directory, then publish atomically. Existing profiles are never overwritten. */
  public static Path restoreBackup(Path backup,Path destination,byte[] key,BooleanSupplier cancel) throws IOException {
    checkKey(key);destination=destination.toAbsolutePath().normalize();rejectLinks(destination);
    if(Files.exists(destination,LinkOption.NOFOLLOW_LINKS))throw new IOException("Восстановление требует нового каталога");
    AtomicFiles.directory(destination.getParent());Path stage=destination.resolveSibling(".migration-restore-"+UUID.randomUUID());AtomicFiles.directory(stage);
    try {scanBackup(backup,key,cancel,stage);cancelled(cancel);Files.move(stage,destination,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(destination.getParent());return destination;}
    finally {if(Files.exists(stage,LinkOption.NOFOLLOW_LINKS))deleteOwned(stage);}
  }
  private static String scanBackup(Path backup,byte[] key,BooleanSupplier cancel,Path restoreRoot) throws IOException {
    checkKey(key);rejectLinks(backup);
    try(var input=Files.newInputStream(backup)) {
      var header=new DataInputStream(input);if(header.readInt()!=0x41454236)throw new IOException("Некорректный формат резервной копии");byte[] expected=header.readNBytes(32);if(expected.length!=32)throw new EOFException();
      try(var decrypted=new AesGcmHkdfStreaming(key,"HmacSha256",32,1024*1024,0).newDecryptingStream(input,LocalIpc.combine(DOMAIN,expected));var in=new DataInputStream(decrypted)) {
        int count=in.readInt();if(count<1||count>MAX_FILES)throw new IOException("Недопустимый размер резервной копии");
        List<Entry> entries=new ArrayList<>(count);Set<String> names=new HashSet<>();long total=0;byte[] buffer=new byte[BUFFER];
        for(int index=0;index<count;index++){cancelled(cancel);String name=in.readUTF();safeName(name);if(!names.add(name))throw new IOException("Повторный путь резервной копии");boolean dir=in.readBoolean();long size=in.readLong();if(size<0 || size>MAX_BYTES || dir&&size!=0 || (total=Math.addExact(total,size))>MAX_BYTES)throw new IOException("Превышен размер резервной копии");MessageDigest hash=MessageDigest.getInstance("SHA-256");long remaining=size;
          Path restored=restoreRoot==null?null:restoreRoot.resolve(name).normalize();
          if(restored!=null){if(!restored.startsWith(restoreRoot))throw new IOException("Выход за каталог восстановления запрещён");if(dir)AtomicFiles.directory(restored);else AtomicFiles.directory(restored.getParent());}
          try(FileChannel target=restored==null||dir?null:FileChannel.open(restored,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.attributes(restored.getParent()));
              OutputStream sink=target==null?OutputStream.nullOutputStream():java.nio.channels.Channels.newOutputStream(target)) {
            while(remaining>0){cancelled(cancel);int n=in.read(buffer,0,(int)Math.min(remaining,buffer.length));if(n<0)throw new EOFException();hash.update(buffer,0,n);sink.write(buffer,0,n);remaining-=n;}
            if(target!=null)target.force(true);
          }
          entries.add(new Entry(name,dir,size,dir?"":HexFormat.of().formatHex(hash.digest())));
        }
        if(in.read()!=-1)throw new IOException("Лишние данные резервной копии");String actual=digest(entries);if(!MessageDigest.isEqual(expected,HexFormat.of().parseHex(actual)))throw new IOException("Проверка резервной копии не пройдена");return actual;
      }
    }catch(GeneralSecurityException|ArithmeticException e){throw new IOException("Проверка резервной копии не пройдена",e);}
  }
  private static List<Entry> inventory(Path root) throws IOException {
    List<Entry> entries=new ArrayList<>();long total=0;
    try(var walk=Files.walk(root)){for(Path path:walk.sorted().toList()){
      if(path.equals(root))continue;rejectLinks(path);String name=root.relativize(path).toString().replace('\\','/');safeName(name);boolean dir=Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS);
      if(!dir&&!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Недопустимый объект снимка");long size=dir?0:Files.size(path);total+=size;if(entries.size()>=MAX_FILES || total>MAX_BYTES)throw new IOException("Слишком большой профиль для миграции");entries.add(new Entry(name,dir,size,dir?"":ComponentInstallation.sha256(path)));
    }}entries.sort(Comparator.comparing(Entry::name));return List.copyOf(entries);
  }
  private static String digest(List<Entry> entries) throws IOException {
    try{MessageDigest digest=MessageDigest.getInstance("SHA-256");String previous="";for(Entry entry:entries){if(entry.name().compareTo(previous)<=0)throw new IOException("Некорректный порядок резервной копии");previous=entry.name();digest.update(entry.name().getBytes(StandardCharsets.UTF_8));digest.update((byte)0);digest.update((byte)(entry.directory()?1:2));digest.update(LocalIpc.longBytes(entry.size()));digest.update(entry.digest().getBytes(StandardCharsets.US_ASCII));digest.update((byte)0);}return HexFormat.of().formatHex(digest.digest());}
    catch(GeneralSecurityException e){throw new IOException(e);}
  }
  private static void copy(Path source,Path target,BooleanSupplier cancel) throws IOException {
    cancelled(cancel);rejectLinks(source);rejectLinks(target);if(Files.isDirectory(source,LinkOption.NOFOLLOW_LINKS)){
      AtomicFiles.directory(target);try(var list=Files.list(source)){for(Path child:list.toList())copy(child,target.resolve(child.getFileName()),cancel);}AtomicFiles.syncDirectory(target);
    }else if(Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS)){
      AtomicFiles.directory(target.getParent());String before=ComponentInstallation.sha256(source);try(var input=Files.newInputStream(source);var out=FileChannel.open(target,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.attributes(target.getParent()))){byte[] buffer=new byte[BUFFER];int n;while((n=input.read(buffer))!=-1){cancelled(cancel);var bytes=java.nio.ByteBuffer.wrap(buffer,0,n);while(bytes.hasRemaining())out.write(bytes);}out.force(true);}
      if(!before.equals(ComponentInstallation.sha256(target)) || !before.equals(ComponentInstallation.sha256(source)))throw new IOException("Копия профиля не прошла проверку");
    }else throw new IOException("Недопустимый объект профиля");
  }
  private static void safeName(String name) throws IOException {if(name.isBlank()||name.length()>4096||name.startsWith("/")||name.contains("\\")||name.contains(":")||name.codePoints().anyMatch(Character::isISOControl))throw new IOException("Некорректный путь резервной копии");for(String part:name.split("/",-1))if(part.isEmpty()||part.equals(".")||part.equals(".."))throw new IOException("Выход за каталог резервной копии запрещён");}
  private static void rejectLinks(Path path) throws IOException {for(Path current=path.toAbsolutePath().normalize();current!=null;current=current.getParent())if(Files.isSymbolicLink(current))throw new IOException("Ссылки в профиле миграции запрещены");}
  private static byte[] encode(Properties value) throws IOException {var bytes=new ByteArrayOutputStream();value.store(bytes,"AEGIS 6 verified migration; no secret keys");return bytes.toByteArray();}
  private static void checkKey(byte[] key){if(key==null||key.length!=32)throw new IllegalArgumentException("Резервной копии требуется отдельный 256-битный ключ");}
  private static void cancelled(BooleanSupplier cancel) throws IOException {if(cancel.getAsBoolean()||Thread.currentThread().isInterrupted())throw new java.io.InterruptedIOException("Миграция отменена; старый профиль сохранён");}
  private static void deleteOwned(Path directory) throws IOException {if(!Files.exists(directory,LinkOption.NOFOLLOW_LINKS))return;try(var walk=Files.walk(directory)){for(Path path:walk.sorted(Comparator.reverseOrder()).toList()){if(Files.isSymbolicLink(path))throw new IOException("Неожиданная ссылка во временной копии");Files.delete(path);}}}
}
