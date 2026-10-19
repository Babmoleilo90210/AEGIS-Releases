package org.securemail.client.ecosystem;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.securemail.client.*;
import org.securemail.client.archive.EncryptedArchive;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

/** Actual Mail-only migration before pairing/unlock; Core never receives the Mail or archive password. */
public final class MailProfileMigration600 {
  public static final class ExternalArchiveRequired extends IOException{private static final long serialVersionUID=1L;public ExternalArchiveRequired(){super("Внешний архив требует отдельного полного переноса. Старый профиль сохранён; автоматическая миграция приостановлена.");}}
  private MailProfileMigration600(){}
  public static Path destination(){return AppPaths.root().resolve("mail600/migrated-profile6").toAbsolutePath().normalize();}
  public static boolean required(ClientConfig config){return Files.isRegularFile(config.storagePath().resolve("state.vault"),LinkOption.NOFOLLOW_LINKS)&&!config.storagePath().toAbsolutePath().normalize().equals(destination().resolve("mail/profile"));}
  public static Path mainArchive(ClientConfig config){return config.storagePath().resolveSibling(config.storagePath().getFileName()+".personal-archive");}
  public static boolean needsArchivePassword(ClientConfig config){return required(config)&&Files.isDirectory(mainArchive(config),LinkOption.NOFOLLOW_LINKS);}
  /** The caller holds the Mail app lock; all other old writers are closed. Old storage is never opened writable. */
  public static ClientConfig beforeOpen(ClientConfig config,char[] mailPassword,char[] archivePassword,BooleanSupplier cancelled)throws IOException {
    if(!required(config))return config;Objects.requireNonNull(cancelled);byte[] key=null;Path auth=null;
    try{
      for(Path p=config.storagePath().toAbsolutePath();p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылка в старом профиле запрещена");
      byte[] salt=AtomicFiles.read(config.storagePath().resolve("salt"),16);try{key=LocalStore.modernVault(config.storagePath())?Secrets.deriveVault(mailPassword,salt):Secrets.derive(mailPassword,salt);}finally{Arrays.fill(salt,(byte)0);}
      // Authenticate a private ciphertext-only minimal copy before performing a potentially large backup.
      Path parent=AppPaths.root().resolve("mail600");AtomicFiles.directory(parent);auth=parent.resolve(".verify-identity-"+UUID.randomUUID());AtomicFiles.directory(auth);
      for(String name:List.of("state.vault","salt","vault-kdf")){Path source=config.storagePath().resolve(name);if(Files.exists(source,LinkOption.NOFOLLOW_LINKS)){if(Files.isSymbolicLink(source)||!Files.isRegularFile(source)||Files.size(source)>(name.equals("state.vault")?2*1024*1024:64))throw new IOException("Формат старого профиля не поддерживается");Files.copy(source,auth.resolve(name));}}
      String account;try(var opened=LocalStore.resume(auth,key,Clock.fixed(Instant.EPOCH,ZoneOffset.UTC),config.maxCiphertext(),config.maxLocalStorage())){account=opened.identity().userId();}
      boolean archive=needsArchivePassword(config);if(archive&&(archivePassword==null||archivePassword.length<12))throw new IOException("Для проверки переноса нужен пароль личного архива");
      Path expectedOldArchive=mainArchive(config).toAbsolutePath().normalize();String expectedAccount=account;
      var result=ProfileMigration600.migrate(config,destination(),AppPaths.root().resolve("mail600/encrypted-migration-backups"),key,(snapshot,candidate)->{
        try(var opened=new LocalStore(candidate.resolve("profile"),mailPassword,Clock.fixed(Instant.EPOCH,ZoneOffset.UTC),config.maxCiphertext(),config.maxLocalStorage())){
          if(!opened.identity().userId().equals(expectedAccount))throw new IOException("Идентичность изменилась при переносе");
          for(var contact:opened.contacts())if(!Identity.id(contact.publicKey()).equals(contact.userId()))throw new IOException("Повреждён ключ контакта");
          for(boolean outgoing:new boolean[]{false,true})for(var item:opened.mailboxIndex(outgoing)){var packet=opened.loadHistory(item.id(),outgoing);if(!Identity.verifyPacket(packet.packet()))throw new IOException("Повреждена подпись сохранённого письма");}
          byte[] preferences=opened.readArchivePreferences();if(preferences!=null)try(var input=new DataInputStream(new ByteArrayInputStream(preferences))){if(input.readInt()!=1)throw new IOException("Неизвестные настройки архива");Path chosen=Path.of(Binary.text(input,4096)).toAbsolutePath().normalize();if(!chosen.equals(expectedOldArchive))throw new ExternalArchiveRequired();}finally{Arrays.fill(preferences,(byte)0);}
          if(archive)try(var checked=EncryptedArchive.open(candidate.resolve("profile.personal-archive"),candidate.resolve(".verified-archive-guards"),archivePassword,true,Clock.fixed(Instant.EPOCH,ZoneOffset.UTC))){checked.verifyAll(EncryptedArchive.QUIET,cancelled);}
          return new ProfileMigration600.Verification(expectedAccount,EnumSet.allOf(ProfileMigration600.Check.class));
        }catch(GeneralSecurityException invalid){throw new IOException("Пароль неверен или перенесённые данные повреждены",invalid);}
      },cancelled);
      if(cancelled.getAsBoolean())throw new InterruptedIOException("Миграция отменена до переключения профиля");Path target=result.profile().resolve("mail/profile"),newArchive=target.resolveSibling("profile.personal-archive");
      // Recreate a verified path-bound archive anchor for the actual destination, never reuse an old-path guard blindly.
      if(archive)try(var checked=EncryptedArchive.open(newArchive,AppPaths.root().resolveSibling("aegis-archive-guards"),archivePassword,true,Clock.systemUTC())){checked.verifyAll(EncryptedArchive.QUIET,cancelled);}
      try(var opened=new LocalStore(target,mailPassword,Clock.fixed(Instant.EPOCH,ZoneOffset.UTC),config.maxCiphertext(),config.maxLocalStorage())){
        byte[] previous=opened.readArchivePreferences();if(previous!=null)try(var input=new DataInputStream(new ByteArrayInputStream(previous))){int schema=input.readInt();Binary.text(input,4096);byte[] remaining=input.readAllBytes();byte[] next=Binary.encode(out->{out.writeInt(schema);Binary.text(out,newArchive.toString());out.write(remaining);});try{opened.writeArchivePreferences(next);}finally{Arrays.fill(next,(byte)0);Arrays.fill(remaining,(byte)0);}}finally{Arrays.fill(previous,(byte)0);}
      }
      if(cancelled.getAsBoolean())throw new InterruptedIOException("Миграция отменена до переключения профиля");ClientConfig migrated=config.withStorage(target);migrated.save(AppPaths.config());return migrated;
    }catch(GeneralSecurityException|IllegalArgumentException invalid){throw new IOException("Не удалось проверить пароль и перенести профиль Почты",invalid);}
    finally{if(key!=null)Arrays.fill(key,(byte)0);if(auth!=null&&Files.exists(auth))try(var paths=Files.walk(auth)){for(Path file:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(file);}}
  }
}
