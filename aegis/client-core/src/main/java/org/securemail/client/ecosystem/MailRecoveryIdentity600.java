package org.securemail.client.ecosystem;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.securemail.client.*;
import org.securemail.client.storage.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Mail-only identity recovery. Never opens or changes an archive and never returns a private key/password to Core. */
public final class MailRecoveryIdentity600 implements AutoCloseable {
  private final LocalStore mail;private final Path temporary;private boolean closed;
  private MailRecoveryIdentity600(LocalStore mail,Path temporary){this.mail=mail;this.temporary=temporary;}
  public LocalStore mail(){if(closed)throw new IllegalStateException("Идентичность закрыта");return mail;}
  /** Read an existing identity through a private copy. LocalStore cleanup/checkpoint must never mutate the original profile. */
  public static MailRecoveryIdentity600 openExisting(ClientConfig config,char[] password,String expectedAccount,BooleanSupplier cancelled)throws Exception {
    MailFilesystemBoundary600.require(config);IdentityProtocol.idValue(expectedAccount);Path source=config.storagePath().toAbsolutePath().normalize();rejectLinks(source);Path work=workingRoot().resolve(".existing-"+UUID.randomUUID());bounded(work.getParent(),32);AtomicFiles.directory(work);LocalStore opened=null;boolean ready=false;
    try{check(cancelled);copy(source.resolve("salt"),work.resolve("salt"),16);copy(source.resolve("state.vault"),work.resolve("state.vault"),2*1024*1024+128);if(Files.exists(source.resolve("vault-kdf"),LinkOption.NOFOLLOW_LINKS))copy(source.resolve("vault-kdf"),work.resolve("vault-kdf"),64);
      Path recovery=source.resolve("lifecycle/identity6-recovery-root-v1.enc");if(Files.exists(recovery,LinkOption.NOFOLLOW_LINKS)){AtomicFiles.directory(work.resolve("lifecycle"));copy(recovery,work.resolve("lifecycle/identity6-recovery-root-v1.enc"),1152);}
      check(cancelled);opened=new LocalStore(work,password,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage());verify(opened,expectedAccount);check(cancelled);ready=true;return new MailRecoveryIdentity600(opened,work);
    }finally{if(!ready){if(opened!=null)try{opened.close();}catch(IOException ignored){}deleteOwned(work);}}
  }
  /** Explicitly restore the existing encrypted identity-backup format into a new verified profile. Original data/backup remain intact. */
  public static MailRecoveryIdentity600 restoreBackup(ClientConfig config,Path backup,char[] password,String expectedAccount,BooleanSupplier cancelled)throws Exception {
    MailFilesystemBoundary600.require(config);IdentityProtocol.idValue(expectedAccount);rejectLinks(backup);Path parent=AppPaths.root().resolve("mail600/recovered-identities");rejectLinks(parent);AtomicFiles.directory(parent);bounded(parent,8);Path stage=parent.resolve(".candidate-"+UUID.randomUUID()),target=parent.resolve("identity-"+expectedAccount.substring(0,12)+"-"+UUID.randomUUID());LocalStore opened=null;boolean published=false;
    try{MailFilesystemBoundary600.require(config.withStorage(stage));MailFilesystemBoundary600.require(config.withStorage(target));check(cancelled);LocalStore.restoreIdentity(backup,stage,password,config.maxCiphertext(),config.maxLocalStorage());try(var verified=new LocalStore(stage,password,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage())){verify(verified,expectedAccount);verified.checkpoint();}check(cancelled);
      // Preserve only public/ordinary configuration; existing root/archive/profile files are untouched.
      Path previous=AppPaths.config();if(Files.exists(previous,LinkOption.NOFOLLOW_LINKS)){rejectLinks(previous);Path backups=workingRoot().resolve("configuration-backups");AtomicFiles.directory(backups);bounded(backups,32);AtomicFiles.write(backups.resolve("config-"+UUID.randomUUID()+".properties"),AtomicFiles.read(previous,65536));}
      Files.move(stage,target,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(parent);published=true;opened=new LocalStore(target,password,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage());verify(opened,expectedAccount);check(cancelled);MailFilesystemBoundary600.require(config.withStorage(target));config.withStorage(target).save(AppPaths.config());return new MailRecoveryIdentity600(opened,null);
    }catch(Exception failure){if(opened!=null)try{opened.close();}catch(IOException ignored){}if(!published)deleteOwned(stage);/* A published verified encrypted identity is kept even if config save/consent is interrupted. */throw failure;}
  }
  /** Sign only the standard device-recovery domain after the Mail UI's pinned live inspection and explicit consent. */
  public synchronized MailPairing600.DeviceRecoveryResult approve(IdentityProtocol.DeviceRecovery recovery,MailRecoveryKey600 independent)throws GeneralSecurityException {
    LocalStore store=mail();if(recovery.expiresAt<=System.currentTimeMillis()||recovery.expiresAt>System.currentTimeMillis()+300000||!store.identity().userId().equals(recovery.accountId)||independent==null||MessageDigest.isEqual(store.identity().publicKey(),independent.publicKey()))throw new GeneralSecurityException("Материалы или срок восстановления не подходят");byte[] fixed=IdentityProtocol.deviceRecoveryBytes(recovery);return new MailPairing600.DeviceRecoveryResult(store.identity().publicKey(),independent.publicKey(),recovery,store.identity().sign(fixed),independent.approveRecovery(recovery.audience,recovery.accountId,recovery.challenge,recovery.newDevicePublic(),recovery.expiresAt));
  }
  private static Path workingRoot()throws IOException{Path root=AppPaths.root().resolve("mail600/recovery-work");rejectLinks(root);AtomicFiles.directory(root);return root;}
  private static void bounded(Path directory,int maximum)throws IOException{int count=0;try(var files=Files.newDirectoryStream(directory)){for(Path file:files){if(Files.isSymbolicLink(file)||++count>=maximum)throw new IOException("Достигнут лимит защищённых копий восстановления. Откройте ранее восстановленную идентичность вместо создания новой копии.");}}}
  private static void verify(LocalStore mail,String expected)throws GeneralSecurityException{if(mail.identity()==null||!mail.identity().userId().equals(expected)||!IdentityProtocol.id(mail.identity().publicKey()).equals(expected))throw new GeneralSecurityException("Резервная копия принадлежит другому аккаунту");}
  private static void copy(Path source,Path destination,int maximum)throws IOException{rejectLinks(source);if(!Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS))throw new IOException("Файл идентичности отсутствует");byte[] bytes=AtomicFiles.read(source,maximum);try{AtomicFiles.write(destination,bytes);}finally{Arrays.fill(bytes,(byte)0);}}
  private static void rejectLinks(Path path)throws IOException{for(Path p=path.toAbsolutePath();p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылка в пути идентичности запрещена");}
  private static void check(BooleanSupplier cancelled)throws InterruptedIOException{if(cancelled==null||cancelled.getAsBoolean()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("Восстановление отменено");}
  private static void deleteOwned(Path root)throws IOException{if(!Files.exists(root,LinkOption.NOFOLLOW_LINKS))return;try(var files=Files.walk(root)){for(Path path:files.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
  @Override public synchronized void close()throws IOException{if(closed)return;closed=true;IOException failure=null;try{mail.close();}catch(IOException e){failure=e;}if(temporary!=null)try{deleteOwned(temporary);}catch(IOException e){if(failure==null)failure=e;else failure.addSuppressed(e);}if(failure!=null)throw failure;}
}
