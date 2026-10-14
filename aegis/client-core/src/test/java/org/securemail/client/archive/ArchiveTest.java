package org.securemail.client.archive;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.securemail.client.storage.AtomicFiles;

final class ArchiveTest {
  @TempDir Path temporary;
  private final char[] pass="Synthetic archive password 150".toCharArray();
  private Path root(){return temporary.resolve("archive");}private Path guards(){return temporary.resolve("guards");}
  private EncryptedArchive create()throws Exception{return EncryptedArchive.create(root(),guards(),pass,false,Clock.systemUTC()).archive();}
  @Test void createWrongPasswordAndNoRecovery()throws Exception {
    try(var a=create()){assertTrue(a.entries().isEmpty());assertFalse(a.locked());}
    assertThrows(GeneralSecurityException.class,()->EncryptedArchive.open(root(),guards(),"Wrong password 150".toCharArray(),false,Clock.systemUTC()));
    try(var a=EncryptedArchive.open(root(),guards(),pass,false,Clock.systemUTC())){assertTrue(a.entries().isEmpty());}
    assertThrows(GeneralSecurityException.class,()->EncryptedArchive.recover(root(),guards(),new char[43],false,Clock.systemUTC()));
  }
  @Test void separatePasswordChangeKeepsCiphertextAndRecovery()throws Exception {
    var created=EncryptedArchive.create(root(),guards(),pass,true,Clock.systemUTC());char[] recovery=created.recoveryKey();String id;
    try(var a=created.archive()){
      id=a.importBytes("private.txt","text","Private payload".getBytes(StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false).id();
      byte[] before=Files.readAllBytes(root().resolve("objects/"+id+".bin"));a.changePassword("A different archive password".toCharArray());assertArrayEquals(before,Files.readAllBytes(root().resolve("objects/"+id+".bin")));
    }
    assertThrows(GeneralSecurityException.class,()->EncryptedArchive.open(root(),guards(),pass,false,Clock.systemUTC()));
    try(var a=EncryptedArchive.recover(root(),guards(),recovery,false,Clock.systemUTC())){assertEquals("Private payload",new String(a.previewBytes(id,1024),StandardCharsets.UTF_8));}
    Arrays.fill(recovery,'\0');
  }
  @Test void filenamesFoldersTagsIndexAndContentAreEncryptedAtRest()throws Exception {
    try(var a=create()){
      var f=a.folder("","PrivateFolderName");var item=a.importBytes("PrivateFileName.txt","text","TOP SECRET: КИРИЛЛИЦА контрольная строка".getBytes(StandardCharsets.UTF_8),f.id(),false,EncryptedArchive.QUIET,()->false);a.metadata(item.id(),f.id(),item.name(),List.of("PrivateTagName"),true);
      assertEquals(1,a.search(new EncryptedArchive.Filter("кириллица",f.id(),"text",0,Long.MAX_VALUE,true,false,true),EncryptedArchive.QUIET,()->false).size());
      a.close(); // File locks are mandatory on NTFS; inspect the actual locked archive on both OSes.
      try(var files=Files.walk(root())){for(Path p:files.filter(Files::isRegularFile).toList()){String bytes=new String(Files.readAllBytes(p),StandardCharsets.ISO_8859_1);for(String secret:List.of("PrivateFolderName","PrivateFileName","PrivateTagName","TOP SECRET")){assertFalse(p.toString().contains(secret));assertFalse(bytes.contains(secret));}}}
    }
  }
  @Test void foldersMoveTrashPurgeAndCycles()throws Exception {
    try(var a=create()){
      var f=a.folder("","one");var nested=a.folder(f.id(),"two");assertThrows(IOException.class,()->a.metadata(f.id(),nested.id(),"one",List.of(),false));
      var e=a.importBytes("letter.txt","letter","Letter fixture".getBytes(StandardCharsets.UTF_8),nested.id(),false,EncryptedArchive.QUIET,()->false);a.trash(f.id(),true);assertTrue(a.entry(e.id()).trash());a.trash(f.id(),false);assertFalse(a.entry(e.id()).trash());a.trash(f.id(),true);a.purge(f.id());assertTrue(a.entries().isEmpty());assertFalse(Files.exists(root().resolve("objects/"+e.id()+".bin")));
    }
  }
  @Test void ciphertextTamperingAndIndexRepair()throws Exception {
    try(var a=create()){
      var e=a.importBytes("read.txt","text","Index term needle".getBytes(StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false);Path index=root().resolve("objects/"+e.id()+".idx");byte[] data=Files.readAllBytes(index);data[data.length-1]^=1;Files.write(index,data);
      assertThrows(EncryptedArchive.IndexDamaged.class,()->a.search(new EncryptedArchive.Filter("needle","","",0,Long.MAX_VALUE,false,false,true),EncryptedArchive.QUIET,()->false));a.rebuildIndex(EncryptedArchive.QUIET,()->false);assertEquals(1,a.search(new EncryptedArchive.Filter("needle","","",0,Long.MAX_VALUE,false,false,true),EncryptedArchive.QUIET,()->false).size());
      Path object=root().resolve("objects/"+e.id()+".bin");data=Files.readAllBytes(object);data[data.length-1]^=1;Files.write(object,data);assertThrows(IOException.class,()->a.previewBytes(e.id(),1024));
    }
  }
  @Test void knownContainerRollbackIsRejected()throws Exception {
    byte[] old;
    try(var a=create()){old=Files.readAllBytes(root().resolve("catalog.enc"));a.folder("","later");}
    AtomicFiles.write(root().resolve("catalog.enc"),old);
    assertThrows(IOException.class,()->EncryptedArchive.open(root(),guards(),pass,false,Clock.systemUTC()));
  }
  @Test void encryptedBackupSeparatePasswordRestoresOnDifferentDevice()throws Exception {
    Path backup=temporary.resolve("full.aegis-archive");char[] secret="Separate backup password".toCharArray();String id;
    try(var a=create()){id=a.importBytes("letter.txt","letter","Protected revealed letter fixture".getBytes(StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false).id();a.backup(backup,secret,EncryptedArchive.QUIET,()->false);}
    assertThrows(GeneralSecurityException.class,()->ArchiveBackup.restore(backup,temporary.resolve("wrong"),temporary.resolve("other-guards"),pass,Clock.systemUTC(),EncryptedArchive.QUIET,()->false));
    try(var a=ArchiveBackup.restore(backup,temporary.resolve("restored"),temporary.resolve("other-guards"),secret,Clock.systemUTC(),EncryptedArchive.QUIET,()->false)){assertEquals("Protected revealed letter fixture",new String(a.previewBytes(id,1024),StandardCharsets.UTF_8));}
    byte[] bad=Files.readAllBytes(backup);bad[bad.length-1]^=1;Files.write(backup,bad);assertThrows(IOException.class,()->ArchiveBackup.restore(backup,temporary.resolve("tampered"),temporary.resolve("other-guards"),secret,Clock.systemUTC(),EncryptedArchive.QUIET,()->false));assertFalse(Files.exists(temporary.resolve("tampered")));
  }
  @Test void duplicatesAndCancelledImportDoNotOverwrite()throws Exception {
    try(var a=create()){
      byte[] body="Same data".getBytes(StandardCharsets.UTF_8);a.importBytes("first.txt","text",body,"",false,EncryptedArchive.QUIET,()->false);assertThrows(EncryptedArchive.Duplicate.class,()->a.importBytes("second.txt","text",body,"",false,EncryptedArchive.QUIET,()->false));assertEquals(1,a.entries().size());
      AtomicBoolean cancel=new AtomicBoolean();byte[] large=new byte[2*1024*1024];new SecureRandom().nextBytes(large);assertThrows(InterruptedIOException.class,()->a.importBytes("binary.zip","file",large,"",false,(done,total)->cancel.set(true),cancel::get));assertEquals(1,a.entries().size());
    }
  }
  @Test void explicitExportAndLockGate()throws Exception {
    try(var a=create()){
      byte[] data="Explicit export fixture".getBytes(StandardCharsets.UTF_8);var e=a.importBytes("saved.txt","text",data,"",false,EncryptedArchive.QUIET,()->false);Path target=temporary.resolve("selected-output.txt");a.export(e.id(),target,EncryptedArchive.QUIET,()->false);assertArrayEquals(data,Files.readAllBytes(target));assertThrows(IOException.class,()->a.export(e.id(),target,EncryptedArchive.QUIET,()->false));a.requestLock();assertThrows(IOException.class,()->a.entries());assertThrows(IOException.class,()->a.previewBytes(e.id(),1024));
    }
  }
  @Test void automaticEncryptedBackupAndMerge()throws Exception {
    try(var a=create()){
      a.importBytes("one.txt","text","One".getBytes(StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false);a.backupSchedule(temporary.resolve("copies"),60,null);assertTrue(a.backupDue());Path p=a.automaticBackup(EncryptedArchive.QUIET,()->false);assertNotNull(p);assertFalse(a.backupDue());
      try(var other=ArchiveBackup.restore(p,temporary.resolve("other"),guards(),pass,Clock.systemUTC(),EncryptedArchive.QUIET,()->false)){
        other.importBytes("two.txt","text","Two".getBytes(StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false);assertEquals(1,a.merge(other,false,EncryptedArchive.QUIET,()->false));assertEquals(2,a.entries().size());
      }
    }
  }
  @Test void repairOperatesOnCopyAndPreservesOriginal()throws Exception {
    byte[] damaged;
    try(var a=create()){a.importBytes("doc.txt","text","Repair fixture".getBytes(StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false);}
    damaged=Files.readAllBytes(root().resolve("catalog.enc"));damaged[damaged.length-1]^=1;Files.write(root().resolve("catalog.enc"),damaged);
    try(var copy=EncryptedArchive.repairCopy(root(),temporary.resolve("repair"),guards(),pass,Clock.systemUTC(),EncryptedArchive.QUIET)){assertEquals(1,copy.entries().size());assertArrayEquals(damaged,Files.readAllBytes(root().resolve("catalog.enc")));}
  }
}
