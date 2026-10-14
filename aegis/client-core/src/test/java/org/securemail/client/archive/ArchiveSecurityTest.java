package org.securemail.client.archive;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.protocol.Binary;
import org.securemail.client.storage.AtomicFiles;
import static org.junit.jupiter.api.Assertions.*;

/** Real filesystem/AEAD tests; no production keys or profiles. */
class ArchiveSecurityTest {
  @TempDir Path root;
  private final char[] pass="archive-security-password-123".toCharArray();
  private Path archive(){return root.resolve("archive");}
  private Path guards(){return root.resolve("guards");}
  @Test void wrappersUseIndependentRandomSaltAndNonceAndAuthenticateHeader()throws Exception {
    byte[] key=new byte[32];new SecureRandom().nextBytes(key);Set<String> nonces=new HashSet<>(),salts=new HashSet<>();
    for(int i=0;i<20;i++){var h=ArchiveCrypto.header(UUID.randomUUID().toString(),key,pass,null);assertTrue(salts.add(HexFormat.of().formatHex(h.salt())));assertTrue(nonces.add(HexFormat.of().formatHex(Arrays.copyOf(h.passwordWrap(),12))));assertArrayEquals(key,ArchiveCrypto.unlock(h,pass));byte[] b=h.passwordWrap().clone();b[b.length-1]^=1;var changed=new ArchiveCrypto.Header(h.id(),h.salt(),b,h.recoveryWrap());assertThrows(GeneralSecurityException.class,()->ArchiveCrypto.unlock(changed,pass));}
    Arrays.fill(key,(byte)0);
  }
  @Test void recoveryRotationAndDisableDoNotChangeDataObjects()throws Exception {
    var made=EncryptedArchive.create(archive(),guards(),pass,true,Clock.systemUTC());char[] first=made.recoveryKey(),second;
    String id;byte[] original;
    try(var a=made.archive()){id=a.importBytes("private.txt","text","секрет".getBytes(java.nio.charset.StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false).id();original=Files.readAllBytes(archive().resolve("objects/"+id+".bin"));second=a.rotateRecovery(true);}
    assertThrows(GeneralSecurityException.class,()->EncryptedArchive.recover(archive(),guards(),first,false,Clock.systemUTC()));
    try(var recovered=EncryptedArchive.recover(archive(),guards(),second,false,Clock.systemUTC())){assertArrayEquals(original,Files.readAllBytes(archive().resolve("objects/"+id+".bin")));recovered.rotateRecovery(false);}
    assertThrows(GeneralSecurityException.class,()->EncryptedArchive.recover(archive(),guards(),second,false,Clock.systemUTC()));Arrays.fill(first,'\0');Arrays.fill(second,'\0');
  }
  @Test void objectSubstitutionAndMissingAnchorFailClosed()throws Exception {
    try(var a=EncryptedArchive.create(archive(),guards(),pass,false,Clock.systemUTC()).archive()){
      var first=a.importBytes("one.txt","text","alpha".getBytes(),"",false,EncryptedArchive.QUIET,()->false);var second=a.importBytes("two.txt","text","omega".getBytes(),"",false,EncryptedArchive.QUIET,()->false);
      Files.copy(archive().resolve("objects/"+second.id()+".bin"),archive().resolve("objects/"+first.id()+".bin"),StandardCopyOption.REPLACE_EXISTING);
      assertThrows(IOException.class,()->a.previewBytes(first.id(),100));
    }
    assertThrows(IOException.class,()->EncryptedArchive.open(archive(),root.resolve("new-device-guards"),pass,false,Clock.systemUTC()));
    assertThrows(IOException.class,()->EncryptedArchive.open(archive(),root.resolve("new-device-guards"),pass,true,Clock.systemUTC()));
  }
  @Test void twelveFolderLevelsAndInvalidSubtreeMoveAreNonDestructive()throws Exception {
    try(var a=EncryptedArchive.create(archive(),guards(),pass,false,Clock.systemUTC()).archive()){
      String parent="";for(int i=0;i<12;i++)parent=a.folder(parent,"Folder "+i).id();final String deepest=parent;
      assertThrows(IOException.class,()->a.folder(deepest,"Too deep"));var extra=a.folder("","Other");
      assertThrows(IOException.class,()->a.metadata(extra.id(),deepest,extra.name(),List.of(),false));assertFalse(a.locked());assertEquals("",a.entry(extra.id()).folder());
    }
    try(var a=EncryptedArchive.open(archive(),guards(),pass,false,Clock.systemUTC())){assertEquals(13,a.entries().size());}
  }
  @Test void preparedCommitAnchorAcceptsEitherCrashSideThenRejectsHistoricalRollback()throws Exception {
    byte[] oldCatalog,newCatalog,key;String headerHash,id;
    try(var a=EncryptedArchive.create(archive(),guards(),pass,false,Clock.systemUTC()).archive()){oldCatalog=Files.readAllBytes(archive().resolve("catalog.enc"));a.folder("","Committed");newCatalog=Files.readAllBytes(archive().resolve("catalog.enc"));key=a.backupKey();id=a.archiveId();headerHash=ArchiveCrypto.digest(Files.readAllBytes(archive().resolve("key.bin")));}
    Path guard;try(var files=Files.list(guards())){guard=files.findFirst().orElseThrow();}
    String oldHash=ArchiveCrypto.digest(oldCatalog),newHash=ArchiveCrypto.digest(newCatalog);
    byte[] pending=Binary.encode(o->{o.writeInt(1);Binary.text(o,headerHash);Binary.text(o,oldHash);Binary.text(o,headerHash);Binary.text(o,newHash);});
    AtomicFiles.write(guard,ArchiveCrypto.seal(key,pending,id+"/guard/"+guard.getFileName()));
    try(var a=EncryptedArchive.open(archive(),guards(),pass,false,Clock.systemUTC())){assertEquals(1,a.entries().size());}
    Files.write(archive().resolve("catalog.enc"),oldCatalog);assertThrows(IOException.class,()->EncryptedArchive.open(archive(),guards(),pass,false,Clock.systemUTC()));Arrays.fill(key,(byte)0);
  }
  @Test void malformedTextCancelAndRejectedLimitLeaveNoPlaintextOrOrphanObject()throws Exception {
    try(var a=EncryptedArchive.create(archive(),guards(),pass,false,Clock.systemUTC()).archive()){
      assertThrows(IOException.class,()->a.importBytes("invalid.txt","text",new byte[]{(byte)0xff},"",false,EncryptedArchive.QUIET,()->false));
      assertThrows(InterruptedIOException.class,()->a.importBytes("cancel.txt","text",new byte[1000],"",false,EncryptedArchive.QUIET,()->true));
      assertThrows(IOException.class,()->a.settings(1024,10));assertEquals(0,a.entries().size());try(var files=Files.list(archive().resolve("objects"))){assertEquals(0,files.count());}
    }
  }
}
