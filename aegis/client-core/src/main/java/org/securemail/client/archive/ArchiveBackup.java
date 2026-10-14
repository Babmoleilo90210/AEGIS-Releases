package org.securemail.client.archive;

import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.protocol.Binary;

/** Authenticated streaming backup: ciphertext-only staging; never ZIP extraction or native serialization. */
public final class ArchiveBackup {
  private static final int MAGIC=0x41454742;
  private ArchiveBackup(){}
  static void write(EncryptedArchive archive,Path target,char[] password,EncryptedArchive.Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {writePrepared(archive,target,archive.backupHeader(password),progress,cancel);}
  static boolean name(String s){return Set.of("key.bin","catalog.enc","previous.enc").contains(s)||s.matches("objects/[a-f0-9-]{36}\\.(bin|meta|idx)");}
  static void writePrepared(EncryptedArchive archive,Path destination,byte[] encoded,EncryptedArchive.Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    Path target=destination.toAbsolutePath().normalize();EncryptedArchive.rejectLinks(target);if(target.startsWith(archive.root())||Files.exists(target,LinkOption.NOFOLLOW_LINKS))throw new IOException("Копию сохраняйте под новым именем вне контейнера");
    byte[] key=archive.backupKey();String backupId=UUID.randomUUID().toString();List<Path> files;
    try(var walk=Files.walk(archive.root())){files=walk.filter(p->Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)&&name(archive.root().relativize(p).toString().replace('\\','/'))).sorted().toList();}
    long total=archive.usedBytes(),done=0;boolean created=false,success=false;
    try(var channel=FileChannel.open(target,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.exportAttributes(target.getParent()))){
      created=true;OutputStream file=new FilterOutputStream(Channels.newOutputStream(channel)){@Override public void close()throws IOException{flush();}};var outer=new DataOutputStream(file);outer.writeInt(MAGIC);outer.writeInt(1);Binary.text(outer,backupId);Binary.bytes(outer,encoded);outer.flush();
      try(var encrypted=ArchiveCrypto.stream(key).newEncryptingStream(file,ArchiveCrypto.aad("backup/"+backupId+"/"+ArchiveCrypto.digest(encoded)));var out=new DataOutputStream(encrypted)){
        out.writeInt(files.size());byte[] buffer=new byte[65536];
        try{for(Path path:files){if(Files.isSymbolicLink(path))throw new IOException("Symlink в контейнере");String relative=archive.root().relativize(path).toString().replace('\\','/');Binary.text(out,relative);
          if(relative.equals("key.bin")){out.writeLong(encoded.length);out.write(encoded);continue;}long size=Files.size(path);out.writeLong(size);
          try(var input=Files.newInputStream(path)){long seen=0;int n;while((n=input.read(buffer))!=-1){if(archive.locked()||cancel.getAsBoolean()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("Операция отменена");seen+=n;if(seen>size)throw new IOException("Контейнер изменился");out.write(buffer,0,n);progress.update(done+=n,total);}if(seen!=size)throw new IOException("Контейнер изменился");}
        }}finally{Arrays.fill(buffer,(byte)0);}
      }channel.force(true);success=true;
    }finally{Arrays.fill(key,(byte)0);if(created&&!success)Files.deleteIfExists(target);}
  }
  public static EncryptedArchive restore(Path backup,Path destination,Path guards,char[] password,Clock clock,EncryptedArchive.Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    Path target=destination.toAbsolutePath().normalize();EncryptedArchive.rejectLinks(target);if(Files.exists(target))throw new IOException("Для восстановления выберите новую папку");
    Path staging=target.resolveSibling(target.getFileName()+".restore-"+UUID.randomUUID());AtomicFiles.directory(staging);byte[] key=null;boolean success=false;
    try(InputStream raw=Files.newInputStream(backup);DataInputStream outer=new DataInputStream(raw)){
      if(Files.isSymbolicLink(backup)||outer.readInt()!=MAGIC||outer.readInt()!=1)throw new IOException("Неподдерживаемая резервная копия");String id=Binary.text(outer,36);UUID.fromString(id);byte[] h=Binary.bytes(outer,4096);ArchiveCrypto.Header header=ArchiveCrypto.parse(h);key=ArchiveCrypto.unlock(header,password);
      try(InputStream decrypted=ArchiveCrypto.stream(key).newDecryptingStream(raw,ArchiveCrypto.aad("backup/"+id+"/"+ArchiveCrypto.digest(h)));var in=new DataInputStream(decrypted)){
        int count=in.readInt();if(count<2||count>60008)throw new IOException("Недопустимая структура копии");Set<String> seen=new HashSet<>();long aggregate=0;byte[] buffer=new byte[65536];
        try{for(int n=0;n<count;n++){
          String name=Binary.text(in,256);long size=in.readLong();if(!name(name)||!seen.add(name)||size<0||size>EncryptedArchive.MAX_FILE+4*1024*1024||Math.addExact(aggregate,size)>EncryptedArchive.MAX_ARCHIVE)throw new IOException("Недопустимая структура копии");aggregate+=size;
          Path file=staging.resolve(name);AtomicFiles.directory(file.getParent());try(var channel=FileChannel.open(file,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.attributes(file.getParent()));var out=Channels.newOutputStream(channel)){
            long left=size;while(left>0){if(cancel.getAsBoolean()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("Операция отменена");int amount=in.read(buffer,0,(int)Math.min(buffer.length,left));if(amount<0)throw new IOException("Копия обрезана");out.write(buffer,0,amount);left-=amount;progress.update(aggregate-left,Files.size(backup));}out.flush();channel.force(true);
          }
        }}finally{Arrays.fill(buffer,(byte)0);}
        if(in.read()!=-1||!seen.containsAll(Set.of("key.bin","catalog.enc")))throw new IOException("Повреждена резервная копия");
        if(!MessageDigest.isEqual(AtomicFiles.read(staging.resolve("key.bin"),4096),h))throw new IOException("Заголовки копии не совпадают");
      }
      try(var verified=EncryptedArchive.open(staging,guards,password,true,clock)){verified.verifyAll(progress,cancel);}
      Files.move(staging,target,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(target.getParent());EncryptedArchive restored=EncryptedArchive.open(target,guards,password,true,clock);success=true;return restored;
    }catch(IllegalArgumentException|ArithmeticException invalid){throw new IOException("Повреждена резервная копия",invalid);}
    finally{if(key!=null)Arrays.fill(key,(byte)0);if(!success&&Files.exists(staging))try(var files=Files.walk(staging)){for(Path f:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(f);}}
  }
}
