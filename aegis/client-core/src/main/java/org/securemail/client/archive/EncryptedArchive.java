package org.securemail.client.archive;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.securemail.client.crypto.Secrets;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.protocol.Binary;

/** Independent encrypted archive. Long operations belong on the archive worker, never FX. */
public final class EncryptedArchive implements AutoCloseable {
  public static final long MAX_FILE=1024L*1024*1024,MAX_ARCHIVE=100L*1024*1024*1024,DEFAULT_LIMIT=2L*1024*1024*1024;
  private static final int MAX_ENTRIES=20000,MAX_META=8*1024*1024;
  public interface Progress {void update(long completed,long total);}
  public static final Progress QUIET=(n,total)->{};
  public record Created(EncryptedArchive archive,char[] recoveryKey){@Override public String toString(){return "ArchiveCreated[redacted]";}}
  public record Filter(String query,String folder,String type,long since,long until,boolean favorites,boolean trash,boolean recursive){
    public Filter {if(query==null||query.length()>1024||folder==null||type==null)throw new IllegalArgumentException("Некорректный поиск");}
    public static Filter all(){return new Filter("","","",0,Long.MAX_VALUE,false,false,true);}
  }
  public static final class Duplicate extends IOException {
    private static final long serialVersionUID=1L;
    private final String existingId;Duplicate(String id){super("Такой файл уже есть в архиве");existingId=id;}public String existingId(){return existingId;}
  }
  public static final class IndexDamaged extends IOException {private static final long serialVersionUID=1L;IndexDamaged(){super("Поисковый индекс повреждён. Перестройте его; файлы сохраняются.");}}
  private final Path root,objects,guard;
  private final Clock clock;
  private final FileChannel lockChannel;private final FileLock fileLock;
  private final Map<String,ArchiveEntry> entries=new LinkedHashMap<>();
  private byte[] key;private ArchiveCrypto.Header header;private volatile boolean closed;
  private long revision,limit=DEFAULT_LIMIT,lastActivity=System.nanoTime(),lastBackup,backupInterval;
  private int lockMinutes=10;private String backupDirectory="";private byte[] backupHeader=new byte[0];
  private String committedHeader,committedState;

  private EncryptedArchive(Path path,Path anchors,Clock clock)throws IOException {
    root=path.toAbsolutePath().normalize();objects=root.resolve("objects");this.clock=clock;
    rejectLinks(root);AtomicFiles.directory(root);AtomicFiles.directory(objects);
    Path g=anchors.toAbsolutePath().normalize();if(g.startsWith(root))throw new IOException("Anchor нельзя хранить внутри контейнера");rejectLinks(g);AtomicFiles.directory(g);
    String fingerprint;
    try{fingerprint=ArchiveCrypto.digest(root.toString().getBytes(StandardCharsets.UTF_8));}catch(GeneralSecurityException impossible){throw new IOException(impossible);}
    guard=g.resolve(fingerprint+".guard");lockChannel=FileChannel.open(root.resolve("archive.lock"),Set.of(StandardOpenOption.CREATE,StandardOpenOption.WRITE),AtomicFiles.attributes(root));
    try{fileLock=lockChannel.tryLock();if(fileLock==null)throw new IOException("Архив уже открыт");}catch(IOException|OverlappingFileLockException failure){lockChannel.close();throw new IOException("Архив уже открыт",failure);}
  }
  public static Created create(Path root,Path guards,char[] password,boolean recovery,Clock clock)throws IOException,GeneralSecurityException {
    if(Files.exists(root.resolve("key.bin"),LinkOption.NOFOLLOW_LINKS))throw new IOException("Архив уже существует");
    if(Files.exists(root))try(var f=Files.list(root)){if(f.findAny().isPresent())throw new IOException("Для нового архива выберите пустую папку");}
    var a=new EncryptedArchive(root,guards,clock);byte[] recoveryBytes=recovery?Secrets.random(32):null;
    try{
      a.key=Secrets.random(32);a.header=ArchiveCrypto.header(UUID.randomUUID().toString(),a.key,password,recoveryBytes);
      AtomicFiles.write(a.root.resolve("key.bin"),a.header.encode());a.committedHeader=ArchiveCrypto.digest(a.header.encode());
      a.revision=1;byte[] state=a.sealedCatalog();AtomicFiles.write(a.root.resolve("catalog.enc"),state);a.committedState=ArchiveCrypto.digest(state);a.anchor(a.committedHeader,a.committedState,"","");
      char[] phrase=recoveryBytes==null?new char[0]:Base64.getUrlEncoder().withoutPadding().encodeToString(recoveryBytes).toCharArray();return new Created(a,phrase);
    }catch(IOException|GeneralSecurityException|RuntimeException failure){a.close();throw failure;}finally{if(recoveryBytes!=null)Arrays.fill(recoveryBytes,(byte)0);}
  }
  public static EncryptedArchive open(Path root,Path guards,char[] password,boolean firstDevice,Clock clock)throws IOException,GeneralSecurityException {return openInternal(root,guards,password,false,firstDevice,clock);}
  public static EncryptedArchive recover(Path root,Path guards,char[] recovery,boolean firstDevice,Clock clock)throws IOException,GeneralSecurityException {return openInternal(root,guards,recovery,true,firstDevice,clock);}
  private static EncryptedArchive openInternal(Path root,Path guards,char[] secret,boolean recovery,boolean firstDevice,Clock clock)throws IOException,GeneralSecurityException {
    var a=new EncryptedArchive(root,guards,clock);
    try{
      byte[] h=AtomicFiles.read(a.root.resolve("key.bin"),4096);a.header=ArchiveCrypto.parse(h);a.key=recovery?ArchiveCrypto.recover(a.header,secret):ArchiveCrypto.unlock(a.header,secret);
      if(a.key.length!=32)throw new GeneralSecurityException("Неверный ключ архива");
      byte[] state=AtomicFiles.read(a.root.resolve("catalog.enc"),MAX_META+28);a.readCatalog(state);a.committedHeader=ArchiveCrypto.digest(h);a.committedState=ArchiveCrypto.digest(state);
      if(!Files.isRegularFile(a.guard,LinkOption.NOFOLLOW_LINKS)){if(!firstDevice)throw new IOException("Нет локальной отметки целостности. Откройте как перенесённый архив после проверки.");a.verifyAll(QUIET,()->false);a.anchor(a.committedHeader,a.committedState,"","");}
      else a.checkAnchor();return a;
    }catch(IOException|GeneralSecurityException|RuntimeException failure){a.close();throw failure;}
  }
  private void checkAnchor()throws IOException,GeneralSecurityException {
    byte[] clear=ArchiveCrypto.open(key,AtomicFiles.read(guard,1024),header.id()+"/guard/"+guard.getFileName());
    try(var i=new DataInputStream(new ByteArrayInputStream(clear))){if(i.readInt()!=1)throw new IOException("Повреждена отметка целостности");String oldH=Binary.text(i,64),oldS=Binary.text(i,64),nextH=Binary.text(i,64),nextS=Binary.text(i,64);Binary.end(i);
      if(!committedHeader.equals(oldH)||!committedState.equals(oldS))if(!committedHeader.equals(nextH)||!committedState.equals(nextS))throw new IOException("Обнаружен откат или подмена архива. Восстановление выполняйте над копией.");
      if(!nextH.isEmpty())anchor(committedHeader,committedState,"","");
    }finally{Arrays.fill(clear,(byte)0);}
  }
  private void anchor(String oldH,String oldS,String nextH,String nextS)throws IOException,GeneralSecurityException {
    byte[] data=Binary.encode(o->{o.writeInt(1);Binary.text(o,oldH);Binary.text(o,oldS);Binary.text(o,nextH);Binary.text(o,nextS);});
    try{AtomicFiles.write(guard,ArchiveCrypto.seal(key,data,header.id()+"/guard/"+guard.getFileName()));}finally{Arrays.fill(data,(byte)0);}
  }
  private byte[] sealedCatalog()throws IOException,GeneralSecurityException {
    byte[] data=Binary.encode(o->{o.writeInt(1);o.writeLong(revision);o.writeLong(limit);o.writeInt(lockMinutes);o.writeLong(lastBackup);o.writeLong(backupInterval);Binary.text(o,backupDirectory);Binary.bytes(o,backupHeader);o.writeInt(entries.size());for(var e:entries.values())e.write(o);});
    try{if(data.length>MAX_META)throw new IOException("Достигнут лимит метаданных");return ArchiveCrypto.seal(key,data,header.id()+"/catalog");}finally{Arrays.fill(data,(byte)0);}
  }
  private void readCatalog(byte[] state)throws IOException,GeneralSecurityException {
    byte[] clear=ArchiveCrypto.open(key,state,header.id()+"/catalog");
    try(var i=new DataInputStream(new ByteArrayInputStream(clear))){
      if(i.readInt()!=1)throw new IOException("Неподдерживаемая схема архива");revision=i.readLong();limit=i.readLong();lockMinutes=i.readInt();lastBackup=i.readLong();backupInterval=i.readLong();backupDirectory=Binary.text(i,8192);backupHeader=Binary.bytes(i,4096);
      if(revision<1||limit<1024*1024||limit>MAX_ARCHIVE||lockMinutes<1||lockMinutes>240||backupInterval<0||backupInterval>10080L*60_000)throw new IOException("Повреждены настройки архива");
      int n=i.readInt();if(n<0||n>MAX_ENTRIES)throw new IOException("Повреждён каталог архива");entries.clear();for(int k=0;k<n;k++){ArchiveEntry e=ArchiveEntry.read(i);if(entries.putIfAbsent(e.id(),e)!=null)throw new IOException("Повтор объекта архива");}Binary.end(i);
      for(var e:entries.values())validateFolder(e.folder(),e.directory()?e.id():"");
    }finally{Arrays.fill(clear,(byte)0);}
  }
  private void commit(boolean keepPrevious)throws IOException,GeneralSecurityException {
    requireOpen();revision=Math.addExact(revision,1);byte[] data=sealedCatalog();String next=ArchiveCrypto.digest(data);
    if(usedBytes()+data.length>limit)throw new IOException("Архив достиг лимита размера");
    anchor(committedHeader,committedState,committedHeader,next);
    try{
      AtomicFiles.write(root.resolve("previous.enc"),keepPrevious?AtomicFiles.read(root.resolve("catalog.enc"),MAX_META+28):data);
      AtomicFiles.write(root.resolve("catalog.enc"),data);anchor(committedHeader,next,"","");committedState=next;
    }catch(IOException|GeneralSecurityException failure){closed=true;throw failure;}
  }
  public synchronized void changePassword(char[] password)throws IOException,GeneralSecurityException {
    requireOpen();ArchiveCrypto.Header fresh=ArchiveCrypto.header(header.id(),key,password,null);
    fresh=new ArchiveCrypto.Header(fresh.id(),fresh.salt(),fresh.passwordWrap(),header.recoveryWrap());replaceHeader(fresh);
  }
  public synchronized char[] rotateRecovery(boolean enable)throws IOException,GeneralSecurityException {
    requireOpen();byte[] recovery=enable?Secrets.random(32):null;
    try{replaceHeader(new ArchiveCrypto.Header(header.id(),header.salt(),header.passwordWrap(),enable?ArchiveCrypto.seal(recovery,key,header.id()+"/recovery"):new byte[0]));return enable?Base64.getUrlEncoder().withoutPadding().encodeToString(recovery).toCharArray():new char[0];}finally{if(recovery!=null)Arrays.fill(recovery,(byte)0);}
  }
  private void replaceHeader(ArchiveCrypto.Header next)throws IOException,GeneralSecurityException {
    byte[] data=next.encode();String h=ArchiveCrypto.digest(data);anchor(committedHeader,committedState,h,committedState);
    try{AtomicFiles.write(root.resolve("key.bin"),data);anchor(h,committedState,"","");header=next;committedHeader=h;}catch(IOException|GeneralSecurityException failure){closed=true;throw failure;}
  }
  public boolean locked(){return closed;}public void activity(){lastActivity=System.nanoTime();}public boolean idleExpired(){return System.nanoTime()-lastActivity>lockMinutes*60_000_000_000L;}
  public void requestLock(){closed=true;}
  public Path root(){return root;}
  public synchronized long limit()throws IOException {requireOpen();return limit;}
  public synchronized int lockMinutes()throws IOException {requireOpen();return lockMinutes;}
  public synchronized long usedBytes()throws IOException {long sum=0;try(var files=Files.walk(root)){for(Path f:files.toList()){if(Files.isSymbolicLink(f))throw new IOException("Symlink в архиве запрещён");if(Files.isRegularFile(f,LinkOption.NOFOLLOW_LINKS))sum=Math.addExact(sum,Files.size(f));}}return sum;}
  public synchronized void settings(long bytes,int minutes)throws IOException,GeneralSecurityException {requireOpen();if(bytes<usedBytes()+MAX_META*2L||bytes>MAX_ARCHIVE||minutes<1||minutes>240)throw new IOException("Некорректный лимит или таймер");limit=bytes;lockMinutes=minutes;commit(true);activity();}
  public synchronized List<ArchiveEntry> entries()throws IOException {requireOpen();return List.copyOf(entries.values());}
  public synchronized ArchiveEntry entry(String id)throws IOException {requireOpen();ArchiveEntry e=entries.get(id);if(e==null)throw new IOException("Объект недоступен");return e;}
  public synchronized ArchiveEntry folder(String parent,String name)throws IOException,GeneralSecurityException {
    requireOpen();capacity();validateFolder(parent,"");var e=new ArchiveEntry(UUID.randomUUID().toString(),parent,name,"folder",0,clock.millis(),"",List.of(),false,false);entries.put(e.id(),e);commit(true);return e;
  }
  private void capacity()throws IOException {if(entries.size()>=MAX_ENTRIES)throw new IOException("Достигнут лимит объектов архива");}
  private void validateFolder(String folder,String child)throws IOException {
    Set<String> seen=new HashSet<>();String f=folder;
    for(int depth=0;!f.isEmpty();depth++){if(depth>=12||f.equals(child)||!seen.add(f))throw new IOException("Папки: не более 12 уровней, без циклов");ArchiveEntry e=entries.get(f);if(e==null||!e.directory())throw new IOException("Папка недоступна");f=e.folder();}
  }
  public synchronized void metadata(String id,String folder,String name,List<String> tags,boolean favorite)throws IOException,GeneralSecurityException {
    requireOpen();ArchiveEntry old=entry(id);validateFolder(folder,old.directory()?id:"");ArchiveEntry next=old.metadata(folder,name,tags,favorite,old.trash());entries.put(id,next);
    if(!next.directory())descriptor(next);commit(true);activity();
  }
  public synchronized void trash(String id,boolean value)throws IOException,GeneralSecurityException {
    requireOpen();ArchiveEntry e=entry(id);Set<String> affected=descendants(id);affected.add(id);
    for(String k:affected){ArchiveEntry item=entry(k);entries.put(k,item.metadata(item.folder(),item.name(),item.tags(),item.favorite(),value));}commit(true);activity();
  }
  public synchronized void purge(String id)throws IOException,GeneralSecurityException {
    requireOpen();if(!entry(id).trash())throw new IOException("Окончательно удалять можно только из корзины");Set<String> remove=descendants(id);remove.add(id);
    for(String n:remove)entries.remove(n);commit(false);
    for(String n:remove)for(String suffix:List.of(".bin",".meta",".idx"))Files.deleteIfExists(object(n,suffix));AtomicFiles.syncDirectory(objects);activity();
  }
  private Set<String> descendants(String id){Set<String> set=new HashSet<>();boolean more;do{more=false;for(var e:entries.values())if(e.folder().equals(id)||set.contains(e.folder()))more|=set.add(e.id());}while(more);return set;}
  public synchronized ArchiveEntry importFile(Path source,String folder,boolean allowDuplicate,Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    requireOpen();if(Files.isSymbolicLink(source)||!Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS))throw new IOException("Выберите обычный файл");long size=Files.size(source);if(size>MAX_FILE)throw new IOException("Файл: не более 1 ГБ");
    String type=ArchiveDocuments.type(source);try(var in=Files.newInputStream(source)){return importStream(source.getFileName().toString(),type,size,in,folder,List.of(),false,allowDuplicate,progress,cancel);}
  }
  public synchronized ArchiveEntry importBytes(String name,String type,byte[] data,String folder,boolean allowDuplicate,Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {try(var in=new ByteArrayInputStream(data)){return importStream(name,type,data.length,in,folder,List.of(),false,allowDuplicate,progress,cancel);}}
  synchronized ArchiveEntry importStream(String name,String type,long size,InputStream source,String folder,List<String> tags,boolean favorite,boolean allowDuplicate,Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    requireOpen();capacity();validateFolder(folder,"");if(size<0||size>MAX_FILE||usedBytes()+2*size+MAX_META*2L>limit)throw new IOException("Недостаточно места в лимите архива");
    String id=UUID.randomUUID().toString();Path temporary=Files.createTempFile(objects,".atomic-",".tmp",AtomicFiles.attributes(objects));MessageDigest digest=MessageDigest.getInstance("SHA-256");
    try{
      try(OutputStream file=Files.newOutputStream(temporary);OutputStream sealed=ArchiveCrypto.stream(key).newEncryptingStream(file,ArchiveCrypto.aad(header.id()+"/object/"+id))){copy(source,sealed,digest,size,progress,cancel);}
      String hash=HexFormat.of().formatHex(digest.digest());if(!allowDuplicate)for(var e:entries.values())if(!e.directory()&&e.digest().equals(hash))throw new Duplicate(e.id());
      try(var f=FileChannel.open(temporary,StandardOpenOption.WRITE)){f.force(true);}Files.move(temporary,object(id,".bin"),StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(objects);
      ArchiveEntry e=new ArchiveEntry(id,folder,name,type,size,clock.millis(),hash,tags,favorite,false);descriptor(e);
      writeIndex(e,cancel);entries.put(id,e);commit(true);activity();return e;
    }finally{Files.deleteIfExists(temporary);}
  }
  private void descriptor(ArchiveEntry e)throws IOException,GeneralSecurityException {byte[] b=Binary.encode(e::write);try{AtomicFiles.write(object(e.id(),".meta"),ArchiveCrypto.seal(key,b,header.id()+"/descriptor/"+e.id()));}finally{Arrays.fill(b,(byte)0);}}
  private void writeIndex(ArchiveEntry e,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    Path temp=Files.createTempFile(objects,".atomic-",".tmp",AtomicFiles.attributes(objects));
    try{
      try(OutputStream file=Files.newOutputStream(temp);OutputStream sealed=ArchiveCrypto.stream(key).newEncryptingStream(file,ArchiveCrypto.aad(header.id()+"/index/"+e.id()))){
        if(Set.of("letter","text").contains(e.type()))try(var clear=readStream(e)){
          var reader=new InputStreamReader(clear,StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT));var writer=new OutputStreamWriter(sealed,StandardCharsets.UTF_8);char[] buffer=new char[8192];try{int n;while((n=reader.read(buffer))!=-1){check(cancel);writer.write(buffer,0,n);}writer.flush();}finally{Arrays.fill(buffer,'\0');}
        }else if(e.type().equals("pdf")&&e.size()<=ArchiveDocuments.MAX_PREVIEW){byte[] b=readBytesInternal(e,ArchiveDocuments.MAX_PREVIEW);try{String text=ArchiveDocuments.pdfText(b);sealed.write(text.getBytes(StandardCharsets.UTF_8));}catch(IOException invalidPdf){/* File remains encrypted and exportable; PDF preview reports decoder failure. */}finally{Arrays.fill(b,(byte)0);}}
      }
      try(var f=FileChannel.open(temp,StandardOpenOption.WRITE)){f.force(true);}Files.move(temp,object(e.id(),".idx"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);AtomicFiles.syncDirectory(objects);
    }finally{Files.deleteIfExists(temp);}
  }
  public synchronized void rebuildIndex(Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {requireOpen();var files=entries.values().stream().filter(e->!e.directory()).toList();int n=0;for(var e:files){check(cancel);writeIndex(e,cancel);progress.update(++n,files.size());}activity();}
  public synchronized List<ArchiveEntry> search(Filter filter,Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    requireOpen();String needle=filter.query().strip().toLowerCase(Locale.ROOT);List<ArchiveEntry> result=new ArrayList<>();int n=0;
    for(var e:entries.values()){
      check(cancel);progress.update(++n,entries.size());if(e.trash()!=filter.trash()||filter.favorites()&&!e.favorite()||e.addedAt()<filter.since()||e.addedAt()>filter.until()||!filter.type().isEmpty()&&!e.type().equals(filter.type()))continue;
      if(!filter.folder().isEmpty()&&!e.folder().equals(filter.folder())&&(!filter.recursive()||!descendants(filter.folder()).contains(e.id())))continue;
      if(needle.isEmpty()||(e.name()+" "+String.join(" ",e.tags())).toLowerCase(Locale.ROOT).contains(needle)||!e.directory()&&indexContains(e,needle,cancel))result.add(e);
    }activity();return List.copyOf(result);
  }
  private boolean indexContains(ArchiveEntry e,String needle,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    if(e.directory())return false;Path p=object(e.id(),".idx");if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))throw new IndexDamaged();boolean found=false;
    try(InputStream source=Files.newInputStream(p);InputStream clear=ArchiveCrypto.stream(key).newDecryptingStream(source,ArchiveCrypto.aad(header.id()+"/index/"+e.id()));Reader reader=new InputStreamReader(clear,StandardCharsets.UTF_8)){
      char[] chars=new char[8192];String carry="";try{int n;while((n=reader.read(chars))!=-1){check(cancel);String part=carry+new String(chars,0,n).toLowerCase(Locale.ROOT);found|=part.contains(needle);carry=part.substring(Math.max(0,part.length()-Math.max(1,needle.length())));}return found;}finally{Arrays.fill(chars,'\0');}
    }catch(InterruptedIOException cancelled){throw cancelled;}catch(IOException damaged){throw new IndexDamaged();}
  }
  private InputStream readStream(ArchiveEntry e)throws IOException,GeneralSecurityException {
    Path p=object(e.id(),".bin");if(Files.isSymbolicLink(p)||!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||Files.size(p)>MAX_FILE+MAX_FILE/1000+4096)throw new IOException("Файл архива повреждён");
    InputStream source=Files.newInputStream(p);try{return ArchiveCrypto.stream(key).newDecryptingStream(source,ArchiveCrypto.aad(header.id()+"/object/"+e.id()));}catch(IOException|GeneralSecurityException failure){source.close();throw failure;}
  }
  public synchronized byte[] previewBytes(String id,int max)throws IOException,GeneralSecurityException {requireOpen();ArchiveEntry e=entry(id);if(e.trash()||e.directory()||e.size()>max)throw new IOException("Для этого файла используйте экспорт");activity();return readBytesInternal(e,max);}
  private byte[] readBytesInternal(ArchiveEntry e,int max)throws IOException,GeneralSecurityException {
    try(var in=readStream(e)){byte[] b=in.readNBytes(max+1);if(b.length!=e.size()||b.length>max||in.read()!=-1||!ArchiveCrypto.digest(b).equals(e.digest())){Arrays.fill(b,(byte)0);throw new IOException("Нарушена целостность файла");}return b;}
  }
  public synchronized void export(String id,Path destination,Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    requireOpen();ArchiveEntry e=entry(id);if(e.trash()||e.directory())throw new IOException("Выберите файл вне корзины");Path target=destination.toAbsolutePath().normalize();rejectLinks(target);if(target.startsWith(root)||Files.exists(target))throw new IOException("Выберите новое имя вне контейнера");
    Path temp=Files.createTempFile(target.getParent(),".aegis-export-",".partial",AtomicFiles.exportAttributes(target.getParent()));boolean completed=false;
    try{
      MessageDigest hash=MessageDigest.getInstance("SHA-256");try(var in=readStream(e);var out=Files.newOutputStream(temp)){copy(in,out,hash,e.size(),progress,cancel);}if(!HexFormat.of().formatHex(hash.digest()).equals(e.digest()))throw new IOException("Нарушена целостность файла");
      try(var channel=FileChannel.open(temp,StandardOpenOption.WRITE)){channel.force(true);}Files.move(temp,target,StandardCopyOption.ATOMIC_MOVE);completed=true;activity();
    }finally{if(!completed)Files.deleteIfExists(temp);}
  }
  public synchronized void verifyAll(Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    requireOpen();int n=0;for(var e:entries.values())if(!e.directory()){
      check(cancel);MessageDigest h=MessageDigest.getInstance("SHA-256");try(var in=readStream(e)){copy(in,OutputStream.nullOutputStream(),h,e.size(),QUIET,cancel);}if(!HexFormat.of().formatHex(h.digest()).equals(e.digest()))throw new IOException("Файл архива повреждён");progress.update(++n,entries.size());}
  }
  private void copy(InputStream in,OutputStream out,MessageDigest hash,long size,Progress progress,BooleanSupplier cancel)throws IOException {
    byte[] b=new byte[65536];long done=0;try{int n;while((n=in.read(b))!=-1){check(cancel);done=Math.addExact(done,n);if(done>size)throw new IOException("Размер файла изменился");hash.update(b,0,n);out.write(b,0,n);progress.update(done,size);}if(done!=size)throw new IOException("Файл обрезан");}finally{Arrays.fill(b,(byte)0);}
  }
  private void check(BooleanSupplier cancel)throws IOException {requireOpen();if(cancel.getAsBoolean()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("Операция отменена");}
  private void requireOpen()throws IOException {if(closed||key==null)throw new IOException("Архив заблокирован");}
  private Path object(String id,String suffix)throws IOException {try{UUID.fromString(id);}catch(IllegalArgumentException invalid){throw new IOException("Некорректный идентификатор");}return objects.resolve(id+suffix);}
  static void rejectLinks(Path path)throws IOException {Path p=path.toAbsolutePath().normalize();while(p!=null){if(Files.isSymbolicLink(p))throw new IOException("Symlink в пути архива запрещён");p=p.getParent();}}
  synchronized byte[] backupHeader(char[] password)throws GeneralSecurityException,IOException {requireOpen();return password==null?header.encode():ArchiveCrypto.header(header.id(),key,password,null).encode();}
  synchronized byte[] backupKey()throws IOException {requireOpen();return key.clone();}
  synchronized String archiveId()throws IOException {requireOpen();return header.id();}
  public synchronized void backup(Path path,char[] password,Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {requireOpen();ArchiveBackup.write(this,path,password,progress,cancel);lastBackup=clock.millis();commit(true);}
  public synchronized void backupSchedule(Path folder,long intervalMinutes,char[] separatePassword)throws IOException,GeneralSecurityException {
    requireOpen();if(intervalMinutes<0||intervalMinutes>10080)throw new IOException("Расписание: не более 7 дней");Path dir=folder.toAbsolutePath().normalize();rejectLinks(dir);if(dir.startsWith(root))throw new IOException("Папка копий должна быть вне архива");AtomicFiles.directory(dir);
    backupDirectory=dir.toString();backupInterval=intervalMinutes*60_000;backupHeader=backupHeader(separatePassword);commit(true);
  }
  public synchronized boolean backupDue(){return !closed&&backupInterval>0&&clock.millis()-lastBackup>=backupInterval;}
  public synchronized Path automaticBackup(Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    requireOpen();if(!backupDue())return null;Path target=Path.of(backupDirectory).resolve("AEGIS-archive-"+clock.millis()+"-"+UUID.randomUUID()+".aegis-archive");ArchiveBackup.writePrepared(this,target,backupHeader,progress,cancel);lastBackup=clock.millis();commit(true);return target;
  }
  public synchronized int merge(EncryptedArchive source,boolean includeDuplicates,Progress progress,BooleanSupplier cancel)throws IOException,GeneralSecurityException {
    requireOpen();if(source==this||root.equals(source.root))throw new IOException("Выберите другой архив");source.verifyAll(QUIET,cancel);var sourceEntries=source.entries();Map<String,String> folders=new HashMap<>();folders.put("","");int added=0;
    List<ArchiveEntry> directories=new ArrayList<>(sourceEntries.stream().filter(ArchiveEntry::directory).toList());
    for(int pass=0;!directories.isEmpty()&&pass<13;pass++){for(var e:new ArrayList<>(directories))if(folders.containsKey(e.folder())){String parent=folders.get(e.folder());ArchiveEntry same=entries.values().stream().filter(x->x.directory()&&!x.trash()&&x.folder().equals(parent)&&x.name().equals(e.name())).findFirst().orElse(null);ArchiveEntry target=same==null?folder(parent,e.name()):same;folders.put(e.id(),target.id());directories.remove(e);}}
    if(!directories.isEmpty())throw new IOException("Повреждена структура папок");
    for(var e:sourceEntries)if(!e.directory()){
      check(cancel);if(!includeDuplicates&&entries.values().stream().anyMatch(x->x.digest().equals(e.digest())))continue;
      String title=e.name();String parent=folders.getOrDefault(e.folder(),"");if(entries.values().stream().anyMatch(x->x.folder().equals(parent)&&x.name().equals(e.name())))title=e.name().substring(0,Math.min(220,e.name().length()))+" (копия)";
      try(var in=source.readStream(e)){ArchiveEntry copied=importStream(title,e.type(),e.size(),in,parent,e.tags(),e.favorite(),true,QUIET,cancel);if(!copied.digest().equals(e.digest()))throw new IOException("Повреждён источник объединения");if(e.trash())trash(copied.id(),true);}progress.update(++added,sourceEntries.size());
    }return added;
  }
  public static EncryptedArchive repairCopy(Path source,Path destination,Path guards,char[] password,Clock clock,Progress progress)throws IOException,GeneralSecurityException {
    if(Files.exists(destination))throw new IOException("Выберите новое имя для диагностической копии");rejectLinks(source);rejectLinks(destination);if(destination.toAbsolutePath().normalize().startsWith(source.toAbsolutePath().normalize()))throw new IOException("Копия должна быть вне оригинала");
    AtomicFiles.directory(destination);try(var paths=Files.walk(source)){for(Path f:paths.toList()){if(Files.isSymbolicLink(f))throw new IOException("Symlink в контейнере");Path to=destination.resolve(source.relativize(f));if(Files.isDirectory(f))AtomicFiles.directory(to);else if(!f.getFileName().toString().endsWith(".lock")&&!f.getFileName().toString().startsWith(".atomic-"))Files.copy(f,to);}}
    try{return open(destination,guards,password,true,clock);}catch(IOException|GeneralSecurityException invalid){
      try{Files.deleteIfExists(destination.resolve("archive.lock"));var a=new EncryptedArchive(destination,guards,clock);a.header=ArchiveCrypto.parse(AtomicFiles.read(destination.resolve("key.bin"),4096));a.key=ArchiveCrypto.unlock(a.header,password);
        try{a.readCatalog(AtomicFiles.read(destination.resolve("previous.enc"),MAX_META+28));}catch(IOException|GeneralSecurityException metadataLost){a.entries.clear();}
        try(var files=Files.newDirectoryStream(a.objects,"*.meta")){for(Path f:files){String id=f.getFileName().toString().replace(".meta","");byte[] b=null;try{b=ArchiveCrypto.open(a.key,AtomicFiles.read(f,32768),a.header.id()+"/descriptor/"+id);try(var in=new DataInputStream(new ByteArrayInputStream(b))){ArchiveEntry e=ArchiveEntry.read(in);Binary.end(in);if(!e.id().equals(id))throw new IOException("Descriptor mismatch");a.entries.putIfAbsent(e.id(),e);}}catch(IOException|GeneralSecurityException unreadable){/* Repair copy keeps damaged ciphertext for diagnosis. */}finally{if(b!=null)Arrays.fill(b,(byte)0);}}}
        a.entries.replaceAll((id,e)->e.metadata(a.entries.containsKey(e.folder())?e.folder():"",e.name(),e.tags(),e.favorite(),e.trash()));a.revision=Math.max(1,a.revision);a.verifyAll(progress,()->false);a.committedHeader=ArchiveCrypto.digest(a.header.encode());byte[] repaired=a.sealedCatalog();AtomicFiles.write(destination.resolve("catalog.enc"),repaired);a.committedState=ArchiveCrypto.digest(repaired);a.anchor(a.committedHeader,a.committedState,"","");a.rebuildIndex(progress,()->false);return a;
      }catch(IOException|GeneralSecurityException failed){failed.addSuppressed(invalid);throw failed;}
    }
  }
  @Override public synchronized void close(){closed=true;if(key!=null){Arrays.fill(key,(byte)0);key=null;}Arrays.fill(backupHeader,(byte)0);entries.clear();header=null;try{if(fileLock.isValid())fileLock.release();}catch(IOException ignored){}try{lockChannel.close();}catch(IOException ignored){}}
  @Override public String toString(){return "EncryptedArchive[redacted]";}
}
