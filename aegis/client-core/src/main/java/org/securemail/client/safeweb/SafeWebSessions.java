package org.securemail.client.safeweb;

import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.nio.channels.FileLock;
import java.util.*;
import org.securemail.client.AppPaths;
import org.securemail.client.storage.AtomicFiles;

/** Browser-only state. Trusted receipts/templates are never mounted into the browser sandbox. */
public final class SafeWebSessions {
  public enum Mode {PERSISTENT,TEMPORARY;public String toString(){return this==PERSISTENT?"Обычная изолированная сессия":"Временная сессия";}}
  public record Session(String id,Path bundle,Path control,Mode mode){}
  private final Path root,control,templates,bundles;
  private static final String UUID_PATTERN="[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}";
  public SafeWebSessions(Path root)throws IOException{
    this.root=root.toAbsolutePath().normalize();
    Path messenger=AppPaths.root().toAbsolutePath().normalize();
    Path realMessenger=resolveIncludingMissing(messenger),realBrowser=resolveIncludingMissing(this.root);
    if(this.root.startsWith(messenger)||messenger.startsWith(this.root)||realBrowser.startsWith(realMessenger)||realMessenger.startsWith(realBrowser))throw new IOException("Хранилища браузера и АЕГИС должны быть раздельными");
    rejectLinksInParents(this.root);AtomicFiles.directory(this.root);control=this.root.resolve("control");templates=this.root.resolve("templates");bundles=this.root.resolve("bundles");
    for(Path p:List.of(control,templates,bundles))AtomicFiles.directory(p);
  }
  public static Path defaultRoot(){
    if(AppPaths.windows())return Path.of(Objects.requireNonNull(System.getenv("LOCALAPPDATA"),"LOCALAPPDATA"),"AEGIS-SafeWeb");
    return AppPaths.root().toAbsolutePath().normalize().resolveSibling("aegis-safeweb");
  }
  public Path root(){return root;}
  public Path newInstallationPath()throws IOException{checkRoots();Path p=templates.resolve("install-"+UUID.randomUUID());if(Files.exists(p,LinkOption.NOFOLLOW_LINKS))throw new IOException("Каталог уже существует");return p;}
  /** Call only after TorBrowserSignature verification and successful extraction by TorBrowserInstaller. */
  public synchronized void registerVerifiedBundle(Path source,String archiveHash)throws IOException{
    checkRoots();if(!archiveHash.matches("[a-f0-9]{64}"))throw new IOException("Некорректный отпечаток официального пакета");
    source=source.toAbsolutePath().normalize();if(!source.startsWith(templates)||source.equals(templates))throw new IOException("Пакет должен находиться в отдельном каталоге установки");
    rejectLinksInParents(source);String id="template-"+archiveHash;Path target=templates.resolve(id);
    // A failed copy must never leave a partial directory under its published ID.
    // The caller holds the Safe Web manager lock for this entire transaction.
    JsonObject authenticated=snapshot(source);
    if(Files.exists(target,LinkOption.NOFOLLOW_LINKS)){
      verify(target,authenticated);
      if(Files.exists(manifestPath(id),LinkOption.NOFOLLOW_LINKS))verify(target,readManifest(id));
      else writeManifest(id,authenticated); // recovery against the freshly verified official source
    } else {
      Path staging=templates.resolve(".template-stage-"+UUID.randomUUID());
      try{copyTree(source,staging);verify(staging,authenticated);writeManifest(id,authenticated);publish(staging,target);}
      finally{removeTree(staging);}
    }
    AtomicFiles.write(control.resolve("selected-template"),id.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
  }
  public synchronized boolean installed(){try{selected();return true;}catch(IOException absent){return false;}}
  public synchronized String installedFingerprint()throws IOException{return selected().substring("template-".length());}
  private String selected()throws IOException{
    String value=new String(AtomicFiles.read(control.resolve("selected-template"),128),java.nio.charset.StandardCharsets.US_ASCII);
    if(!value.matches("template-[a-f0-9]{64}")||!Files.isDirectory(templates.resolve(value),LinkOption.NOFOLLOW_LINKS)||!Files.isRegularFile(manifestPath(value),LinkOption.NOFOLLOW_LINKS))throw new IOException("Сначала установите проверенный официальный Tor Browser");return value;
  }
  public synchronized Session prepare(Mode mode)throws IOException{
    checkRoots();Objects.requireNonNull(mode);String template=selected();Path origin=templates.resolve(template);JsonObject trusted=readManifest(template);verify(origin,trusted);
    String id=mode==Mode.PERSISTENT?"normal-"+template.substring(9,25):"temporary-"+UUID.randomUUID();Path target=bundles.resolve(id);
    if(!Files.exists(target,LinkOption.NOFOLLOW_LINKS)){
      Path staging=bundles.resolve(".session-stage-"+UUID.randomUUID());
      try{
        copyTree(origin,staging);
        if(mode==Mode.PERSISTENT){Path previous=previousPersistent();if(previous!=null&&!previous.equals(target))copyBrowserData(previous,staging);}
        verify(staging,trusted);publish(staging,target);
      }finally{removeTree(staging);}
    }
    // An official MAR update may change binaries. It must be re-attested with a signed
    // official archive before a later launch; never silently recompute trusted hashes.
    verify(target,trusted);
    // Also repairs a crash after atomic directory publication but before pointer commit.
    if(mode==Mode.PERSISTENT)AtomicFiles.write(control.resolve("persistent-session"),id.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    Path sessionControl=control.resolve(id);AtomicFiles.directory(sessionControl);return new Session(id,target,sessionControl,mode);
  }
  private Path previousPersistent()throws IOException{
    Path p=control.resolve("persistent-session");if(!Files.exists(p,LinkOption.NOFOLLOW_LINKS))return null;
    String id=new String(AtomicFiles.read(p,128),java.nio.charset.StandardCharsets.US_ASCII);if(!id.matches("normal-[a-f0-9]{16}"))throw new IOException("Повреждён профиль браузера");
    Path old=bundles.resolve(id);rejectLinksInParents(old);return Files.isDirectory(old,LinkOption.NOFOLLOW_LINKS)?old:null;
  }
  /** Existing downloads remain available after restart without creating or opening
   * a browser, recreating its control directory, or adopting changed binaries.
   */
  public synchronized Optional<Session> persistentSession()throws IOException{
    checkRoots();Path old=previousPersistent();if(old==null)return Optional.empty();String id=old.getFileName().toString();
    Session session=new Session(id,old,control.resolve(id),Mode.PERSISTENT);validateSession(session);return Optional.of(session);
  }
  private static void copyBrowserData(Path old,Path next)throws IOException{
    for(String relative:List.of("Browser/TorBrowser/Data","aegis-downloads")){
      Path source=old.resolve(relative);if(!Files.exists(source,LinkOption.NOFOLLOW_LINKS))continue;Path target=next.resolve(relative);removeTree(target);copyTree(source,target);
    }
  }
  public synchronized void complete(Session session)throws IOException{
    validateSession(session);removeTree(session.control());if(session.mode()==Mode.TEMPORARY)removeTree(session.bundle());
  }
  public synchronized List<Path> downloads(Session session)throws IOException{
    validateSession(session);Path directory=session.bundle().resolve("aegis-downloads");rejectLinksInParents(directory);if(!Files.exists(directory,LinkOption.NOFOLLOW_LINKS))AtomicFiles.directory(directory);
    if(Files.isSymbolicLink(directory))throw new IOException("Небезопасный каталог загрузок");
    try(var files=Files.list(directory)){return files.filter(p->Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(p)&&!p.getFileName().toString().endsWith(".part")).limit(500).toList();}
  }
  private void validateSession(Session s)throws IOException{
    checkRoots();if(s==null||s.id()==null||s.mode()==null||!s.id().matches(s.mode()==Mode.PERSISTENT?"normal-[a-f0-9]{16}":"temporary-"+UUID_PATTERN)||!s.bundle().equals(bundles.resolve(s.id()))||!s.control().equals(control.resolve(s.id())))throw new IOException("Некорректная сессия браузера");
    rejectLinksInParents(s.control());rejectLinksInParents(s.bundle());
  }
  /** Call only while holding the exclusive manager lock, before any browser starts.
   * Persistent sessions and their downloads are never considered for deletion.
   * Temporary mode authorizes ordinary filesystem deletion, not forensic erasure.
   */
  public synchronized int cleanupStaleTemporarySessions(FileLock exclusiveManagerLock)throws IOException{
    if(exclusiveManagerLock==null||!exclusiveManagerLock.isValid()||exclusiveManagerLock.isShared())throw new IOException("Для очистки требуется исключительная блокировка Safe Web");
    checkRoots();int cleaned=0;
    for(Path parent:List.of(bundles,control,templates))try(var entries=Files.newDirectoryStream(parent)){
      for(Path entry:entries){String name=entry.getFileName().toString();
        boolean temporary=name.matches("temporary-"+UUID_PATTERN);
        boolean staging=parent.equals(bundles)&&name.matches("\\.session-stage-"+UUID_PATTERN)||parent.equals(templates)&&name.matches("\\.template-stage-"+UUID_PATTERN);
        if(temporary&&(parent.equals(bundles)||parent.equals(control))||staging){removeTree(entry);cleaned++;}
      }
    }
    return cleaned;
  }
  private void checkRoots()throws IOException{for(Path path:List.of(root,control,templates,bundles))rejectLinksInParents(path);}
  private static void publish(Path staged,Path target)throws IOException{
    if(Files.exists(target,LinkOption.NOFOLLOW_LINKS))throw new IOException("Каталог сессии уже существует");
    // Staging and target are siblings on the same private filesystem. Failure of
    // atomic rename is an error; never fall back to a partially visible copy.
    Files.move(staged,target,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(target.getParent());
  }
  private Path manifestPath(String id){return control.resolve(id+".json");}
  private JsonObject readManifest(String id)throws IOException{
    try{return JsonParser.parseString(new String(AtomicFiles.read(manifestPath(id),4_000_000),java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();}catch(RuntimeException bad){throw new IOException("Повреждена запись подлинности браузера",bad);}
  }
  private void writeManifest(String id,JsonObject manifest)throws IOException{AtomicFiles.write(manifestPath(id),manifest.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));}
  private static boolean runtimeData(String name){return name.equals("Browser/TorBrowser/Data")||name.startsWith("Browser/TorBrowser/Data/")||name.equals("aegis-downloads")||name.startsWith("aegis-downloads/")||name.equals("start-tor-browser.desktop");}
  private static void validateMutableRoots(Path base)throws IOException{
    for(String relative:List.of("Browser/TorBrowser/Data","aegis-downloads")){
      Path path=base.resolve(relative);rejectLinksInParents(path);
      if(Files.exists(path,LinkOption.NOFOLLOW_LINKS)&&!Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Некорректный каталог данных браузера");
    }
    Path desktop=base.resolve("start-tor-browser.desktop");
    if(Files.exists(desktop,LinkOption.NOFOLLOW_LINKS)&&!Files.isRegularFile(desktop,LinkOption.NOFOLLOW_LINKS))throw new IOException("Небезопасный изменяемый launcher браузера");
  }
  static JsonObject snapshot(Path base)throws IOException{
    rejectLinksInParents(base);if(!Files.isDirectory(base,LinkOption.NOFOLLOW_LINKS))throw new IOException("Требуется каталог браузера");validateMutableRoots(base);
    JsonObject files=new JsonObject(),links=new JsonObject();Path realBase=base.toRealPath();
    Files.walkFileTree(base,new SimpleFileVisitor<>(){
      private long total;private int count;
      private String name(Path path)throws IOException{String value=base.relativize(path).toString().replace('\\','/');safeRelative(value);return value;}
      private void bounded()throws IOException{if(++count>30000)throw new IOException("Слишком много файлов браузера");}
      @Override public FileVisitResult preVisitDirectory(Path directory,BasicFileAttributes attrs)throws IOException{
        if(directory.equals(base))return FileVisitResult.CONTINUE;
        if(runtimeData(name(directory)))return FileVisitResult.SKIP_SUBTREE;bounded();return FileVisitResult.CONTINUE;
      }
      @Override public FileVisitResult visitFile(Path path,BasicFileAttributes attrs)throws IOException{
        String name=name(path);if(runtimeData(name))return FileVisitResult.CONTINUE;bounded();
        if(attrs.isSymbolicLink()){Path link=Files.readSymbolicLink(path);Path resolved=path.getParent().resolve(link).normalize();if(link.isAbsolute()||!resolved.startsWith(base)||!resolved.toRealPath().startsWith(realBase))throw new IOException("Внешняя ссылка браузера");links.addProperty(name,link.toString().replace('\\','/'));}
        else if(attrs.isRegularFile()){long size=attrs.size();if(size>4_000_000_000L-total)throw new IOException("Слишком большой пакет браузера");total+=size;files.addProperty(name,digest(path));}
        else throw new IOException("Особый файл браузера");return FileVisitResult.CONTINUE;
      }
    });
    if(!files.has("Browser/start-tor-browser")&&!files.has("Browser/firefox.exe"))throw new IOException("Не найден официальный браузер");
    JsonObject result=new JsonObject();result.add("files",files);result.add("links",links);return result;
  }
  static void verify(Path base,JsonObject expected)throws IOException{
    rejectLinksInParents(base);JsonObject actual=snapshot(base);
    if(!actual.equals(expected))throw new IOException("Файлы Tor Browser изменились. Подтвердите официальное обновление установкой свежего подписанного пакета; локальное повторное хэширование запрещено.");
  }
  private static String digest(Path file)throws IOException{
    try(var in=Files.newInputStream(file,LinkOption.NOFOLLOW_LINKS)){MessageDigest md=MessageDigest.getInstance("SHA-256");byte[] b=new byte[65536];for(int n;(n=in.read(b))!=-1;)md.update(b,0,n);return HexFormat.of().formatHex(md.digest());}catch(NoSuchAlgorithmException impossible){throw new IOException(impossible);}
  }
  private static void safeRelative(String name)throws IOException{if(name.length()>4096||name.startsWith("/")||name.indexOf('\0')>=0||name.indexOf('\n')>=0||Arrays.asList(name.split("/")).contains(".."))throw new IOException("Небезопасный путь браузера");}
  static void rejectLinksInParents(Path path)throws IOException{for(Path p=path.toAbsolutePath().normalize();p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылка в пути хранилища браузера");}
  private static Path resolveIncludingMissing(Path path)throws IOException{
    Path current=path.toAbsolutePath().normalize();Deque<Path> suffix=new ArrayDeque<>();
    while(!Files.exists(current,LinkOption.NOFOLLOW_LINKS)){if(current.getParent()==null)throw new IOException("Недоступен путь хранилища");suffix.addFirst(current.getFileName());current=current.getParent();}
    Path result=current.toRealPath();for(Path name:suffix)result=result.resolve(name);return result.normalize();
  }
  static void copyTree(Path source,Path target)throws IOException{
    rejectLinksInParents(source);rejectLinksInParents(target);
    if(!Files.isDirectory(source,LinkOption.NOFOLLOW_LINKS))throw new IOException("Требуется каталог браузера");
    Path absoluteSource=source.toAbsolutePath().normalize(),absoluteTarget=target.toAbsolutePath().normalize();
    if(absoluteTarget.startsWith(absoluteSource)||absoluteSource.startsWith(absoluteTarget))throw new IOException("Пересекающиеся каталоги копирования браузера");
    AtomicFiles.directory(target);Path realSource=source.toRealPath();
    Files.walkFileTree(source,new SimpleFileVisitor<>(){
      private long total;private int count;
      private Path destination(Path path)throws IOException{
        if(++count>100000)throw new IOException("Слишком много объектов профиля браузера");
        Path relative=source.relativize(path);safeRelative(relative.toString().replace('\\','/'));return target.resolve(relative);
      }
      @Override public FileVisitResult preVisitDirectory(Path directory,BasicFileAttributes attrs)throws IOException{
        if(!directory.equals(source))AtomicFiles.directory(destination(directory));return FileVisitResult.CONTINUE;
      }
      @Override public FileVisitResult visitFile(Path path,BasicFileAttributes attrs)throws IOException{
        Path dest=destination(path);
        if(attrs.isSymbolicLink()){Path link=Files.readSymbolicLink(path);if(link.isAbsolute()||!path.getParent().resolve(link).normalize().startsWith(source)||!path.toRealPath().startsWith(realSource))throw new IOException("Внешняя ссылка браузера");Files.createSymbolicLink(dest,link);}
        else if(attrs.isRegularFile()){
          if(attrs.size()>16_000_000_000L-total)throw new IOException("Слишком большой профиль браузера для безопасного копирования");total+=attrs.size();
          Files.copy(path,dest,StandardCopyOption.COPY_ATTRIBUTES,LinkOption.NOFOLLOW_LINKS);
          if(Files.getFileStore(dest).supportsFileAttributeView("posix")){var perms=Files.getPosixFilePermissions(dest);perms.removeAll(Set.of(PosixFilePermission.GROUP_READ,PosixFilePermission.GROUP_WRITE,PosixFilePermission.GROUP_EXECUTE,PosixFilePermission.OTHERS_READ,PosixFilePermission.OTHERS_WRITE,PosixFilePermission.OTHERS_EXECUTE));Files.setPosixFilePermissions(dest,perms);}
        }else throw new IOException("Особый файл браузера");return FileVisitResult.CONTINUE;
      }
    });
  }
  static void removeTree(Path root)throws IOException{
    if(!Files.exists(root,LinkOption.NOFOLLOW_LINKS))return;
    if(Files.isSymbolicLink(root)){Files.delete(root);return;}
    Files.walkFileTree(root,new SimpleFileVisitor<>(){
      @Override public FileVisitResult visitFile(Path file,BasicFileAttributes attrs)throws IOException{Files.delete(file);return FileVisitResult.CONTINUE;}
      @Override public FileVisitResult postVisitDirectory(Path directory,IOException failure)throws IOException{if(failure!=null)throw failure;Files.delete(directory);return FileVisitResult.CONTINUE;}
    });
  }
}
