package org.securemail.client.safeweb;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.concurrent.atomic.AtomicBoolean;
import org.securemail.client.AppPaths;

/** Owns only a separately authenticated Tor Browser and its OS containment.
 * No messenger Tor, identity, archive or credential objects cross this boundary.
 * Stock Tor Browser owns its network/security UI; we never report bootstrap from
 * the messenger's independent Tor as the browser's connection status.
 */
public final class SafeWebProcess implements AutoCloseable {
  public record Snapshot(boolean installed,boolean running,SafeWebSessions.Mode mode,String status){}
  interface Browser extends AutoCloseable {
    Process process();boolean running();String status();void close()throws IOException;
  }
  /** Package-private fixture seam. Production constructors always choose native
   * containment; no runtime flag or test implementation enters release routing.
   * A launcher must clean up all owned resources before throwing.
   */
  @FunctionalInterface interface Launcher {Browser launch(SafeWebSessions.Session session,URI url,List<Path> protectedPaths)throws IOException;}
  private final Path root;
  private final Launcher launcher;
  private SafeWebSessions sessions;
  private SafeWebSessions.Session session,lastPersistent;
  private Browser browser;
  private List<Path> privatePaths=List.of();
  private FileChannel lockChannel;private FileLock lock;
  private String status="Браузер остановлен · Tor браузера: не подключён";
  private volatile Consumer<Snapshot> listener=s->{};
  private final AtomicBoolean notificationPending=new AtomicBoolean();
  private volatile Snapshot published=new Snapshot(false,false,null,"Браузер остановлен · Tor браузера: не подключён");
  private volatile boolean operationInProgress;
  public SafeWebProcess(){this(SafeWebSessions.defaultRoot());}
  public SafeWebProcess(Path root){this(root,SafeWebProcess::launchNative);}
  SafeWebProcess(Path root,Launcher launcher){this.root=Objects.requireNonNull(root);this.launcher=Objects.requireNonNull(launcher);}
  private SafeWebSessions storage()throws IOException{if(sessions==null)sessions=new SafeWebSessions(root);return sessions;}
  public void listener(Consumer<Snapshot> listener){this.listener=Objects.requireNonNull(listener);notifyPublished();}
  public Snapshot snapshot(){return published;}
  public boolean running(){return published.running();}
  /** Nonblocking updater/shutdown guard, including install and pending launch. */
  public boolean busy(){Snapshot current=published;return operationInProgress||current.running()||current.mode()!=null;}
  public synchronized String installedFingerprint()throws IOException{return storage().installedFingerprint();}
  public synchronized void initialize()throws IOException{storage();changed();}
  private void changed(){published=new Snapshot(sessions!=null&&sessions.installed(),browser!=null&&ownedRunning(browser),session==null?null:session.mode(),status);notifyPublished();}
  private static boolean ownedRunning(Browser owned){Process process=owned.process();return owned.running()||process!=null&&process.isAlive();}
  /** Coalesced notifications never invoke UI callbacks while holding the process
   * monitor. A slow/broken listener cannot stall launch, close, or resource locks.
   */
  private void notifyPublished(){
    if(!notificationPending.compareAndSet(false,true))return;
    Thread.startVirtualThread(()->{
      for(;;){Snapshot next=published;Consumer<Snapshot> target=listener;
        try{target.accept(next);}catch(RuntimeException ignored){/* UI disposal cannot change process ownership. */}
        notificationPending.set(false);
        if((published!=next||listener!=target)&&notificationPending.compareAndSet(false,true))continue;
        return;
      }
    });
  }
  private void acquire()throws IOException{
    if(lock!=null&&lock.isValid())return;
    Path path=storage().root().resolve("control/manager.lock");SafeWebSessions.rejectLinksInParents(path);
    lockChannel=FileChannel.open(path,StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);
    try{lock=lockChannel.tryLock();}catch(OverlappingFileLockException busy){lock=null;}
    if(lock==null){release();throw new IOException("Safe Web уже управляется другим экземпляром АЕГИС");}
    try{if(AppPaths.windows())WindowsSafeWebSandbox.recoverAbandoned(storage().root());storage().cleanupStaleTemporarySessions(lock);}catch(IOException failure){release();throw failure;}
  }
  private void release()throws IOException{
    IOException failure=null;
    if(lock!=null)try{if(lock.isValid())lock.release();lock=null;}catch(IOException error){failure=error;}
    if(lock==null&&lockChannel!=null)try{lockChannel.close();lockChannel=null;}catch(IOException error){if(failure==null)failure=error;else failure.addSuppressed(error);}
    if(failure!=null)throw failure;
  }
  /** Only paths cross this boundary, never archive/identity/key objects. */
  public synchronized void privatePaths(Collection<Path> paths)throws IOException{
    List<Path> checked=List.copyOf(paths);Path browserRoot=storage().root().toRealPath();
    List<Path> canonical=new ArrayList<>();
    for(Path path:checked){Path absolute=resolveIncludingMissing(path);if(absolute.startsWith(browserRoot)||browserRoot.startsWith(absolute))throw new IOException("Хранилища АЕГИС и браузера должны быть раздельными");canonical.add(absolute);}
    if(System.getProperty("os.name","").equals("Linux"))LinuxSafeWebSandbox.checkHiddenPaths(checked);
    privatePaths=List.copyOf(canonical);
  }
  private static Path resolveIncludingMissing(Path path)throws IOException{
    Path current=path.toAbsolutePath().normalize();Deque<Path> suffix=new ArrayDeque<>();
    while(!Files.exists(current,LinkOption.NOFOLLOW_LINKS)){if(current.getParent()==null)throw new IOException("Недоступен путь защищённых данных");suffix.addFirst(current.getFileName());current=current.getParent();}
    Path resolved=current.toRealPath();for(Path part:suffix)resolved=resolved.resolve(part);return resolved.normalize();
  }
  /** Installs only detached-signature-authenticated stable vendor packages. */
  public synchronized String install(Path archive,Path signature)throws IOException{
    if(running())throw new IOException("Сначала закройте браузер; его профиль не будет изменён во время работы");
    if(browser!=null)finish(browser);else if(session!=null)finishPrepared();
    acquire();operationInProgress=true;Path target=null;
    try{
      status="Проверка подписи официального Tor Browser…";changed();target=storage().newInstallationPath();
      var installed=TorBrowserInstaller.install(archive,signature,target);
      storage().registerVerifiedBundle(installed.bundle(),installed.archiveSha256());
      status="Официальный пакет Tor Browser · подпись разработчика проверена · браузер остановлен";changed();return installed.label();
    }catch(IOException|RuntimeException failure){status="Установка Tor Browser не выполнена; предыдущая версия сохранена";changed();throw failure;}
    finally{try{try{if(target!=null)SafeWebSessions.removeTree(target);}finally{release();}}finally{operationInProgress=false;changed();}}
  }
  /** URL is one validated argv item, or fixed guest data; never executable code. */
  public synchronized void open(SafeWebSessions.Mode mode,String address)throws IOException{
    URI url=SafeWebUrl.parse(address);
    if(running())throw new IOException("Браузер уже открыт. Используйте его адресную строку или явно перезапустите сессию");
    if(browser!=null)finish(browser);else if(session!=null)finishPrepared();
    acquire();operationInProgress=true;SafeWebSessions.Session prepared=null;
    try{
      status="Подготовка изолированной сессии…";changed();prepared=storage().prepare(mode);session=prepared;changed();
      browser=Objects.requireNonNull(launcher.launch(prepared,url,privatePaths),"Safe Web launcher returned no owned browser");
      if(!ownedRunning(browser))throw new IOException("Процесс Safe Web завершился до подтверждения запуска");
      Browser owned=browser;status=owned.status();changed();
      Thread.ofPlatform().daemon().name("aegis-safeweb-lifecycle").start(()->{
        try{while(ownedRunning(owned)){
          synchronized(SafeWebProcess.this){if(browser!=owned)return;String current=owned.status();if(!current.equals(status)){status=current;changed();}}
          Thread.sleep(500);
        }}catch(InterruptedException interrupted){Thread.currentThread().interrupt();return;}
        synchronized(SafeWebProcess.this){if(browser==owned)try{finish(owned);}catch(IOException error){status="Safe Web завершился; очистка не завершена. Повторите закрытие";changed();}}
      });
    }catch(IOException|RuntimeException failure){
      if(browser!=null){
        try{browser.close();if(ownedRunning(browser))throw new IOException("Процессы Safe Web ещё завершаются");}catch(IOException cleanup){
          failure.addSuppressed(cleanup);status="Запуск не завершён; процессы Safe Web требуют закрытия";changed();throw failure;
        }
        browser=null;
      }
      if(prepared!=null)try{storage().complete(prepared);}catch(IOException cleanup){failure.addSuppressed(cleanup);status="Запуск Safe Web не выполнен; очистка сессии требует повторного закрытия";changed();throw failure;}
      session=null;try{release();}catch(IOException cleanup){failure.addSuppressed(cleanup);}status="Запуск Safe Web не выполнен · небезопасный обход отключён";changed();throw failure;
    }finally{operationInProgress=false;changed();}
  }
  private static Browser launchNative(SafeWebSessions.Session prepared,URI url,List<Path> privatePaths)throws IOException{
    if(AppPaths.windows()){
      var owned=WindowsSafeWebSandbox.start(prepared.bundle(),prepared.control(),url);
      return new Browser(){public Process process(){return owned.process();}public boolean running(){return owned.running();}public String status(){return owned.status();}public void close()throws IOException{owned.close();}};
    }
    if(System.getProperty("os.name","").equals("Linux")){
      var owned=LinuxSafeWebSandbox.start(prepared.bundle(),prepared.control(),url,privatePaths);
      return new Browser(){public Process process(){return owned.process();}public boolean running(){return owned.running();}public String status(){return owned.status();}public void close()throws IOException{owned.close();}};
    }
    throw new IOException("Safe Web поддерживает Windows 11 x64 и Linux x86_64");
  }

  /** Explicit restart, not an unsupported remote command or 'new identity' IPC. */
  public synchronized void newSession(SafeWebSessions.Mode mode,String address)throws IOException{SafeWebUrl.parse(address);close();open(mode,address);}
  public synchronized List<Path> downloads()throws IOException{
    var selected=session!=null?session:lastPersistent!=null?lastPersistent:storage().persistentSession().orElse(null);
    return selected==null?List.of():storage().downloads(selected);
  }
  /** A stale UI selection cannot import an arbitrary path or a symlink. */
  public synchronized Path selectedDownload(Path selected)throws IOException{
    Path absolute=Objects.requireNonNull(selected).toAbsolutePath().normalize();
    for(Path candidate:downloads())if(candidate.toAbsolutePath().normalize().equals(absolute))return candidate;
    throw new IOException("Выбранный файл больше не находится в загрузках Safe Web");
  }
  /** Freeze the explicitly selected download outside the browser's mount before
   * the archive worker reads it; no original path is handed to that worker. */
  public synchronized SafeWebDownload.Snapshot snapshotDownload(Path selected)throws IOException{
    Path file=selectedDownload(selected);
    return SafeWebDownload.capture(file.getParent(),file,AppPaths.root().resolve("safeweb-imports"));
  }
  private void finish(Browser owned)throws IOException{
    if(owned!=browser)return;
    try{
      owned.close(); // Must succeed before the profile or management lock is released.
      if(ownedRunning(owned))throw new IOException("Процесс Safe Web ещё завершается; сессия и блокировка сохранены");
      if(session!=null){storage().complete(session);if(session.mode()==SafeWebSessions.Mode.PERSISTENT)lastPersistent=session;}
      release();browser=null;session=null;status="Браузер остановлен · соединение почты сохранено";changed();
    }catch(IOException failure){status="Остановка или очистка Safe Web не завершена; сессия и блокировка сохранены";changed();throw failure;}
  }
  private void finishPrepared()throws IOException{
    if(session!=null){storage().complete(session);if(session.mode()==SafeWebSessions.Mode.PERSISTENT)lastPersistent=session;session=null;}
    release();status="Браузер остановлен · соединение почты сохранено";changed();
  }
  @Override public synchronized void close()throws IOException{
    if(browser!=null)finish(browser);else finishPrepared();
  }
}
