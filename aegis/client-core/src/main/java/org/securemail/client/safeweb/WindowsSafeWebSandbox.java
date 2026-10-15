package org.securemail.client.safeweb;

import com.sun.jna.*;
import com.sun.jna.platform.win32.*;
import com.sun.jna.win32.StdCallLibrary;
import java.io.*;
import java.net.URI;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.storage.AtomicFiles;

/** Official Windows Sandbox VM around a dedicated, verified stock Tor Browser.
 * The guest receives exactly one writable browser bundle and no AEGIS data.
 * Windows Home is unsupported by Microsoft Windows Sandbox; there is no silent
 * unsandboxed/AppContainer fallback and this code never enables OS features.
 * Guest network connectivity is needed by Tor. Tor-only web traffic relies on
 * stock Tor Browser, not on a kernel rule distinguishing a compromised broker.
 */
public final class WindowsSafeWebSandbox {
  private WindowsSafeWebSandbox() {}
  private static final String GUEST_BASE="C:\\SafeWeb";
  private static final String RUNTIME="Browser/TorBrowser/Data/aegis-bootstrap";
  private static final Duration START_TIMEOUT=Duration.ofMinutes(2);
  private static final Duration LEASE_TIMEOUT=Duration.ofSeconds(20);
  private interface WindowsDirectoryApi extends StdCallLibrary {
    int GetWindowsDirectoryW(char[] value,int capacity);
  }

  /** Starts the isolated VM. Status remains "starting" until the fixed guest
   * bootstrap reports process creation. It never reports Tor bootstrap success.
   * sessionRoot is the controller directory outside the mapped bundle.
   */
  public static Launch start(Path bundle,Path sessionRoot,URI url)throws IOException {
    if(!System.getProperty("os.name","").startsWith("Windows"))
      throw new IOException("Safe Web Windows: неподдерживаемая ОС");
    URI checked=SafeWebUrl.parse(Objects.requireNonNull(url).toASCIIString());
    String edition;
    try {
      edition=Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion","EditionID");
      String build=Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion","CurrentBuildNumber");
      if(Integer.parseInt(build)<26100)throw new IOException("Управляемый Safe Web требует Windows 11 24H2+ x64 с CLI Windows Sandbox");
    }catch(RuntimeException error){throw new IOException("Не удалось определить редакцию Windows",error);}
    requireSupportedEdition(edition);
    if(!System.getProperty("os.arch","").equalsIgnoreCase("amd64")&&
       !System.getProperty("os.arch","").equalsIgnoreCase("x86_64"))
      throw new IOException("Safe Web требует Windows 11 x64");
    Path windows=windowsDirectory(),executable=windows.resolve("System32/WindowsSandbox.exe");
    if(!Files.isRegularFile(executable,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(executable))
      throw new IOException("Windows Sandbox недоступен. Нужны Windows 11 Pro/Enterprise/Education, виртуализация и установленный компонент Windows Sandbox; АЕГИС не меняет компоненты ОС автоматически");
    Path base=directory(bundle),control=directory(sessionRoot);
    if(base.equals(control)||control.startsWith(base))throw new IOException("Каталог управления Safe Web должен находиться вне браузерного пакета");
    Path nativeLocal=Path.of(Shell32Util.getKnownFolderPath(KnownFolders.FOLDERID_LocalAppData)).toRealPath();
    Path allowed=nativeLocal.resolve("AEGIS-SafeWeb/bundles").normalize();
    if(!base.getParent().equals(allowed)||!base.getFileName().toString().matches("[A-Za-z0-9_-]{1,100}"))
      throw new IOException("Windows Sandbox принимает только отдельный браузерный пакет Safe Web");
    if(!control.equals(allowed.getParent().resolve("control").resolve(base.getFileName())))
      throw new IOException("Каталог управления должен соответствовать собственной сессии Safe Web");
    if(!Files.isRegularFile(base.resolve("Browser/firefox.exe"),LinkOption.NOFOLLOW_LINKS)||
       !Files.isDirectory(base.resolve("Browser/TorBrowser/Data/Browser/profile.default"),LinkOption.NOFOLLOW_LINKS))
      throw new IOException("Не найден официальный Windows Tor Browser");
    rejectReparseTree(base);
    Path lockPath=allowed.getParent().resolve("control/windows-sandbox.lock");
    FileChannel channel=FileChannel.open(lockPath,StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);
    FileLock lock;
    try{lock=channel.tryLock();}catch(OverlappingFileLockException busy){channel.close();throw new IOException("Safe Web уже запускает Windows Sandbox",busy);}
    if(lock==null){channel.close();throw new IOException("Safe Web уже запускает Windows Sandbox");}
    Launch launch=null;
    try {
      WindowsSandboxCli cli=new WindowsSandboxCli(windows,nativeLocal,control);
      // A trusted host CLI, not a writable guest status file or launcher PID,
      // identifies and owns the VM. No process-name killing or VM adoption.
      if(cli.list().values().stream().anyMatch(Boolean::booleanValue))throw new IOException("Уже открыт Windows Sandbox. Закройте его перед запуском Safe Web; АЕГИС не управляет посторонними экземплярами");
      String nonce=UUID.randomUUID().toString();
      Path runtime=base.resolve(RUNTIME).resolve(nonce);AtomicFiles.directory(runtime);
      Path downloads=base.resolve("aegis-downloads");AtomicFiles.directory(downloads);
      AtomicFiles.write(runtime.resolve("start.ps1"),bootstrap());
      AtomicFiles.write(runtime.resolve("url.b64"),Base64.getEncoder().encode(checked.toASCIIString().getBytes(StandardCharsets.US_ASCII)));
      Path config=control.resolve("safeweb.wsb");AtomicFiles.write(config,configuration(base,nonce).getBytes(StandardCharsets.UTF_8));
      grantSandboxSystemAccess(allowed.getParent());grantSandboxSystemAccess(allowed);
      try(var paths=Files.walk(base)){for(Path path:paths.toList())grantSandboxSystemAccess(path);}
      launch=new Launch(downloads,runtime,config,nonce,channel,lock,cli);
      launch.runtimeGuard=SafeWebDownload.guardDirectory(runtime);
      launch.heartbeat();
      // Host-private ownership receipt survives a JVM crash. It is not mapped
      // into the guest and is written before any VM creation can be dispatched.
      AtomicFiles.write(control.resolve("owned-vm-id"),nonce.getBytes(StandardCharsets.US_ASCII));
      launch.attemptedStart=true;
      WindowsSandboxCli.Result start=cli.run(List.of("start","--id",nonce,"--config",configuration(base,nonce),"--raw"),START_TIMEOUT);
      Map<String,Boolean> after=cli.list();
      launch.ambiguousOwnership=after.entrySet().stream().anyMatch(e->e.getValue()&&!e.getKey().equals(nonce));
      if(start.exit()!=0||!Boolean.TRUE.equals(after.get(nonce))||launch.ambiguousOwnership)
        throw new IOException("Microsoft Windows Sandbox не подтвердил создание собственной виртуальной машины Safe Web");
      launch.vmOwned=true;
      ProcessBuilder builder=cli.builder(List.of("connect","--id",nonce,"--raw"));
      builder.redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD);
      launch.process=builder.start();
      launch.process.getOutputStream().close();
      Launch owned=launch;Thread.startVirtualThread(owned::monitor);
      return launch;
    }catch(IOException|RuntimeException failure){
      if(launch!=null){Launch retained=launch;
        IOException problem=failure instanceof IOException io?io:new IOException("Запуск Windows Sandbox прерван",failure);
        return retainOnUnverifiedStop(retained,problem,retained::close,()->retained.message="Запуск Safe Web прерван; остановка VM не подтверждена. Повторите закрытие Safe Web");
      }
      lock.release();channel.close();throw failure;
    }
  }
  /** A start failure must not lose the last object owning a possibly live VM. */
  static <T> T retainOnUnverifiedStop(T owned,IOException startFailure,Closeable cleanup,Runnable retained)throws IOException {
    Objects.requireNonNull(owned);
    try{cleanup.close();}catch(IOException|RuntimeException cleanupFailure){
      startFailure.addSuppressed(cleanupFailure);retained.run();return owned;
    }
    throw startFailure;
  }

  static void requireSupportedEdition(String edition)throws IOException {
    if(edition==null||!edition.matches("Professional(?:N|EducationN?|WorkstationN?)?|Enterprise(?:N|S|SN)?|EducationN?"))
      throw new IOException("Windows Sandbox поддерживается Microsoft только в редакциях Pro, Enterprise и Education. Windows Home: изолированный Safe Web недоступен; обычный запуск браузера отключён");
  }
  /** Reconcile only host-private IDs before stale temporary bundles are deleted.
   * Called after the outer session-manager lock is acquired. A failed or absent
   * native control plane preserves every receipt/bundle and prevents cleanup.
   */
  public static void recoverAbandoned(Path safeWebRoot)throws IOException {
    if(!System.getProperty("os.name","").startsWith("Windows"))return;
    Path control=safeWebRoot.toAbsolutePath().normalize().resolve("control");
    if(!Files.isDirectory(control,LinkOption.NOFOLLOW_LINKS))return;
    SafeWebSessions.rejectLinksInParents(control);
    List<Path> receipts=new ArrayList<>();
    try(var children=Files.list(control)) {
      Iterator<Path> iterator=children.iterator();int count=0;
      while(iterator.hasNext()) {
        if(++count>1000)throw new IOException("Слишком много записей управления Safe Web");
        Path session=iterator.next();String name=session.getFileName().toString();
        if(!name.matches("normal-[a-f0-9]{16}|temporary-[a-f0-9-]{36}")||!Files.isDirectory(session,LinkOption.NOFOLLOW_LINKS))continue;
        Path receipt=session.resolve("owned-vm-id");
        if(Files.exists(receipt,LinkOption.NOFOLLOW_LINKS)){if(receipts.size()>=64)throw new IOException("Слишком много незавершённых сессий Windows Sandbox");receipts.add(receipt);}
      }
    }
    if(receipts.isEmpty())return;
    Path local=Path.of(Shell32Util.getKnownFolderPath(KnownFolders.FOLDERID_LocalAppData)).toRealPath();
    if(!safeWebRoot.toAbsolutePath().normalize().equals(local.resolve("AEGIS-SafeWeb")))
      throw new IOException("Нельзя восстановить сессии Windows Sandbox из постороннего каталога");
    try(FileChannel channel=FileChannel.open(control.resolve("windows-sandbox.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)) {
      FileLock lock;
      try{lock=channel.tryLock();}catch(OverlappingFileLockException busy){throw new IOException("Safe Web уже управляет Windows Sandbox",busy);}
      if(lock==null)throw new IOException("Safe Web уже управляет Windows Sandbox");
      try(lock;Closeable guard=SafeWebDownload.guardDirectory(control)) {
        WindowsSandboxCli cli=new WindowsSandboxCli(windowsDirectory(),local,control);
        for(Path receipt:receipts) {
          try(Closeable sessionGuard=SafeWebDownload.guardDirectory(receipt.getParent())) {
            String id=readOwnedId(receipt);
            if(Boolean.TRUE.equals(cli.list().get(id)))cli.stop(id);
            if(Boolean.TRUE.equals(cli.list().get(id)))throw new IOException("Предыдущая виртуальная машина Safe Web ещё работает; файлы сохранены");
            Path runtime=safeWebRoot.resolve("bundles").resolve(receipt.getParent().getFileName()).resolve(RUNTIME).resolve(id);
            SafeWebSessions.rejectLinksInParents(runtime);SafeWebSessions.removeTree(runtime);
            Files.delete(receipt);
          }
        }
      }
    }
  }
  private static String readOwnedId(Path receipt)throws IOException {
    try(InputStream input=Files.newInputStream(receipt,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS)) {
      byte[] bytes=input.readNBytes(65);if(bytes.length!=36)throw new IOException("Повреждена запись принадлежности Windows Sandbox");
      String id=new String(bytes,StandardCharsets.US_ASCII);
      if(!id.matches("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"))throw new IOException("Повреждён идентификатор собственной VM");
      return id;
    }
  }
  private static Path windowsDirectory()throws IOException {
    char[] path=new char[32768];int n=Native.load("kernel32",WindowsDirectoryApi.class).GetWindowsDirectoryW(path,path.length);
    if(n<=0||n>=path.length)throw new IOException("Не найден системный каталог Windows");
    Path directory=Path.of(new String(path,0,n)).toRealPath();
    if(!directory.isAbsolute()||Files.isSymbolicLink(directory))throw new IOException("Небезопасный системный каталог Windows");
    return directory;
  }
  private static void grantSandboxSystemAccess(Path path)throws IOException {
    var view=Files.getFileAttributeView(path,AclFileAttributeView.class,LinkOption.NOFOLLOW_LINKS);
    if(view==null)throw new IOException("Windows Sandbox требует NTFS ACL");
    var lookup=path.getFileSystem().getUserPrincipalLookupService();
    UserPrincipal owner=lookup.lookupPrincipalByName(System.getProperty("user.name"));
    UserPrincipal system=lookup.lookupPrincipalByName(Advapi32Util.getAccountBySid("S-1-5-18").fqn);
    AclEntry.Builder entry=AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPermissions(EnumSet.allOf(AclEntryPermission.class));
    if(Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))entry.setFlags(AclEntryFlag.FILE_INHERIT,AclEntryFlag.DIRECTORY_INHERIT);
    view.setAcl(List.of(entry.setPrincipal(owner).build(),entry.setPrincipal(system).build()));
  }
  private static void writeGuestData(Path destination,byte[] data)throws IOException {
    // Runtime parents stay pinned by a native no-SHARE_DELETE guard. Create the
    // user+SYSTEM ACL atomically with the new file: never apply ACLs to a leaf
    // that a writable guest can replace with a reparse point after a rename.
    var lookup=destination.getFileSystem().getUserPrincipalLookupService();
    UserPrincipal owner=lookup.lookupPrincipalByName(System.getProperty("user.name"));
    UserPrincipal system=lookup.lookupPrincipalByName(Advapi32Util.getAccountBySid("S-1-5-18").fqn);
    List<AclEntry> acl=List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build(),
      AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(system).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build());
    FileAttribute<List<AclEntry>> attribute=new FileAttribute<>(){
      public String name(){return "acl:acl";}public List<AclEntry> value(){return acl;}
    };
    Path temporary=destination.resolveSibling(".lease-"+UUID.randomUUID()+".tmp");
    try {
      try(FileChannel file=FileChannel.open(temporary,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),attribute)) {
        java.nio.ByteBuffer bytes=java.nio.ByteBuffer.wrap(data);while(bytes.hasRemaining())file.write(bytes);file.force(true);
      }
      Files.move(temporary,destination,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
    } finally {Files.deleteIfExists(temporary);}
  }
  private static Path directory(Path path)throws IOException {
    SafeWebSessions.rejectLinksInParents(path);
    if(!Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Не найден каталог Safe Web");
    return path.toRealPath();
  }
  private static void rejectReparseTree(Path root)throws IOException {
    // Runtime profile/download files are mutable and are not trusted binaries.
    // They still must not introduce a host junction into the shared directory.
    try(var paths=Files.walk(root)) {
      Iterator<Path> iterator=paths.iterator();int count=0;
      while(iterator.hasNext()) {
        Path path=iterator.next();if(++count>80000)throw new IOException("Слишком много файлов в сессии Safe Web");
        int attributes=Kernel32.INSTANCE.GetFileAttributes(path.toString());
        if(attributes==WinBase.INVALID_FILE_ATTRIBUTES||(attributes&WinNT.FILE_ATTRIBUTE_REPARSE_POINT)!=0)
          throw new IOException("Ссылки и точки повторной обработки в Windows-пакете браузера запрещены");
      }
    }
  }
  static byte[] bootstrap()throws IOException {
    try(InputStream input=WindowsSafeWebSandbox.class.getResourceAsStream("/org/securemail/client/safeweb/windows-sandbox-start.ps1")) {
      if(input==null)throw new IOException("Отсутствует компонент Windows Sandbox");
      byte[] script=input.readNBytes(65537);if(script.length==0||script.length>65536)throw new IOException("Некорректный компонент Windows Sandbox");return script;
    }
  }
  static String configuration(Path bundle,String nonce) {
    if(!nonce.matches("[a-f0-9-]{36}"))throw new IllegalArgumentException("Session id");
    String command="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\SafeWeb\\Browser\\TorBrowser\\Data\\aegis-bootstrap\\"+nonce+"\\start.ps1";
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Configuration>\n"+
      "  <vGPU>Disable</vGPU>\n  <Networking>Enable</Networking>\n"+
      "  <AudioInput>Disable</AudioInput>\n  <VideoInput>Disable</VideoInput>\n"+
      "  <PrinterRedirection>Disable</PrinterRedirection>\n  <ClipboardRedirection>Disable</ClipboardRedirection>\n"+
      "  <ProtectedClient>Enable</ProtectedClient>\n  <MemoryInMB>4096</MemoryInMB>\n"+
      "  <MappedFolders><MappedFolder><HostFolder>"+xml(bundle.toString())+"</HostFolder>"+
      "<SandboxFolder>"+GUEST_BASE+"</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder></MappedFolders>\n"+
      "  <LogonCommand><Command>"+xml(command)+"</Command></LogonCommand>\n</Configuration>\n";
  }
  private static String xml(String value){return value.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&apos;");}

  public static final class Launch implements AutoCloseable {
    private Process process;private final Path downloads,runtime,config;
    private final String nonce;private final FileChannel channel;private final FileLock lock;
    private final WindowsSandboxCli cli;
    private Closeable runtimeGuard;
    private volatile boolean closing,stopped,guestActive,guestEnded,attemptedStart,vmOwned,ambiguousOwnership;
    private volatile String message="Windows Sandbox запускается; гостевая система ещё не подтвердила запуск";
    private long heartbeat,guestCounter=-1,lastGuest=System.nanoTime();
    private Launch(Path downloads,Path runtime,Path config,String nonce,FileChannel channel,FileLock lock,WindowsSandboxCli cli){
      this.downloads=downloads;this.runtime=runtime;this.config=config;this.nonce=nonce;this.channel=channel;this.lock=lock;this.cli=cli;
    }
    public synchronized Process process(){return process;}
    public Path downloads(){return downloads;}
    public synchronized boolean running(){return !stopped;}
    public synchronized String status(){return message;}
    private synchronized void heartbeat()throws IOException {
      if(!closing)writeGuestData(runtime.resolve("lease.txt"),(nonce+":"+(++heartbeat)).getBytes(StandardCharsets.US_ASCII));
    }
    private synchronized void readGuest()throws IOException {
      Path state=runtime.resolve("state.txt");if(!Files.isRegularFile(state,LinkOption.NOFOLLOW_LINKS))return;
      byte[] bytes;
      try(InputStream input=Files.newInputStream(state,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS)){
        bytes=input.readNBytes(257);if(bytes.length>256)throw new IOException("Некорректное состояние гостевой системы");
      }catch(NoSuchFileException absent){return;}
      String value=new String(bytes,StandardCharsets.US_ASCII);
      String[] parts=value.split(":",-1);if(parts.length!=3||!parts[1].equals(nonce)||!parts[2].matches("[0-9]{1,16}"))return;
      long counter=Long.parseLong(parts[2]);if(counter<=guestCounter)return;guestCounter=counter;lastGuest=System.nanoTime();
      switch(parts[0]) {
        case "PROCESS_CREATED" -> {guestActive=true;message="Tor Browser запущен внутри Windows Sandbox; состояние Tor проверяется в браузере";}
        case "CLOSED" -> {guestActive=false;guestEnded=true;message="Браузер завершён; проверяется остановка собственной виртуальной машины";}
        case "ERROR" -> {guestActive=false;guestEnded=true;message="Tor Browser не запустился в Windows Sandbox; защита не отключалась";}
        default -> { /* Guest data is untrusted; never render arbitrary guest text. */ }
      }
    }
    private void monitor() {
      long started=System.nanoTime();
      try {
        while(!closing&&!stopped){heartbeat();readGuest();
          if(guestEnded||!Boolean.TRUE.equals(cli.list().get(nonce)))break;
          long now=System.nanoTime();
          if(!guestActive&&now-started>START_TIMEOUT.toNanos()){
            message="Windows Sandbox не подтвердил запуск за две минуты; проверьте компонент и виртуализацию";break;}
          if(guestActive&&now-lastGuest>LEASE_TIMEOUT.toNanos()){
            message="Связь с гостевым процессом Safe Web прервалась";break;}
          Thread.sleep(1000);
        }
      }catch(IOException error){message="Не удалось обновить контрольную сессию Windows Sandbox";}
       catch(InterruptedException interrupted){Thread.currentThread().interrupt();message="Управление Windows Sandbox прервано";}
      finally {try{close();}catch(IOException error){message="Windows Sandbox ещё завершается; закройте принадлежащее Safe Web окно";}}
    }
    @Override public synchronized void close()throws IOException {
      if(stopped){releaseController();return;}
      closing=true;guestActive=false;
      try{writeGuestData(runtime.resolve("stop.txt"),nonce.getBytes(StandardCharsets.US_ASCII));}catch(IOException ignored){/* Host CLI stops the exact VM even if guest files were corrupted. */}
      // Guest stops its Job Object and shuts down its own disposable VM. A Java
      // crash also expires the guest's monotonic stdin-independent lease.
      try {
        if(ambiguousOwnership)throw new IOException("Принадлежность виртуальной машины не подтверждена; данные сохранены, посторонняя VM не затрагивалась");
        if(attemptedStart){Map<String,Boolean> current=cli.list();
          if(!vmOwned&&!Boolean.TRUE.equals(current.get(nonce))&&current.entrySet().stream().anyMatch(e->e.getValue()&&!e.getKey().equals(nonce)))
            throw new IOException("Собственная VM не идентифицирована; посторонняя сессия сохранена");
          if(Boolean.TRUE.equals(current.get(nonce))){vmOwned=true;cli.stop(nonce);}
          if(Boolean.TRUE.equals(cli.list().get(nonce)))throw new IOException("Остановка собственной VM не подтверждена");}
      }catch(IOException error){message="Остановка Windows Sandbox не подтверждена; данные и блокировка сохранены";throw error;}
      // Only the trusted host CLI has proved our VM stopped. Guest CLOSED is an
      // untrusted hint and launcher exit is irrelevant to this decision.
      stopped=true;
      releaseController();
      // Keep runtime/URL/status until the owner session manager removes the
      // completed temporary bundle. Never delete a mapped folder while live.
      Files.deleteIfExists(config);if(!message.contains("не ")&&!message.contains("прервал"))message="Safe Web остановлен";
    }
    private void releaseController()throws IOException {
      if(runtimeGuard!=null){runtimeGuard.close();runtimeGuard=null;}
      // Host proof of VM termination already exists. Only this session's random
      // bootstrap is removed; ordinary profile/bookmarks/downloads are retained.
      SafeWebSessions.rejectLinksInParents(runtime);SafeWebSessions.removeTree(runtime);
      if(process!=null&&process.isAlive())try{
        if(!process.waitFor(3,TimeUnit.SECONDS)){process.destroy();if(!process.waitFor(2,TimeUnit.SECONDS))process.destroyForcibly();}
        if(!process.waitFor(3,TimeUnit.SECONDS))throw new IOException("Собственный клиент Windows Sandbox ещё завершается");
      }catch(InterruptedException error){Thread.currentThread().interrupt();throw new IOException("Остановка клиента Windows Sandbox прервана",error);}
      Files.deleteIfExists(config.getParent().resolve("owned-vm-id"));
      Files.deleteIfExists(config);
      if(lock.isValid())lock.release();channel.close();
    }
  }
}
