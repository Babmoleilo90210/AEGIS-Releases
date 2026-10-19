package org.securemail.client.safeweb600;

import java.io.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.AppPaths;
import org.securemail.client.safeweb.SafeWebUrl;
import org.securemail.client.safeweb.LinuxSafeWebSandbox;

/** Explicit user-action entry into a detached browser-manager JVM. No account IPC or close-on-Core-exit ownership. */
public final class VzorLaunch600 {
  private static final Semaphore STARTING=new Semaphore(1);
  private static final Set<String> ENVIRONMENT=Set.of("HOME","USER","LOGNAME","USERPROFILE","LOCALAPPDATA","APPDATA","SYSTEMROOT","WINDIR","SYSTEMDRIVE","COMSPEC","TEMP","TMP","TMPDIR","PATH","PATHEXT","LANG","LANGUAGE","LC_ALL","LC_CTYPE","TZ","DISPLAY","WAYLAND_DISPLAY","XAUTHORITY","XDG_RUNTIME_DIR","XDG_SESSION_TYPE","XDG_DATA_HOME","XDG_CONFIG_HOME","XDG_CACHE_HOME","DBUS_SESSION_BUS_ADDRESS","XDG_CURRENT_DESKTOP");
  public enum Status {STARTED,ALREADY_RUNNING}
  /** Deliberately not AutoCloseable: Core logout and Core shutdown must not stop a successfully launched Взор. */
  public static final class Detached {
    private final Status status;private final Process owned;
    private Detached(Status status,Process owned){this.status=status;this.owned=owned;}
    public Status status(){return status;}
    public long managerPid(){return owned==null?-1:owned.pid();}
    public boolean managerAlive(){return owned!=null&&owned.isAlive();}
  }
  private VzorLaunch600(){}
  private static final String UNSAFE_STORAGE="Небезопасное расположение данных АЕГИС. Выберите личный каталог вне системных папок и каталогов Взора.";
  /** Core/Mail-side path-only preflight. These paths never enter the detached manager, browser, URL or diagnostics.
   * Call again before opening/migrating a changed Mail configuration, including while independent Vzor is open. */
  public static void requireHiddenData(Collection<Path> protectedPaths)throws IOException {
    try{String os=System.getProperty("os.name","");if(!os.equals("Linux")&&!os.startsWith("Windows"))throw new IOException(UNSAFE_STORAGE);
      checkHiddenData(protectedPaths,VzorState600.roots(os,System.getProperty("user.home",""),System.getenv()),os.equals("Linux"));
    }catch(IOException|RuntimeException invalid){throw new IOException(UNSAFE_STORAGE,invalid);}
  }
  // Compile-time filesystem fixture seam: no paths or OS flags can be supplied by a URL/IPC command.
  static void checkHiddenData(Collection<Path> protectedPaths,List<Path> browserRoots,boolean linux)throws IOException {
    try{
      if(protectedPaths==null||protectedPaths.isEmpty()||protectedPaths.size()>64||browserRoots==null||browserRoots.size()!=2)throw new IOException(UNSAFE_STORAGE);
      List<Path> checked=List.copyOf(protectedPaths);List<Path> exposed=new ArrayList<>();for(Path root:browserRoots)exposed.add(canonical(root));
      for(Path path:checked){Path secret=canonical(path);for(Path root:exposed)if(secret.startsWith(root)||root.startsWith(secret))throw new IOException(UNSAFE_STORAGE);}
      if(linux)LinuxSafeWebSandbox.checkHiddenPaths(checked);
    }catch(IOException|RuntimeException invalid){throw new IOException(UNSAFE_STORAGE,invalid);}
  }
  private static Path canonical(Path path)throws IOException {
    if(path==null||!path.isAbsolute())throw new IOException(UNSAFE_STORAGE);Path cursor=path.normalize();Deque<Path> missing=new ArrayDeque<>();
    while(!Files.exists(cursor,LinkOption.NOFOLLOW_LINKS)){if(cursor.getParent()==null)throw new IOException(UNSAFE_STORAGE);missing.addFirst(cursor.getFileName());cursor=cursor.getParent();}
    Path result=cursor.toRealPath();for(Path name:missing)result=result.resolve(name);return result.normalize();
  }
  public static boolean managerBusy()throws IOException{return STARTING.availablePermits()==0||VzorState600.managerRunning();}
  public static Detached openAuthorized(Path bundle,String address)throws IOException{
    Objects.requireNonNull(bundle);SafeWebUrl.parse(address);Path home=bundle.toAbsolutePath().normalize();
    Path java=home.resolve(AppPaths.windows()?"runtime/bin/java.exe":"runtime/bin/java");Path app=home.resolve("app");
    if(!Files.isRegularFile(java,LinkOption.NOFOLLOW_LINKS)||!Files.isDirectory(app,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(app))throw new VzorFailure600(VzorFailure600.Code.RUNTIME_MISSING);
    List<String> command=List.of(java.toString(),"-Xmx768m","-XX:+DisableAttachMechanism","-XX:-HeapDumpOnOutOfMemoryError","-Daegis.home="+home,"-cp",app.resolve("*").toString(),"org.securemail.ui.VzorApp600");
    return launch(command,address,Duration.ofSeconds(25),true);
  }
  /** Compile-time package-private fixture seam, never a runtime class name or executable supplied by a URL. */
  static Detached launch(List<String> command,String address,Duration timeout,boolean sanitizeEnvironment)throws IOException{
    return launch(command,address,timeout,sanitizeEnvironment,owned->{});
  }
  static Detached launch(List<String> command,String address,Duration timeout,boolean sanitizeEnvironment,java.util.function.Consumer<Process> observer)throws IOException{
    Objects.requireNonNull(observer);SafeWebUrl.parse(address);if(!STARTING.tryAcquire())throw new VzorFailure600(VzorFailure600.Code.STARTUP_BUSY);
    byte[] nonce=VzorBootstrap600.freshNonce();Process process=null;boolean detached=false;
    try{
      ProcessBuilder builder=new ProcessBuilder(List.copyOf(command)).redirectInput(ProcessBuilder.Redirect.PIPE).redirectOutput(ProcessBuilder.Redirect.PIPE).redirectError(ProcessBuilder.Redirect.DISCARD);
      if(sanitizeEnvironment){Map<String,String> allowed=filteredEnvironment(builder.environment());builder.environment().clear();builder.environment().putAll(allowed);}
      process=builder.start();observer.accept(process);try(var input=process.getOutputStream()){VzorBootstrap600.write(input,nonce,address);}
      var acknowledgement=VzorBootstrap600.readAcknowledgement(process.getInputStream(),nonce,process.pid(),timeout);
      if(acknowledgement.reply()==VzorBootstrap600.Reply.ALREADY_RUNNING){waitOwnExit(process);return new Detached(Status.ALREADY_RUNNING,null);}
      if(acknowledgement.reply()!=VzorBootstrap600.Reply.READY)throw new VzorFailure600(acknowledgement.reply()==VzorBootstrap600.Reply.STATE_UNAVAILABLE?VzorFailure600.Code.STATE_UNAVAILABLE:VzorFailure600.Code.UI_UNAVAILABLE);
      if(!process.isAlive())throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);
      detached=true;return new Detached(Status.STARTED,process);
    }finally{
      Arrays.fill(nonce,(byte)0);STARTING.release();
      if(process!=null){if(!detached)stopOwnedStartupProcess(process);try{process.getInputStream().close();}catch(IOException ignored){}}
    }
  }
  static Map<String,String> filteredEnvironment(Map<String,String> source){
    Map<String,String> safe=new HashMap<>();source.forEach((key,value)->{if(ENVIRONMENT.contains(key.toUpperCase(Locale.ROOT)))safe.put(key,value);});return Map.copyOf(safe);
  }
  private static void waitOwnExit(Process process)throws IOException{try{if(!process.waitFor(3,TimeUnit.SECONDS))throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);}catch(InterruptedException error){Thread.currentThread().interrupt();throw new InterruptedIOException("Запуск Взора отменён");}}
  private static void stopOwnedStartupProcess(Process process){
    // No /proc lookup, process-name search, or ProcessHandle descendant traversal:
    // PID namespaces can make those identify a foreign host process. The manager
    // starts a browser only after READY and owns its own shutdown hook/resources.
    if(!process.isAlive())return;process.destroy();
    try{if(!process.waitFor(3,TimeUnit.SECONDS)){process.destroyForcibly();process.waitFor(3,TimeUnit.SECONDS);}}
    catch(InterruptedException error){Thread.currentThread().interrupt();process.destroyForcibly();}
  }
}
