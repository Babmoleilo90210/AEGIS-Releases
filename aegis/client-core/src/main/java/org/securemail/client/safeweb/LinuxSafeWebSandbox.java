package org.securemail.client.safeweb;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.securemail.client.AppPaths;

/** Linux boundary around an unmodified, dedicated official Tor Browser bundle.
 * The caller verifies that bundle against trusted metadata OUTSIDE the bundle.
 * The bundle and its own Tor remain together in a rootless network namespace;
 * Tor Browser's stock proxy enforcement, not this namespace, provides Tor-only
 * web traffic. A compromised browser broker is not given a kernel Tor firewall.
 * Host home, host X server, D-Bus, audio and clipboard are not exposed.
 */
public final class LinuxSafeWebSandbox {
  private LinuxSafeWebSandbox() {}
  private static final Path BWRAP=Path.of("/usr/bin/bwrap");
  private static final Path SLIRP=Path.of("/usr/bin/slirp4netns");
  private static final Path XEPHYR=Path.of("/usr/bin/Xephyr");
  private static final Pattern CHILD_PID=Pattern.compile("\\\"child-pid\\\"\\s*:\\s*([0-9]{1,10})");
  private static final SecureRandom RANDOM=new SecureRandom();
  private static final Duration START_TIMEOUT=Duration.ofSeconds(20);

  /** Starts only a session bundle owned and prepared by SafeWebProcess.
   * sessionRoot is private; only bundle, downloads and one X cookie are mounted.
   * KDE Wayland uses its Xwayland DISPLAY as the host of a nested Xephyr server.
   * Missing Xwayland/dependencies/user namespaces fail closed, without fallback.
   */
  public static Launch start(Path bundle,Path sessionRoot,URI url)throws IOException {
    return start(bundle,sessionRoot,url,List.of());
  }
  public static Launch start(Path bundle,Path sessionRoot,URI url,Collection<Path> protectedPaths)throws IOException {
    String hostDisplay=requireEnvironment();
    Objects.requireNonNull(url);SafeWebUrl.parse(url.toASCIIString());
    checkHiddenPaths(protectedPaths);
    Path base=existingDirectory(bundle);Path root=privateDirectory(sessionRoot);
    if(base.equals(root)||root.startsWith(base))throw new IOException("Каталог управления Взор должен находиться вне браузерного пакета");
    if(!Files.isExecutable(base.resolve("Browser/start-tor-browser")))throw new IOException("Не найден официальный Linux Tor Browser");
    Path downloads=privateDirectory(base.resolve("aegis-downloads"));
    Path run=Files.createTempDirectory(root,"display-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    // The resolver belongs to this netns; never expose the host resolver or its
    // loopback. Stock Tor Browser resolves website names through SOCKS. Tor's own
    // optional bridge/PT bootstrap can use this resolver, as in the stock bundle.
    Files.writeString(run.resolve("resolv.conf"),"nameserver 10.0.2.3\noptions timeout:2 attempts:2\n",StandardOpenOption.CREATE_NEW);
    Launch launch=new Launch(downloads,run);
    try {
      int display=startDisplay(launch,run,hostDisplay);
      Path socket=Path.of("/tmp/.X11-unix/X"+display);
      List<String> command=sandboxCommand(base,downloads,run.resolve("Xauthority"),socket,display,url);
      ProcessBuilder builder=cleanBuilder(command);builder.redirectError(ProcessBuilder.Redirect.DISCARD);
      launch.process=launch.own(builder.start());
      long childPid=readChildPid(launch.process,START_TIMEOUT);
      // Check the published PID is actually a child of our bwrap, not an arbitrary
      // host process. No external PID is ever signalled or adopted by this class.
      if(launch.process.descendants().noneMatch(p->p.pid()==childPid))throw new IOException("Недостоверный PID сетевого контекста Взор");
      launch.slirp=startNetwork(childPid,launch);
      launch.process.getOutputStream().write(1);launch.process.getOutputStream().flush();
      launch.process.getOutputStream().close();
      // info-fd is a closed, bounded startup channel. Browser output is redirected
      // to /dev/null by a fixed shell command with positional arguments only.
      launch.started=true;
      watch(launch,launch.process);watch(launch,launch.slirp);watch(launch,launch.display);
      return launch;
    } catch(IOException|RuntimeException failure) {
      return cleanupFailedStart(launch,failure);
    }
  }
  /** A failed startup may still own an OS process. Never throw away the only
   * controller and let the outer manager delete a live temporary profile.
   */
  static Launch cleanupFailedStart(Launch launch,Exception failure)throws IOException{
    try{launch.close();}catch(IOException|RuntimeException cleanup){
      failure.addSuppressed(cleanup);
      synchronized(launch){if(launch.anyAlive()){launch.started=true;launch.startupFailed=true;return launch;}}
    }
    if(failure instanceof IOException io)throw io;
    if(failure instanceof RuntimeException runtime)throw runtime;
    throw new IOException("Запуск Взор не выполнен",failure);
  }

  static List<String> sandboxCommand(Path bundle,Path downloads,Path auth,Path socket,int display,URI url) {
    List<String> args=new ArrayList<>(List.of(BWRAP.toString(),"--die-with-parent","--new-session","--unshare-all","--cap-drop","ALL","--clearenv","--info-fd","1","--block-fd","0","--proc","/proc","--dev","/dev","--tmpfs","/tmp","--dir","/home","--dir","/home/web","--dir","/run","--dir","/tmp/.X11-unix"));
    // Read-only distro libraries/fonts/certificates only. Neither /etc as a whole,
    // host /tmp, /run/user, the AEGIS directory nor the host home is visible.
    for(String system:List.of("/usr","/lib","/lib64","/etc/fonts","/etc/ssl/certs"))
      if(Files.exists(Path.of(system)))args.addAll(List.of("--ro-bind",system,system));
    args.addAll(List.of("--symlink","usr/bin","/bin","--symlink","usr/sbin","/sbin",
      "--bind",bundle.toString(),"/home/web/tor-browser",
      "--bind",downloads.toString(),"/home/web/Downloads",
      "--ro-bind",auth.toString(),"/home/web/.Xauthority",
      "--ro-bind",auth.getParent().resolve("resolv.conf").toString(),"/etc/resolv.conf",
      "--ro-bind",socket.toString(),"/tmp/.X11-unix/X"+display,
      "--setenv","HOME","/home/web","--setenv","XAUTHORITY","/home/web/.Xauthority",
      "--setenv","DISPLAY",":"+display,"--setenv","PATH","/usr/bin:/bin",
      "--setenv","LANG","C.UTF-8","--setenv","XDG_CACHE_HOME","/tmp/cache",
      "--chdir","/home/web/tor-browser","--","/bin/sh","-c",
      "exec \"$@\" </dev/null >/dev/null 2>&1","aegis-safeweb",
      "/home/web/tor-browser/Browser/start-tor-browser",url.toASCIIString()));
    return List.copyOf(args);
  }

  private static int startDisplay(Launch launch,Path run,String hostDisplay)throws IOException {
    Map<String,String> hostEnv=new HashMap<>();hostEnv.put("DISPLAY",hostDisplay);
    String supplied=System.getenv("XAUTHORITY");
    Path hostAuth=supplied==null||supplied.isBlank()?Path.of(System.getProperty("user.home"),".Xauthority"):Path.of(supplied);
    if(Files.isRegularFile(hostAuth))hostEnv.put("XAUTHORITY",hostAuth.toRealPath().toString());
    for(int attempt=0;attempt<8;attempt++) {
      int display=100+RANDOM.nextInt(20000);Path socket=Path.of("/tmp/.X11-unix/X"+display);
      if(Files.exists(socket,LinkOption.NOFOLLOW_LINKS)||Files.exists(Path.of("/tmp/.X"+display+"-lock"),LinkOption.NOFOLLOW_LINKS))continue;
      Path auth=run.resolve("Xauthority");writeXAuthority(auth,display);
      ProcessBuilder builder=cleanBuilder(monitoredDisplayCommand(List.of(XEPHYR.toString(),":"+display,"-auth",auth.toString(),"-nolisten","tcp","-screen","1280x800","-resizeable","-terminate","-br","-title","AEGIS Взор — Tor Browser")));
      builder.environment().putAll(hostEnv);builder.environment().put("HOME",run.toString());
      builder.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);
      Process process=launch.own(builder.start());launch.display=process;
      long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);
      while(process.isAlive()&&System.nanoTime()<deadline) {
        launch.capture(process);
        if(Files.exists(socket,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(socket))return display;
        pause(25);
      }
      stop(launch,process);launch.display=null;
    }
    throw new IOException("Не удалось создать изолированный экран Взор (проверьте Xephyr/Xwayland)");
  }

  /** A private stdin lease also tears down the nested display after JVM crashes.
   * Fixed shell code, executable and every argument remain separate argv items.
   * Only its own child PID is signalled; no process-name or global display kill.
   */
  static List<String> monitoredDisplayCommand(List<String> displayCommand) {
    List<String> command=new ArrayList<>(List.of("/bin/sh","-c",
      "exec 3<&0; \"$@\" 3<&- & child=$!; trap 'kill \"$child\" 2>/dev/null' HUP INT TERM; " +
      "( IFS= read -r ignored <&3; kill \"$child\" 2>/dev/null ) 0<&3 & monitor=$!; " +
      "wait \"$child\"; result=$?; kill \"$monitor\" 2>/dev/null; wait \"$monitor\" 2>/dev/null; exit \"$result\"",
      "aegis-display-lease"));
    command.addAll(displayCommand);return List.copyOf(command);
  }

  /** MIT-MAGIC-COOKIE-1 record. FamilyWild lets a single private cookie work
   * across the host and the mount/network namespace; the display number matches.
   */
  static void writeXAuthority(Path path,int display)throws IOException {
    byte[] cookie=new byte[16];RANDOM.nextBytes(cookie);
    try(DataOutputStream out=new DataOutputStream(Files.newOutputStream(path,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS))) {
      out.writeShort(65535);field(out,new byte[0]);field(out,Integer.toString(display).getBytes(StandardCharsets.US_ASCII));
      field(out,"MIT-MAGIC-COOKIE-1".getBytes(StandardCharsets.US_ASCII));field(out,cookie);
    }
    Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));Arrays.fill(cookie,(byte)0);
  }
  private static void field(DataOutputStream out,byte[] value)throws IOException {out.writeShort(value.length);out.write(value);}

  private static Process startNetwork(long childPid,Launch launch)throws IOException {
    Process bwrap=launch.process;
    IOException last=null;
    for(int attempt=0;attempt<12&&bwrap.isAlive();attempt++) {
      List<String> command=List.of(SLIRP.toString(),"--configure","--disable-host-loopback","--ready-fd=1","--exit-fd=0","--userns-path=/proc/"+childPid+"/ns/user",Long.toString(childPid),"tap0");
      ProcessBuilder builder=cleanBuilder(command);builder.redirectError(ProcessBuilder.Redirect.DISCARD);Process process=launch.own(builder.start());
      try {
        int ready=readByte(process,Duration.ofSeconds(5));
        if(ready=='1'&&process.isAlive())return process;
        last=new IOException("Сетевой контекст Взор не подтвердил готовность");
      }catch(IOException error){last=error;}
      stop(launch,process);pause(50);
    }
    throw new IOException("Изолированная сеть Взор недоступна (slirp4netns/user namespaces)",last);
  }

  private static long readChildPid(Process process,Duration timeout)throws IOException {
    ByteArrayOutputStream data=new ByteArrayOutputStream();long until=System.nanoTime()+timeout.toNanos();
    while(System.nanoTime()<until) {
      int value=pollByte(process);
      if(value>=0) {
        if(data.size()>=8192)throw new IOException("Некорректный ответ bwrap");data.write(value);
        if(value=='}') {
          var match=CHILD_PID.matcher(data.toString(StandardCharsets.UTF_8));
          if(!match.find())throw new IOException("bwrap не сообщил PID");
          long pid=Long.parseLong(match.group(1));if(pid<=1)throw new IOException("Некорректный PID bwrap");return pid;
        }
      } else if(!process.isAlive())throw new IOException("bwrap не смог создать песочницу: проверьте поддержку unprivileged user namespaces");
      else pause(20);
    }
    throw new IOException("Истекло время создания песочницы Взор");
  }
  private static int readByte(Process process,Duration timeout)throws IOException {
    long until=System.nanoTime()+timeout.toNanos();
    while(System.nanoTime()<until){int value=pollByte(process);if(value>=0)return value;if(!process.isAlive())return -1;pause(20);}
    throw new IOException("Истекло время запуска изолированной сети");
  }
  private static int pollByte(Process process)throws IOException {return process.getInputStream().available()>0?process.getInputStream().read():-1;}
  private static void pause(long millis)throws IOException {try{Thread.sleep(millis);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IOException("Запуск Взор прерван",interrupted);}}
  private static ProcessBuilder cleanBuilder(List<String> command) {
    ProcessBuilder builder=new ProcessBuilder(command);builder.environment().clear();builder.environment().put("PATH","/usr/bin:/bin");builder.environment().put("LANG","C.UTF-8");return builder;
  }
  private static Path existingDirectory(Path path)throws IOException {
    if(Files.isSymbolicLink(path)||!Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Небезопасный каталог Взор");return path.toRealPath();
  }
  /** The orchestrator passes paths only, never identity/archive/key objects.
   * Reject custom storage locations that would be readable in a distro bind.
   * These paths are never sent to the browser, its environment or diagnostics.
   */
  public static void checkHiddenPaths(Collection<Path> protectedPaths)throws IOException{
    List<Path> paths=new ArrayList<>(List.of(AppPaths.root(),AppPaths.config()));
    for(Path path:Objects.requireNonNull(protectedPaths))if(path==null)throw new IOException("Некорректный путь защищённых данных");else paths.add(path);
    for(Path privatePath:paths){
      Path real=resolveIncludingMissing(privatePath);
      for(String exposed:List.of("/usr","/lib","/lib64","/etc/fonts","/etc/ssl/certs")){
        Path mount=Path.of(exposed);if(!Files.exists(mount))continue;Path visible=mount.toRealPath();
        if(real.startsWith(visible)||visible.startsWith(real))throw new IOException("Каталог данных АЕГИС пересекается с системными каталогами браузерной песочницы");
      }
    }
  }
  private static Path resolveIncludingMissing(Path path)throws IOException{
    Path current=path.toAbsolutePath().normalize();Deque<Path> suffix=new ArrayDeque<>();
    while(!Files.exists(current,LinkOption.NOFOLLOW_LINKS)){
      if(current.getParent()==null)throw new IOException("Недоступен путь данных АЕГИС");suffix.addFirst(current.getFileName());current=current.getParent();
    }
    Path resolved=current.toRealPath();for(Path part:suffix)resolved=resolved.resolve(part);return resolved.normalize();
  }
  private static Path privateDirectory(Path path)throws IOException {
    if(Files.isSymbolicLink(path))throw new IOException("Ссылка вместо каталога Взор");
    Files.createDirectories(path);Path real=existingDirectory(path);Files.setPosixFilePermissions(real,PosixFilePermissions.fromString("rwx------"));return real;
  }
  /** Read-only shared preflight; namespaces and actual X access are checked only on launch. */
  static String requireEnvironment()throws IOException {
    String os=System.getProperty("os.name","");
    SandboxPrerequisites.requirePlatform(os,System.getProperty("os.arch",""));
    if(!os.equals("Linux"))throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.UNSUPPORTED_OS);
    SandboxPrerequisites.requireSystemExecutable(BWRAP,SandboxPrerequisites.Code.LINUX_BWRAP_MISSING);
    SandboxPrerequisites.requireSystemExecutable(SLIRP,SandboxPrerequisites.Code.LINUX_SLIRP_MISSING);
    SandboxPrerequisites.requireSystemExecutable(XEPHYR,SandboxPrerequisites.Code.LINUX_XEPHYR_MISSING);
    String display=SandboxPrerequisites.requireLocalDisplay(System.getenv("DISPLAY"));
    String number=display.substring(1).split("\\.",2)[0];
    Path socket=Path.of("/tmp/.X11-unix/X"+number);
    try {
      if(Files.isSymbolicLink(socket)||!Files.exists(socket,LinkOption.NOFOLLOW_LINKS)||
          (((Integer)Files.getAttribute(socket,"unix:mode",LinkOption.NOFOLLOW_LINKS))&0170000)!=0140000)
        throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.LINUX_DISPLAY_REQUIRED);
    }catch(IOException|RuntimeException error){
      if(error instanceof SandboxPrerequisites.Failure failure)throw failure;
      throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.LINUX_DISPLAY_REQUIRED,error);
    }
    return display;
  }
  private static void watch(Launch launch,Process owned) {Thread.startVirtualThread(()->{try{owned.waitFor();launch.close();}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}catch(IOException ignored){/* status remains failed/closed; no private browser output is logged */}});}
  private static void stop(Launch launch,Process process)throws IOException {
    if(process==null)return;
    // Only descendants captured from our own process, never process-name matching.
    launch.capture(process);Set<ProcessHandle> children=launch.children.get(process);
    try {
      // Kill the blocked bwrap before closing its gate pipe: EOF on --block-fd
      // also releases the command, so closing that pipe first could run it briefly.
      process.destroy();
      if(!process.waitFor(3,TimeUnit.SECONDS)){process.destroyForcibly();process.waitFor(3,TimeUnit.SECONDS);}
      try{process.getOutputStream().close();}catch(IOException ignored){}
      for(ProcessHandle child:children)if(child.isAlive())child.destroy();
      for(ProcessHandle child:children)if(child.isAlive())child.destroyForcibly();
      long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
      while(children.stream().anyMatch(ProcessHandle::isAlive)&&System.nanoTime()<until)Thread.sleep(20);
      if(process.isAlive()||children.stream().anyMatch(ProcessHandle::isAlive))throw new IOException("Процессы Взор ещё завершаются");
    }catch(InterruptedException interrupted){Thread.currentThread().interrupt();process.destroyForcibly();throw new IOException("Остановка Взор прервана",interrupted);}
     catch(RuntimeException failure){throw new IOException("Не удалось завершить собственные процессы Взор",failure);}
  }

  public static final class Launch implements AutoCloseable {
    private Process process,slirp,display;private final Path downloads,displayRoot;private boolean started,closed,cleanupComplete,startupFailed;
    private final Map<Process,Set<ProcessHandle>> children=new LinkedHashMap<>();
    Launch(Path downloads,Path displayRoot){this.downloads=downloads;this.displayRoot=displayRoot;}
    synchronized Process own(Process owned){children.computeIfAbsent(owned,ignored->new LinkedHashSet<>());capture(owned);return owned;}
    private synchronized void capture(Process owned){Set<ProcessHandle> tracked=children.computeIfAbsent(owned,ignored->new LinkedHashSet<>());owned.descendants().forEach(tracked::add);}
    public synchronized Process process(){return process;}
    public Path downloads(){return downloads;}
    private boolean anyAlive(){return children.entrySet().stream().anyMatch(entry->entry.getKey().isAlive()||entry.getValue().stream().anyMatch(ProcessHandle::isAlive));}
    public synchronized boolean running(){return started&&anyAlive();}
    public synchronized String status(){
      if(startupFailed)return anyAlive()?"Ошибка запуска Взор; собственные процессы ещё завершаются. Повторите закрытие":"Запуск Взор не выполнен; собственные процессы остановлены";
      return closed?(anyAlive()?"Процессы Взор ещё завершаются":cleanupComplete?"Взор остановлен":"Процессы Взор остановлены; очистка не завершена"):running()?"Tor Browser: изолированный процесс запущен; состояние Tor проверяется в браузере":"Взор запускается";
    }
    @Override public synchronized void close()throws IOException {
      if(cleanupComplete)return;closed=true;IOException problem=null;
      // Disconnect egress first. PID namespace teardown then stops only our Tor.
      List<Process> order=new ArrayList<>();
      // Includes partially started slirp attempts whose ready-fd never succeeded.
      for(Process owned:children.keySet())if(owned!=process&&owned!=display)order.add(owned);
      for(Process owned:new Process[]{process,display})if(owned!=null&&!order.contains(owned))order.add(owned);
      for(Process owned:order)try{stop(this,owned);}catch(IOException|RuntimeException failure){IOException error=failure instanceof IOException io?io:new IOException("Не удалось завершить собственный процесс Взор",failure);if(problem==null)problem=error;else problem.addSuppressed(error);}
      if(anyAlive()){if(problem==null)problem=new IOException("Собственные процессы Взор ещё завершаются");throw problem;}
      try{Files.deleteIfExists(displayRoot.resolve("Xauthority"));Files.deleteIfExists(displayRoot.resolve("resolv.conf"));Files.deleteIfExists(displayRoot);}catch(IOException error){if(problem==null)problem=error;else problem.addSuppressed(error);}
      if(problem!=null)throw problem;cleanupComplete=true;
    }
  }
}
