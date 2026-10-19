package org.securemail.client.security600;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;

/** Desktop lock observation only. Start for an active Core session; every callback must invalidate that session.
 * No automatic unlock, shell, elevation, network service, account data, or JavaFX-thread polling. */
public final class OperatingSystemLockMonitor600 implements AutoCloseable {
  public enum Reason {
    LOCKED("Операционная система заблокирована. Сессия АЕГИС закрыта."),
    STATUS_UNAVAILABLE("Не удалось подтвердить состояние блокировки ОС. Для безопасности сессия АЕГИС закрыта; войдите повторно после восстановления системного наблюдения.");
    private final String russian;Reason(String russian){this.russian=russian;}public String russian(){return russian;}
  }
  enum State {UNLOCKED,LOCKED,UNKNOWN}
  interface Probe extends AutoCloseable {State read()throws Exception;@Override default void close(){}}
  private final Probe probe;private final Consumer<Reason> listener;
  private final ScheduledThreadPoolExecutor scheduler;
  private final ThreadPoolExecutor query;
  private final Duration timeout;
  private final AtomicBoolean closed=new AtomicBoolean();
  private volatile State lastState=State.UNKNOWN;private Reason emitted;
  private OperatingSystemLockMonitor600(Probe probe,Consumer<Reason> listener,Duration interval,Duration timeout){
    this.probe=Objects.requireNonNull(probe);this.listener=Objects.requireNonNull(listener);this.timeout=Objects.requireNonNull(timeout);
    if(interval.compareTo(Duration.ofMillis(10))<0||interval.compareTo(Duration.ofSeconds(10))>0||timeout.compareTo(Duration.ofMillis(10))<0||timeout.compareTo(Duration.ofSeconds(5))>0)throw new IllegalArgumentException("Bounded observation interval required");
    scheduler=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-os-lock-monitor");t.setDaemon(true);return t;});scheduler.setRemoveOnCancelPolicy(true);
    query=new ThreadPoolExecutor(1,1,0,TimeUnit.MILLISECONDS,new SynchronousQueue<>(),r->{Thread t=new Thread(r,"aegis-os-lock-query");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    scheduler.scheduleWithFixedDelay(this::poll,0,interval.toMillis(),TimeUnit.MILLISECONDS);
  }
  public static OperatingSystemLockMonitor600 start(Consumer<Reason> listener){
    String os=System.getProperty("os.name","");Probe probe;
    if(os.startsWith("Windows"))probe=new WindowsLockProbe600();
    else if(os.equals("Linux"))probe=new LinuxProbe(new OwnedCommands(),System.getenv());
    else probe=()->State.UNKNOWN;
    return new OperatingSystemLockMonitor600(probe,listener,Duration.ofSeconds(1),Duration.ofSeconds(3));
  }
  static OperatingSystemLockMonitor600 start(Probe probe,Consumer<Reason> listener,Duration interval,Duration timeout){return new OperatingSystemLockMonitor600(probe,listener,interval,timeout);}
  /** Observation availability is diagnostic only; it never authorizes or restores a session. */
  public boolean observationAvailable(){return !closed.get()&&lastState!=State.UNKNOWN;}
  private void poll(){
    if(closed.get())return;Future<State> future=null;State state=State.UNKNOWN;
    try{future=query.submit(probe::read);State observed=future.get(timeout.toMillis(),TimeUnit.MILLISECONDS);if(observed!=null)state=observed;}
    catch(InterruptedException stopped){Thread.currentThread().interrupt();}
    catch(ExecutionException|TimeoutException|RejectedExecutionException|LinkageError unavailable){/* UNKNOWN locks active Core; no raw native error enters diagnostics. */}
    finally{if(future!=null&&!future.isDone())future.cancel(true);}
    if(closed.get())return;lastState=state;Reason reason=state==State.LOCKED?Reason.LOCKED:state==State.UNKNOWN?Reason.STATUS_UNAVAILABLE:null;
    if(reason==null){emitted=null;return;}if(reason==emitted)return;
    try{listener.accept(reason);emitted=reason;}catch(RuntimeException ignored){/* A disposed UI cannot kill the observer or reveal native details. */}
  }
  @Override public void close(){if(closed.compareAndSet(false,true)){scheduler.shutdownNow();query.shutdownNow();try{probe.close();}catch(RuntimeException|LinkageError ignored){/* Core disposal must remain fail closed. */}}}

  static final class LinuxProbe implements Probe {
    private final Commands commands;private final java.util.function.Supplier<String> userBus;private final java.util.function.BooleanSupplier binariesTrusted;
    LinuxProbe(Commands commands,Map<String,String> environment){this(commands,()->localUserBus(environment.get("XDG_RUNTIME_DIR")),()->trustedExecutable(Path.of("/usr/bin/loginctl"))&&trustedExecutable(Path.of("/usr/bin/busctl")));}
    LinuxProbe(Commands commands,java.util.function.Supplier<String> userBus,java.util.function.BooleanSupplier binariesTrusted){this.commands=commands;this.userBus=userBus;this.binariesTrusted=binariesTrusted;}
    @Override public State read(){
      if(!binariesTrusted.getAsBoolean())return State.UNKNOWN;
      CommandResult login=commands.run(List.of("/usr/bin/loginctl","--no-pager","--no-ask-password","show-session","self","--property=LockedHint","--value"),Duration.ofMillis(900),128);
      State logind=login.success?parseLoginctl(login.output):State.UNKNOWN;if(logind==State.LOCKED)return State.LOCKED;
      String address=userBus.get();if(address==null)return State.UNKNOWN;
      CommandResult kde=commands.run(List.of("/usr/bin/busctl","--address="+address,"--no-pager","--auto-start=no","--allow-interactive-authorization=no","--timeout=1","call","org.freedesktop.ScreenSaver","/ScreenSaver","org.freedesktop.ScreenSaver","GetActive"),Duration.ofMillis(1100),128);
      State screen=kde.success?parseBusctl(kde.output):State.UNKNOWN;
      return combine(logind,screen);
    }
    @Override public void close(){commands.close();}
  }
  /** LockedHint is a desktop-maintained hint: require agreement with the KDE lock service before UNLOCKED. */
  static State combine(State logind,State kde){if(logind==State.LOCKED||kde==State.LOCKED)return State.LOCKED;return logind==State.UNLOCKED&&kde==State.UNLOCKED?State.UNLOCKED:State.UNKNOWN;}
  static State parseLoginctl(byte[] bytes){String value=scalar(bytes);return "yes".equals(value)?State.LOCKED:"no".equals(value)?State.UNLOCKED:State.UNKNOWN;}
  static State parseBusctl(byte[] bytes){String value=scalar(bytes);return "b true".equals(value)?State.LOCKED:"b false".equals(value)?State.UNLOCKED:State.UNKNOWN;}
  private static String scalar(byte[] bytes){if(bytes==null||bytes.length>128)return "";for(byte b:bytes)if(b<0)return "";String value=new String(bytes,StandardCharsets.US_ASCII);if(value.endsWith("\n"))value=value.substring(0,value.length()-1);if(value.endsWith("\r"))value=value.substring(0,value.length()-1);return value;}
  static String localUserBus(String runtime){
    // Never inherit arbitrary DBUS_* addresses: tcp/autolaunch/multiple addresses could bypass Tor.
    if(runtime==null||!runtime.matches("/run/user/[0-9]{1,10}"))return null;Path root=Path.of(runtime);
    try{
      var user=root.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
      return checkedLocalUserBus(root,user);
    }catch(IOException|UnsupportedOperationException|SecurityException unavailable){return null;}
  }
  static String checkedLocalUserBus(Path root,java.nio.file.attribute.UserPrincipal user){
    Path socket=root.resolve("bus");
    try{
      if(Files.isSymbolicLink(root)||Files.isSymbolicLink(socket)||!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)||!root.toRealPath().equals(root.toAbsolutePath().normalize()))return null;
      // XDG runtime directories are private (0700); another local user must not substitute the bus.
      if(!Files.getPosixFilePermissions(root,LinkOption.NOFOLLOW_LINKS).equals(Set.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE,PosixFilePermission.OWNER_EXECUTE)))return null;
      if(!Files.getOwner(root,LinkOption.NOFOLLOW_LINKS).equals(user)||!Files.getOwner(socket,LinkOption.NOFOLLOW_LINKS).equals(user))return null;
      int mode=((Number)Files.getAttribute(socket,"unix:mode",LinkOption.NOFOLLOW_LINKS)).intValue();if((mode&0170000)!=0140000)return null;
      return "unix:path="+socket;
    }catch(IOException|UnsupportedOperationException|SecurityException unavailable){return null;}
  }
  static boolean trustedExecutable(Path file){
    try{
      Path real=file.toRealPath();if(!Files.isRegularFile(real)||!Files.isExecutable(real))return false;
      for(Path p=real;p!=null;p=p.getParent()){
        if(((Number)Files.getAttribute(p,"unix:uid",LinkOption.NOFOLLOW_LINKS)).longValue()!=0)return false;
        Set<PosixFilePermission> mode=Files.getPosixFilePermissions(p,LinkOption.NOFOLLOW_LINKS);if(mode.contains(PosixFilePermission.GROUP_WRITE)||mode.contains(PosixFilePermission.OTHERS_WRITE))return false;
      }
      return true;
    }catch(IOException|UnsupportedOperationException|SecurityException unavailable){return false;}
  }
  record CommandResult(boolean success,byte[] output){CommandResult{output=output.clone();} @Override public byte[] output(){return output.clone();}}
  interface Commands extends AutoCloseable {CommandResult run(List<String> arguments,Duration timeout,int maximum);@Override default void close(){}}
  /** Fixed callers only; package-private fixture seam starts actual owned JVMs in tests. */
  static final class OwnedCommands implements Commands {
    interface Starter {Process start(List<String> arguments,Map<String,String> environment)throws IOException;}
    private final Starter starter;private final AtomicReference<Process> active=new AtomicReference<>();private final AtomicBoolean closed=new AtomicBoolean();private final Semaphore single=new Semaphore(1);
    OwnedCommands(){this((arguments,environment)->{var builder=new ProcessBuilder(arguments).redirectInput(ProcessBuilder.Redirect.PIPE).redirectOutput(ProcessBuilder.Redirect.PIPE).redirectError(ProcessBuilder.Redirect.DISCARD);builder.environment().clear();builder.environment().putAll(environment);return builder.start();});}
    OwnedCommands(Starter starter){this.starter=starter;}
    @Override public CommandResult run(List<String> arguments,Duration timeout,int maximum){
      if(maximum<1||maximum>1024||timeout.isNegative()||timeout.isZero()||timeout.compareTo(Duration.ofSeconds(2))>0)throw new IllegalArgumentException("Bounded lock command required");
      if(closed.get()||!single.tryAcquire())return new CommandResult(false,new byte[0]);Process process=null;FutureTask<byte[]> read=null;
      try{
        if(closed.get())return new CommandResult(false,new byte[0]);
        process=starter.start(List.copyOf(arguments),Map.of("LANG","C","LC_ALL","C","SYSTEMD_COLORS","0","SYSTEMD_PAGERSECURE","1","DBUS_SYSTEM_BUS_ADDRESS","unix:path=/run/dbus/system_bus_socket"));
        active.set(process);process.getOutputStream().close();if(closed.get()){process.destroyForcibly();return new CommandResult(false,new byte[0]);}
        Process owned=process;read=new FutureTask<>(()->owned.getInputStream().readNBytes(maximum+1));Thread reader=new Thread(read,"aegis-os-lock-output");reader.setDaemon(true);reader.start();
        if(!process.waitFor(timeout.toMillis(),TimeUnit.MILLISECONDS))return new CommandResult(false,new byte[0]);
        byte[] output=read.get(100,TimeUnit.MILLISECONDS);if(process.exitValue()!=0||output.length>maximum)return new CommandResult(false,new byte[0]);return new CommandResult(true,output);
      }catch(IOException|ExecutionException|TimeoutException unavailable){return new CommandResult(false,new byte[0]);}
      catch(InterruptedException stopped){Thread.currentThread().interrupt();return new CommandResult(false,new byte[0]);}
      finally{
        if(process!=null){if(process.isAlive()){process.destroy();try{if(!process.waitFor(100,TimeUnit.MILLISECONDS)){process.destroyForcibly();process.waitFor(1000,TimeUnit.MILLISECONDS);}}catch(InterruptedException stopped){Thread.currentThread().interrupt();process.destroyForcibly();}}
          try{process.getInputStream().close();}catch(IOException ignored){}active.compareAndSet(process,null);}
        if(read!=null)read.cancel(true);single.release();
      }
    }
    @Override public void close(){closed.set(true);Process owned=active.getAndSet(null);if(owned!=null&&owned.isAlive())owned.destroyForcibly();}
  }
}
