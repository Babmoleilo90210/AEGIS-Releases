package org.securemail.client.ecosystem;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/** Owns only AEGIS child JVMs. Tor Browser and personal Obsidian must be launched independently, outside this broker. */
public final class DesktopProcessBroker implements AutoCloseable {
  public enum State { STARTING, RUNNING, LOCKED, STOPPING, STOPPED, FAILED }
  public record Status(ComponentId component,State state,long pid,int notifications,boolean queueFlushConfirmed,String reason) {}
  private static final long START_MILLIS=10000, STOP_MILLIS=15000;
  private final ComponentInstallation installation;
  private final SessionAuthority authority;
  private final Consumer<Status> changes;
  private final EnumMap<ComponentId,Managed> children=new EnumMap<>(ComponentId.class);
  private final EnumMap<ComponentId,PendingLaunch> pendingLaunches=new EnumMap<>(ComponentId.class);
  private final EnumMap<ComponentId,Status> statuses=new EnumMap<>(ComponentId.class);
  private final EnumMap<ComponentId,CompletableFuture<Integer>> exits=new EnumMap<>(ComponentId.class);
  private final ScheduledExecutorService monitor=Executors.newSingleThreadScheduledExecutor(r->daemon(r,"aegis-component-monitor"));
  private volatile boolean locked,closed;
  private volatile Consumer<java.net.URI> linkHandler=url->{throw new IllegalStateException("Открытие Взора не подключено");};
  private volatile Runnable activityHandler=()->{};
  public void activityHandler(Runnable handler){activityHandler=Objects.requireNonNull(handler);}
  public void linkHandler(Consumer<java.net.URI> handler){linkHandler=Objects.requireNonNull(handler);}
  public DesktopProcessBroker(ComponentInstallation installation,SessionAuthority authority,Consumer<Status> changes) {
    this.installation=Objects.requireNonNull(installation);this.authority=Objects.requireNonNull(authority);this.changes=Objects.requireNonNull(changes);
    monitor.scheduleWithFixedDelay(this::tick,2,2,TimeUnit.SECONDS);
  }
  /** Blocking operation: invoke on the Core worker, never on the JavaFX Application Thread. */
  public Status launch(ComponentId component) throws IOException {
    Objects.requireNonNull(component);PendingLaunch pending=new PendingLaunch();Managed old;
    synchronized(this){
      if(closed||locked)throw new IOException("АЕГИС заблокирован: сначала подтвердите вход");old=children.get(component);
      if(old!=null&&old.process.isAlive()&&statuses.get(component).state()!=State.LOCKED)return statuses.get(component);
      if(pendingLaunches.putIfAbsent(component,pending)!=null)throw new IOException("Это приложение уже запускается");
    }
    ComponentLease lease=null;boolean transferred=false;LocalIpc.Channel channel=null;Process process=null;
    ExecutorService starter=Executors.newSingleThreadExecutor(r->daemon(r,"aegis-component-bootstrap"));
    try{
      if(old!=null&&old.process.isAlive())stop(component);
      // Remote authorization and installer hashing never hold the broker map monitor.
      lease=authority.authorize(component);if(lease.component()!=component)throw LocalIpc.rejected();authority.validate(lease);pending.check();
      installation.verify();pending.check();
      synchronized(this){if(closed||locked)throw LocalIpc.rejected();publish(new Status(component,State.STARTING,0,0,false,"Подготовка приложения"));}
      long launchStarted=System.nanoTime();
      try(ServerSocket listener=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"));LocalIpc.Bootstrap bootstrap=new LocalIpc.Bootstrap(lease,listener.getLocalPort())){
        pending.own(listener);listener.setSoTimeout((int)START_MILLIS);ProcessBuilder command=new ProcessBuilder(installation.command(component));
        command.redirectOutput(ProcessBuilder.Redirect.DISCARD);command.redirectError(ProcessBuilder.Redirect.DISCARD);command.environment().keySet().removeIf(key->!allowedEnvironment(key));pending.check();
        process=command.start();pending.own(process);Process child=process;
        Future<?> pipe=starter.submit(()->{try(OutputStream out=child.getOutputStream()){bootstrap.write(out);}catch(IOException e){throw new UncheckedIOException(e);}});
        try{pipe.get(START_MILLIS,TimeUnit.MILLISECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("Запуск прерван",e);}catch(ExecutionException|TimeoutException e){pipe.cancel(true);throw new IOException("Приложение не приняло защищённый допуск",e);}
        long remaining=START_MILLIS-TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-launchStarted);if(remaining<=0)throw new IOException("Истёк срок подтверждения запуска");listener.setSoTimeout((int)remaining);
        Socket socket=listener.accept();pending.own(socket);channel=LocalIpc.acceptParent(socket,bootstrap,process.pid());channel.startupTimeout(45000);
        if(channel.receive().type()!=LocalIpc.Type.READY)throw LocalIpc.rejected();authority.validate(lease);pending.check();
        if(System.nanoTime()-launchStarted>TimeUnit.SECONDS.toNanos(60))throw LocalIpc.rejected();channel.startupTimeout(6500);
        synchronized(this){
          if(closed||locked)throw LocalIpc.rejected();pending.check();Managed managed=new Managed(component,lease,process,channel);children.put(component,managed);exits.put(component,process.onExit().thenApply(Process::exitValue));
          publish(new Status(component,State.RUNNING,process.pid(),0,false,"Приложение открыто"));pending.release();transferred=true;managed.start();return statuses.get(component);
        }
      }
    }catch(IOException|RuntimeException e){
      if(channel!=null)try{channel.close();}catch(IOException ignored){}pending.cancel();if(process!=null&&process.isAlive())killOwned(process);
      publish(new Status(component,State.FAILED,0,0,false,closed?"Запуск отменён: АЕГИС закрыт":locked?"Запуск отменён: АЕГИС заблокирован":"Не удалось подтвердить запуск приложения"));throw e;
    }finally{starter.shutdownNow();if(!transferred&&lease!=null)lease.close();synchronized(this){pendingLaunches.remove(component,pending);}}
  }
  private static final class PendingLaunch{
    private boolean cancelled,released;private ServerSocket listener;private Socket socket;private Process process;
    synchronized void check()throws IOException{if(cancelled)throw new IOException("Запуск приложения отменён");}
    void own(ServerSocket value)throws IOException{synchronized(this){if(!cancelled){listener=value;return;}}value.close();throw new IOException("Запуск отменён");}
    void own(Socket value)throws IOException{synchronized(this){if(!cancelled){socket=value;return;}}value.close();throw new IOException("Запуск отменён");}
    void own(Process value)throws IOException{synchronized(this){if(!cancelled){process=value;return;}}killOwned(value);throw new IOException("Запуск отменён");}
    synchronized void release(){released=true;listener=null;socket=null;process=null;}
    void cancel(){ServerSocket pendingListener;Socket pendingSocket;Process pendingProcess;synchronized(this){if(released)return;cancelled=true;pendingListener=listener;listener=null;pendingSocket=socket;socket=null;pendingProcess=process;process=null;}if(pendingListener!=null)try{pendingListener.close();}catch(IOException ignored){}if(pendingSocket!=null)try{pendingSocket.close();}catch(IOException ignored){}if(pendingProcess!=null&&pendingProcess.isAlive())killOwned(pendingProcess);}
  }
  public synchronized Optional<Status> status(ComponentId component) { return Optional.ofNullable(statuses.get(component)); }
  public synchronized List<Status> statuses() { return List.copyOf(statuses.values()); }
  public synchronized boolean isRunning(ComponentId component){Managed child=children.get(component);return child!=null&&child.process.isAlive();}
  /** Kernel-backed exit receipt for the current instance; does not scan or signal unrelated PIDs. */
  public synchronized CompletionStage<Integer> termination(ComponentId component)throws IOException {var exit=exits.get(component);if(exit==null)throw new IOException("Приложение не запускалось");return exit.minimalCompletionStage();}
  public void lock(){List<Managed> owned;List<PendingLaunch> pending;synchronized(this){if(closed||locked)return;locked=true;owned=List.copyOf(children.values());pending=List.copyOf(pendingLaunches.values());}for(PendingLaunch launch:pending)launch.cancel();for(Managed managed:owned)managed.enqueue(LocalIpc.Type.LOCK);}
  /** Called only after fresh Core authentication. Locked children remain locked; their data requires an explicit authenticated restart. */
  public synchronized void authenticatedUnlock() throws IOException {
    if(closed)throw new IOException("АЕГИС закрыт");
    for(Managed managed:children.values())authority.validate(managed.lease);
    locked=false;
  }
  public synchronized boolean locked() { return locked; }
  public synchronized void answerLockedCall(boolean accept) throws IOException {
    if(closed || !locked)throw LocalIpc.rejected(); Managed glas=children.get(ComponentId.GLAS);
    if(glas==null || !glas.process.isAlive())throw new IOException("Глас недоступен");authority.validate(glas.lease);
    glas.enqueue(accept?LocalIpc.Type.CALL_ACCEPT:LocalIpc.Type.CALL_REJECT);
  }
  public void stop(ComponentId component) {
    Managed managed; synchronized(this){managed=children.get(component);if(managed==null)return;publish(new Status(component,State.STOPPING,managed.process.pid(),0,false,"Сохранение очереди"));}
    if(!managed.stopping.compareAndSet(false,true)){try{managed.stopComplete.get(STOP_MILLIS*2+2000,TimeUnit.MILLISECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}catch(ExecutionException|TimeoutException ignored){}return;}
    managed.enqueue(LocalIpc.Type.SHUTDOWN);
    boolean flushed=false;
    try { flushed=managed.flushed.get(STOP_MILLIS,TimeUnit.MILLISECONDS); } catch(InterruptedException e){Thread.currentThread().interrupt();}catch(ExecutionException|TimeoutException ignored){}
    try { managed.process.waitFor(STOP_MILLIS,TimeUnit.MILLISECONDS); } catch(InterruptedException e){Thread.currentThread().interrupt();}
    managed.close(); if(managed.process.isAlive())killOwned(managed.process);
    synchronized(this){Managed current=children.get(component);if(current==null||current==managed){children.remove(component,managed);publish(new Status(component,flushed&&!managed.process.isAlive()?State.STOPPED:State.FAILED,0,0,flushed,flushed?"Приложение закрыто, очередь сохранена":"Приложение остановлено; сохранение очереди не подтверждено"));}}managed.stopComplete.complete(null);
  }
  private void tick(){
    List<Managed> snapshot;synchronized(this){if(closed)return;snapshot=List.copyOf(children.values());}
    for(Managed managed:snapshot){
      if(managed.stopping.get())continue;
      if(!managed.process.isAlive()||System.nanoTime()-managed.lastReply>TimeUnit.SECONDS.toNanos(8)){managed.revoke();continue;}
      // Heartbeats cannot wait for a slow onion Identity RPC in another component.
      managed.enqueue(LocalIpc.Type.HEARTBEAT);managed.checkAuthorization();
    }
  }
  private synchronized void publish(Status status) { statuses.put(status.component(),status);try{changes.accept(status);}catch(RuntimeException ignored){} }
  @Override public void close(){List<PendingLaunch> pending;synchronized(this){if(closed)return;closed=true;locked=true;pending=List.copyOf(pendingLaunches.values());}monitor.shutdownNow();for(PendingLaunch launch:pending)launch.cancel();for(ComponentId component:ComponentId.values())stop(component);}
  private final class Managed {
    final ComponentId component;final ComponentLease lease;final Process process;final LocalIpc.Channel channel;
    final java.util.concurrent.atomic.AtomicBoolean stopping=new java.util.concurrent.atomic.AtomicBoolean(),checkingAuthorization=new java.util.concurrent.atomic.AtomicBoolean();
    final CompletableFuture<Void> stopComplete=new CompletableFuture<>();
    final ThreadPoolExecutor authorization=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(1),r->daemon(r,"aegis-component-authorization"),new ThreadPoolExecutor.AbortPolicy());
    final CompletableFuture<Boolean> flushed=new CompletableFuture<>();volatile long lastReply=System.nanoTime();
    final ThreadPoolExecutor writer=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(4),r->daemon(r,"aegis-component-writer"),new ThreadPoolExecutor.AbortPolicy());
    final ExecutorService reader=Executors.newSingleThreadExecutor(r->daemon(r,"aegis-component-reader"));
    Managed(ComponentId component,ComponentLease lease,Process process,LocalIpc.Channel channel){this.component=component;this.lease=lease;this.process=process;this.channel=channel;}
    void start(){reader.submit(()->{try{while(!Thread.currentThread().isInterrupted()){
      LocalIpc.Packet packet=channel.receive();lastReply=System.nanoTime();
      switch(packet.type()){
        case PONG -> { }
        case USER_ACTIVITY -> {if(!locked&&!closed)activityHandler.run();}
        case LOCKED -> publish(new Status(component,State.LOCKED,process.pid(),0,false,"Приложение заблокировано"));
        case FLUSHED -> flushed.complete(true);
        case OPEN_URL -> {if(locked||closed)throw LocalIpc.rejected();authority.validate(lease);linkHandler.accept(org.securemail.client.safeweb.SafeWebUrl.parse(new String(packet.payload(),java.nio.charset.StandardCharsets.UTF_8)));}
        case NOTIFICATION_COUNT -> {Status old; synchronized(DesktopProcessBroker.this){old=statuses.get(component);}if(old!=null)publish(new Status(component,old.state(),process.pid(),java.nio.ByteBuffer.wrap(packet.payload()).getInt(),old.queueFlushConfirmed(),old.reason()));}
        default -> throw LocalIpc.rejected();
      }
    }}catch(IOException|RuntimeException e){flushed.complete(false);close();if(process.isAlive())killOwned(process);synchronized(DesktopProcessBroker.this){if(children.remove(component,this))publish(new Status(component,State.FAILED,0,0,false,"Соединение приложения закрыто"));}}});}
    void checkAuthorization(){if(!checkingAuthorization.compareAndSet(false,true))return;try{authorization.execute(()->{try{authority.validate(lease);}catch(IOException|RuntimeException invalid){revoke();}finally{checkingAuthorization.set(false);}});}catch(RejectedExecutionException closing){checkingAuthorization.set(false);}}
    void revoke(){if(stopping.get())return;enqueue(LocalIpc.Type.LOCK);stop(component);synchronized(DesktopProcessBroker.this){Managed current=children.get(component);if(current==null||current==this){Status previous=statuses.get(component);publish(new Status(component,State.FAILED,0,0,previous!=null&&previous.queueFlushConfirmed(),"Допуск отозван или приложение недоступно"));}}}
    void enqueue(LocalIpc.Type type){try{writer.execute(()->{try{channel.send(LocalIpc.Packet.command(type));}catch(IOException e){close();}});}catch(RejectedExecutionException e){close();}}
    void close(){try{channel.close();}catch(IOException ignored){}lease.close();writer.shutdownNow();reader.shutdownNow();authorization.shutdownNow();}
  }
  private static boolean allowedEnvironment(String key) {
    return key.startsWith("LC_") || Set.of("HOME","USER","LOGNAME","PATH","LANG","DISPLAY","WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR","XDG_SESSION_TYPE","XDG_CURRENT_DESKTOP","DBUS_SESSION_BUS_ADDRESS","XAUTHORITY","XDG_CONFIG_HOME","XDG_DATA_HOME","XDG_CACHE_HOME",
        "SystemRoot","SYSTEMROOT","WINDIR","LOCALAPPDATA","APPDATA","TEMP","TMP","PROGRAMDATA","USERPROFILE").contains(key);
  }
  private static Thread daemon(Runnable action,String name){Thread thread=new Thread(action,name);thread.setDaemon(true);return thread;}
  private static void killOwned(Process process) {
    // Some container environments expose a host /proc under a nested PID namespace. Never use an unverifiable PID scan there.
    List<ProcessHandle> descendants=List.of();
    try {var known=process.toHandle().info().startInstant();var lookup=ProcessHandle.of(process.pid());
      if(known.isPresent()&&lookup.isPresent()&&lookup.get().info().startInstant().equals(known))descendants=process.descendants().toList();
    }catch(SecurityException|UnsupportedOperationException ignored){}
    for(ProcessHandle child:descendants)child.destroy();process.destroy();
    try{process.waitFor(500,TimeUnit.MILLISECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}
    for(ProcessHandle child:descendants)if(child.isAlive())child.destroyForcibly();if(process.isAlive())process.destroyForcibly();
    try{process.waitFor(1000,TimeUnit.MILLISECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}
  }
}
