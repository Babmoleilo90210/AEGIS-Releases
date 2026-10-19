package org.securemail.client.safeweb600;

import java.io.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import org.securemail.client.*;
import org.securemail.client.net.EmbeddedTor;
import org.securemail.client.safeweb.SafeWebProcess;

/** Runs exclusively inside the detached manager. Owns its download Tor and strict managed browser, never mail resources. */
public final class VzorManager600 implements AutoCloseable {
  private final VzorState600 state;
  private final VzorState600.Ports ports;
  private final ClientConfig config;
  private final SafeWebProcess browser;
  private final ThreadPoolExecutor operations,network;
  private final AtomicReference<EmbeddedTor> tor=new AtomicReference<>();
  private final AtomicBoolean connecting=new AtomicBoolean(),closing=new AtomicBoolean();
  private boolean closed;
  public VzorManager600(VzorState600 state)throws IOException{
    this.state=Objects.requireNonNull(state);
    if(!AppPaths.root().toAbsolutePath().normalize().equals(state.root()))throw new VzorFailure600(VzorFailure600.Code.STATE_UNAVAILABLE);
    ports=VzorState600.reservePorts();config=ports.config(state.root());browser=new SafeWebProcess(state.browser());
    operations=executor("aegis-vzor-operation",8);network=executor("aegis-vzor-download-tor",1);
  }
  private static ThreadPoolExecutor executor(String name,int queue){return new ThreadPoolExecutor(1,1,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(queue),r->{Thread t=new Thread(r,name);t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());}
  public ClientConfig config(){return config;} public SafeWebProcess browser(){return browser;}
  public ExecutorService operations(){return operations;}
  /** This is the package-download Tor only. Browser Tor status remains in official Tor Browser. */
  public boolean downloadTorReady(){EmbeddedTor owned=tor.get();return owned!=null&&owned.ready()&&!closing.get();}
  public void connect(EmbeddedTor.Mode mode,IntConsumer progress,Consumer<String> status){
    Objects.requireNonNull(mode);Objects.requireNonNull(progress);Objects.requireNonNull(status);
    if(closing.get()||downloadTorReady()||!connecting.compareAndSet(false,true))return;
    try{network.execute(()->{
      EmbeddedTor attempt=null;
      try{
        if(closing.get())return;
        Path executable=AppPaths.bundle().resolve(AppPaths.windows()?"tor/tor.exe":"tor/tor");
        if(!Files.isRegularFile(executable,LinkOption.NOFOLLOW_LINKS))throw new VzorFailure600(VzorFailure600.Code.TOR_BINARY_MISSING);
        EmbeddedTor previous=tor.getAndSet(null);if(previous!=null)previous.close();ports.close();
        attempt=new EmbeddedTor(config);tor.set(attempt);status.accept("Отдельный Tor подготовки Взора: подключение…");
        attempt.start(mode,Duration.ofMinutes(4),progress);
        if(closing.get()){attempt.close();return;}status.accept("Отдельный Tor подготовки Взора подключён. Состояние Tor браузера показано в его окне.");
      }catch(Exception|LinkageError error){if(attempt!=null)attempt.close();tor.compareAndSet(attempt,null);status.accept(error instanceof IOException&&!(error instanceof VzorFailure600)&&!(error instanceof EmbeddedTor.BootstrapFailure)&&!(error instanceof InterruptedIOException)?VzorFailure600.Code.TOR_RUNTIME_FAILED.russian():VzorFailure600.safeMessage(error));}
      finally{connecting.set(false);}
    });}catch(RejectedExecutionException full){connecting.set(false);status.accept(VzorFailure600.Code.STARTUP_BUSY.russian());}
  }
  /** Idempotent, off-FX close; only this JVM's browser/network handles can be stopped. */
  @Override public synchronized void close()throws IOException{
    if(closed)return;closing.set(true);
    operations.shutdownNow();network.shutdownNow();EmbeddedTor owned=tor.getAndSet(null);if(owned!=null)owned.close();ports.close();
    boolean workersStopped=false;
    try{
      workersStopped=operations.awaitTermination(15,TimeUnit.SECONDS)&&network.awaitTermination(5,TimeUnit.SECONDS);
      browser.close();
    }catch(InterruptedException error){Thread.currentThread().interrupt();throw new VzorFailure600(VzorFailure600.Code.CLOSE_INCOMPLETE);}
    catch(IOException error){throw new VzorFailure600(VzorFailure600.Code.CLOSE_INCOMPLETE);}
    // Keep the manager lease on an incomplete shutdown; a repeated Close may retry cleanup.
    if(!workersStopped||browser.busy())throw new VzorFailure600(VzorFailure600.Code.CLOSE_INCOMPLETE);
    try{state.close();}catch(IOException error){throw new VzorFailure600(VzorFailure600.Code.CLOSE_INCOMPLETE);}
    closed=true;
  }
}
