package org.securemail.client.net;
import java.time.Duration;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.*;
import org.securemail.client.*;
import org.securemail.client.storage.AtomicFiles;

/** Reuses the last successful mode; never races two Tor processes. */
public final class TorConnection implements AutoCloseable {
  public interface Attempt extends AutoCloseable {
    void start(EmbeddedTor.Mode mode,Duration timeout,IntConsumer progress)throws Exception;
    boolean ready();void close();
  }
  private final Supplier<Attempt> factory;private final Path modeFile;
  private volatile Attempt current;private volatile boolean closed;private final java.util.concurrent.atomic.AtomicBoolean starting=new java.util.concurrent.atomic.AtomicBoolean();
  private volatile EmbeddedTor.Mode mode=EmbeddedTor.Mode.DIRECT;
  public TorConnection(ClientConfig config){this(()->new EmbeddedTor(config),AppPaths.root().resolve("tor-mode.txt"));}
  public TorConnection(Supplier<Attempt> factory){this(factory,null);}
  public TorConnection(Supplier<Attempt> factory,Path modeFile){this.factory=Objects.requireNonNull(factory);this.modeFile=modeFile;}
  public EmbeddedTor.Mode mode(){return mode;}
  public boolean ready(){var value=current;return !closed&&value!=null&&value.ready();}
  private EmbeddedTor.Mode remembered(){
    if(modeFile!=null)try{String name=new String(AtomicFiles.read(modeFile,32),StandardCharsets.US_ASCII).strip();if(name.equals("snowflake"))return EmbeddedTor.Mode.SNOWFLAKE;}catch(java.io.IOException ignored){}return EmbeddedTor.Mode.DIRECT;
  }
  public void start(Duration directTimeout,Duration snowflakeTimeout,BiConsumer<EmbeddedTor.Mode,Integer> progress)throws Exception {
    if(!starting.compareAndSet(false,true))throw new java.io.IOException("Подключение уже выполняется");
    try{
    EmbeddedTor.Mode first=remembered(),other=first==EmbeddedTor.Mode.DIRECT?EmbeddedTor.Mode.SNOWFLAKE:EmbeddedTor.Mode.DIRECT;
    try{run(first,first==EmbeddedTor.Mode.DIRECT?directTimeout:snowflakeTimeout,progress);}
    catch(EmbeddedTor.BootstrapFailure failure){if(closed)throw failure;TechnicalLog.record(TechnicalLog.Event.TOR_FALLBACK,other.ordinal());run(other,other==EmbeddedTor.Mode.DIRECT?directTimeout:snowflakeTimeout,progress);}
    if(modeFile!=null){AtomicFiles.directory(modeFile.toAbsolutePath().getParent());AtomicFiles.write(modeFile,(mode==EmbeddedTor.Mode.DIRECT?"direct\n":"snowflake\n").getBytes(StandardCharsets.US_ASCII));}
    }
    finally{starting.set(false);}
  }
  private void run(EmbeddedTor.Mode selected,Duration timeout,BiConsumer<EmbeddedTor.Mode,Integer> progress)throws Exception {
    Attempt attempt;synchronized(this){if(closed)throw new java.io.IOException("Приложение закрывается");if(current!=null)current.close();mode=selected;current=attempt=factory.get();}
    progress.accept(selected,0);try{attempt.start(selected,timeout,n->progress.accept(selected,n));}catch(Exception failure){attempt.close();throw failure;}
  }
  @Override public synchronized void close(){closed=true;if(current!=null)current.close();}
}
