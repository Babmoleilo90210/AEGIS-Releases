package org.securemail.client.crypto;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.function.*;

/** Debounced candidate calculation. One running KDF and one pending code maximum.
 * A stale result cannot reach the UI, even if its queued UI callback runs later. */
public final class LiveCode implements AutoCloseable {
  private final ScheduledThreadPoolExecutor executor;
  private final Function<char[],String> calculate;
  private final Consumer<Runnable> dispatch;
  private final Consumer<String> display;
  private long generation;
  private Pending pending;
  private boolean closed;
  private static final class Pending {
    char[] code; ScheduledFuture<?> future;
    Pending(char[] code) { this.code=code; }
    synchronized char[] take() { char[] value=code;code=null;return value; }
    synchronized void wipe() { if(code!=null){Arrays.fill(code,'\0');code=null;} }
  }
  public LiveCode(Function<char[],String> calculate,Consumer<Runnable> dispatch,Consumer<String> display) {
    this.calculate=calculate;this.dispatch=dispatch;this.display=display;
    executor=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-live-code");t.setDaemon(true);return t;});
    executor.setRemoveOnCancelPolicy(true);
  }
  public synchronized void change(char[] code,String emptyDisplay) {
    if(closed){Arrays.fill(code,'\0');return;}
    long token=++generation;
    if(pending!=null){pending.future.cancel(false);pending.wipe();}
    pending=null;
    if(code.length==0){Arrays.fill(code,'\0');publish(token,emptyDisplay);return;}
    Pending request=new Pending(code);pending=request;
    request.future=executor.schedule(()-> {
      char[] input=request.take();if(input==null)return;
      try { String result=calculate.apply(input);publish(token,result); }
      catch(RuntimeException ignored){publish(token,"Не удалось обработать письмо");}
      finally{Arrays.fill(input,'\0');}
    },100,TimeUnit.MILLISECONDS);
  }
  private void publish(long token,String result) {
    dispatch.accept(()-> { synchronized(this) { if(!closed&&token==generation)display.accept(result); } });
  }
  @Override public synchronized void close() {
    closed=true;++generation;if(pending!=null){pending.future.cancel(false);pending.wipe();}executor.shutdownNow();
  }
}

