package org.securemail.client.ecosystem;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Explicit full-exit coordinator. Detached Tor Browser and personal Obsidian are intentionally not registered here. */
public final class CoreLifecycle implements AutoCloseable {
  @FunctionalInterface public interface ProtectedLibrary { void lockAndDiscardPlaintext() throws Exception; }
  private final DesktopProcessBroker broker;private final ProtectedLibrary library;private final List<AutoCloseable> userServices;
  private final AtomicBoolean closed=new AtomicBoolean();
  private final ThreadPoolExecutor cleanup=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(1),r->{Thread thread=new Thread(r,"aegis-exit-cleanup");thread.setDaemon(true);return thread;},new ThreadPoolExecutor.AbortPolicy());
  public CoreLifecycle(DesktopProcessBroker broker,ProtectedLibrary library,List<? extends AutoCloseable> userServices){this.broker=Objects.requireNonNull(broker);this.library=Objects.requireNonNull(library);this.userServices=List.copyOf(userServices);if(this.userServices.size()>16)throw new IllegalArgumentException("Слишком много пользовательских служб");}
  public void lock()throws IOException {broker.lock();bounded("Блокировка защищённой библиотеки",()->library.lockAndDiscardPlaintext());}
  /** Invoke off the FX thread. Exceptions report incomplete cleanup rather than claiming a successful safe exit. */
  @Override public void close()throws IOException {
    if(!closed.compareAndSet(false,true))return;IOException failure=null;
    try{lock();}catch(IOException e){failure=e;}
    broker.close();
    for(AutoCloseable service:userServices)try{bounded("Остановка пользовательской службы",service::close);}catch(IOException e){if(failure==null)failure=e;else failure.addSuppressed(e);}
    cleanup.shutdownNow();if(failure!=null)throw failure;
  }
  @FunctionalInterface private interface Checked {void run()throws Exception;}
  private void bounded(String action,Checked work)throws IOException {
    Future<?> done;
    try { done=cleanup.submit(()->{try{work.run();}catch(Exception e){throw new CompletionException(e);}}); }
    catch(RejectedExecutionException e){throw new IOException(action+" не выполнена: предыдущая очистка ещё занята",e);}
    try {done.get(3,TimeUnit.SECONDS);}
    catch(InterruptedException e){Thread.currentThread().interrupt();done.cancel(true);throw new IOException(action+" прервана",e);}
    catch(ExecutionException|TimeoutException e){done.cancel(true);throw new IOException(action+" не подтверждена",e);}
  }
}
