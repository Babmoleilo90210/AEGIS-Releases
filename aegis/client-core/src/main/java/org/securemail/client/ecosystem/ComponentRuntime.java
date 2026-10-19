package org.securemail.client.ecosystem;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/** Child-side lifecycle. Callbacks must finish on bounded workers; queue persistence happens before FLUSHED. */
public final class ComponentRuntime implements AutoCloseable {
  public interface Callbacks {
    void lockProtectedData() throws Exception;
    void persistQueuesAndStop() throws Exception;
    default void limitedIncomingCall(boolean accept) throws Exception { throw new IOException("Управление вызовом недоступно"); }
  }
  private final LocalIpc.ChildConnection connection;private final Callbacks callbacks;
  private final AtomicBoolean stopped=new AtomicBoolean();private volatile boolean locked;private boolean ready;private int pendingCount=-1;
  public ComponentRuntime(LocalIpc.ChildConnection connection,Callbacks callbacks) {this.connection=Objects.requireNonNull(connection);this.callbacks=Objects.requireNonNull(callbacks);}
  /** Run off the FX thread. No other reader may use this channel. */
  public void run() throws IOException {
    try {
      synchronized(this){connection.channel().send(LocalIpc.Packet.command(LocalIpc.Type.READY));ready=true;if(pendingCount>=0)connection.channel().send(LocalIpc.Packet.count(pendingCount));}
      while(!stopped.get()) {
        LocalIpc.Packet packet=connection.channel().receive();
        switch(packet.type()) {
          case HEARTBEAT -> connection.channel().send(LocalIpc.Packet.command(LocalIpc.Type.PONG));
          case LOCK -> { callbacks.lockProtectedData();locked=true;connection.channel().send(LocalIpc.Packet.command(LocalIpc.Type.LOCKED)); }
          case SHUTDOWN -> {
            stopOnce();connection.channel().send(LocalIpc.Packet.command(LocalIpc.Type.FLUSHED));return;
          }
          case CALL_ACCEPT,CALL_REJECT -> {
            if(!locked || connection.lease().component()!=ComponentId.GLAS)throw LocalIpc.rejected();
            callbacks.limitedIncomingCall(packet.type()==LocalIpc.Type.CALL_ACCEPT);
          }
          // Unlock cannot reuse an old ticket: Core must reauthenticate and restart the component with a fresh capability.
          default -> throw LocalIpc.rejected();
        }
      }
    } catch(Exception failure) {
      try{stopOnce();}catch(Exception cleanup){failure.addSuppressed(cleanup);}
      if(failure instanceof IOException io)throw io;
      throw new IOException("Приложение безопасно остановлено после ошибки",failure);
    } finally {connection.close();}
  }
  public boolean locked(){return locked;}
  public synchronized void notifications(int count) throws IOException {if(stopped.get())return;LocalIpc.Packet packet=LocalIpc.Packet.count(count);pendingCount=count;if(ready)connection.channel().send(packet);}
  private void stopOnce() throws Exception {if(stopped.compareAndSet(false,true))callbacks.persistQueuesAndStop();}
  @Override public void close() throws IOException {try{stopOnce();}catch(Exception e){throw new IOException("Сохранение очереди не подтверждено",e);}finally{connection.close();}}
}
