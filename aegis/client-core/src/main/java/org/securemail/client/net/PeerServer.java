package org.securemail.client.net;

import java.io.*;
import java.net.*;
import java.util.Set;
import java.util.concurrent.*;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.*;

public final class PeerServer implements AutoCloseable {
  private final ServerSocket listener;
  private final LocalStore store;
  private final int maxCiphertext;
  private final PacketAcceptor acceptor;
  private final java.util.function.Function<byte[],org.securemail.client.lifecycle.DeviceCapabilities> capabilities;
  @FunctionalInterface public interface Extension { void handle(Socket socket)throws Exception; }
  private final Extension voice;
  private final ExecutorService preface = new ThreadPoolExecutor(0,2,30,TimeUnit.SECONDS,new SynchronousQueue<>(),new ThreadPoolExecutor.AbortPolicy());
  private final ExecutorService voiceWorker = new ThreadPoolExecutor(0,2,30,TimeUnit.SECONDS,new SynchronousQueue<>(),new ThreadPoolExecutor.AbortPolicy());
  private final ExecutorService worker =
      new ThreadPoolExecutor(
          1,
          1,
          0,
          TimeUnit.SECONDS,
          new SynchronousQueue<>(),
          new ThreadPoolExecutor.AbortPolicy());
  private final ScheduledThreadPoolExecutor timer = new ScheduledThreadPoolExecutor(1);

  {
    timer.setRemoveOnCancelPolicy(true);
  }

  private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
  private volatile boolean closed;

  public PeerServer(int port, LocalStore store, int max) throws IOException {
    this(port,store,max,store::accept,null);
  }
  public PeerServer(int port,LocalStore store,int max,PacketAcceptor acceptor,java.util.function.Function<byte[],org.securemail.client.lifecycle.DeviceCapabilities> capabilities)throws IOException {
    this(port,store,max,acceptor,capabilities,null);
  }
  public PeerServer(int port,LocalStore store,int max,PacketAcceptor acceptor,java.util.function.Function<byte[],org.securemail.client.lifecycle.DeviceCapabilities> capabilities,Extension voice)throws IOException {
    this.store = store;
    maxCiphertext = max;
    this.acceptor=acceptor;this.capabilities=capabilities;this.voice=voice;
    listener = new ServerSocket();
    listener.bind(
        new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), port), 4);
  }

  public int port() {
    return listener.getLocalPort();
  }

  public void start() {
    Thread.ofPlatform()
        .daemon(true)
        .name("peer-accept")
        .start(
            () -> {
              while (!closed)
                try {
                  Socket s = listener.accept();
                  s.setSoTimeout(10_000);
                  sockets.add(s);
                  try {
                    preface.execute(() -> route(s));
                  } catch (RejectedExecutionException e) {
                    sockets.remove(s);
                    s.close();
                  }
                } catch (IOException ignored) {
                  if (closed) return;
                }
            });
  }

  /** Read only the fixed preface before TLS. Buffered read-ahead would consume TLS bytes. */
  private void route(Socket socket){
    var deadline=timer.schedule(()->{try{socket.close();}catch(IOException ignored){}},10,TimeUnit.SECONDS);
    try{
      var input=new DataInputStream(socket.getInputStream());Binary.header(input);int operation=input.readUnsignedByte();
      if(!Binary.text(input,64).isEmpty())throw new IOException("Bad peer request");
      if(operation==101&&voice!=null){
        voiceWorker.execute(()->{try(socket){voice.handle(socket);}catch(Exception ignored){}finally{sockets.remove(socket);}});
      }else worker.execute(()->handle(socket,operation));
    }catch(IOException|RejectedExecutionException failure){sockets.remove(socket);try{socket.close();}catch(IOException ignored){}}
    finally{deadline.cancel(false);}
  }

  private void handle(Socket socket,int operation) {
    var timeout =
        timer.schedule(
            () -> {
              try {
                socket.close();
              } catch (IOException ignored) {
              }
            },
            5,
            TimeUnit.MINUTES);
    try (socket;
        var in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        var out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))) {
      try {
        socket.setSoTimeout(30_000);
        if(operation==org.securemail.client.lifecycle.DeviceCapabilities.OPERATION&&capabilities!=null){byte[] challenge=Binary.bytes(in,32);if(challenge.length!=32)throw new IOException("Challenge length");var answer=capabilities.apply(challenge);Binary.header(out);out.writeInt(0);answer.write(out);out.flush();return;}
        if(operation!=Operation.DELIVER.code)throw new IOException("Bad peer operation");
        var ack = acceptor.accept(PacketCodec.read(in, maxCiphertext()));
        Binary.header(out);
        out.writeInt(0);
        ack.write(out);
        out.flush();
      } catch (Exception e) {
        Binary.header(out);
        out.writeInt(1);
        out.flush();
      }
    } catch (IOException ignored) {
    } finally {
      timeout.cancel(false);
      sockets.remove(socket);
    }
  }

  private int maxCiphertext() {
    return maxCiphertext;
  }

  @Override
  public void close() throws IOException {
    closed = true;
    listener.close();
    for (Socket s : sockets)
      try {
        s.close();
      } catch (IOException ignored) {
      }
    worker.shutdownNow();
    preface.shutdownNow();voiceWorker.shutdownNow();
    timer.shutdownNow();
  }
}
