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
    this.store = store;
    maxCiphertext = max;
    this.acceptor=acceptor;this.capabilities=capabilities;
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
                  s.setSoTimeout(30_000);
                  sockets.add(s);
                  try {
                    worker.execute(() -> handle(s));
                  } catch (RejectedExecutionException e) {
                    sockets.remove(s);
                    s.close();
                  }
                } catch (IOException ignored) {
                  if (closed) return;
                }
            });
  }

  private void handle(Socket socket) {
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
        Binary.header(in);
        int operation=in.readUnsignedByte();if(!Binary.text(in,64).isEmpty())throw new IOException("Bad peer request");
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
    timer.shutdownNow();
  }
}
