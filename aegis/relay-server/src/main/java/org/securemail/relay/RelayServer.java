package org.securemail.relay;

import java.io.*;
import java.net.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import org.securemail.protocol.*;

/** Bounded loopback TCP server. Optional 6.0 gate contacts only a pinned literal-loopback Identity service. */
public final class RelayServer implements AutoCloseable {
  private record Session(UserInfo user, long expiresAt,RelaySessionGate600.Binding binding) {}
  private record PublishedRoute(Route route,UserInfo owner,RelaySessionGate600.Binding binding) {}

  private final RelayConfig config;
  private final RelayStore store;
  private final Clock clock;
  private final RelaySessionGate600 sessionGate;
  private final ServerSocket listener;
  private final ExecutorService workers =
      new ThreadPoolExecutor(
          4,
          4,
          0,
          TimeUnit.SECONDS,
          new SynchronousQueue<>(),
          new ThreadPoolExecutor.AbortPolicy());
  private final ScheduledThreadPoolExecutor timer = new ScheduledThreadPoolExecutor(1);

  {
    timer.setRemoveOnCancelPolicy(true);
  }

  private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
  private final Map<String, Session> sessions = new ConcurrentHashMap<>();
  private final Map<String, PublishedRoute> routes = new ConcurrentHashMap<>();
  private final Semaphore authSlot = new Semaphore(1), transferSlot = new Semaphore(1);
  private final ArrayDeque<Long> attempts = new ArrayDeque<>();
  private final Map<String, ArrayDeque<Long>> perAccount = new HashMap<>();
  private final SecureRandom random = new SecureRandom();
  private final AtomicLong rejected = new AtomicLong();
  private final long started = System.nanoTime();
  private volatile boolean closed;

  public RelayServer(RelayConfig config, RelayStore store, Clock clock) throws IOException {
    this(config,store,clock,null);
  }
  public RelayServer(RelayConfig config,RelayStore store,Clock clock,RelaySessionGate600 sessionGate)throws IOException {
    this.config = config;
    this.store = store;
    this.clock = clock;
    this.sessionGate=sessionGate;
    listener = new ServerSocket();
    listener.bind(
        new InetSocketAddress(
            InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), config.listenPort()),
        8);
    timer.scheduleAtFixedRate(
        () -> {
          try {
            store.cleanup();
            sessions.entrySet().removeIf(e -> e.getValue().expiresAt() < clock.millis());
            routes.entrySet().removeIf(e -> e.getValue().route().expiresAt() < clock.millis());
          } catch (Exception ignored) {
            rejected.incrementAndGet();
          }
        },
        30,
        30,
        TimeUnit.SECONDS);
  }

  public int port() {
    return listener.getLocalPort();
  }

  public long uptimeSeconds() {
    return (System.nanoTime() - started) / 1_000_000_000;
  }

  public long rejectedRequests() {
    return rejected.get();
  }

  public void start() {
    Thread.ofPlatform()
        .daemon(true)
        .name("relay-accept")
        .start(
            () -> {
              while (!closed)
                try {
                  Socket s = listener.accept();
                  s.setSoTimeout(30_000);
                  sockets.add(s);
                  try {
                    workers.execute(() -> handle(s));
                  } catch (RejectedExecutionException e) {
                    sockets.remove(s);
                    s.close();
                  }
                } catch (IOException e) {
                  if (!closed) rejected.incrementAndGet();
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
      boolean responseStarted=false;
      try {
        Binary.header(in);
        Operation op = Operation.fromCode(in.readUnsignedByte());
        String token = Binary.text(in, 64);
        if (op == Operation.REGISTER || op == Operation.LOGIN || op==Operation.LOGIN6||op==Operation.REGISTER6) {
          authenticate(op, in, out);
          return;
        }
        Session session = sessions.get(tokenHash(token));
        if (session == null || session.expiresAt() <= clock.millis())
          throw new IOException("Unauthenticated");
        UserInfo user = session.user();
        check(session);if(sessionGate!=null)sessionGate.authorizeOperation(user,session.binding(),op);
        switch (op) {
          case CAPABILITIES -> {ok(out);out.writeInt(sessionGate==null?3:7);out.flush();}
          case PROFILE_PUT -> {var profile=PublicProfile.read(in);check(session);store.putProfile(user,profile);ok(out);}
          case PROFILE_GET -> {String target=Binary.text(in,32);check(session);var profile=store.profile(target);ok(out);out.writeBoolean(profile!=null);if(profile!=null)profile.write(out);out.flush();}
          case CONTACT_PUT -> {var assertion=ContactAssertion.read(in);check(session);store.putAssertion(user,assertion);ok(out);}
          case CONTACT_GET -> {
            String target=Binary.text(in,64);Limits.userId(target);
            check(session);
            var ours=store.assertion(user.userId(),target);var theirs=store.assertion(target,user.userId());
            ok(out);out.writeBoolean(ours!=null);if(ours!=null)ours.write(out);out.writeBoolean(theirs!=null);if(theirs!=null)theirs.write(out);out.flush();
          }
          case FIND -> {
            String nickname=Binary.text(in,32);check(session);var found = store.find(nickname);
            if (found == null) throw new IOException("Unknown user");
            PublishedRoute published=routes.get(found.userId());Route route=published==null?null:published.route();
            if(route!=null&&(route.expiresAt()<=clock.millis()||!routeCurrent(published))){routes.remove(found.userId(),published);route=null;}
            ok(out);
            new UserInfo(found.userId(), found.nickname(), found.publicKey(), route).write(out);
          }
          case PUBLISH -> {
            Route r = Route.read(in);
            check(session);
            long now = clock.millis();
            if (!r.userId().equals(user.userId())
                || r.expiresAt() <= now
                || r.expiresAt() > now + 120_000
                || !Signatures.verify(user.publicKey(), r.signingBytes(), r.signature()))
              throw new IOException("Bad route");
            routes.put(user.userId(), new PublishedRoute(r,user,session.binding()));
            ok(out);
          }
          case STORE -> {
            if (!transferSlot.tryAcquire()) throw new IOException("Busy");
            try {
              var packet=PacketCodec.read(in,config.maxCiphertext());check(session);store.store(user,packet,()->{if(sessionGate!=null)sessionGate.checkFresh(user,session.binding());});
              ok(out);
            } finally {
              transferSlot.release();
            }
          }
          case FETCH -> {
            if (!transferSlot.tryAcquire()) throw new IOException("Busy");
            try {
              var p = store.fetch(user);check(session);responseStarted=true;
              ok(out);out.writeBoolean(p != null);
              if(p!=null){DataOutputStream guarded=new DataOutputStream(new OutputStream(){@Override public void write(int value)throws IOException{check(session);out.write(value);}@Override public void write(byte[] value,int offset,int length)throws IOException{for(int start=offset;start<offset+length;){check(session);int n=Math.min(65536,offset+length-start);out.write(value,start,n);start+=n;}}});PacketCodec.write(guarded,p);check(session);}
              out.flush();
            } finally {
              transferSlot.release();
            }
          }
          case ACK -> {
            var receipt=Receipt.read(in);check(session);store.acknowledge(user,receipt);
            ok(out);
          }
          case DELETE -> {
            String id=Binary.text(in,36);check(session);store.discard(user,id);
            ok(out);
          }
          case LOGOUT -> {
            sessions.remove(tokenHash(token));
            routes.remove(user.userId());
            ok(out);
          }
          default -> throw new IOException("Bad operation");
        }
        out.flush();
      } catch (Exception e) {
        rejected.incrementAndGet();
        if(responseStarted)throw new IOException("Передача остановлена после отзыва сессии");
        Binary.header(out);
        out.writeInt(e instanceof Rejection r ? r.code : 1);
        out.flush();
      }
    } catch (IOException ignored) {
      rejected.incrementAndGet();
    } finally {
      timeout.cancel(false);
      sockets.remove(socket);
    }
  }

  private void authenticate(Operation op, DataInputStream in, DataOutputStream out)
      throws Exception {
    String nick = Limits.nickname(Binary.text(in, 32));
    if (!allowAttempt(nick) || !authSlot.tryAcquire()) throw new Rejection(7);
    byte[] password = null;
    try {
      password = Binary.bytes(in, 4096);
      UserInfo user;RelaySessionGate600.Binding binding=new RelaySessionGate600.Binding("");
      if(op==Operation.REGISTER||op==Operation.REGISTER6){byte[] pub=Binary.bytes(in,44);UserInfo candidate=new UserInfo(org.securemail.ecosystem.protocol.IdentityProtocol.id(pub),nick,pub,null);if(op==Operation.REGISTER6&&sessionGate==null)throw new IOException("Relay 6 не настроен");if(sessionGate!=null){if(op==Operation.REGISTER6)binding=sessionGate.register(candidate,nick,password,in);else sessionGate.checkFresh(candidate,binding);}final RelaySessionGate600.Binding checked=binding;user=store.register(nick,password,pub,()->{if(sessionGate!=null)sessionGate.checkFresh(candidate,checked);});}
      else {
        if(op==Operation.LOGIN6&&sessionGate==null)throw new IOException("Relay 6 не настроен");
        user=store.login(nick,password);
        if(sessionGate!=null){if(op==Operation.LOGIN6)binding=sessionGate.authenticate(user,nick,password,in);else sessionGate.check(user,binding);}
      }
      if (op == Operation.REGISTER||op==Operation.REGISTER6) {
        ok(out);
        user.write(out);
      } else {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = HexFormat.of().formatHex(bytes);
        if(sessionGate!=null)sessionGate.checkFresh(user,binding);
        routes.remove(user.userId());
        sessions.entrySet().removeIf(e -> e.getValue().user().userId().equals(user.userId()));
        sessions.put(tokenHash(token), new Session(user, clock.millis() + 12 * 3600_000L,binding));
        ok(out);
        Binary.text(out, token);
        user.write(out);
      }
      out.flush();
    } finally {
      if (password != null) Arrays.fill(password, (byte) 0);
      authSlot.release();
    }
  }

  private void check(Session session)throws IOException {if(session.expiresAt()<=clock.millis())throw new IOException("Сессия истекла");if(sessionGate!=null)sessionGate.check(session.user(),session.binding());}
  private boolean routeCurrent(PublishedRoute route){if(sessionGate==null)return true;try{sessionGate.check(route.owner(),route.binding());return true;}catch(IOException denied){return false;}}

  private synchronized boolean allowAttempt(String nick) {
    long now = clock.millis();
    attempts.removeIf(t -> t < now - 60_000);
    if (attempts.size() >= 12) return false;
    attempts.add(now);
    perAccount.entrySet().removeIf(e -> e.getValue().isEmpty() || e.getValue().peekLast() < now - 900_000);
    if(!perAccount.containsKey(nick) && perAccount.size() >= 256)return false;
    var q = perAccount.computeIfAbsent(nick, k -> new ArrayDeque<>());
    q.removeIf(t -> t < now - 900_000);
    if (q.size() >= 8) return false;
    q.add(now);
    return true;
  }

  private static String tokenHash(String token) throws GeneralSecurityException {
    return HexFormat.of()
        .formatHex(
            MessageDigest.getInstance("SHA-256")
                .digest(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
  }

  private static void ok(DataOutput out) throws IOException {
    Binary.header(out);
    out.writeInt(0);
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
    workers.shutdownNow();
    timer.shutdownNow();
    sessions.clear();
    routes.clear();
    if(sessionGate!=null)sessionGate.close();
  }
}
