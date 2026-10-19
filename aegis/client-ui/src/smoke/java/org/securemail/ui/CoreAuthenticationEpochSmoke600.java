package org.securemail.ui;

import com.google.gson.*;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import javafx.application.Platform;
import javafx.scene.layout.BorderPane;
import org.securemail.client.ecosystemauth.*;
import org.securemail.client.net.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.identity.*;

/** Exact authentication/lock races against real Core methods, encrypted vault and signed HTTP/SQLite.
 * Tor readiness and loopback SOCKS are explicit fixtures. This is not native desktop/Tor acceptance. */
public final class CoreAuthenticationEpochSmoke600 {
 private static final String ONION="a".repeat(56)+".onion";private static final char[] PASSWORD="Synthetic device password 600!".toCharArray();
 private static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
 private static KeyPair pair()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
 private static <T>T fx(Callable<T> c)throws Exception{FutureTask<T> task=new FutureTask<>(c);Platform.runLater(task);return task.get(10,TimeUnit.SECONDS);}
 private static Object get(Object o,String name)throws Exception{Field f=o.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(o);}
 private static void set(Object o,String name,Object value)throws Exception{Field f=o.getClass().getDeclaredField(name);f.setAccessible(true);f.set(o,value);}
 private static Object call(CoreApp600 app,String name,Class<?>[] types,Object...args)throws Exception{Method m=CoreApp600.class.getDeclaredMethod(name,types);m.setAccessible(true);try{return m.invoke(app,args);}catch(InvocationTargetException e){if(e.getCause() instanceof Exception x)throw x;if(e.getCause() instanceof Error x)throw x;throw e;}}
 private static long epoch(CoreApp600 app)throws Exception{return ((AtomicLong)get(app,"uiEpoch")).get();}
 private static void lock(CoreApp600 app)throws Exception{fx(()->{call(app,"lock",new Class<?>[0]);return null;});}
 private static void drain(CoreApp600 app)throws Exception{((ThreadPoolExecutor)get(app,"worker")).submit(()->{}).get(15,TimeUnit.SECONDS);fx(()->null);}
 private static long generation(Path db,String account)throws Exception{try(var c=java.sql.DriverManager.getConnection("jdbc:sqlite:"+db);var p=c.prepareStatement("SELECT generation FROM accounts WHERE id=?")){p.setString(1,account);try(var rows=p.executeQuery()){check(rows.next(),"Test account");return rows.getLong(1);}}}
 public static void main(String[] args)throws Exception{
  Path output=Path.of(args[0]);Files.createDirectories(output);Path home=Files.createTempDirectory("aegis-auth-epoch-");System.setProperty("aegis.profile",home.resolve("profile").toString());CountDownLatch boot=new CountDownLatch(1);Platform.startup(boot::countDown);check(boot.await(10,TimeUnit.SECONDS),"FX startup");Platform.setImplicitExit(false);CoreApp600 app=fx(CoreApp600::new);Path db=home.resolve("identity.db");KeyPair service=pair(),root=pair(),device=pair(),recovery=pair();String account=IdentityProtocol.id(root.getPublic().getEncoded());AtomicInteger networkChecks=new AtomicInteger();
  try(var store=new IdentityStore(db,service,new byte[32],Clock.systemUTC());var http=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),store,service)){
   http.start();try(var socks=new Socks(http.port());var client=new IdentityClient600(ONION,80,service.getPublic().getEncoded(),new TorTransport("127.0.0.1",socks.port()))){
    long t=System.currentTimeMillis();String n=IdentityProtocol.nonce();byte[] body=IdentityProtocol.registration(store.audience(),root.getPublic().getEncoded(),device.getPublic().getEncoded(),recovery.getPublic().getEncoded(),"Испытатель блокировки",t,n);store.register(root.getPublic().getEncoded(),device.getPublic().getEncoded(),recovery.getPublic().getEncoded(),"Испытатель блокировки",t,n,IdentityProtocol.sign(root.getPrivate(),body),IdentityProtocol.sign(device.getPrivate(),body));
    DeviceCredentialStore600 vault=(DeviceCredentialStore600)get(app,"credentials");try(var credentials=new DeviceCredentials600(root.getPublic().getEncoded(),device,recovery.getPublic().getEncoded())){vault.create(credentials,PASSWORD);}
    TorConnection tor=new TorConnection(()->new TorConnection.Attempt(){boolean ready;public void start(EmbeddedTor.Mode mode,Duration timeout,java.util.function.IntConsumer progress){ready=true;}public boolean ready(){networkChecks.incrementAndGet();return ready;}public void close(){ready=false;}});tor.start(Duration.ofSeconds(1),Duration.ofSeconds(1),(m,v)->{});fx(()->{set(app,"root",new BorderPane());set(app,"config",new CorePublicConfig600(ONION,80,service.getPublic().getEncoded(),socks.port()));set(app,"tor",tor);set(app,"identity",client);return null;});
    List<String> checks=new ArrayList<>();
    for(String operation:List.of("openExisting","enroll")){
     CountDownLatch passedWorkCheck=new CountDownLatch(1),continueOperation=new CountDownLatch(1);AtomicBoolean rejected=new AtomicBoolean(),callback=new AtomicBoolean();long captured=epoch(app);int before=networkChecks.get();long oldGeneration=generation(db,account);char[] secret=PASSWORD.clone();
     fx(()->{call(app,"work",new Class<?>[]{Callable.class,Consumer.class},(Callable<Object>)()->{passedWorkCheck.countDown();check(continueOperation.await(5,TimeUnit.SECONDS),"Release authentication operation");try{return call(app,operation,new Class<?>[]{char[].class,long.class},secret,captured);}catch(IOException expected){rejected.set(true);throw expected;}finally{Arrays.fill(secret,'\0');}},(Consumer<Object>)value->callback.set(true));return null;});
     check(passedWorkCheck.await(5,TimeUnit.SECONDS),"Worker passed initial epoch check");lock(app);continueOperation.countDown();drain(app);check(rejected.get()&&!callback.get()&&get(app,"session")==null,"Stale operation published session or callback");check(networkChecks.get()==before&&generation(db,account)==oldGeneration,"Stale operation reached network or changed generation");check(allZero(secret),"Captured password wiped");checks.add(operation+": lock between work pre-check and method entry rejects original action before network/vault unlock");
    }
    socks.pauseNextLogin.set(true);long captured=epoch(app);AtomicBoolean rejected=new AtomicBoolean(),callback=new AtomicBoolean();char[] secret=PASSWORD.clone();fx(()->{call(app,"work",new Class<?>[]{Callable.class,Consumer.class},(Callable<Object>)()->{try{return call(app,"openExisting",new Class<?>[]{char[].class,long.class},secret,captured);}catch(IOException expected){rejected.set(true);throw expected;}finally{Arrays.fill(secret,'\0');}},(Consumer<Object>)value->callback.set(true));return null;});
    check(socks.loginResponse.await(10,TimeUnit.SECONDS),"Actual signed login response reached SOCKS fixture");lock(app);socks.releaseLogin.countDown();drain(app);check(rejected.get()&&!callback.get()&&get(app,"session")==null,"In-flight login bypassed lock publication guard");check(allZero(secret),"In-flight password wiped");checks.add("Actual signed HTTP login response held during Core.lock: candidate publication rejected, no unlocked session or stale UI callback");check(store.verifyAudit(),"Identity audit integrity");
    Files.writeString(output.resolve("RESULT.json"),new GsonBuilder().setPrettyPrinting().create().toJson(Map.of("status","PASS_HEADLESS","scope","Actual Core private authentication methods, JavaFX, encrypted device vault, signed HTTP and SQLite; explicit local SOCKS/Tor readiness fixtures; native platforms and real Tor NOT_RUN","checks",checks,"tests",3,"passed",3)));System.out.println("PASS_HEADLESS: 3 actual Core authentication epoch races; no late session publication, stale callbacks or retained password arrays.");tor.close();
   }
  }finally{for(String name:List.of("worker","guardWorker","protectedCleanup","consentCleanup"))((ExecutorService)get(app,name)).shutdownNow();Platform.exit();Arrays.fill(PASSWORD,'\0');}
 }
 private static boolean allZero(char[] data){for(char c:data)if(c!='\0')return false;return true;}
 private static final class Socks implements AutoCloseable{
  final ServerSocket server;final int target;final ExecutorService workers=Executors.newFixedThreadPool(4,r->{Thread t=new Thread(r,"auth-epoch-socks");t.setDaemon(true);return t;});final Thread accept;final AtomicBoolean pauseNextLogin=new AtomicBoolean();final CountDownLatch loginResponse=new CountDownLatch(1),releaseLogin=new CountDownLatch(1);
  Socks(int target)throws Exception{this.target=target;server=new ServerSocket(0,8,InetAddress.getByAddress(new byte[]{127,0,0,1}));accept=new Thread(()->{while(!server.isClosed())try{Socket socket=server.accept();workers.execute(()->forward(socket));}catch(IOException ignored){}},"auth-epoch-accept");accept.setDaemon(true);accept.start();}int port(){return server.getLocalPort();}
  void forward(Socket socket){try(socket){socket.setSoTimeout(10000);DataInputStream in=new DataInputStream(socket.getInputStream());OutputStream out=socket.getOutputStream();check(in.readUnsignedByte()==5&&in.readUnsignedByte()==1&&in.readUnsignedByte()==0,"SOCKS greeting");out.write(new byte[]{5,0});out.flush();check(in.readUnsignedByte()==5&&in.readUnsignedByte()==1&&in.readUnsignedByte()==0&&in.readUnsignedByte()==3,"SOCKS domain");check(new String(in.readNBytes(in.readUnsignedByte()),StandardCharsets.US_ASCII).equals(ONION)&&in.readUnsignedShort()==80,"Onion fixture route");out.write(new byte[]{5,0,0,1,127,0,0,1,0,0});out.flush();ByteArrayOutputStream header=new ByteArrayOutputStream();int end=0;byte[] marker={13,10,13,10};while(end<4){int value=in.read();if(value<0)throw new EOFException();header.write(value);end=value==marker[end]?end+1:(value==13?1:0);if(header.size()>8192)throw new IOException("Header limit");}int length=-1;for(String h:header.toString(StandardCharsets.US_ASCII).split("\r\n"))if(h.toLowerCase(Locale.ROOT).startsWith("content-length:"))length=Integer.parseInt(h.substring(h.indexOf(':')+1).strip());if(length<0||length>65536)throw new IOException("Request limit");byte[] payload=in.readNBytes(length);try(Socket remote=new Socket(InetAddress.getByAddress(new byte[]{127,0,0,1}),target)){remote.getOutputStream().write(header.toByteArray());remote.getOutputStream().write(payload);remote.getOutputStream().flush();byte[] response=remote.getInputStream().readNBytes(131073);if(response.length>131072)throw new IOException("Response limit");if(new String(payload,StandardCharsets.UTF_8).contains("\"operation\":\"login\"")&&pauseNextLogin.compareAndSet(true,false)){loginResponse.countDown();check(releaseLogin.await(5,TimeUnit.SECONDS),"Release signed login response");}out.write(response);out.flush();}}catch(Exception ignored){/* Fixture closes its sockets; clients retain strict timeouts. */}}
  public void close()throws Exception{releaseLogin.countDown();server.close();workers.shutdownNow();accept.join(1000);}
 }
}
