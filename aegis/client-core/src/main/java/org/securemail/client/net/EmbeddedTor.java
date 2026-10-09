package org.securemail.client.net;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.function.IntConsumer;
import org.securemail.client.*;
import org.securemail.client.storage.AtomicFiles;
/** Own binary, own configuration, own child process; never adopts an unrelated Tor. */
public final class EmbeddedTor implements TorConnection.Attempt {
  public enum Mode{DIRECT,SNOWFLAKE}
  public static final class BootstrapFailure extends IOException { private static final long serialVersionUID=1L; public BootstrapFailure(){super("Tor не смог подключиться");} }
  private final ClientConfig config;private final Path root,bundle;private volatile Process child;private volatile boolean ready,closed;private volatile SnowflakeProcess transport;
  public EmbeddedTor(ClientConfig config){this.config=config;root=AppPaths.root().resolve("tor");bundle=AppPaths.bundle().resolve("tor");}
  public boolean ready(){return ready&&child!=null&&child.isAlive()&&(transport==null||transport.alive())&&!closed;}
  public void start(Mode mode,Duration timeout,IntConsumer progress)throws Exception{
    if(child!=null)throw new IOException("Tor уже запущен");if(closed)throw new IOException("Приложение закрывается");
    Path exe=bundle.resolve(AppPaths.windows()?"tor.exe":"tor");if(!Files.isRegularFile(exe))throw new IOException("Встроенный Tor отсутствует. Распакуйте полный пакет АЕГИС.");
    freePort(config.torSocksPort());freePort(config.torUpdateSocksPort());freePort(config.torControlPort());
    AtomicFiles.directory(root);AtomicFiles.directory(root.resolve("state"));
    // Explicitly replaces both default and regular torrc, including on systems with a global User option.
    AtomicFiles.write(root.resolve("defaults-torrc"),new byte[0]);
    String rc=baseConfiguration();
    if(mode==Mode.SNOWFLAKE){Path pt=bundle.resolve("pluggable_transports/lyrebird"+(AppPaths.windows()?".exe":""));if(!Files.isRegularFile(pt))throw new IOException("Компонент Snowflake отсутствует");transport=new SnowflakeProcess();int ptPort=transport.start(pt,root.resolve("transport-state"));rc+="UseBridges 1\nClientTransportPlugin snowflake socks5 127.0.0.1:"+ptPort+"\n";for(String bridge:bridges(bundle.resolve("snowflake-bridges.txt")))rc+="Bridge "+bridge+"\n";}
    AtomicFiles.write(root.resolve("torrc"),rc.getBytes(StandardCharsets.UTF_8));
    var args=new ArrayList<>(List.of(exe.toString(),"--defaults-torrc",root.resolve("defaults-torrc").toString(),"-f",root.resolve("torrc").toString()));
    var verifyArgs=new ArrayList<>(args);verifyArgs.add("--verify-config");Process verify=builder(verifyArgs).start();
    try{if(!verify.waitFor(15,java.util.concurrent.TimeUnit.SECONDS)||verify.exitValue()!=0)throw new IOException("Не удалось проверить настройки Tor");}finally{if(verify.isAlive())verify.destroyForcibly();}
    synchronized(this){if(closed)throw new IOException("Приложение закрывается");child=builder(args).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.PIPE).start();
      TechnicalLog.record(mode==Mode.DIRECT?TechnicalLog.Event.TOR_DIRECT_START:TechnicalLog.Event.TOR_SNOWFLAKE_START,0);
      Process owned=child; Thread reader=new Thread(()->readSafeEvents(owned),"aegis-tor-events");reader.setDaemon(true);reader.start();}
    long until=System.nanoTime()+timeout.toNanos();int previous=-1;
    var watch=new BootstrapWatch(Duration.ofSeconds(mode==Mode.DIRECT?30:75),System.nanoTime());
    while(System.nanoTime()<until){
      if(closed)throw new IOException("Приложение закрывается");
      if(!child.isAlive()){TechnicalLog.record(TechnicalLog.Event.TOR_EXIT,child.exitValue());close();throw new BootstrapFailure();}
      if(transport!=null&&!transport.alive()){TechnicalLog.record(TechnicalLog.Event.TRANSPORT_ERROR,0);close();throw new BootstrapFailure();}
      try(var control=new TorControl(config.torControlPort(),config.torCookiePath())){
        int value=control.bootstrapProgress();watch.progress(value,System.nanoTime());if(previous!=value){previous=value;TechnicalLog.record(TechnicalLog.Event.TOR_BOOTSTRAP,value);progress.accept(value);}
        if(value==100&&socksReady(config.torSocksPort())&&socksReady(config.torUpdateSocksPort())){ready=true;TechnicalLog.record(TechnicalLog.Event.TOR_READY,100);return;}
      }catch(IOException|java.security.GeneralSecurityException ignored){}
      if(watch.stalled(System.nanoTime())){TechnicalLog.record(mode==Mode.DIRECT?TechnicalLog.Event.TOR_DIRECT_STALLED:TechnicalLog.Event.TOR_SNOWFLAKE_STALLED,previous);close();throw new BootstrapFailure();}
      Thread.sleep(400); // Polling interval, never the readiness decision.
    }
    TechnicalLog.record(TechnicalLog.Event.TOR_TIMEOUT,previous);close();throw new BootstrapFailure();
  }
  public static List<String> bridges(Path path)throws IOException{
    if(Files.size(path)>16384)throw new IOException("Snowflake config too large");var list=Files.readAllLines(path,StandardCharsets.UTF_8).stream().filter(s->!s.isBlank()&&!s.startsWith("#")).toList();
    if(list.isEmpty()||list.size()>8)throw new IOException("Snowflake config invalid");
    for(String line:list)if(!line.startsWith("snowflake ")||line.length()>4096||line.chars().anyMatch(c->c<32)||line.matches(".*(?:^| )front=[^ ]*,[^ ]*.*"))throw new IOException("Snowflake config invalid");
    return list;
  }
  private ProcessBuilder builder(List<String> args){var b=new ProcessBuilder(args).directory(bundle.toFile()).redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD);if(!AppPaths.windows())b.environment().put("LD_LIBRARY_PATH",bundle.toString());return b;}
  String baseConfiguration()throws IOException {
    return "ClientOnly 1\nSocksPort 127.0.0.1:"+config.torSocksPort()+" OnionTrafficOnly\nSocksPort 127.0.0.1:"+config.torUpdateSocksPort()+"\nControlPort 127.0.0.1:"+config.torControlPort()+"\nCookieAuthentication 1\nCookieAuthFile "+quoted(config.torCookiePath())+"\nDataDirectory "+quoted(root.resolve("state"))+"\nSafeLogging 1\nAvoidDiskWrites 1\nLog notice stdout\nGeoIPFile "+quoted(bundle.resolve("data/geoip"))+"\nGeoIPv6File "+quoted(bundle.resolve("data/geoip6"))+"\n";
  }
  private boolean socksReady(int port){try(var s=new Socket(Proxy.NO_PROXY)){s.connect(new InetSocketAddress("127.0.0.1",port),1000);s.setSoTimeout(1000);s.getOutputStream().write(new byte[]{5,1,0});return s.getInputStream().read()==5&&s.getInputStream().read()==0;}catch(IOException e){return false;}}
  private static void freePort(int port)throws IOException{try(var s=new ServerSocket()){s.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),port));}catch(IOException e){throw new IOException("Локальный порт занят другим приложением. Закройте другой экземпляр АЕГИС.");}}
  private static String quoted(Path p)throws IOException{String s=p.toAbsolutePath().toString().replace('\\','/');if(s.indexOf('"')>=0||s.chars().anyMatch(c->c<32))throw new IOException("Неподдерживаемый путь профиля");return "\""+s+"\"";}
  private void readSafeEvents(Process owned) {
    try(var reader=new BufferedReader(new InputStreamReader(owned.getInputStream(),StandardCharsets.UTF_8))) {
      String line;while((line=reader.readLine())!=null) {
        if(line.length()>8192)continue;
        String lower=line.toLowerCase(Locale.ROOT);
        if(lower.contains("managed proxy")&&(lower.contains("failed")||lower.contains("error"))) TechnicalLog.record(TechnicalLog.Event.TRANSPORT_ERROR,0);
        else if(lower.contains("no such host")||lower.contains("connection refused")||lower.contains("no route to host")||lower.contains("tls error")) TechnicalLog.record(TechnicalLog.Event.NETWORK_ERROR,0);
      }
    }catch(IOException ignored){}
  }
  public synchronized void close(){
    closed=true;ready=false;Process owned=child;child=null;if(owned!=null)stopOwnedTree(owned);
    if(transport!=null){transport.close();transport=null;}
  }
  static void stopOwnedTree(Process owned){
    var descendants=owned.descendants().toList();owned.destroy();
    try { if(!owned.waitFor(3,java.util.concurrent.TimeUnit.SECONDS)){owned.destroyForcibly();owned.waitFor(3,java.util.concurrent.TimeUnit.SECONDS);} }
    catch(InterruptedException e){Thread.currentThread().interrupt();owned.destroyForcibly();}
    for(var p:descendants)if(p.isAlive())p.destroy();
    long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(2);
    while(descendants.stream().anyMatch(ProcessHandle::isAlive)&&System.nanoTime()<deadline){
      try{Thread.sleep(50);}catch(InterruptedException e){Thread.currentThread().interrupt();break;}
    }
    for(var p:descendants)if(p.isAlive())p.destroyForcibly();
  }
}
