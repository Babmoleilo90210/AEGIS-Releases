package org.securemail.client.safeweb600;

import java.io.*;
import java.net.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.securemail.client.*;
import org.securemail.client.storage.AtomicFiles;

/** Separate browser-manager state. Does not load ClientConfig, identity, mail, archive, or Core profile. */
public final class VzorState600 implements AutoCloseable {
  private static final Map<Path,VzorState600> OWNED=new HashMap<>();
  private static final byte[] MARKER="AEGIS-VZOR-MANAGER-600\n".getBytes(StandardCharsets.US_ASCII);
  private final Path root,browser;
  private final FileChannel channel;
  private final FileLock lock;
  private boolean closed;
  private VzorState600(Path root,Path browser,FileChannel channel,FileLock lock){this.root=root;this.browser=browser;this.channel=channel;this.lock=lock;}
  public Path root(){return root;}
  public Path browser(){return browser;}
  public static Path defaultRoot(){return roots(System.getProperty("os.name",""),System.getProperty("user.home",""),System.getenv()).getFirst();}
  static List<Path> roots(String os,String home,Map<String,String> env){
    if(os.startsWith("Windows")){
      String data=env.get("LOCALAPPDATA");if(data==null||data.isBlank())throw new IllegalStateException("LOCALAPPDATA unavailable");Path base=Path.of(data).toAbsolutePath().normalize();return List.of(base.resolve("AEGIS-Vzor-Manager"),base.resolve("AEGIS-SafeWeb"));
    }
    String data=env.get("XDG_DATA_HOME");Path base=data==null||data.isBlank()?Path.of(home,".local","share"):Path.of(data);base=base.toAbsolutePath().normalize();return List.of(base.resolve("aegis-vzor-manager"),base.resolve("aegis-safeweb"));
  }
  /** Run exclusively in the detached manager JVM before ThemeManager or EmbeddedTor construction. */
  public static VzorState600 openProcessState()throws IOException{
    List<Path> paths=roots(System.getProperty("os.name",""),System.getProperty("user.home",""),System.getenv());Path root=paths.getFirst();String prior=System.getProperty("aegis.profile");
    if(prior!=null&&!Path.of(prior).toAbsolutePath().normalize().equals(root))throw new VzorFailure600(VzorFailure600.Code.STATE_UNAVAILABLE);
    VzorState600 state=open(root,paths.get(1));System.setProperty("aegis.profile",root.toString());return state;
  }
  static synchronized VzorState600 open(Path directory,Path browser)throws IOException{
    Path root=directory.toAbsolutePath().normalize(),web=browser.toAbsolutePath().normalize();
    if(OWNED.containsKey(root))throw new VzorFailure600(VzorFailure600.Code.ALREADY_RUNNING);
    if(root.startsWith(web)||web.startsWith(root))throw new VzorFailure600(VzorFailure600.Code.STATE_UNAVAILABLE);
    rejectLinks(root);rejectLinks(web);boolean existed=Files.exists(root,LinkOption.NOFOLLOW_LINKS);
    if(existed&&!Files.exists(root.resolve("manager-format"),LinkOption.NOFOLLOW_LINKS)){
      try(var items=Files.list(root)){if(items.findAny().isPresent())throw new VzorFailure600(VzorFailure600.Code.STATE_UNAVAILABLE);}
    }
    AtomicFiles.directory(root);rejectLinks(root);Path marker=root.resolve("manager-format");
    if(Files.exists(marker,LinkOption.NOFOLLOW_LINKS)){if(!Arrays.equals(AtomicFiles.read(marker,64),MARKER))throw new VzorFailure600(VzorFailure600.Code.STATE_UNAVAILABLE);}
    else AtomicFiles.write(marker,MARKER);
    FileChannel channel=FileChannel.open(root.resolve("manager.lock"),Set.of(StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),AtomicFiles.attributes(root));
    FileLock lock=null;
    try{try{lock=channel.tryLock();}catch(OverlappingFileLockException busy){/* Current process already owns it. */}
      if(lock==null)throw new VzorFailure600(VzorFailure600.Code.ALREADY_RUNNING);
      VzorState600 state=new VzorState600(root,web,channel,lock);OWNED.put(root,state);return state;
    }catch(IOException|RuntimeException error){channel.close();throw error;}
  }
  /** Read-only updater guard. The probe never creates a manager or adopts a PID. */
  public static boolean managerRunning()throws IOException{return lockHeld(defaultRoot());}
  static synchronized boolean lockHeld(Path directory)throws IOException{
    Path root=directory.toAbsolutePath().normalize();
    // POSIX fcntl locks can be released by closing another descriptor for the same inode.
    if(OWNED.containsKey(root))return true;
    rejectLinks(root);Path file=root.resolve("manager.lock");
    if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS))return false;if(Files.isSymbolicLink(file))throw new VzorFailure600(VzorFailure600.Code.STATE_UNAVAILABLE);
    try(FileChannel probe=FileChannel.open(file,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
      try{FileLock acquired=probe.tryLock();if(acquired==null)return true;acquired.release();return false;}
      catch(OverlappingFileLockException owned){return true;}
    }
  }
  static void rejectLinks(Path path)throws IOException{for(Path p=path;p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new VzorFailure600(VzorFailure600.Code.STATE_UNAVAILABLE);}
  /** Reserves four distinct loopback ports. Release immediately before own Tor checks/binds them; a race fails closed. */
  public static final class Ports implements AutoCloseable {
    private final List<ServerSocket> sockets;
    private Ports(List<ServerSocket> sockets){this.sockets=List.copyOf(sockets);}
    public int socks(){return sockets.get(0).getLocalPort();} public int control(){return sockets.get(1).getLocalPort();}
    public int update(){return sockets.get(2).getLocalPort();} public int unusedService(){return sockets.get(3).getLocalPort();}
    public ClientConfig config(Path managerRoot){return new ClientConfig("127.0.0.1",socks(),control(),update(),managerRoot.resolve("tor/control_auth_cookie"),unusedService(),1800,"",80,managerRoot.resolve("unused-no-mail-storage"),1024,1048576,86400000);}
    @Override public void close(){for(ServerSocket socket:sockets)try{socket.close();}catch(IOException ignored){/* Owned reservation only. */}}
  }
  public static Ports reservePorts()throws IOException{
    List<ServerSocket> sockets=new ArrayList<>();
    try{for(int i=0;i<4;i++){ServerSocket socket=new ServerSocket();socket.setReuseAddress(false);socket.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),0));sockets.add(socket);}return new Ports(sockets);}
    catch(IOException error){for(ServerSocket socket:sockets)try{socket.close();}catch(IOException ignored){}throw new VzorFailure600(VzorFailure600.Code.PORT_UNAVAILABLE);}
  }
  @Override public synchronized void close()throws IOException{if(!closed){closed=true;try{if(lock.isValid())lock.release();}finally{try{channel.close();}finally{synchronized(VzorState600.class){OWNED.remove(root,this);}}}}}
}
