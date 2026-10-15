package org.securemail.client;
import java.io.*;
import java.nio.file.*;
import java.nio.channels.*;
import org.securemail.client.storage.AtomicFiles;
public final class AppPaths {
  private AppPaths() {}
  public static boolean windows(){return System.getProperty("os.name").startsWith("Windows");}
  public static Path root(){
    String override=System.getProperty("aegis.profile");if(override!=null)return Path.of(override).toAbsolutePath();
    if(windows()){String p=System.getenv("LOCALAPPDATA");if(p==null)throw new IllegalStateException("Нет каталога профиля Windows");return Path.of(p,"AEGIS");}
    String data=System.getenv("XDG_DATA_HOME");return (data==null||data.isBlank()?Path.of(System.getProperty("user.home"),".local","share"):Path.of(data)).resolve("aegis-app");
  }
  public static Path config(){if(windows()||System.getProperty("aegis.profile")!=null)return root().resolve("config/client.properties");String config=System.getenv("XDG_CONFIG_HOME");return (config==null||config.isBlank()?Path.of(System.getProperty("user.home"),".config"):Path.of(config)).resolve("aegis/client.properties");}
  public static Path bundle(){return Path.of(System.getProperty("aegis.home", ".")).toAbsolutePath().normalize();}
  public static Instance lock() throws IOException {AtomicFiles.directory(root());return new Instance(root().resolve("aegis.lock"));}
  public static final class Instance implements AutoCloseable {
    private final FileChannel channel;private final FileLock lock;
    private Instance(Path file)throws IOException{channel=FileChannel.open(file,StandardOpenOption.CREATE,StandardOpenOption.WRITE);FileLock found;
      try{found=channel.tryLock();}catch(OverlappingFileLockException e){channel.close();throw new IOException("АЕГИС уже запущен");}
      if(found==null){channel.close();throw new IOException("АЕГИС уже запущен");}lock=found;
    }
    public void close()throws IOException{lock.release();channel.close();}
  }
}
