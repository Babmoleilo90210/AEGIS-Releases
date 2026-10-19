package org.securemail.client.maintenance600;

import java.io.IOException;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import org.securemail.client.storage.AtomicFiles;

/** Cross-process installation lease. It contains no account identifier or secret. */
public final class RuntimeLease600 {
  private static final Map<Path,Held> HELD=new HashMap<>();
  private static final String BUSY="Обновление заблокировано: закройте АЕГИС, Письма, Глас, Взор и личную библиотеку.";
  private RuntimeLease600(){}

  /** Keep this shared lease until the component has finished using every bundled runtime file. */
  public static Lease running()throws IOException{return acquire(guardFile(),true);}
  /** Hold exclusively throughout replacement. Never closes or signals another process. */
  public static Lease updating()throws IOException{return acquire(guardFile(),false);}
  public static Path guardFile()throws IOException{return path(System.getProperty("os.name",""),System.getProperty("user.home",""),System.getenv());}

  static Path path(String os,String home,Map<String,String> env)throws IOException{
    String base;String directory;
    if(os.startsWith("Windows")){base=env.get("LOCALAPPDATA");directory="AEGIS-Runtime600-Guard";}
    else if(os.equals("Linux")){base=env.get("XDG_DATA_HOME");if(base==null||base.isBlank())base=Path.of(home,".local","share").toString();directory="aegis-runtime600-guard";}
    else throw new IOException("Обновление: операционная система не поддерживается.");
    if(base==null||base.isBlank())throw new IOException("Не удалось определить личный каталог блокировки обновления.");
    try{Path root=Path.of(base);if(!root.isAbsolute())throw new IOException("Каталог блокировки обновления должен быть абсолютным.");return root.normalize().resolve(directory).resolve("installation.lock");}
    catch(InvalidPathException invalid){throw new IOException("Некорректный каталог блокировки обновления.",invalid);}
  }

  // The single channel per inode is essential on POSIX: closing a second descriptor can
  // release the process's first fcntl lock. Same-JVM probes therefore never open a new FD.
  static synchronized Lease acquire(Path path,boolean shared)throws IOException{
    path=path.toAbsolutePath().normalize();Held existing=HELD.get(path);
    if(existing!=null){if(!shared||!existing.shared)throw new IOException(BUSY);existing.references++;return new Lease(path,existing);}
    Path parent=path.getParent();rejectLinks(parent);
    UserPrincipal owner=parent.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
    if(Files.exists(parent,LinkOption.NOFOLLOW_LINKS)&&!Files.getOwner(parent,LinkOption.NOFOLLOW_LINKS).equals(owner))throw new IOException("Каталог блокировки принадлежит другому пользователю.");
    AtomicFiles.directory(parent);rejectLinks(parent);
    if(!Files.getOwner(parent,LinkOption.NOFOLLOW_LINKS).equals(owner))throw new IOException("Каталог блокировки принадлежит другому пользователю.");
    if(Files.exists(path,LinkOption.NOFOLLOW_LINKS)&&!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Небезопасный файл блокировки обновления.");
    FileChannel channel=FileChannel.open(path,Set.of(StandardOpenOption.CREATE,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),AtomicFiles.attributes(parent));
    try{
      if(!Files.getOwner(path,LinkOption.NOFOLLOW_LINKS).equals(owner)||Files.size(path)!=0)throw new IOException("Небезопасный файл блокировки обновления.");
      if(Files.getFileStore(path).supportsFileAttributeView("unix")&&((Number)Files.getAttribute(path,"unix:nlink",LinkOption.NOFOLLOW_LINKS)).longValue()!=1)throw new IOException("Связанный файл блокировки обновления запрещён.");
      FileLock lock;
      try{lock=channel.tryLock(0,Long.MAX_VALUE,shared);}catch(OverlappingFileLockException busy){throw new IOException(BUSY,busy);}
      if(lock==null)throw new IOException(BUSY);
      if(shared&&!lock.isShared()){lock.release();throw new IOException("Файловая система не поддерживает совместную блокировку компонентов АЕГИС.");}
      Held held=new Held(channel,lock,shared);HELD.put(path,held);return new Lease(path,held);
    }catch(IOException|RuntimeException failure){try{channel.close();}catch(IOException close){failure.addSuppressed(close);}throw failure;}
  }
  private static void rejectLinks(Path path)throws IOException{
    Path cursor=path.getRoot();for(Path segment:path){cursor=cursor.resolve(segment);if(Files.isSymbolicLink(cursor))throw new IOException("Символические ссылки в каталоге блокировки запрещены.");}
  }
  private static final class Held{final FileChannel channel;final FileLock lock;final boolean shared;int references=1;Held(FileChannel c,FileLock l,boolean s){channel=c;lock=l;shared=s;}}
  public static final class Lease implements AutoCloseable{
    private final Path path;private Held held;private Lease(Path p,Held h){path=p;held=h;}
    @Override public void close()throws IOException{
      synchronized(RuntimeLease600.class){if(held==null)return;Held h=held;held=null;if(--h.references!=0)return;
        HELD.remove(path);try{h.lock.release();}finally{h.channel.close();}
      }
    }
  }
}
