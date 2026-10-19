package org.securemail.client.maintenance600;
import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import org.securemail.client.*;
import org.securemail.client.storage.*;

/** Installer backup helper, copied runtime outside the installed bundle. Never signals processes. */
public final class MaintenanceMain600 {
  private MaintenanceMain600(){}
  public static void main(String[] args){
    try{
      if(args.length!=1||!args[0].equals("backup"))throw new IOException("Некорректная команда обслуживания.");
      // The native installer retains the exclusive RuntimeLease throughout this subprocess
      // and replacement. These existing locks additionally reject pre-6 clients/components.
      try(var legacy=AppPaths.lock()){
        Path core=AppPaths.root().resolve("core600");
        if(Files.isSymbolicLink(core))throw new IOException("Небезопасный каталог профиля.");
        if(Files.isDirectory(core,LinkOption.NOFOLLOW_LINKS)){
          try(var channel=FileChannel.open(core.resolve("core.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
            FileLock lock;try{lock=channel.tryLock();}catch(OverlappingFileLockException busy){throw new IOException("Закройте главное окно АЕГИС.",busy);}
            if(lock==null)throw new IOException("Закройте главное окно АЕГИС.");try(lock){backup();}
          }
        }else backup();
      }
      System.out.println("Защищённая резервная копия профиля создана и проверена.");
    }catch(Exception failure){System.err.println("Обслуживание остановлено. Закройте компоненты АЕГИС и проверьте доступ к личному хранилищу. Данные сохранены.");System.exit(1);}
  }
  private static void backup()throws IOException{ClientConfig config=ClientConfig.load(AppPaths.config());Path snapshot=UpdateSupport.backup(config);ProfileSnapshot.verify(snapshot,config);}
}
