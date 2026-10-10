package org.securemail.client.storage;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import org.securemail.client.*;

/** User-invoked update support. No network downloads, process-name kills or plaintext backups. */
public final class UpdateSupport {
  private UpdateSupport(){}
  public static Path backup(ClientConfig config)throws IOException {
    return ProfileSnapshot.create(config,AppPaths.root().resolve("backups"));
  }
  public static boolean scheduleWindowsRollback()throws IOException {
    if(!AppPaths.windows())return false;Path program=AppPaths.bundle(),previous=program.resolveSibling(program.getFileName()+".rollback-1.1.1");
    Path expected=Path.of(System.getenv("LOCALAPPDATA"),"Programs","AEGIS").toAbsolutePath();
    if(!program.equals(expected)||!Files.isRegularFile(previous.resolve("AEGIS.exe")))return false;
    Path temp=AppPaths.root().resolve("tmp");AtomicFiles.directory(temp);Path helper=temp.resolve("rollback-"+UUID.randomUUID()+".exe");Files.copy(program.resolve("AEGIS-Maintenance.exe"),helper);
    long launcher=ProcessHandle.current().parent().orElseThrow(()->new IOException("Launcher missing")).pid();
    Process prepared=new ProcessBuilder(helper.toString(),"--prepare-rollback",program.toString(),Long.toString(ProcessHandle.current().pid()),Long.toString(launcher)).start();
    try{if(!prepared.waitFor(5,java.util.concurrent.TimeUnit.SECONDS)||prepared.exitValue()!=0)throw new IOException("Не удалось подготовить откат программы");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("Подготовка отката прервана",e);}return true;
  }
  public static Path installedImage(){return Path.of(System.getProperty("user.home"),".local/opt/aegis/AEGIS.AppImage");}
  public static Path downloadedImage(){String image=System.getenv("APPIMAGE");return image==null?null:Path.of(image).toAbsolutePath();}
  public static Optional<Path> oldImage()throws IOException {
    Path installed=installedImage(),current=downloadedImage();
    if(current==null||!Files.isRegularFile(current)||current.equals(installed))return Optional.empty();
    if(Files.isRegularFile(installed,LinkOption.NOFOLLOW_LINKS))return Optional.of(installed);
    Path directory=installed.getParent();if(Files.isDirectory(directory))try(var paths=Files.list(directory)){
      List<Path> matches=paths.filter(p->p.getFileName().toString().matches("AEGIS-0\\.3\\.0.*\\.AppImage")&&Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)).toList();if(matches.size()==1)return Optional.of(matches.getFirst());
    }return Optional.empty();
  }
  /** Proves ownership from the inherited APPIMAGE path, not a global Java/Tor process name. */
  public static void closeOldLinux(Path old)throws IOException,InterruptedException {
    List<ProcessHandle> roots=new ArrayList<>();
    try(var processes=ProcessHandle.allProcesses()){
      for(ProcessHandle process:processes.toList()){
        if(process.pid()==ProcessHandle.current().pid())continue;
        String command=process.info().commandLine().orElse("");if(!command.contains("org.securemail.ui.Launcher"))continue;
        Path env=Path.of("/proc",Long.toString(process.pid()),"environ");
        try{byte[] bytes=AtomicFiles.read(env,65536);boolean owns=Arrays.asList(new String(bytes,StandardCharsets.UTF_8).split("\u0000")).contains("APPIMAGE="+old.toAbsolutePath());Arrays.fill(bytes,(byte)0);if(owns)roots.add(process);}catch(IOException ignored){}
      }
    }
    for(ProcessHandle process:roots){
      List<LinuxOwnedProcess> children=new ArrayList<>();
      try(var pinned=LinuxOwnedProcess.pin(process)){
        for(ProcessHandle child:process.descendants().toList())try{children.add(LinuxOwnedProcess.pin(child));}catch(IOException vanished){if(child.isAlive())throw vanished;}
        pinned.signal(15);if(!pinned.await(10000))throw new IOException("Закройте старый АЕГИС и повторите обновление");
        for(var child:children){child.signal(15);if(!child.await(3000)){child.signal(9);if(!child.await(3000))throw new IOException("Прежний Tor ещё завершает работу");}}
      }finally{children.forEach(LinuxOwnedProcess::close);}
    }

  }
  /** Called after password migration has succeeded. Same-filesystem atomic replacement. */
  public static void installLinux(Path downloaded,Path old,Path desktop,Path icon)throws IOException {
    Path installed=installedImage();AtomicFiles.directory(installed.getParent());
    Path staged=installed.resolveSibling(".AEGIS-1.1.1-"+UUID.randomUUID()+".AppImage"),rollback=installed.resolveSibling("AEGIS.pre-1.1.1.AppImage");
    Path applications=desktop.getParent();AtomicFiles.directory(applications);Path iconTarget=Path.of(System.getProperty("user.home"),".local/share/icons/hicolor/256x256/apps/aegis.png");AtomicFiles.directory(iconTarget.getParent());
    byte[] previousDesktop=Files.exists(desktop)?AtomicFiles.read(desktop,16384):null,previousIcon=Files.exists(iconTarget)?AtomicFiles.read(iconTarget,1024*1024):null;
    boolean replaced=false;
    try{
      Files.copy(downloaded,staged);if(!staged.toFile().setExecutable(true,true))throw new IOException("Не удалось разрешить запуск AppImage");try(var ch=FileChannel.open(staged,StandardOpenOption.WRITE)){ch.force(true);}
      if(Files.exists(installed)){Files.copy(installed,rollback,StandardCopyOption.REPLACE_EXISTING);try(var ch=FileChannel.open(rollback,StandardOpenOption.WRITE)){ch.force(true);}}
      String path=installed.toAbsolutePath().toString();if(path.chars().anyMatch(c->c=='\n'||c=='\r'))throw new IOException("Недопустимый путь ярлыка");
      Files.move(staged,installed,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);replaced=true;AtomicFiles.syncDirectory(installed.getParent());
      String quoted=path.replace("\\","\\\\").replace("\"","\\\"").replace("`","\\`").replace("$","\\$").replace("%","%%");
      String entry="[Desktop Entry]\nType=Application\nName=АЕГИС\nExec=\""+quoted+"\"\nIcon=aegis\nTerminal=false\nCategories=Network;Email;\nX-AEGIS-Version=1.1.1\n";
      AtomicFiles.write(desktop,entry.getBytes(StandardCharsets.UTF_8));AtomicFiles.write(iconTarget,AtomicFiles.read(icon,1024*1024));
      // Retain the previous AppImage for an explicit rollback. No user profile directory is removed.
    }catch(IOException failure){
      if(replaced){if(Files.exists(rollback))Files.move(rollback,installed,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);else Files.deleteIfExists(installed);}
      if(previousDesktop!=null)AtomicFiles.write(desktop,previousDesktop);else Files.deleteIfExists(desktop);
      if(previousIcon!=null)AtomicFiles.write(iconTarget,previousIcon);else Files.deleteIfExists(iconTarget);throw failure;
    }finally{Files.deleteIfExists(staged);}
  }
}
