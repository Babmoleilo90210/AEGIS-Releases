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
  /** Core6 only. A child Mail JVM does not have the required fixed native launcher parent. */
  public static boolean canWindowsRollback600()throws IOException{return currentRollback600().isPresent();}
  public static boolean scheduleWindowsRollback600()throws IOException {
    Optional<WindowsRollbackPlan600> ready=currentRollback600();if(ready.isEmpty())return false;var plan=ready.orElseThrow();Path helper=stageRollbackHelper600(plan);
    Process prepared=new ProcessBuilder(rollbackCommand600(plan,helper)).directory(helper.getParent().toFile()).start();prepared.getOutputStream().close();
    try{if(!prepared.waitFor(5,java.util.concurrent.TimeUnit.SECONDS)||prepared.exitValue()!=0)throw new IOException("Не удалось подготовить откат программы. Данные сохранены.");}
    catch(InterruptedException interrupted){Thread.currentThread().interrupt();prepared.destroy();throw new IOException("Подготовка отката прервана. Данные сохранены.",interrupted);}finally{if(prepared.isAlive())prepared.destroy();}
    return true;
  }
  private static Optional<WindowsRollbackPlan600> currentRollback600()throws IOException {
    if(!AppPaths.windows())return Optional.empty();String local=System.getenv("LOCALAPPDATA");if(local==null||local.isBlank())return Optional.empty();ProcessHandle current=ProcessHandle.current(),parent=current.parent().orElse(null);if(parent==null||!parent.isAlive())return Optional.empty();
    String executable=current.info().command().orElse(""),launcher=parent.info().command().orElse("");if(executable.isBlank()||launcher.isBlank())return Optional.empty();
    return rollbackPlan600(AppPaths.bundle(),Path.of(local),AppPaths.root(),Path.of(executable),current.pid(),Path.of(launcher),parent.pid());
  }
  record WindowsRollbackPlan600(Path program,Path previous,Path source,Path temporary,String helperHash,long clientPid,long launcherPid){}
  /** Filesystem/image contract seam; tests never run a fake Windows executable. */
  static Optional<WindowsRollbackPlan600> rollbackPlan600(Path program,Path local,Path profile,Path current,long clientPid,Path launcher,long launcherPid)throws IOException {
    if(program==null||local==null||profile==null||current==null||launcher==null||clientPid<1||launcherPid<1||clientPid==launcherPid)return Optional.empty();
    for(Path path:List.of(program,local,profile,current,launcher))if(!path.isAbsolute()||path.toString().codePoints().anyMatch(Character::isISOControl))return Optional.empty();
    Path expected=local.resolve("Programs/AEGIS").toAbsolutePath().normalize();program=program.toAbsolutePath().normalize();if(!program.equals(expected))return Optional.empty();
    Path java=program.resolve("runtime/bin/javaw.exe"),parent=program.resolve("AEGIS.exe");if(!current.toAbsolutePath().normalize().equals(java)||!launcher.toAbsolutePath().normalize().equals(parent))return Optional.empty();
    Path previous=program.resolveSibling(program.getFileName()+".rollback-6.0.0"),source=program.resolve("AEGIS-Maintenance.exe"),temporary=profile.toAbsolutePath().normalize().resolve("tmp");
    if(temporary.startsWith(program)||program.startsWith(temporary)||temporary.startsWith(previous)||previous.startsWith(temporary))throw new IOException("Каталог подготовки отката должен находиться вне программы. Данные сохранены.");
    for(Path path:List.of(program,previous,source,temporary,java,parent))rollbackPath600(path);
    if(!Files.isRegularFile(previous.resolve("AEGIS.exe"),LinkOption.NOFOLLOW_LINKS))return Optional.empty();rollbackPath600(previous.resolve("AEGIS.exe"));
    if(!Files.isRegularFile(java,LinkOption.NOFOLLOW_LINKS)||!Files.isRegularFile(parent,LinkOption.NOFOLLOW_LINKS))return Optional.empty();
    return Optional.of(new WindowsRollbackPlan600(program,previous,source,temporary,helperHash600(program,source),clientPid,launcherPid));
  }
  private static void rollbackPath600(Path path)throws IOException {
    for(Path cursor=path;cursor!=null;cursor=cursor.getParent())if(Files.exists(cursor,LinkOption.NOFOLLOW_LINKS)){
      if(Files.isSymbolicLink(cursor)||Files.readAttributes(cursor,java.nio.file.attribute.BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS).isOther())throw new IOException("Ссылки в путях отката запрещены. Данные сохранены.");
      if(AppPaths.windows())try{int flags=com.sun.jna.platform.win32.Kernel32.INSTANCE.GetFileAttributes(cursor.toString());if(flags==-1||(flags&0x400)!=0)throw new IOException("Небезопасный путь отката. Данные сохранены.");}catch(RuntimeException|LinkageError unavailable){throw new IOException("Не удалось проверить путь отката. Данные сохранены.",unavailable);}
    }
  }
  private static String helperHash600(Path program,Path source)throws IOException {
    Path inventory=program.resolve("maintenance600.json");rollbackPath600(inventory);
    try{var json=org.securemail.client.community.CommunityJson.parse(AtomicFiles.read(inventory,4096));
      if(!json.keySet().equals(Set.of("schema","sha256","sourceCommit"))||!json.get("schema").isJsonPrimitive()||!json.getAsJsonPrimitive("schema").isNumber()||json.get("schema").getAsBigDecimal().intValueExact()!=1||!json.get("sha256").isJsonPrimitive()||!json.getAsJsonPrimitive("sha256").isString()||!json.get("sourceCommit").isJsonPrimitive()||!json.getAsJsonPrimitive("sourceCommit").isString()||!json.get("sourceCommit").getAsString().matches("[a-f0-9]{40}"))throw new IOException("Некорректный состав средства отката.");String expected=json.get("sha256").getAsString();
      if(!expected.matches("[a-f0-9]{64}")||!Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS)||Files.size(source)>32*1024*1024||!java.security.MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),org.securemail.client.ecosystem.ComponentInstallation.sha256(source).getBytes(StandardCharsets.US_ASCII)))throw new IOException("Средство отката повреждено. Требуется проверенная переустановка.");return expected;
    }catch(RuntimeException invalid){throw new IOException("Средство отката повреждено. Требуется проверенная переустановка.",invalid);}
  }
  static Path stageRollbackHelper600(WindowsRollbackPlan600 plan)throws IOException {
    rollbackPath600(plan.temporary());rollbackPath600(plan.source());if(!helperHash600(plan.program(),plan.source()).equals(plan.helperHash()))throw new IOException("Средство отката изменилось. Данные сохранены.");
    AtomicFiles.directory(plan.temporary());Path directory=Files.createTempDirectory(plan.temporary(),"rollback600-");AtomicFiles.directory(directory);rollbackPath600(directory);Path helper=directory.resolve("AEGIS-Maintenance.exe");
    try(var source=java.nio.channels.FileChannel.open(plan.source(),StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS);var target=java.nio.channels.FileChannel.open(helper,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),AtomicFiles.attributes(directory))){
      if(source.size()>32*1024*1024)throw new IOException("Средство отката слишком большое.");ByteBuffer block=ByteBuffer.allocate(65536);long total=0;while(source.read(block)!=-1){block.flip();total+=block.remaining();if(total>32*1024*1024)throw new IOException("Средство отката слишком большое.");while(block.hasRemaining())target.write(block);block.clear();}target.force(true);
    }catch(IOException failed){Files.deleteIfExists(helper);throw failed;}
    if(!org.securemail.client.ecosystem.ComponentInstallation.sha256(helper).equals(plan.helperHash())){Files.deleteIfExists(helper);throw new IOException("Копия средства отката не прошла проверку. Данные сохранены.");}AtomicFiles.syncDirectory(directory);return helper;
  }
  static List<String> rollbackCommand600(WindowsRollbackPlan600 plan,Path helper){return List.of(helper.toString(),"--prepare-rollback",plan.program().toString(),Long.toString(plan.clientPid()),Long.toString(plan.launcherPid()));}
  public static boolean scheduleWindowsRollback()throws IOException {
    if(!AppPaths.windows())return false;Path program=AppPaths.bundle(),previous=program.resolveSibling(program.getFileName()+".rollback-1.1.5");
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
    Path staged=installed.resolveSibling(".AEGIS-1.1.5-"+UUID.randomUUID()+".AppImage"),rollback=installed.resolveSibling("AEGIS.pre-1.1.5.AppImage");
    Path applications=desktop.getParent();AtomicFiles.directory(applications);Path iconTarget=Path.of(System.getProperty("user.home"),".local/share/icons/hicolor/256x256/apps/aegis.png");AtomicFiles.directory(iconTarget.getParent());
    byte[] previousDesktop=Files.exists(desktop)?AtomicFiles.read(desktop,16384):null,previousIcon=Files.exists(iconTarget)?AtomicFiles.read(iconTarget,1024*1024):null;
    boolean replaced=false;
    try{
      Files.copy(downloaded,staged);if(!staged.toFile().setExecutable(true,true))throw new IOException("Не удалось разрешить запуск AppImage");try(var ch=FileChannel.open(staged,StandardOpenOption.WRITE)){ch.force(true);}
      if(Files.exists(installed)){Files.copy(installed,rollback,StandardCopyOption.REPLACE_EXISTING);try(var ch=FileChannel.open(rollback,StandardOpenOption.WRITE)){ch.force(true);}}
      String path=installed.toAbsolutePath().toString();if(path.chars().anyMatch(c->c=='\n'||c=='\r'))throw new IOException("Недопустимый путь ярлыка");
      Files.move(staged,installed,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);replaced=true;AtomicFiles.syncDirectory(installed.getParent());
      String quoted=path.replace("\\","\\\\").replace("\"","\\\"").replace("`","\\`").replace("$","\\$").replace("%","%%");
      String entry="[Desktop Entry]\nType=Application\nName=АЕГИС\nExec=\""+quoted+"\"\nIcon=aegis\nTerminal=false\nCategories=Network;Email;\nX-AEGIS-Version=1.1.5\n";
      AtomicFiles.write(desktop,entry.getBytes(StandardCharsets.UTF_8));AtomicFiles.write(iconTarget,AtomicFiles.read(icon,1024*1024));
      // Retain the previous AppImage for an explicit rollback. No user profile directory is removed.
    }catch(IOException failure){
      if(replaced){if(Files.exists(rollback))Files.move(rollback,installed,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);else Files.deleteIfExists(installed);}
      if(previousDesktop!=null)AtomicFiles.write(desktop,previousDesktop);else Files.deleteIfExists(desktop);
      if(previousIcon!=null)AtomicFiles.write(iconTarget,previousIcon);else Files.deleteIfExists(iconTarget);throw failure;
    }finally{Files.deleteIfExists(staged);}
  }
}
