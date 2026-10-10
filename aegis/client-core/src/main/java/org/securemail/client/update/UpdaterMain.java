package org.securemail.client.update;

import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.AppPaths;
import org.securemail.client.storage.AtomicFiles;

/** Internal detached updater: re-verifies pinned Ed25519, size, hash and package sanity. */
public final class UpdaterMain {
  private UpdaterMain(){}
  public static void main(String[] args){Path dir=null;try {
    if(args.length!=2||!args[0].equals("--job"))throw new IOException("Invalid updater arguments");
    Path job=Path.of(args[1]).toAbsolutePath().normalize();Path allowed=AppPaths.root().resolve("updates").toAbsolutePath().normalize();
    if(!job.startsWith(allowed)||!job.getFileName().toString().equals("job.json")||Files.isSymbolicLink(job)||Files.isSymbolicLink(job.getParent()))throw new IOException("Invalid updater transaction");dir=job.getParent();
    JsonObject o=JsonData.object(AtomicFiles.read(job,16384),16384);JsonData.fields(o,"schema","version","channel","target","oldProgram","clientPid","clientStart","launcherPid","launcherStart","token","windows");
    if(JsonData.number(o,"schema")!=1||JsonData.bool(o,"windows")!=AppPaths.windows())throw new IOException("Wrong updater platform");
    String channel=JsonData.text(o,"channel",8),token=JsonData.text(o,"token",36);if(!token.matches("[a-f0-9-]{36}"))throw new IOException("Invalid transaction token");
    SignedManifest release=SignedManifest.verify(AtomicFiles.read(dir.resolve("manifest.json"),SignedManifest.MAX_BYTES),AtomicFiles.read(dir.resolve("manifest.sig"),64),channel,SignedManifest.CURRENT,new UpdateStateStore(AppPaths.root()).highest(channel));
    if(!release.version().equals(JsonData.text(o,"version",100))||!release.newerThan(SignedManifest.CURRENT))throw new IOException("Update version mismatch");
    Path expected=AppPaths.windows()?Path.of(Objects.requireNonNull(System.getenv("LOCALAPPDATA")),"Programs","AEGIS"):org.securemail.client.storage.UpdateSupport.installedImage();Path target=Path.of(JsonData.text(o,"target",4000)).toAbsolutePath().normalize();if(!target.equals(expected.toAbsolutePath().normalize()))throw new IOException("Updater target rejected");
    Path artifact=dir.resolve(AppPaths.windows()?"package.zip":"package.AppImage");UpdateService.verifyFile(artifact,release.clientAsset(AppPaths.windows()));PackageSanity.check(artifact,release.clientAsset(AppPaths.windows()),release.version());
    long pid=JsonData.number(o,"clientPid"),launcher=JsonData.number(o,"launcherPid");Instant birth=Instant.parse(JsonData.text(o,"clientStart",60));
    ProcessHandle client=pin(pid,birth);ProcessHandle parent=launcher==0?null:pin(launcher,Instant.parse(JsonData.text(o,"launcherStart",60)));
    AtomicFiles.write(dir.resolve("ready"),new byte[]{1});waitExit(client);if(parent!=null)waitExit(parent);
    var previousConfig=org.securemail.client.ClientConfig.load(AppPaths.config());Path backup;
    try(var appLock=AppPaths.lock()){
      backup=org.securemail.client.storage.ProfileSnapshot.create(previousConfig,AppPaths.root().resolve("backups"));
      org.securemail.client.storage.ProfileSnapshot.verify(backup,previousConfig);
      AtomicFiles.write(dir.resolve("profile-backup"),backup.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    AtomicFiles.directory(target.getParent());Path candidate=artifact;
    if(AppPaths.windows()){candidate=dir.resolve("payload");PackageSanity.extractWindows(artifact,candidate);Path uninstall=target.resolve("Uninstall.exe");if(Files.isRegularFile(uninstall,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(uninstall))Files.copy(uninstall,candidate.resolve("Uninstall.exe"));}
    Path confirmation=dir.resolve("confirmed");Path finalDir=dir;List<Process> started=new ArrayList<>();
    try{UpdateInstaller.replace(candidate,target,token,confirmation,new UpdateInstaller.Starter(){public boolean start(Path installed)throws Exception{
      Path command=AppPaths.windows()?installed.resolve("AEGIS.exe"):installed;ProcessBuilder builder=new ProcessBuilder(command.toString());builder.environment().put("AEGIS_UPDATE_JOB",job.toString());builder.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);Process process=builder.start();started.add(process);return process.isAlive();
    }public void stop()throws Exception{stopOwned(started);}});}
    catch(Exception failure){stopOwned(started);if(Files.exists(target.resolveSibling(target.getFileName()+".old"))){Path old=target.resolveSibling(target.getFileName()+".old");if(Files.exists(target))UpdateInstaller.deleteTree(target);Files.move(old,target,StandardCopyOption.ATOMIC_MOVE);}
      try(var appLock=AppPaths.lock()){org.securemail.client.storage.ProfileSnapshot.restore(backup,previousConfig);}
      AtomicFiles.write(dir.resolve("rolled-back"),new byte[]{1});
      if(Files.exists(target)){new ProcessBuilder((AppPaths.windows()?target.resolve("AEGIS.exe"):target).toString()).start();}throw failure;}
    // Metadata/shortcut cleanup follows the commit and cannot roll back a working client.
    try{AtomicFiles.write(finalDir.resolve("installed"),release.version().getBytes(java.nio.charset.StandardCharsets.US_ASCII));if(AppPaths.windows()){String registry="Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AEGIS";if(com.sun.jna.platform.win32.Advapi32Util.registryKeyExists(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER,registry))com.sun.jna.platform.win32.Advapi32Util.registrySetStringValue(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER,registry,"DisplayVersion",release.version());}else integrateLinux(target,finalDir.resolve("helper/resources/aegis.png"),release.version());}catch(Exception|LinkageError optionalMetadata){/* Binary replacement and startup confirmation already succeeded. */}
  }catch(Exception failure){if(dir!=null)try{AtomicFiles.write(dir.resolve("failed"),"Установка не завершена. Предыдущая версия сохранена.\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));}catch(IOException ignored){}System.exit(1);}}
  private static ProcessHandle pin(long pid,Instant start)throws IOException{if(pid<=0||pid==ProcessHandle.current().pid())throw new IOException("Invalid old client PID");ProcessHandle p=ProcessHandle.of(pid).orElseThrow(()->new IOException("Old client disappeared"));if(!p.info().startInstant().orElseThrow().equals(start))throw new IOException("PID identity changed");return p;}
  private static void waitExit(ProcessHandle p)throws Exception{if(p.isAlive())p.onExit().get(90,TimeUnit.SECONDS);}
  private static void stopOwned(List<Process> processes)throws Exception{
    var handles=new ArrayList<ProcessHandle>();for(var process:processes){handles.addAll(process.descendants().toList());handles.add(process.toHandle());}
    for(var handle:handles)if(handle.isAlive())handle.destroy();long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
    for(var handle:handles)if(handle.isAlive())try{handle.onExit().get(Math.max(1,end-System.nanoTime()),TimeUnit.NANOSECONDS);}catch(java.util.concurrent.TimeoutException timeout){handle.destroyForcibly();}
    for(var handle:handles)if(handle.isAlive()){handle.destroyForcibly();handle.onExit().get(5,TimeUnit.SECONDS);}
  }
  private static void integrateLinux(Path installed,Path icon,String version)throws IOException {
    Path desktop=Path.of(System.getProperty("user.home"),".local/share/applications/aegis.desktop"),image=Path.of(System.getProperty("user.home"),".local/share/icons/hicolor/256x256/apps/aegis.png");AtomicFiles.directory(desktop.getParent());AtomicFiles.directory(image.getParent());String path=installed.toAbsolutePath().toString();if(path.contains("\n")||path.contains("\r"))throw new IOException("Invalid desktop path");String quoted=path.replace("\\","\\\\").replace("\"","\\\"").replace("`","\\`").replace("$","\\$").replace("%","%%");AtomicFiles.write(desktop,("[Desktop Entry]\nType=Application\nName=АЕГИС\nExec=\""+quoted+"\"\nIcon=aegis\nTerminal=false\nCategories=Network;Email;\nX-AEGIS-Version="+version+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));AtomicFiles.write(image,AtomicFiles.read(icon,1024*1024));
  }
}
