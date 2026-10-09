package org.securemail.client.update;

import com.google.gson.*;
import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.*;
import org.securemail.client.storage.AtomicFiles;
import com.sun.jna.platform.win32.*;

/** Detached helper files are copied out of the old installation before its JVM exits. */
public final class UpdateInstaller {
  private UpdateInstaller(){}
  public static Path prepare(Path updates,Path program,Path artifact,byte[] manifest,byte[] signature,SignedManifest release,long client,long launcher,boolean windows)throws Exception {
    Path transaction=updates.resolve("install-"+UUID.randomUUID());AtomicFiles.directory(transaction);Path helper=transaction.resolve("helper");AtomicFiles.directory(helper);
    copyTree(program.resolve("runtime"),helper.resolve("runtime"));copyTree(program.resolve("app"),helper.resolve("app"));
    AtomicFiles.directory(helper.resolve("resources"));Files.copy(program.resolve("resources/aegis.png"),helper.resolve("resources/aegis.png"));
    if(windows)Files.copy(program.resolve("AEGIS-Updater.exe"),helper.resolve("AEGIS-Updater.exe"));
    Path target=windows?Path.of(Objects.requireNonNull(System.getenv("LOCALAPPDATA")),"Programs","AEGIS"):org.securemail.client.storage.UpdateSupport.installedImage();
    Path packageFile=transaction.resolve(windows?"package.zip":"package.AppImage");Files.move(artifact,packageFile,StandardCopyOption.ATOMIC_MOVE);
    AtomicFiles.write(transaction.resolve("manifest.json"),manifest);AtomicFiles.write(transaction.resolve("manifest.sig"),signature);
    JsonObject job=new JsonObject();job.addProperty("schema",1);job.addProperty("version",release.version());job.addProperty("channel",release.channel());job.addProperty("target",target.toAbsolutePath().toString());job.addProperty("oldProgram",program.toAbsolutePath().toString());job.addProperty("clientPid",client);job.addProperty("clientStart",ProcessHandle.of(client).flatMap(p->p.info().startInstant()).orElseThrow().toString());job.addProperty("launcherPid",windows?launcher:0);job.addProperty("launcherStart",windows?ProcessHandle.of(launcher).flatMap(p->p.info().startInstant()).orElseThrow().toString():"");job.addProperty("token",UUID.randomUUID().toString());job.addProperty("windows",windows);
    Path path=transaction.resolve("job.json");AtomicFiles.write(path,JsonData.encode(job));return path;
  }
  static void copyTree(Path source,Path target)throws IOException {
    if(!Files.isDirectory(source,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(source))throw new IOException("Invalid helper source");Files.createDirectories(target);long size=0;
    try(var paths=Files.walk(source)){for(Path p:paths.toList()){if(Files.isSymbolicLink(p))throw new IOException("Helper symlink rejected");Path q=target.resolve(source.relativize(p));if(Files.isDirectory(p))Files.createDirectories(q);else{if((size+=Files.size(p))>768L*1024*1024)throw new IOException("Helper size limit");Files.copy(p,q,StandardCopyOption.COPY_ATTRIBUTES);}}}
  }
  public static void launch(Path job)throws IOException,InterruptedException {
    Path helper=job.getParent().resolve("helper");
    if(AppPaths.windows()) {
      String executable=helper.resolve("AEGIS-Updater.exe").toString(),command=quote(executable)+" --job "+quote(job.toString());
      WinBase.STARTUPINFO start=new WinBase.STARTUPINFO();start.cb=new WinDef.DWORD(start.size());WinBase.PROCESS_INFORMATION process=new WinBase.PROCESS_INFORMATION();
      if(!Kernel32.INSTANCE.CreateProcess(executable,command,null,null,false,new WinDef.DWORD(0x01000000|0x08000000),null,helper.toString(),start,process))throw new IOException("Не удалось запустить updater");
      Kernel32.INSTANCE.CloseHandle(process.hThread);Kernel32.INSTANCE.CloseHandle(process.hProcess);
    }else new ProcessBuilder(helper.resolve("runtime/bin/java").toString(),"-Xmx256m","-XX:+DisableAttachMechanism","-XX:-HeapDumpOnOutOfMemoryError","-cp",helper.resolve("app/*").toString(),"org.securemail.client.update.UpdaterMain","--job",job.toString()).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);while(System.nanoTime()<end){if(Files.isRegularFile(job.getParent().resolve("ready")))return;if(Files.exists(job.getParent().resolve("failed")))throw new IOException("Updater отклонил установку");Thread.sleep(100);}throw new IOException("Updater не подтвердил готовность");
  }
  private static String quote(String value)throws IOException {if(value.contains("\"")||value.contains("\r")||value.contains("\n"))throw new IOException("Invalid updater path");return "\""+value+"\"";}
  public static void confirmStartup()throws IOException {
    String value=System.getenv("AEGIS_UPDATE_JOB");if(value==null)return;Path path=Path.of(value).toAbsolutePath().normalize();Path allowed=AppPaths.root().resolve("updates").toAbsolutePath().normalize();
    if(!path.startsWith(allowed)||!path.getFileName().toString().equals("job.json"))throw new IOException("Invalid update confirmation path");
    JsonObject job=JsonData.object(AtomicFiles.read(path,16384),16384);String token=JsonData.text(job,"token",36);if(!token.matches("[a-f0-9-]{36}"))throw new IOException("Invalid confirmation token");
    String current=JsonData.text(job,"version",100);if(!current.equals(SignedManifest.CURRENT))throw new IOException("Installed version mismatch");AtomicFiles.write(path.getParent().resolve("confirmed"),(token+"\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
  }
  /** Same-filesystem rename and startup acknowledgement, with rollback on every failure. */
  static void replace(Path candidate,Path target,String token,Path confirmation,Starter starter)throws Exception {
    replace(candidate,target,token,confirmation,starter,TimeUnit.MINUTES.toMillis(10));
  }
  static void replace(Path candidate,Path target,String token,Path confirmation,Starter starter,long timeoutMillis)throws Exception {
    Path old=target.resolveSibling(target.getFileName()+".old"),next=target.resolveSibling(target.getFileName()+".new");
    if(Files.exists(old)||Files.exists(next)||Files.isSymbolicLink(target))throw new IOException("Previous update needs recovery");
    if(Files.isDirectory(candidate))copyTree(candidate,next);else{Files.copy(candidate,next);if(!next.toFile().setExecutable(true,true))throw new IOException("Executable permission denied");try(var ch=FileChannel.open(next,StandardOpenOption.WRITE)){ch.force(true);}}
    boolean backed=false,replaced=false;
    try {
      if(Files.exists(target)){Files.move(target,old,StandardCopyOption.ATOMIC_MOVE);backed=true;}
      Files.move(next,target,StandardCopyOption.ATOMIC_MOVE);replaced=true;AtomicFiles.syncDirectory(target.getParent());
      if(!starter.start(target))throw new IOException("New client failed to start");
      long end=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeoutMillis);boolean accepted=false;
      while(System.nanoTime()<end){if(Files.isRegularFile(confirmation)&&new String(AtomicFiles.read(confirmation,100),java.nio.charset.StandardCharsets.US_ASCII).trim().equals(token)){accepted=true;break;}Thread.sleep(100);}
      if(!accepted)throw new IOException("No startup acknowledgement");
      // The acknowledged new application is now committed. Failed cleanup must not
      // replace it with an old directory which may already be partly removed.
      if(backed)try{deleteTree(old);}catch(IOException cleanup){/* Retain remaining .old for explicit recovery/cleanup. */}AtomicFiles.syncDirectory(target.getParent());
    }catch(Exception failure){
      try{starter.stop();}catch(Exception stopping){failure.addSuppressed(stopping);throw failure;}
      // A process with locked Windows binaries prevents deleting them: retain both copies and report recovery rather than destroying .old.
      if(replaced)try{deleteTree(target);}catch(IOException locked){failure.addSuppressed(locked);}
      if(backed&&!Files.exists(target))Files.move(old,target,StandardCopyOption.ATOMIC_MOVE);
      throw failure;
    }finally{if(Files.exists(next))deleteTree(next);}
  }
  @FunctionalInterface interface Starter{boolean start(Path installed)throws Exception;default void stop()throws Exception{}}
  static void deleteTree(Path root)throws IOException {if(Files.isSymbolicLink(root))throw new IOException("Symlink cleanup rejected");if(Files.isDirectory(root)){try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}else Files.deleteIfExists(root);}
}
