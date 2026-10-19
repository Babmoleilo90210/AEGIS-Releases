package org.securemail.client.update;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.maintenance600.RuntimeLease600;
import org.securemail.client.AppPaths;

/** Actual separate JVM fixture. No executable package or production key is substituted. */
public final class UpdaterLeaseFixture600 {
  public static void main(String[] args)throws Exception {
    if(args[0].equals("runtime")||args[0].equals("legacy")){
      try(var held=args[0].equals("legacy")?AppPaths.lock():RuntimeLease600.running()){System.out.println("HELD");System.out.flush();System.in.read();}
      catch(IOException blocked){System.out.println("BLOCKED");System.out.flush();}return;
    }
    Path root=Path.of(args[1]);String mode=args[0];List<Process> children=new ArrayList<>();
    Path target=root.resolve("AEGIS.AppImage"),candidate=root.resolve("candidate"),ack=root.resolve("ack");
    try{
      UpdateInstaller.replace(candidate,target,"startup-token",ack,new UpdateInstaller.Starter(){
        Process owned;
        public boolean start(Path installed)throws Exception {
          owned=startRuntime();children.add(owned);if(!line(owned).equals("HELD"))throw new IOException("Updater kept exclusive lease during startup");
          if(mode.equals("race")){Process independent=startRuntime();children.add(independent);if(!line(independent).equals("HELD"))throw new IOException("Independent Core failed");}
          if(mode.equals("success"))Files.writeString(ack,"startup-token\n");return true;
        }
        public void stop()throws Exception{if(owned!=null){finish(owned);Files.writeString(root.resolve("exact-child-stopped"),"true");}}
      },200,()->{
        Files.writeString(root.resolve("backup-phase"),"exclusive");
        Process probe=startRuntime();children.add(probe);if(!line(probe).equals("BLOCKED"))throw new IOException("Backup was not exclusively guarded");finish(probe);
      },()->{
        if(!Files.exists(root.resolve("exact-child-stopped")))throw new IOException("Rollback before exact child stop");
        Process probe=startRuntime();children.add(probe);if(!line(probe).equals("BLOCKED"))throw new IOException("Rollback was not exclusively guarded");finish(probe);Files.writeString(root.resolve("profile-restored"),"true");
      },AppPaths::lock);
      System.out.println("COMMITTED");
    }catch(UpdateInstaller.InstallFailure failure){System.out.println(failure.rolledBack()?"ROLLED_BACK":"RECOVERY_BLOCKED");}
    catch(IOException blocked){System.out.println("INITIAL_BLOCKED");}
    finally{for(Process child:children)finish(child);System.out.flush();}
  }
  static Process startRuntime()throws IOException{return new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",System.getProperty("java.class.path"),UpdaterLeaseFixture600.class.getName(),"runtime").redirectError(ProcessBuilder.Redirect.INHERIT).start();}
  static String line(Process p)throws Exception{return CompletableFuture.supplyAsync(()->{try{return new BufferedReader(new InputStreamReader(p.getInputStream())).readLine();}catch(IOException e){throw new UncheckedIOException(e);}}).get(5,TimeUnit.SECONDS);}
  static void finish(Process p)throws Exception{if(p.isAlive()){p.getOutputStream().close();if(!p.waitFor(5,TimeUnit.SECONDS)){p.destroy();if(!p.waitFor(2,TimeUnit.SECONDS))p.destroyForcibly().waitFor(5,TimeUnit.SECONDS);}}}
}
