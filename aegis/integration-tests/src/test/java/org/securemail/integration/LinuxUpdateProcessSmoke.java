package org.securemail.integration;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.storage.UpdateSupport;
/** Actual released 0.3 JavaFX/Tor child; verifies update shutdown and ownership isolation. */
public final class LinuxUpdateProcessSmoke {
 public static void main(String[] args)throws Exception{
  Path bundle=Path.of(args[0]).toAbsolutePath(),monocle=Path.of(args[1]).toAbsolutePath(),root=Files.createTempDirectory("aegis-update-with-spaces "),old=root.resolve("AEGIS-0.3.0.AppImage");Files.writeString(old,"ownership test path");
  Path unrelated=root.resolve("unrelated");Files.createDirectories(unrelated);Path rc=unrelated.resolve("torrc");Files.writeString(rc,"");
  ProcessBuilder foreignBuilder=new ProcessBuilder(bundle.resolve("tor/tor").toString(),"--defaults-torrc",rc.toString(),"-f",rc.toString(),"--DataDirectory",unrelated.toString(),"--SocksPort","0","--ControlPort","0","--DisableNetwork","1").redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);foreignBuilder.environment().put("LD_LIBRARY_PATH",bundle.resolve("tor").toString());Process foreign=foreignBuilder.start();
  String cp=bundle.resolve("app/*")+java.io.File.pathSeparator+monocle;Path log=root.resolve("old-gui.log");
  ProcessBuilder start=new ProcessBuilder(bundle.resolve("runtime/bin/java").toString(),"-Daegis.profile="+root.resolve("profile"),"-Daegis.home="+bundle,"-Dglass.platform=Monocle","-Dmonocle.platform=Headless","-Dheadless.geometry=1280x900-32","-Dprism.order=sw","-cp",cp,"org.securemail.ui.Launcher").redirectOutput(log.toFile()).redirectError(log.toFile());start.environment().put("APPIMAGE",old.toString());Process client=start.start();
  try{
   boolean tor=false;long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(20);while(System.nanoTime()<until&&client.isAlive()){tor=Files.exists(root.resolve("profile/logs/connection.log"))&&Files.readString(root.resolve("profile/logs/connection.log")).contains("TOR_START");if(tor)break;Thread.sleep(100);}if(!tor)throw new AssertionError("Old JavaFX/Tor not started: "+Files.readString(log));
   Thread.sleep(500);List<ProcessHandle> children=client.descendants().toList();UpdateSupport.closeOldLinux(old);if(client.isAlive()||children.stream().anyMatch(ProcessHandle::isAlive))throw new AssertionError("Owned old process remains");if(!foreign.isAlive())throw new AssertionError("Foreign Tor was stopped");
   for(int port:new int[]{19050,19051})try(var s=new java.net.ServerSocket()){s.bind(new java.net.InetSocketAddress("127.0.0.1",port));}
   System.out.println("Linux updater process test passed: actual released 0.3.0 JavaFX client/Tor, verified APPIMAGE ownership, owned children stopped, unrelated Tor survives, ports released");
  }finally{if(client.isAlive())client.destroy();foreign.destroy();if(!foreign.waitFor(5,TimeUnit.SECONDS))foreign.destroyForcibly();}
 }
}
