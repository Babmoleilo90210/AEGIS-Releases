package org.securemail.client.maintenance600;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class RuntimeLease600Test {
  @TempDir Path temp;
  @Test void pathsDoNotDependOnPrivateProfileOrInstallation()throws Exception{
    assertEquals(Path.of("/home/test/.local/share/aegis-runtime600-guard/installation.lock"),RuntimeLease600.path("Linux","/home/test",Map.of()));
    assertEquals(temp.resolve("AEGIS-Runtime600-Guard/installation.lock"),RuntimeLease600.path("Windows 11","ignored",Map.of("LOCALAPPDATA",temp.toString())));
    assertThrows(IOException.class,()->RuntimeLease600.path("Linux","/home/test",Map.of("XDG_DATA_HOME","relative")));
    assertThrows(IOException.class,()->RuntimeLease600.path("Windows 11","/home/test",Map.of()));
    assertThrows(IOException.class,()->RuntimeLease600.path("unsupported","/home/test",Map.of()));
  }
  @Test void sharedReferencesReleaseOnlyAfterLastClose()throws Exception{
    Path path=temp.resolve("guard/installation.lock");var first=RuntimeLease600.acquire(path,true);var second=RuntimeLease600.acquire(path,true);
    try{first.close();first.close();assertThrows(IOException.class,()->RuntimeLease600.acquire(path,false));assertEquals("BLOCKED",oneShot(path,"exclusive"));}
    finally{second.close();}
    try(var exclusive=RuntimeLease600.acquire(path,false)){assertThrows(IOException.class,()->RuntimeLease600.acquire(path,true));assertEquals("BLOCKED",oneShot(path,"shared"));}
    try(var shared=RuntimeLease600.acquire(path,true)){assertEquals(0,Files.size(path));}
  }
  @Test void actualIndependentProcessesShareAndPreventReplacement()throws Exception{
    Path path=temp.resolve("guard/installation.lock");Process first=start(path,"shared"),second=null;
    try{assertEquals("HELD",line(first));second=start(path,"shared");assertEquals("HELD",line(second));assertThrows(IOException.class,()->RuntimeLease600.acquire(path,false));
      stop(first);assertThrows(IOException.class,()->RuntimeLease600.acquire(path,false));stop(second);second=null;
      try(var replacement=RuntimeLease600.acquire(path,false)){assertEquals("BLOCKED",oneShot(path,"shared"));}
    }finally{stop(first);if(second!=null)stop(second);}
  }
  @Test void actualExclusiveProcessBlocksBothRuntimeAndOtherInstaller()throws Exception{
    Path path=temp.resolve("guard/installation.lock");Process exclusive=start(path,"exclusive");
    try{assertEquals("HELD",line(exclusive));assertThrows(IOException.class,()->RuntimeLease600.acquire(path,true));assertThrows(IOException.class,()->RuntimeLease600.acquire(path,false));}
    finally{stop(exclusive);}
    try(var runtime=RuntimeLease600.acquire(path,true)){assertNotNull(runtime);}
  }
  @Test void sameJvmDeniedProbesDoNotReleaseKernelLock()throws Exception{
    Path path=temp.resolve("guard/installation.lock");try(var shared=RuntimeLease600.acquire(path,true)){
      for(int i=0;i<10;i++){assertThrows(IOException.class,()->RuntimeLease600.acquire(path,false));try(var extra=RuntimeLease600.acquire(path,true)){}}
      assertEquals("BLOCKED",oneShot(path,"exclusive"));
    }
  }
  @Test void rejectsLinkedAncestorAndLinkedLockWithoutChangingTarget()throws Exception{
    Path real=temp.resolve("real");Files.createDirectories(real);Path target=real.resolve("secret");Files.writeString(target,"keep");
    try{Files.createSymbolicLink(temp.resolve("linked"),real);Files.createSymbolicLink(real.resolve("installation.lock"),target);}
    catch(UnsupportedOperationException|FileSystemException unsupported){Assumptions.abort("Host cannot create symlinks: "+unsupported.getClass().getSimpleName());}
    assertThrows(IOException.class,()->RuntimeLease600.acquire(temp.resolve("linked/guard/installation.lock"),true));
    assertThrows(IOException.class,()->RuntimeLease600.acquire(real.resolve("installation.lock"),true));assertEquals("keep",Files.readString(target));
  }
  @Test void rejectsUnexpectedExistingContentAndHardlinks()throws Exception{
    Path path=temp.resolve("guard/installation.lock");Files.createDirectories(path.getParent());Files.writeString(path,"unexpected");assertThrows(IOException.class,()->RuntimeLease600.acquire(path,true));assertEquals("unexpected",Files.readString(path));
    Files.delete(path);Files.createFile(path);try{Files.createLink(temp.resolve("other-link"),path);}catch(UnsupportedOperationException|FileSystemException unsupported){Assumptions.abort("Host cannot create hardlinks");}
    assertThrows(IOException.class,()->RuntimeLease600.acquire(path,false));
  }
  private static String classpath(){try{return String.join(File.pathSeparator,new LinkedHashSet<>(List.of(Path.of(RuntimeLeaseFixture600.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString(),Path.of(RuntimeLease600.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString())));}catch(Exception error){throw new IllegalStateException(error);}}
  private static Process start(Path path,String mode)throws IOException{return new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",classpath(),RuntimeLeaseFixture600.class.getName(),path.toString(),mode).redirectError(ProcessBuilder.Redirect.INHERIT).start();}
  private static String line(Process p)throws Exception{return CompletableFuture.supplyAsync(()->{try{return new BufferedReader(new InputStreamReader(p.getInputStream())).readLine();}catch(IOException e){throw new UncheckedIOException(e);}}).get(5,TimeUnit.SECONDS);}
  private static String oneShot(Path p,String mode)throws Exception{Process child=start(p,mode);try{String result=line(child);stop(child);return result;}finally{stop(child);}}
  private static void stop(Process p)throws Exception{if(p.isAlive()){p.getOutputStream().close();if(!p.waitFor(5,TimeUnit.SECONDS)){p.destroy();if(!p.waitFor(1,TimeUnit.SECONDS))p.destroyForcibly().waitFor(5,TimeUnit.SECONDS);}}}
}
