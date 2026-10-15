package org.securemail.client.safeweb;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import static org.junit.jupiter.api.Assertions.*;

/** Ownership/controller tests with real harmless shell children. These synthetic
 * fixtures prove neither Tor Browser execution nor native sandbox acceptance.
 */
@EnabledOnOs(OS.LINUX)
class SafeWebProcessTest {
  @TempDir Path temporary;
  private Path fixture()throws Exception{
    Path root=temporary.resolve("browser");SafeWebSessions storage=new SafeWebSessions(root);Path source=storage.newInstallationPath();
    Files.createDirectories(source.resolve("Browser/TorBrowser/Data/Browser/profile.default"));Files.writeString(source.resolve("Browser/start-tor-browser"),"unit fixture, not a vendor browser");Files.writeString(source.resolve("Browser/firefox"),"unit fixture");
    storage.registerVerifiedBundle(source,"a".repeat(64));return root;
  }
  private static final class Child implements SafeWebProcess.Browser {
    final Process process;final AtomicBoolean failClose=new AtomicBoolean(),leaveAlive=new AtomicBoolean();
    Child()throws IOException{process=new ProcessBuilder("/bin/sh","-c","IFS= read -r ignored").redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();}
    public Process process(){return process;}
    public boolean running(){return process.isAlive();}
    public String status(){return "unit fixture child only";}
    public void close()throws IOException{
      if(failClose.get())throw new IOException("controlled close failure");if(leaveAlive.get())return;
      process.getOutputStream().close();
      try{if(!process.waitFor(2,TimeUnit.SECONDS)){process.destroyForcibly();if(!process.waitFor(2,TimeUnit.SECONDS))throw new IOException("fixture child still alive");}}
      catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IOException(interrupted);}
    }
    void terminate()throws Exception{process.destroy();assertTrue(process.waitFor(2,TimeUnit.SECONDS));}
  }
  private static void until(BooleanSupplier condition)throws Exception{
    long limit=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);while(!condition.getAsBoolean()&&System.nanoTime()<limit)Thread.sleep(20);assertTrue(condition.getAsBoolean(),"controller state did not settle");
  }
  @Test void repeatedOpenCannotCreateAnotherProcess()throws Exception{
    Path root=fixture();AtomicInteger launches=new AtomicInteger();AtomicReference<Child> child=new AtomicReference<>();
    try(SafeWebProcess manager=new SafeWebProcess(root,(s,u,p)->{launches.incrementAndGet();Child owned=new Child();child.set(owned);return owned;})){
      manager.initialize();manager.open(SafeWebSessions.Mode.PERSISTENT,"https://example.org/");assertTrue(manager.running());
      assertThrows(IOException.class,()->manager.open(SafeWebSessions.Mode.TEMPORARY,"https://example.org/second"));assertEquals(1,launches.get());assertTrue(child.get().process.isAlive());
    }
    assertFalse(child.get().process.isAlive());
  }
  @Test void failedCloseRetainsProcessSessionAndManagerLockForRetry()throws Exception{
    Path root=fixture();AtomicReference<Child> child=new AtomicReference<>();AtomicReference<Path> bundle=new AtomicReference<>();
    SafeWebProcess manager=new SafeWebProcess(root,(s,u,p)->{bundle.set(s.bundle());Child owned=new Child();child.set(owned);return owned;});
    AtomicInteger foreignLaunches=new AtomicInteger();
    try(SafeWebProcess foreign=new SafeWebProcess(root,(s,u,p)->{foreignLaunches.incrementAndGet();return new Child();})){
      manager.open(SafeWebSessions.Mode.TEMPORARY,"https://example.org/");child.get().failClose.set(true);
      assertThrows(IOException.class,manager::close);assertTrue(manager.running());assertEquals(SafeWebSessions.Mode.TEMPORARY,manager.snapshot().mode());assertTrue(Files.isDirectory(bundle.get()));assertTrue(child.get().process.isAlive());
      assertThrows(IOException.class,()->foreign.open(SafeWebSessions.Mode.TEMPORARY,"https://example.org/"));assertEquals(0,foreignLaunches.get());assertTrue(Files.isDirectory(bundle.get()));
      child.get().failClose.set(false);manager.close();assertFalse(child.get().process.isAlive());assertFalse(Files.exists(bundle.get()));
      foreign.open(SafeWebSessions.Mode.TEMPORARY,"https://example.org/");assertEquals(1,foreignLaunches.get());
    }finally{child.get().failClose.set(false);manager.close();}
  }
  @Test void backendCannotReleaseOwnershipWhileItsProcessRemainsAlive()throws Exception{
    AtomicReference<Child> child=new AtomicReference<>();SafeWebProcess manager=new SafeWebProcess(fixture(),(s,u,p)->{Child owned=new Child();child.set(owned);return owned;});
    try{manager.open(SafeWebSessions.Mode.PERSISTENT,"https://example.org/");child.get().leaveAlive.set(true);assertThrows(IOException.class,manager::close);assertTrue(manager.running());}
    finally{child.get().leaveAlive.set(false);manager.close();}
  }
  @Test void naturalExitCleansTemporaryProfileButKeepsPersistentDownloads()throws Exception{
    Path root=fixture();AtomicReference<Child> child=new AtomicReference<>();AtomicReference<SafeWebSessions.Session> selected=new AtomicReference<>();
    try(SafeWebProcess manager=new SafeWebProcess(root,(s,u,p)->{selected.set(s);Child owned=new Child();child.set(owned);return owned;})){
      manager.open(SafeWebSessions.Mode.PERSISTENT,"https://example.org/");Path normal=selected.get().bundle(),control=selected.get().control();Path download=normal.resolve("aegis-downloads/keep.txt");Files.createDirectory(download.getParent());Files.writeString(download,"synthetic download");
      child.get().terminate();until(()->!manager.running()&&manager.snapshot().mode()==null);assertTrue(Files.exists(normal));assertFalse(Files.exists(control));assertEquals(List.of(download),manager.downloads());
      manager.open(SafeWebSessions.Mode.TEMPORARY,"https://example.org/");Path ephemeral=selected.get().bundle();child.get().terminate();until(()->!manager.running()&&manager.snapshot().mode()==null);assertFalse(Files.exists(ephemeral));assertEquals(List.of(download),manager.downloads());
    }
  }
  @Test void failedLaunchCleansOnlyPreparedTemporarySessionAndAllowsRetry()throws Exception{
    Path root=fixture();AtomicInteger attempts=new AtomicInteger();AtomicReference<Path> failed=new AtomicReference<>();
    try(SafeWebProcess manager=new SafeWebProcess(root,(s,u,p)->{if(attempts.incrementAndGet()==1){failed.set(s.bundle());throw new IOException("controlled launcher failure before process creation");}return new Child();})){
      assertThrows(IOException.class,()->manager.open(SafeWebSessions.Mode.TEMPORARY,"https://example.org/"));assertFalse(Files.exists(failed.get()));assertFalse(manager.running());assertNull(manager.snapshot().mode());
      manager.open(SafeWebSessions.Mode.PERSISTENT,"https://example.org/");assertTrue(manager.running());assertEquals(2,attempts.get());
    }
  }
  @Test void uiSnapshotAndListenerDoNotWaitForSlowLaunchOrBlockingCallback()throws Exception{
    Path root=fixture();CountDownLatch entering=new CountDownLatch(1),continueLaunch=new CountDownLatch(1),callbackEntered=new CountDownLatch(1),continueCallback=new CountDownLatch(1);
    SafeWebProcess manager=new SafeWebProcess(root,(s,u,p)->{entering.countDown();try{if(!continueLaunch.await(5,TimeUnit.SECONDS))throw new IOException("test launch barrier timed out");}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IOException(interrupted);}return new Child();});
    ExecutorService worker=Executors.newSingleThreadExecutor();
    try{
      Future<?> opening=worker.submit(()->{try{manager.open(SafeWebSessions.Mode.PERSISTENT,"https://example.org/");}catch(IOException error){throw new CompletionException(error);}});assertTrue(entering.await(5,TimeUnit.SECONDS));
      assertTimeoutPreemptively(Duration.ofSeconds(1),()->{assertNotNull(manager.snapshot());assertFalse(manager.running());assertTrue(manager.busy());assertEquals(SafeWebSessions.Mode.PERSISTENT,manager.snapshot().mode());manager.listener(s->{callbackEntered.countDown();try{continueCallback.await(5,TimeUnit.SECONDS);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}});});
      assertTrue(callbackEntered.await(2,TimeUnit.SECONDS));continueLaunch.countDown();opening.get(3,TimeUnit.SECONDS);assertTrue(manager.running());
      Future<?> closing=worker.submit(()->{try{manager.close();}catch(IOException error){throw new CompletionException(error);}});closing.get(3,TimeUnit.SECONDS);assertFalse(manager.running());assertFalse(manager.busy());
    }finally{continueLaunch.countDown();continueCallback.countDown();manager.close();worker.shutdownNow();}
  }
  @Test void privatePathChecksResolveMissingChildrenOfSymlinkAliases()throws Exception{
    Path root=fixture(),alias=temporary.resolve("alias");Files.createSymbolicLink(alias,root);
    try(SafeWebProcess manager=new SafeWebProcess(root,(s,u,p)->new Child())){
      assertThrows(IOException.class,()->manager.privatePaths(List.of(alias.resolve("not-created/profile"))));
      manager.privatePaths(List.of(temporary.resolve("private-messenger/not-created")));
    }
  }
}
