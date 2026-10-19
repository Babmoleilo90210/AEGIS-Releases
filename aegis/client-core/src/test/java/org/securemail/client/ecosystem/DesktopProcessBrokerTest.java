package org.securemail.client.ecosystem;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.*;
import java.util.jar.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class DesktopProcessBrokerTest {
  @TempDir Path root;
  private ComponentInstallation installation;
  @BeforeEach void fixtureJar()throws Exception {
    Path jar=root.resolve("installed components.jar");Set<String> copied=new HashSet<>();
    try(var out=new JarOutputStream(Files.newOutputStream(jar))) {
      addPackage(out,copied,DesktopProcessBroker.class,"org/securemail/client/ecosystem/");
      addPackage(out,copied,DetachedChild.class,"org/securemail/client/ecosystem/");
      addPackage(out,copied,org.securemail.ui.ecosystem.ComponentEntrypoint.class,"org/securemail/ui/ecosystem/");
    }
    Path java=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java");
    installation=new ComponentInstallation(java,ComponentInstallation.sha256(java),Map.of(jar,ComponentInstallation.sha256(jar)));
  }
  private static void addPackage(JarOutputStream out,Set<String> copied,Class<?> type,String prefix)throws Exception {
    Path classes=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());
    try(var walk=Files.walk(classes.resolve(prefix))){for(Path file:walk.filter(Files::isRegularFile).toList()){
      String name=classes.relativize(file).toString().replace('\\','/');if(copied.add(name)){out.putNextEntry(new JarEntry(name));Files.copy(file,out);out.closeEntry();}
    }}
  }
  private SessionAuthority authority(String mode,AtomicBoolean valid) {
    return new SessionAuthority(){
      public ComponentLease authorize(ComponentId component){return new ComponentLease(component,"existing-account-id",7,("fixture|"+mode+"|"+root.resolve(component+"-queue")).getBytes(StandardCharsets.UTF_8));}
      public void validate(ComponentLease lease)throws IOException{if(!valid.get())throw new IOException("revoked");}
    };
  }
  @Test void actualSeparateJvmsAuthenticateDeduplicateLockAndFlushBeforeClosing()throws Exception {
    try(var broker=new DesktopProcessBroker(installation,authority("normal",new AtomicBoolean(true)),ignored->{})) {
      var mail=broker.launch(ComponentId.MAIL);assertNotEquals(ProcessHandle.current().pid(),mail.pid());assertTrue(broker.isRunning(ComponentId.MAIL));var exited=broker.termination(ComponentId.MAIL).toCompletableFuture();
      assertTrue(installation.command(ComponentId.MAIL).stream().noneMatch(arg->arg.contains("fixture|")||arg.contains("existing-account-id")));
      assertEquals(mail.pid(),broker.launch(ComponentId.MAIL).pid());
      await(()->broker.status(ComponentId.MAIL).orElseThrow().notifications()==101,3000);
      broker.lock();await(()->Files.exists(root.resolve("MAIL-queue.locked")),3000);
      assertThrows(IOException.class,()->broker.launch(ComponentId.GLAS));
      broker.stop(ComponentId.MAIL);assertEquals(DesktopProcessBroker.State.STOPPED,broker.status(ComponentId.MAIL).orElseThrow().state());
      assertTrue(broker.status(ComponentId.MAIL).orElseThrow().queueFlushConfirmed());assertEquals("flushed",Files.readString(root.resolve("MAIL-queue")));
      assertNotNull(exited.get(3,TimeUnit.SECONDS));assertFalse(broker.isRunning(ComponentId.MAIL));
    }
  }
  @Test void coreCloseStopsOwnedChildrenButLeavesUnrelatedDetachedProcess()throws Exception {
    Process detached=new ProcessBuilder(installation.javaExecutable().toString(),"-cp",installation.classpath().keySet().iterator().next().toString(),DetachedChild.class.getName()).start();
    try {
      long mail,glas;java.util.concurrent.CompletableFuture<Integer> mailExit,glasExit;
      try(var broker=new DesktopProcessBroker(installation,authority("normal",new AtomicBoolean(true)),ignored->{})) {
        mail=broker.launch(ComponentId.MAIL).pid();glas=broker.launch(ComponentId.GLAS).pid();assertNotEquals(mail,glas);mailExit=broker.termination(ComponentId.MAIL).toCompletableFuture();glasExit=broker.termination(ComponentId.GLAS).toCompletableFuture();
      }
      assertNotNull(mailExit.get(3,TimeUnit.SECONDS));assertNotNull(glasExit.get(3,TimeUnit.SECONDS));
      assertEquals("flushed",Files.readString(root.resolve("MAIL-queue")));assertEquals("flushed",Files.readString(root.resolve("GLAS-queue")));assertTrue(detached.isAlive());
    } finally {detached.destroyForcibly();detached.waitFor(3,TimeUnit.SECONDS);}
  }
  @Test void revokedGenerationClosesActualChildAndPersistsItsQueue()throws Exception {
    AtomicBoolean valid=new AtomicBoolean(true);
    try(var broker=new DesktopProcessBroker(installation,authority("normal",valid),ignored->{})) {
      broker.launch(ComponentId.MAIL);var exit=broker.termination(ComponentId.MAIL).toCompletableFuture();valid.set(false);
      await(()->broker.status(ComponentId.MAIL).orElseThrow().state()==DesktopProcessBroker.State.FAILED,8000);
      assertNotNull(exit.get(3,TimeUnit.SECONDS));
      assertEquals(DesktopProcessBroker.State.FAILED,broker.status(ComponentId.MAIL).orElseThrow().state());
      // Socket EOF invokes child persistence even though server authorization is already revoked.
      assertEquals("flushed",Files.readString(root.resolve("MAIL-queue")));
    }
  }
  @Test void actualChildCrashIsDetectedAndDoesNotClaimSavedQueue()throws Exception {
    try(var broker=new DesktopProcessBroker(installation,authority("crash",new AtomicBoolean(true)),ignored->{})) {
      broker.launch(ComponentId.MAIL);await(()->broker.status(ComponentId.MAIL).orElseThrow().state()==DesktopProcessBroker.State.FAILED,3000);
      assertFalse(broker.status(ComponentId.MAIL).orElseThrow().queueFlushConfirmed());
    }
  }
  @Test void unresponsiveChildIsKilledWithoutInventingQueueConfirmation()throws Exception {
    try(var broker=new DesktopProcessBroker(installation,authority("silent",new AtomicBoolean(true)),ignored->{})) {
      broker.launch(ComponentId.MAIL);var exit=broker.termination(ComponentId.MAIL).toCompletableFuture();await(()->exit.isDone()&&broker.status(ComponentId.MAIL).orElseThrow().state()==DesktopProcessBroker.State.FAILED,15000);
      assertEquals(DesktopProcessBroker.State.FAILED,broker.status(ComponentId.MAIL).orElseThrow().state());assertFalse(broker.status(ComponentId.MAIL).orElseThrow().queueFlushConfirmed());
    }
  }
  @Test void installedJarMutationIsRejectedBeforeAnyProcessStarts()throws Exception {
    Path jar=installation.classpath().keySet().iterator().next();Files.writeString(jar,"tampered");
    try(var broker=new DesktopProcessBroker(installation,authority("normal",new AtomicBoolean(true)),ignored->{})) {
      assertThrows(IOException.class,()->broker.launch(ComponentId.MAIL));assertFalse(broker.isRunning(ComponentId.MAIL));assertThrows(IOException.class,()->broker.termination(ComponentId.MAIL));
    }
  }
  @Test void directChildInvocationWithNoPipeCannotOpenAnApplication()throws Exception {
    Process process=new ProcessBuilder(installation.command(ComponentId.MAIL)).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();process.getOutputStream().close();
    assertTrue(process.waitFor(3,TimeUnit.SECONDS));assertNotEquals(0,process.exitValue());assertFalse(Files.exists(root.resolve("MAIL-queue")));
  }
  @Test void lockedGlasAllowsOnlyExplicitLimitedCallDecision()throws Exception {
    try(var broker=new DesktopProcessBroker(installation,authority("normal",new AtomicBoolean(true)),ignored->{})) {
      broker.launch(ComponentId.GLAS);assertThrows(IOException.class,()->broker.answerLockedCall(true));broker.lock();await(()->Files.exists(root.resolve("GLAS-queue.locked")),3000);
      broker.answerLockedCall(false);await(()->Files.exists(root.resolve("GLAS-queue.call")),3000);assertEquals("rejected",Files.readString(root.resolve("GLAS-queue.call")));
    }
  }
  @Test void closingCoreDuringAnotherComponentsRemoteAuthorizationDoesNotBlockMailFlush()throws Exception{
    var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);SessionAuthority base=authority("normal",new AtomicBoolean(true));SessionAuthority delayed=new SessionAuthority(){
      public ComponentLease authorize(ComponentId component)throws IOException{if(component==ComponentId.GLAS){entered.countDown();try{if(!release.await(20,TimeUnit.SECONDS))throw new IOException("test deadline");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}}return base.authorize(component);}
      public void validate(ComponentLease lease)throws IOException{base.validate(lease);}
    };
    try(var work=java.util.concurrent.Executors.newSingleThreadExecutor();var broker=new DesktopProcessBroker(installation,delayed,ignored->{})){
      broker.launch(ComponentId.MAIL);var exit=broker.termination(ComponentId.MAIL).toCompletableFuture();var pending=work.submit(()->broker.launch(ComponentId.GLAS));assertTrue(entered.await(3,TimeUnit.SECONDS));
      try{assertTimeoutPreemptively(java.time.Duration.ofSeconds(4),broker::close);assertNotNull(exit.get(2,TimeUnit.SECONDS));assertEquals("flushed",Files.readString(root.resolve("MAIL-queue")));}finally{release.countDown();}
      assertThrows(java.util.concurrent.ExecutionException.class,()->pending.get(3,TimeUnit.SECONDS));assertFalse(broker.isRunning(ComponentId.GLAS));assertFalse(Files.exists(root.resolve("GLAS-queue")));
    }
  }
  @Test void slowAuthorizationCheckCannotStarveActualChildHeartbeats()throws Exception{
    var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);var count=new AtomicInteger();SessionAuthority base=authority("normal",new AtomicBoolean(true));SessionAuthority delayed=new SessionAuthority(){
      public ComponentLease authorize(ComponentId component)throws IOException{return base.authorize(component);}
      public void validate(ComponentLease lease)throws IOException{if(count.incrementAndGet()>2){entered.countDown();try{if(!release.await(15,TimeUnit.SECONDS))throw new IOException("test deadline");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}}}
    };
    try(var broker=new DesktopProcessBroker(installation,delayed,ignored->{})){
      broker.launch(ComponentId.MAIL);assertTrue(entered.await(4,TimeUnit.SECONDS));try{Thread.sleep(7100);assertTrue(broker.isRunning(ComponentId.MAIL));assertEquals(DesktopProcessBroker.State.RUNNING,broker.status(ComponentId.MAIL).orElseThrow().state());}finally{release.countDown();}
      broker.stop(ComponentId.MAIL);assertTrue(broker.status(ComponentId.MAIL).orElseThrow().queueFlushConfirmed());
    }
  }
  @Test void concurrentSameComponentLaunchesCannotCreateTwoProcesses()throws Exception{
    var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);var authorizations=new AtomicInteger();SessionAuthority base=authority("normal",new AtomicBoolean(true));SessionAuthority delayed=new SessionAuthority(){
      public ComponentLease authorize(ComponentId component)throws IOException{authorizations.incrementAndGet();entered.countDown();try{release.await(10,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}return base.authorize(component);}
      public void validate(ComponentLease lease)throws IOException{base.validate(lease);}
    };
    try(var work=java.util.concurrent.Executors.newSingleThreadExecutor();var broker=new DesktopProcessBroker(installation,delayed,ignored->{})){
      var first=work.submit(()->broker.launch(ComponentId.MAIL));assertTrue(entered.await(3,TimeUnit.SECONDS));try{assertThrows(IOException.class,()->broker.launch(ComponentId.MAIL));assertEquals(1,authorizations.get());}finally{release.countDown();}assertTrue(first.get(5,TimeUnit.SECONDS).pid()>0);assertTrue(broker.isRunning(ComponentId.MAIL));
    }
  }
  @Test void closingCoreCancelsAnActuallyStartedChildBeforeReadyAndReleasesItsKernelLock()throws Exception{
    try(var work=java.util.concurrent.Executors.newSingleThreadExecutor();var broker=new DesktopProcessBroker(installation,authority("no-ready",new AtomicBoolean(true)),ignored->{})){
      var pending=work.submit(()->broker.launch(ComponentId.MAIL));Path receipt=root.resolve("MAIL-queue.started");await(()->Files.exists(receipt),4000);
      assertFalse(kernelLockAvailable(receipt));assertTimeoutPreemptively(java.time.Duration.ofSeconds(4),broker::close);assertThrows(java.util.concurrent.ExecutionException.class,()->pending.get(3,TimeUnit.SECONDS));await(()->kernelLockAvailable(receipt),3000);assertFalse(Files.exists(root.resolve("MAIL-queue")));assertFalse(broker.status(ComponentId.MAIL).orElseThrow().queueFlushConfirmed());
    }
  }
  private static boolean kernelLockAvailable(Path file){try(var channel=java.nio.channels.FileChannel.open(file,StandardOpenOption.WRITE);var acquired=channel.tryLock()){return acquired!=null;}catch(IOException|java.nio.channels.OverlappingFileLockException busy){return false;}}
  @Test void inheritedProfileIsExplicitOnlyWhenTheParentActuallyOverridesIt(){String old=System.getProperty("aegis.profile");try{System.clearProperty("aegis.profile");assertTrue(installation.command(ComponentId.MAIL).stream().noneMatch(arg->arg.startsWith("-Daegis.profile=")));System.setProperty("aegis.profile",root.resolve("profile").toString());assertTrue(installation.command(ComponentId.MAIL).stream().anyMatch(arg->arg.equals("-Daegis.profile="+root.resolve("profile"))));}finally{if(old==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",old);}}
  private static void await(java.util.function.BooleanSupplier condition,long millis)throws Exception {
    long end=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(millis);while(!condition.getAsBoolean() && System.nanoTime()-end<0)Thread.sleep(20);assertTrue(condition.getAsBoolean(),"Timed out waiting for an actual child transition");
  }
}
