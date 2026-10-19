package org.securemail.client.safeweb600;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.AppPaths;

class VzorIndependent600Test {
  @TempDir Path temp;
  @Test void bootstrapCarriesOnlyValidatedUrlAndSingleUseNonce()throws Exception{
    byte[] nonce=VzorBootstrap600.freshNonce();var bytes=new ByteArrayOutputStream();VzorBootstrap600.write(bytes,nonce,"https://example.org/path?a=1");
    try(var boot=VzorBootstrap600.read(new ByteArrayInputStream(bytes.toByteArray()),Duration.ofSeconds(1))){
      assertEquals("https://example.org/path?a=1",boot.address());var ack=new ByteArrayOutputStream();boot.acknowledge(ack,VzorBootstrap600.Reply.READY);
      var parsed=VzorBootstrap600.readAcknowledgement(new ByteArrayInputStream(ack.toByteArray()),nonce,ProcessHandle.current().pid(),Duration.ofSeconds(1));assertEquals(VzorBootstrap600.Reply.READY,parsed.reply());
      assertThrows(IOException.class,()->boot.acknowledge(new ByteArrayOutputStream(),VzorBootstrap600.Reply.READY));
    }
  }
  @Test void rejectsTruncationExtraBytesInvalidUtf8AndBadMagic()throws Exception{
    var bytes=new ByteArrayOutputStream();VzorBootstrap600.write(bytes,VzorBootstrap600.freshNonce(),"https://example.org/");byte[] valid=bytes.toByteArray();
    for(byte[] wrong:List.of(Arrays.copyOf(valid,10),Arrays.copyOf(valid,valid.length-1),Arrays.copyOf(valid,valid.length+1))){assertThrows(IOException.class,()->VzorBootstrap600.read(new ByteArrayInputStream(wrong),Duration.ofSeconds(1)));}
    byte[] magic=valid.clone();magic[0]^=1;assertThrows(IOException.class,()->VzorBootstrap600.read(new ByteArrayInputStream(magic),Duration.ofSeconds(1)));
    byte[] utf=valid.clone();utf[utf.length-1]=(byte)0xff;assertThrows(IOException.class,()->VzorBootstrap600.read(new ByteArrayInputStream(utf),Duration.ofSeconds(1)));
  }
  @Test void rejectsCommandsLocalAddressesAndAccountBearingUrls()throws Exception{
    for(String url:List.of("file:///etc/passwd","javascript:alert(1)","https://localhost/","https://127.0.0.1/","https://user:password@example.org/","--profile=/tmp/ordinary-firefox","https://example.org/\ncommand"))assertThrows(IllegalArgumentException.class,()->VzorBootstrap600.write(new ByteArrayOutputStream(),VzorBootstrap600.freshNonce(),url));
  }
  @Test void acknowledgementRejectsWrongPidChangedStatusAndReplayedNonce()throws Exception{
    byte[] nonce=VzorBootstrap600.freshNonce();var input=new ByteArrayOutputStream();VzorBootstrap600.write(input,nonce,"https://example.org/");var ack=new ByteArrayOutputStream();
    try(var boot=VzorBootstrap600.read(new ByteArrayInputStream(input.toByteArray()),Duration.ofSeconds(1))){boot.acknowledge(ack,VzorBootstrap600.Reply.READY);}
    byte[] valid=ack.toByteArray();assertThrows(IOException.class,()->VzorBootstrap600.readAcknowledgement(new ByteArrayInputStream(valid),nonce,ProcessHandle.current().pid()+1,Duration.ofSeconds(1)));
    assertThrows(IOException.class,()->VzorBootstrap600.readAcknowledgement(new ByteArrayInputStream(valid),VzorBootstrap600.freshNonce(),ProcessHandle.current().pid(),Duration.ofSeconds(1)));
    byte[] changed=valid.clone();changed[5]=(byte)VzorBootstrap600.Reply.ALREADY_RUNNING.ordinal();assertThrows(IOException.class,()->VzorBootstrap600.readAcknowledgement(new ByteArrayInputStream(changed),nonce,ProcessHandle.current().pid(),Duration.ofSeconds(1)));
  }
  @Test void bootstrapTimeoutDoesNotCreateManagerState()throws Exception{
    try(var pipe=new PipedInputStream();var writer=new PipedOutputStream(pipe)){
      long began=System.nanoTime();var error=assertThrows(VzorFailure600.class,()->VzorBootstrap600.read(pipe,Duration.ofMillis(100)));assertEquals(VzorFailure600.Code.STARTUP_TIMEOUT,error.code());assertTrue(Duration.ofNanos(System.nanoTime()-began).compareTo(Duration.ofSeconds(2))<0);
    }
  }
  @Test void environmentNeverPassesAccountSecretsProxiesOrJavaInjection(){
    var result=VzorLaunch600.filteredEnvironment(Map.of("HOME","/home/test","DISPLAY",":0","AEGIS_PASSWORD","secret","AEGIS_TOKEN","secret","HTTPS_PROXY","http://secret@proxy","JAVA_TOOL_OPTIONS","-Dattack=1","JDK_JAVA_OPTIONS","-javaagent:/tmp/attack","_JAVA_OPTIONS","-Daegis.profile=/tmp/private","LD_PRELOAD","/tmp/hook.so"));
    assertEquals(Map.of("HOME","/home/test","DISPLAY",":0"),result);
  }
  @Test void stateLockIsExclusiveAndReopensOnlyAfterOwnedClose()throws Exception{
    Path root=temp.resolve("manager"),browser=temp.resolve("browser");
    assertFalse(VzorState600.lockHeld(root));
    try(var state=VzorState600.open(root,browser)){assertTrue(VzorState600.lockHeld(root));assertEquals(root,state.root());var busy=assertThrows(VzorFailure600.class,()->VzorState600.open(root,browser));assertEquals(VzorFailure600.Code.ALREADY_RUNNING,busy.code());}
    assertFalse(VzorState600.lockHeld(root));
    try(var reopened=VzorState600.open(root,browser)){assertEquals(browser,reopened.browser());}
  }
  @Test void sameJvmProbesCannotReleaseKernelLeaseOwnedByAnotherDescriptor()throws Exception{
    Path root=temp.resolve("owner"),stop=temp.resolve("stop");
    try(var state=VzorState600.open(root,temp.resolve("web"))){
      assertTrue(VzorState600.lockHeld(root));assertThrows(VzorFailure600.class,()->VzorState600.open(root,temp.resolve("second-web")));
      var other=VzorLaunch600.launch(command("manager",root.toString(),stop.toString()),"https://example.org/",Duration.ofSeconds(5),true);
      assertEquals(VzorLaunch600.Status.ALREADY_RUNNING,other.status(),"Actual second JVM must still see the kernel-held lease");
    }finally{Files.writeString(stop,"stop");}
  }
  @Test void neverAdoptsUnknownOrOverlappingProfileDirectory()throws Exception{
    Path root=temp.resolve("private-core");Files.createDirectories(root);Files.writeString(root.resolve("identity.key"),"PRIVATE-FIXTURE");
    assertThrows(IOException.class,()->VzorState600.open(root,temp.resolve("web")));assertEquals("PRIVATE-FIXTURE",Files.readString(root.resolve("identity.key")));
    assertThrows(IOException.class,()->VzorState600.open(temp.resolve("web/manager"),temp.resolve("web")));
  }
  @Test void rejectsLinkedStateAndPreservesExistingBrowserProfile()throws Exception{
    Path browser=temp.resolve("browser");Files.createDirectories(browser);Files.writeString(browser.resolve("existing-profile-fixture"),"keep");
    try(var ignored=VzorState600.open(temp.resolve("manager"),browser)){assertEquals("keep",Files.readString(browser.resolve("existing-profile-fixture")));}
    try{Files.createSymbolicLink(temp.resolve("linked"),browser);}catch(UnsupportedOperationException|IOException unsupported){return;}
    assertThrows(IOException.class,()->VzorState600.open(temp.resolve("linked/manager"),temp.resolve("other-browser")));
  }
  @Test void defaultRootsAreSeparateAndRetainBrowserOnlyFiveProfile(){
    var linux=VzorState600.roots("Linux","/home/test",Map.of());assertEquals(Path.of("/home/test/.local/share/aegis-vzor-manager"),linux.get(0));assertEquals(Path.of("/home/test/.local/share/aegis-safeweb"),linux.get(1));
    var windows=VzorState600.roots("Windows 11","unused",Map.of("LOCALAPPDATA",temp.toString()));assertEquals(temp.resolve("AEGIS-Vzor-Manager"),windows.get(0));assertEquals(temp.resolve("AEGIS-SafeWeb"),windows.get(1));
  }
  @Test void reservesDistinctLoopbackPortsAndCreatesNoMailConfiguration()throws Exception{
    try(var ports=VzorState600.reservePorts()){
      assertEquals(4,Set.of(ports.socks(),ports.control(),ports.update(),ports.unusedService()).size());var config=ports.config(temp);
      assertEquals("",config.relayOnionAddress());assertEquals(temp.resolve("tor/control_auth_cookie"),config.torCookiePath());assertEquals(temp.resolve("unused-no-mail-storage"),config.storagePath());
      assertThrows(IOException.class,()->{try(var socket=new ServerSocket()){socket.bind(new InetSocketAddress("127.0.0.1",ports.socks()));}});
    }
  }
  @Test void detachedManagerSurvivesItsLaunchingCoreJvmExit()throws Exception{
    Path root=temp.resolve("detached"),stop=temp.resolve("stop"),pid=temp.resolve("manager-pid");Process parent=new ProcessBuilder(command("core",classpath(),root.toString(),stop.toString(),pid.toString())).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    try{
      assertTrue(parent.waitFor(10,TimeUnit.SECONDS));assertEquals(0,parent.exitValue());assertTrue(Long.parseLong(Files.readString(pid))>0);assertTrue(VzorState600.lockHeld(root),"Actual manager-JVM lease must survive Core-JVM termination");
      var busy=assertThrows(VzorFailure600.class,()->VzorState600.open(root,temp.resolve("other-web")));assertEquals(VzorFailure600.Code.ALREADY_RUNNING,busy.code());
      assertFalse(AutoCloseable.class.isAssignableFrom(VzorLaunch600.Detached.class));
      Files.writeString(stop,"stop");awaitFile(Path.of(stop+"-released"));
      try(var ignored=VzorState600.open(root,temp.resolve("other-web"))){assertEquals("released",Files.readString(Path.of(stop+"-released")));}
    }finally{if(parent.isAlive())parent.destroyForcibly();Files.writeString(stop,"stop");}
  }
  @Test void repeatedManagerLaunchDoesNotAdoptOrStopTheExistingManager()throws Exception{
    Path root=temp.resolve("one"),stop=temp.resolve("stop");var first=VzorLaunch600.launch(command("manager",root.toString(),stop.toString()),"https://example.org/",Duration.ofSeconds(5),true);
    try{var second=VzorLaunch600.launch(command("manager",root.toString(),stop.toString()),"https://example.org/other",Duration.ofSeconds(5),true);assertEquals(VzorLaunch600.Status.ALREADY_RUNNING,second.status());assertEquals(-1,second.managerPid());assertTrue(first.managerAlive());}
    finally{Files.writeString(stop,"stop");awaitFile(Path.of(stop+"-released"));}
  }
  @Test void failedStartupStopsOnlyItsOwnJvmAndLeavesUnrelatedJvmAlive()throws Exception{
    Path stop=temp.resolve("unrelated-stop"),otherPid=temp.resolve("other-pid"),stalled=temp.resolve("stalled-pid");Process unrelated=new ProcessBuilder(command("unrelated",stop.toString(),otherPid.toString())).start();
    try{
      awaitFile(otherPid);var stalledOwned=new AtomicReference<Process>();
      var timeout=assertThrows(VzorFailure600.class,()->VzorLaunch600.launch(command("stalled",stalled.toString()),"https://example.org/",Duration.ofMillis(500),true,stalledOwned::set));
      assertEquals(VzorFailure600.Code.STARTUP_TIMEOUT,timeout.code());assertNotNull(stalledOwned.get());assertFalse(stalledOwned.get().isAlive(),"Known owned startup Process must actually exit");assertTrue(unrelated.isAlive());
      if(Files.exists(stalled))assertEquals(stalledOwned.get().pid(),Long.parseLong(Files.readString(stalled)));
      var rejectedOwned=new AtomicReference<Process>();
      assertThrows(IOException.class,()->VzorLaunch600.launch(command("bad-ack"),"https://example.org/",Duration.ofSeconds(3),true,rejectedOwned::set));
      assertNotNull(rejectedOwned.get());assertFalse(rejectedOwned.get().isAlive());assertTrue(unrelated.isAlive());
    }finally{Files.writeString(stop,"stop");if(!unrelated.waitFor(3,TimeUnit.SECONDS))unrelated.destroyForcibly();}
  }
  @Test void managerRejectsInheritedCoreProfileInsteadOfReadingIt()throws Exception{
    String prior=System.getProperty("aegis.profile");System.setProperty("aegis.profile",temp.resolve("core-private").toString());
    try{assertThrows(VzorFailure600.class,VzorState600::openProcessState);assertFalse(Files.exists(temp.resolve("core-private")));}
    finally{if(prior==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",prior);}
  }
  @Test void missingOwnedTorHasConcreteSafeCauseAndCloseReleasesOwnState()throws Exception{
    String profile=System.getProperty("aegis.profile"),home=System.getProperty("aegis.home");Path root=temp.resolve("manager");
    System.setProperty("aegis.profile",root.toString());System.setProperty("aegis.home",temp.resolve("bundle-without-tor").toString());
    try{
      VzorState600 state=VzorState600.open(root,temp.resolve("browser"));try(var manager=new VzorManager600(state)){
        var message=new CompletableFuture<String>();manager.connect(org.securemail.client.net.EmbeddedTor.Mode.DIRECT,p->{},message::complete);
        assertEquals(VzorFailure600.Code.TOR_BINARY_MISSING.russian(),message.get(3,TimeUnit.SECONDS));assertFalse(manager.downloadTorReady());assertTrue(VzorState600.lockHeld(root));
      }
      assertFalse(VzorState600.lockHeld(root));
    }finally{if(profile==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",profile);if(home==null)System.clearProperty("aegis.home");else System.setProperty("aegis.home",home);}
  }
  @Test void publicLauncherRejectsIncompleteBundleWithoutAnyChildProcess(){
    var failure=assertThrows(VzorFailure600.class,()->VzorLaunch600.openAuthorized(temp,"https://example.org/"));assertEquals(VzorFailure600.Code.RUNTIME_MISSING,failure.code());
  }
  @Test void safeDiagnosticsNeverRenderRawPrivatePathsHeadersOrSecrets(){
    String marker="PASSWORD=private /home/test/archive.key https://example.org/?token=secret";String shown=VzorFailure600.safeMessage(new IOException(marker));assertFalse(shown.contains("private"));assertFalse(shown.contains("token="));assertEquals(VzorFailure600.Code.TOR_UNAVAILABLE.russian(),VzorFailure600.safeMessage(new RuntimeException(marker,new VzorFailure600(VzorFailure600.Code.TOR_UNAVAILABLE))));
  }
  private static List<String> command(String... arguments){List<String> result=new ArrayList<>(List.of(Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString(),"-cp",classpath(),VzorDetachedFixture600.class.getName()));result.addAll(List.of(arguments));return result;}
  private static String classpath(){try{return String.join(File.pathSeparator,new LinkedHashSet<>(List.of(Path.of(VzorDetachedFixture600.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString(),Path.of(VzorLaunch600.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString(),Path.of(AppPaths.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString())));}catch(Exception error){throw new IllegalStateException(error);}}
  private static void awaitFile(Path path)throws Exception{long until=System.nanoTime()+Duration.ofSeconds(8).toNanos();while(!Files.exists(path)&&System.nanoTime()<until)Thread.sleep(20);assertTrue(Files.exists(path),"Fixture confirmation missing");}
}
