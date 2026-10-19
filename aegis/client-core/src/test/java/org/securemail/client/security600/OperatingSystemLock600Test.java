package org.securemail.client.security600;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.securemail.client.security600.OperatingSystemLockMonitor600.*;

class OperatingSystemLock600Test {
  @TempDir Path temp;
  @Test void windowsWin64AbiLayoutMatchesDocumentedWtsInfoExHeader(){
    var shape=new WindowsLockProbe600.Information();assertEquals(232,shape.size());assertEquals(8,shape.offset("Data"));assertEquals(4,shape.Data.offset("SessionState"));assertEquals(8,shape.Data.offset("SessionFlags"));assertEquals(16,shape.offset("Data")+shape.Data.offset("SessionFlags"));
  }
  @Test void windowsUnknownDisconnectedAndFlagsFailClosed(){
    assertEquals(State.UNLOCKED,WindowsLockProbe600.parse(1,0,1));assertEquals(State.LOCKED,WindowsLockProbe600.parse(1,0,0));assertEquals(State.LOCKED,WindowsLockProbe600.parse(1,4,1));assertEquals(State.UNKNOWN,WindowsLockProbe600.parse(1,0,-1));assertEquals(State.UNKNOWN,WindowsLockProbe600.parse(2,0,1));assertEquals(State.UNKNOWN,WindowsLockProbe600.parse(1,100,1));
  }
  @Test void legacyWindowsWithInvertedLockFlagsIsNotInterpretedAsSupported(){
    assertFalse(WindowsLockProbe600.supportedVersion("6.1"));assertFalse(WindowsLockProbe600.supportedVersion("6.3"));assertFalse(WindowsLockProbe600.supportedVersion(null));assertFalse(WindowsLockProbe600.supportedVersion("unknown"));assertTrue(WindowsLockProbe600.supportedVersion("10.0"));assertTrue(WindowsLockProbe600.supportedVersion("10.0.26100"));
  }
  @Test void linuxParsersAcceptOnlyBoundedCanonicalScalarReplies(){
    assertEquals(State.LOCKED,parseLoginctl(bytes("yes\n")));assertEquals(State.UNLOCKED,parseLoginctl(bytes("no\n")));assertEquals(State.LOCKED,parseBusctl(bytes("b true\n")));assertEquals(State.UNLOCKED,parseBusctl(bytes("b false\n")));
    for(String value:List.of("","no\nyes\n","yes\0"," true","PASSWORD=secret","(false,)","b false extra","x".repeat(129),"b false\n\n")){assertEquals(State.UNKNOWN,parseLoginctl(bytes(value)));assertEquals(State.UNKNOWN,parseBusctl(bytes(value)));}
    assertEquals(State.UNKNOWN,parseBusctl(new byte[]{(byte)0xff}));
  }
  @Test void oneLockedSourceWinsAndAnUnknownSourceCannotAuthorizeUnlocked(){
    assertEquals(State.LOCKED,combine(State.LOCKED,State.UNKNOWN));assertEquals(State.LOCKED,combine(State.UNLOCKED,State.LOCKED));assertEquals(State.UNKNOWN,combine(State.UNLOCKED,State.UNKNOWN));assertEquals(State.UNKNOWN,combine(State.UNKNOWN,State.UNLOCKED));assertEquals(State.UNLOCKED,combine(State.UNLOCKED,State.UNLOCKED));
  }
  @Test void userBusNeverAcceptsTcpAutolaunchAdditionalAddressesOrUserShell(){
    for(String address:List.of("tcp:host=example.org,port=1","autolaunch:","/run/user/1000;tcp:host=example.org","/tmp/fake-user-bus","/run/user/1000\ncommand","/run/user/../1000","/run/user/1000/bus"))assertNull(localUserBus(address));assertNull(localUserBus(null));
  }
  @Test void actualUnixBusRequiresPrivateRuntimeOwnerAndSocketWithoutLinks()throws Exception{
    org.junit.jupiter.api.Assumptions.assumeTrue(System.getProperty("os.name").equals("Linux"),"Actual Unix socket filesystem fixture requires Linux; Windows WTS is separately scoped");
    Path runtime=Files.createDirectory(temp.resolve("runtime")),socket=runtime.resolve("bus");Files.setPosixFilePermissions(runtime,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
    var owner=Files.getOwner(runtime);java.nio.channels.ServerSocketChannel opened;
    try{opened=java.nio.channels.ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX);}
    catch(java.net.SocketException|UnsupportedOperationException unavailable){org.junit.jupiter.api.Assumptions.abort("Host sandbox forbids AF_UNIX: actual private user-bus socket acceptance NOT_RUN");return;}
    try(var server=opened){
      server.bind(java.net.UnixDomainSocketAddress.of(socket));assertEquals("unix:path="+socket,checkedLocalUserBus(runtime,owner));
      assertNull(checkedLocalUserBus(runtime,()->"foreign-user"));
      for(String mode:List.of("rwxr-x---","rwx-----x","rwxrwxrwx")){Files.setPosixFilePermissions(runtime,java.nio.file.attribute.PosixFilePermissions.fromString(mode));assertNull(checkedLocalUserBus(runtime,owner));}
      Files.setPosixFilePermissions(runtime,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));Path alias=temp.resolve("runtime-alias");Files.createSymbolicLink(alias,runtime);assertNull(checkedLocalUserBus(alias,owner));
      Path realSocket=runtime.resolve("real-bus");Files.move(socket,realSocket);Files.createSymbolicLink(socket,realSocket);assertNull(checkedLocalUserBus(runtime,owner));
    }
  }
  @Test void untrustedExecutableInUserWritableTreeIsRejected()throws Exception{
    Path binary=temp.resolve("loginctl");Files.writeString(binary,"untrusted fixture");binary.toFile().setExecutable(true);assertFalse(trustedExecutable(binary));assertFalse(trustedExecutable(temp.resolve("missing")));
  }
  @Test void linuxProbeUsesOnlyFixedLocalReadOnlyCommandsAndNoInteractiveAuthorization(){
    List<List<String>> observed=new ArrayList<>();Commands commands=(arguments,timeout,maximum)->{observed.add(arguments);assertTrue(timeout.compareTo(Duration.ofSeconds(2))<0);assertEquals(128,maximum);return new CommandResult(true,bytes(observed.size()==1?"no\n":"b false\n"));};
    var probe=new LinuxProbe(commands,()->"unix:path=/run/user/1234/bus",()->true);assertEquals(State.UNLOCKED,probe.read());assertEquals(2,observed.size());
    assertEquals(List.of("/usr/bin/loginctl","--no-pager","--no-ask-password","show-session","self","--property=LockedHint","--value"),observed.get(0));
    assertEquals("/usr/bin/busctl",observed.get(1).getFirst());assertTrue(observed.get(1).contains("--address=unix:path=/run/user/1234/bus"));assertTrue(observed.get(1).contains("--auto-start=no"));assertTrue(observed.get(1).contains("--allow-interactive-authorization=no"));assertTrue(observed.get(1).contains("GetActive"));assertFalse(observed.stream().flatMap(Collection::stream).anyMatch(x->x.equals("sh")||x.equals("-c")||x.contains("--host")));
  }
  @Test void logindLockDoesNotWaitForSecondProbeAndMissingBackendIsUnknown(){
    AtomicInteger calls=new AtomicInteger();Commands commands=(a,t,m)->{calls.incrementAndGet();return new CommandResult(true,bytes("yes\n"));};assertEquals(State.LOCKED,new LinuxProbe(commands,()->null,()->true).read());assertEquals(1,calls.get());assertEquals(State.UNKNOWN,new LinuxProbe(commands,()->null,()->false).read());assertEquals(1,calls.get());
  }
  @Test void actualOwnedCommandReadsScalarAndDropsInheritedSensitiveEnvironment()throws Exception{
    AtomicReference<Map<String,String>> environment=new AtomicReference<>();AtomicReference<Process> child=new AtomicReference<>();
    try(var runner=new OwnedCommands((arguments,env)->{environment.set(env);Process p=new ProcessBuilder(arguments).start();child.set(p);return p;})){
      CommandResult result=runner.run(command("no"),Duration.ofSeconds(1),128);assertTrue(result.success());assertEquals(State.UNLOCKED,parseLoginctl(result.output()));assertNotNull(child.get());assertFalse(child.get().isAlive());
      assertEquals(Set.of("LANG","LC_ALL","SYSTEMD_COLORS","SYSTEMD_PAGERSECURE","DBUS_SYSTEM_BUS_ADDRESS"),environment.get().keySet());assertEquals("unix:path=/run/dbus/system_bus_socket",environment.get().get("DBUS_SYSTEM_BUS_ADDRESS"));
    }
  }
  @Test void actualDefaultRunnerDoesNotInheritProxySecretsOrJvmInjection(){
    try(var runner=new OwnedCommands()){CommandResult result=runner.run(command("environment"),Duration.ofSeconds(1),128);assertTrue(result.success());assertEquals("clear",new String(result.output(),StandardCharsets.US_ASCII));}
  }
  @Test void actualOwnedCommandRejectsOversizedNonzeroAndStalledProcesses()throws Exception{
    List<Process> owned=new ArrayList<>();try(var runner=new OwnedCommands((arguments,env)->{Process p=new ProcessBuilder(arguments).start();owned.add(p);return p;})){
      assertFalse(runner.run(command("large"),Duration.ofSeconds(1),64).success());assertFalse(runner.run(command("failure"),Duration.ofSeconds(1),64).success());long start=System.nanoTime();assertFalse(runner.run(command("stall"),Duration.ofMillis(150),64).success());assertTrue(System.nanoTime()-start<Duration.ofSeconds(3).toNanos());assertTrue(owned.stream().noneMatch(Process::isAlive));
    }
  }
  @Test void closeStopsOnlyActiveOwnedCommandAndDoesNotWaitForStall()throws Exception{
    var owned=new AtomicReference<Process>();var began=new CountDownLatch(1);Process unrelated=new ProcessBuilder(command("stall")).start();
    var runner=new OwnedCommands((arguments,env)->{Process p=new ProcessBuilder(arguments).start();owned.set(p);began.countDown();return p;});var result=new CompletableFuture<CommandResult>();Thread worker=Thread.startVirtualThread(()->result.complete(runner.run(command("stall"),Duration.ofSeconds(2),64)));
    try{assertTrue(began.await(3,TimeUnit.SECONDS));runner.close();assertFalse(result.get(3,TimeUnit.SECONDS).success());assertFalse(owned.get().isAlive());assertTrue(unrelated.isAlive());assertFalse(runner.run(command("no"),Duration.ofSeconds(1),64).success());}
    finally{runner.close();worker.interrupt();unrelated.destroyForcibly();unrelated.waitFor(3,TimeUnit.SECONDS);}
  }
  @Test void commandBoundsAreEnforcedBeforeStartingAnyProcess(){
    try(var runner=new OwnedCommands((a,e)->{throw new AssertionError("No command should start");})){
      assertThrows(IllegalArgumentException.class,()->runner.run(command("no"),Duration.ofSeconds(3),64));assertThrows(IllegalArgumentException.class,()->runner.run(command("no"),Duration.ofSeconds(1),1025));
    }
  }
  @Test void backgroundPollingCoalescesNotificationsAndNeverUnlocksCore()throws Exception{
    var states=List.of(State.UNKNOWN,State.UNKNOWN,State.UNLOCKED,State.LOCKED,State.LOCKED);AtomicInteger index=new AtomicInteger();List<Reason> reasons=new CopyOnWriteArrayList<>();var done=new CountDownLatch(2);String caller=Thread.currentThread().getName();AtomicReference<String> callbackThread=new AtomicReference<>();
    try(var monitor=start(()->states.get(Math.min(index.getAndIncrement(),states.size()-1)),reason->{callbackThread.set(Thread.currentThread().getName());reasons.add(reason);done.countDown();},Duration.ofMillis(20),Duration.ofSeconds(1))){
      assertTrue(done.await(3,TimeUnit.SECONDS));assertEquals(List.of(Reason.STATUS_UNAVAILABLE,Reason.LOCKED),reasons);assertNotEquals(caller,callbackThread.get());assertTrue(monitor.observationAvailable());
    }
  }
  @Test void blockedNativeStyleQueryTimesOutFailClosedWithoutCreatingMoreWorkers()throws Exception{
    AtomicInteger reads=new AtomicInteger();var release=new CountDownLatch(1);var notified=new CountDownLatch(1);List<Reason> reasons=new CopyOnWriteArrayList<>();
    Probe probe=()->{reads.incrementAndGet();while(release.getCount()>0)try{release.await();}catch(InterruptedException ignored){/* Simulates an uninterruptible native API. */}return State.UNLOCKED;};
    try(var monitor=start(probe,reason->{reasons.add(reason);notified.countDown();},Duration.ofMillis(20),Duration.ofMillis(60))){assertTrue(notified.await(2,TimeUnit.SECONDS));Thread.sleep(100);assertEquals(1,reads.get());assertEquals(List.of(Reason.STATUS_UNAVAILABLE),reasons);assertFalse(monitor.observationAvailable());}
    finally{release.countDown();}
  }
  @Test void callbackExceptionIsRetriedInsteadOfSilentlyDisablingProtection()throws Exception{
    AtomicInteger calls=new AtomicInteger();var notified=new CountDownLatch(1);try(var monitor=start(()->State.UNKNOWN,reason->{if(calls.incrementAndGet()==1)throw new IllegalStateException("sensitive fixture should not be logged");notified.countDown();},Duration.ofMillis(20),Duration.ofSeconds(1))){assertTrue(notified.await(2,TimeUnit.SECONDS));assertEquals(2,calls.get());}
  }
  private static byte[] bytes(String value){return value.getBytes(StandardCharsets.US_ASCII);}
  private static List<String> command(String mode){try{return List.of(Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString(),"-cp",Path.of(LockCommandFixture600.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString(),LockCommandFixture600.class.getName(),mode);}catch(Exception error){throw new IllegalStateException(error);}}
}
