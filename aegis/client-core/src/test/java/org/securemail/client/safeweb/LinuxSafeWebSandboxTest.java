package org.securemail.client.safeweb;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import java.io.*;
import java.net.URI;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Policy and serialization checks only; not evidence of a native launch. */
@EnabledOnOs(OS.LINUX)
class LinuxSafeWebSandboxTest {
  @TempDir Path temporary;
  @Test void isolatesNetworkAndOnlyExposesDedicatedFiles() {
    Path bundle=temporary.resolve("session bundle"),downloads=temporary.resolve("downloads"),auth=temporary.resolve("cookie"),socket=Path.of("/tmp/.X11-unix/X740");
    List<String> command=LinuxSafeWebSandbox.sandboxCommand(bundle,downloads,auth,socket,740,URI.create("https://example.org/"));
    assertTrue(command.containsAll(List.of("--unshare-all","--new-session","--die-with-parent","--clearenv")));
    assertFalse(command.contains("--share-net"));assertFalse(command.contains("--dev-bind"));
    List<String> writable=new ArrayList<>();
    for(int n=0;n<command.size();n++)if(command.get(n).equals("--bind"))writable.add(command.get(n+1));
    assertEquals(List.of(bundle.toString(),downloads.toString()),writable);
    assertFalse(command.contains(System.getProperty("user.home")));assertFalse(command.contains("/run/user"));
    assertFalse(command.contains("WAYLAND_DISPLAY"));assertFalse(command.contains("DBUS_SESSION_BUS_ADDRESS"));
    assertTrue(command.containsAll(List.of("--info-fd","1","--block-fd","0")));
  }
  @Test void urlIsAlwaysOnePositionalArgumentNeverShellSource() {
    URI uri=URI.create("https://example.org/?a=$HOME&b=%22;touch%20/tmp/bad&c=%60id%60");
    List<String> command=LinuxSafeWebSandbox.sandboxCommand(temporary.resolve("bundle"),temporary.resolve("downloads"),temporary.resolve("auth"),Path.of("/tmp/.X11-unix/X800"),800,uri);
    int shell=command.indexOf("-c");
    assertEquals("exec \"$@\" </dev/null >/dev/null 2>&1",command.get(shell+1));
    assertEquals(uri.toASCIIString(),command.getLast());assertFalse(command.get(shell+1).contains(uri.toASCIIString()));
    assertFalse(command.contains("TOR_SKIP_LAUNCH"));assertFalse(command.contains("MOZ_DISABLE_CONTENT_SANDBOX"));
  }
  @Test void cookieIsPrivateWellFormedAndDifferentEverySession()throws Exception {
    Path first=temporary.resolve("first"),second=temporary.resolve("second");
    LinuxSafeWebSandbox.writeXAuthority(first,123);LinuxSafeWebSandbox.writeXAuthority(second,123);
    try(DataInputStream in=new DataInputStream(Files.newInputStream(first))) {
      assertEquals(65535,in.readUnsignedShort());assertEquals(0,in.readUnsignedShort());
      assertEquals("123",new String(in.readNBytes(in.readUnsignedShort()),java.nio.charset.StandardCharsets.US_ASCII));
      assertEquals("MIT-MAGIC-COOKIE-1",new String(in.readNBytes(in.readUnsignedShort()),java.nio.charset.StandardCharsets.US_ASCII));
      assertEquals(16,in.readUnsignedShort());assertEquals(16,in.readNBytes(16).length);assertEquals(-1,in.read());
    }
    assertFalse(Arrays.equals(Files.readAllBytes(first),Files.readAllBytes(second)));
    if(first.getFileSystem().supportedFileAttributeViews().contains("posix"))assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(first));
  }
  @Test void cookieDoesNotFollowSymbolicLinks()throws Exception {
    if(!temporary.getFileSystem().supportedFileAttributeViews().contains("posix"))return;
    Path target=Files.writeString(temporary.resolve("target"),"keep"),link=temporary.resolve("link");Files.createSymbolicLink(link,target);
    assertThrows(IOException.class,()->LinuxSafeWebSandbox.writeXAuthority(link,123));assertEquals("keep",Files.readString(target));
  }
  @Test void displayLeaseStopsItsChildWhenControllerPipeCloses()throws Exception {
    // Real harmless subprocess test of the controller lease, not a browser test.
    Process process=new ProcessBuilder(LinuxSafeWebSandbox.monitoredDisplayCommand(List.of("/bin/sleep","30")))
      .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    try {
      Thread.sleep(100);assertTrue(process.isAlive());
      process.getOutputStream().close();assertTrue(process.waitFor(3,java.util.concurrent.TimeUnit.SECONDS));
      // wait(1) returns the server's SIGTERM status after EOF; no browser or
      // namespace is faked here. /proc PID views may differ in build containers.
      assertEquals(143,process.exitValue());
    } finally {process.getOutputStream().close();if(!process.waitFor(3,TimeUnit.SECONDS))process.destroyForcibly();}
  }
  @Test void customSecretDirectoriesInSystemMountsAreRejectedEvenThroughSymlinks()throws Exception{
    assertThrows(IOException.class,()->LinuxSafeWebSandbox.checkHiddenPaths(List.of(Path.of("/usr/private-aegis"))));
    Path alias=temporary.resolve("alias");Files.createSymbolicLink(alias,Path.of("/usr"));
    assertThrows(IOException.class,()->LinuxSafeWebSandbox.checkHiddenPaths(List.of(alias.resolve("missing-private-profile"))));
    assertDoesNotThrow(()->LinuxSafeWebSandbox.checkHiddenPaths(List.of(temporary.resolve("private-profile"))));
  }
  /** A deterministic refusal to terminate wraps a REAL harmless child. This is
   * controller failure-path testing, not evidence of any native browser launch.
   */
  private static class GuardedChild extends Process {
    final Process actual;final AtomicBoolean allowClose=new AtomicBoolean();
    GuardedChild()throws IOException{actual=new ProcessBuilder("/bin/sleep","30").start();}
    public OutputStream getOutputStream(){return actual.getOutputStream();}
    public InputStream getInputStream(){return actual.getInputStream();}
    public InputStream getErrorStream(){return actual.getErrorStream();}
    public int waitFor()throws InterruptedException{return actual.waitFor();}
    public boolean waitFor(long timeout,TimeUnit unit)throws InterruptedException{return allowClose.get()?actual.waitFor(timeout,unit):false;}
    public int exitValue(){return actual.exitValue();}
    public void destroy(){if(allowClose.get())actual.destroy();}
    public Process destroyForcibly(){if(allowClose.get())actual.destroyForcibly();return this;}
    public boolean isAlive(){return actual.isAlive();}
    public ProcessHandle toHandle(){return actual.toHandle();}
    public Stream<ProcessHandle> descendants(){return Stream.empty();}
  }
  /** Process-backed adapter avoids depending on the build host's /proc PID view. */
  private static final class CapturedHandle implements ProcessHandle {
    final Process actual;
    CapturedHandle(Process actual){this.actual=actual;}
    public long pid(){return actual.pid();}
    public Optional<ProcessHandle> parent(){return Optional.empty();}
    public Stream<ProcessHandle> children(){return Stream.empty();}
    public Stream<ProcessHandle> descendants(){return Stream.empty();}
    public Info info(){return actual.toHandle().info();}
    public java.util.concurrent.CompletableFuture<ProcessHandle> onExit(){return actual.onExit().thenApply(ignored->this);}
    public boolean supportsNormalTermination(){return actual.supportsNormalTermination();}
    public boolean destroy(){actual.destroy();return true;}
    public boolean destroyForcibly(){actual.destroyForcibly();return true;}
    public boolean isAlive(){return actual.isAlive();}
    public int compareTo(ProcessHandle other){return Long.compare(pid(),other.pid());}
  }
  @Test void failedStartupRetainsControllerAndFilesWhenCleanupCannotStopOwnedChild()throws Exception{
    Path control=Files.createDirectory(temporary.resolve("control")),downloads=Files.createDirectory(temporary.resolve("downloads"));Files.writeString(control.resolve("Xauthority"),"unit cookie");Files.writeString(control.resolve("resolv.conf"),"unit resolver");
    GuardedChild child=new GuardedChild();LinuxSafeWebSandbox.Launch launch=new LinuxSafeWebSandbox.Launch(downloads,control);launch.own(child);
    try{
      LinuxSafeWebSandbox.Launch retained=LinuxSafeWebSandbox.cleanupFailedStart(launch,new IOException("unit startup failure"));
      assertSame(launch,retained);assertTrue(retained.running());assertTrue(child.actual.isAlive());assertTrue(retained.status().contains("Ошибка запуска"));assertFalse(retained.status().contains("Tor Browser: изолированный процесс запущен"));assertTrue(Files.exists(control.resolve("Xauthority")));
      child.allowClose.set(true);retained.close();assertFalse(child.actual.isAlive());assertFalse(retained.running());assertFalse(Files.exists(control));
    }finally{child.allowClose.set(true);child.actual.destroyForcibly();child.actual.waitFor(3,TimeUnit.SECONDS);launch.close();}
  }
  @Test void successfulStartupFailureCleanupThrowsOriginalFailureAfterOwnedChildStopped()throws Exception{
    Path control=Files.createDirectory(temporary.resolve("control")),downloads=Files.createDirectory(temporary.resolve("downloads"));
    GuardedChild child=new GuardedChild();child.allowClose.set(true);LinuxSafeWebSandbox.Launch launch=new LinuxSafeWebSandbox.Launch(downloads,control);launch.own(child);IOException reason=new IOException("unit startup failure");
    try{assertSame(reason,assertThrows(IOException.class,()->LinuxSafeWebSandbox.cleanupFailedStart(launch,reason)));assertFalse(child.actual.isAlive());assertFalse(Files.exists(control));}
    finally{child.actual.destroyForcibly();child.actual.waitFor(3,TimeUnit.SECONDS);launch.close();}
  }
  @Test void cleanupWaitsForEveryCapturedOwnedHandleAndPreservesForeignProcess()throws Exception{
    Path control=Files.createDirectory(temporary.resolve("control")),downloads=Files.createDirectory(temporary.resolve("downloads"));
    Process captured=new ProcessBuilder("/bin/sleep","30").start(),foreign=new ProcessBuilder("/bin/sleep","30").start();
    // Explicitly supplied captured handle tests teardown policy independently of
    // /proc enumeration, which is unavailable in some build PID namespaces.
    CapturedHandle capturedHandle=new CapturedHandle(captured);
    GuardedChild parent=new GuardedChild(){@Override public Stream<ProcessHandle> descendants(){return Stream.of(capturedHandle);}};
    parent.allowClose.set(true);LinuxSafeWebSandbox.Launch launch=new LinuxSafeWebSandbox.Launch(downloads,control);launch.own(parent);
    try{launch.close();assertFalse(parent.actual.isAlive());assertTrue(captured.waitFor(3,TimeUnit.SECONDS));assertFalse(captured.isAlive());assertTrue(foreign.isAlive());}
    finally{parent.actual.destroyForcibly();captured.destroyForcibly();foreign.destroyForcibly();parent.actual.waitFor(3,TimeUnit.SECONDS);captured.waitFor(3,TimeUnit.SECONDS);foreign.waitFor(3,TimeUnit.SECONDS);}
  }
}
