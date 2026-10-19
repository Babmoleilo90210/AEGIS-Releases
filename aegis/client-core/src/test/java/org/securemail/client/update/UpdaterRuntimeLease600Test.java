package org.securemail.client.update;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

/** Real independent JVM runtime locks plus actual copy/rename/rollback; not native updater E2E. */
class UpdaterRuntimeLease600Test {
  @TempDir Path temp;
  @BeforeEach void files()throws IOException{Files.writeString(temp.resolve("AEGIS.AppImage"),"old-version");Files.writeString(temp.resolve("candidate"),"new-version");}
  @Test void anotherRuntimeBlocksBeforeBackupAndPreservesEveryFile()throws Exception{
    Process runtime=start("runtime");try{assertEquals("HELD",UpdaterLeaseFixture600.line(runtime));assertEquals("INITIAL_BLOCKED",run("success"));assertEquals("old-version",Files.readString(temp.resolve("AEGIS.AppImage")));assertFalse(Files.exists(temp.resolve("backup-phase")));assertFalse(Files.exists(temp.resolve("AEGIS.AppImage.new")));}finally{UpdaterLeaseFixture600.finish(runtime);}
  }
  @Test void oldClientWithoutRuntimeLeaseStillBlocksBeforeBackupAndReplacement()throws Exception{
    Process runtime=start("legacy");try{assertEquals("HELD",UpdaterLeaseFixture600.line(runtime));assertEquals("RECOVERY_BLOCKED",run("success"));assertEquals("old-version",Files.readString(temp.resolve("AEGIS.AppImage")));assertFalse(Files.exists(temp.resolve("backup-phase")));}finally{UpdaterLeaseFixture600.finish(runtime);}
  }
  @Test void exclusiveCopyReleasesBeforeSharedNewCoreStartup()throws Exception{assertEquals("COMMITTED",run("success"));assertEquals("new-version",Files.readString(temp.resolve("AEGIS.AppImage")));assertTrue(Files.exists(temp.resolve("backup-phase")));assertFalse(Files.exists(temp.resolve("AEGIS.AppImage.old")));}
  @Test void failureStopsExactCoreThenReacquiresExclusiveBeforeRollback()throws Exception{assertEquals("ROLLED_BACK",run("no-ack"));assertEquals("old-version",Files.readString(temp.resolve("AEGIS.AppImage")));assertTrue(Files.exists(temp.resolve("exact-child-stopped")));assertTrue(Files.exists(temp.resolve("profile-restored")));assertFalse(Files.exists(temp.resolve("AEGIS.AppImage.old")));}
  @Test void independentManagerRaceBlocksRollbackAndRetainsOldAndNew()throws Exception{assertEquals("RECOVERY_BLOCKED",run("race"));assertEquals("new-version",Files.readString(temp.resolve("AEGIS.AppImage")));assertEquals("old-version",Files.readString(temp.resolve("AEGIS.AppImage.old")));assertTrue(Files.exists(temp.resolve("exact-child-stopped")));assertFalse(Files.exists(temp.resolve("profile-restored")));}
  @Test void previousUnownedCandidateIsNeverCleanedOnPreflightFailure()throws Exception{Files.writeString(temp.resolve("AEGIS.AppImage.new"),"other-transaction");assertEquals("RECOVERY_BLOCKED",run("success"));assertEquals("other-transaction",Files.readString(temp.resolve("AEGIS.AppImage.new")));assertEquals("old-version",Files.readString(temp.resolve("AEGIS.AppImage")));}
  private Process start(String mode)throws Exception{
    List<String> cp=new ArrayList<>();for(Class<?> type:List.of(UpdaterLeaseFixture600.class,UpdateInstaller.class,com.google.gson.JsonObject.class,com.sun.jna.Native.class,com.sun.jna.platform.win32.Kernel32.class))cp.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
    ProcessBuilder pb=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",String.join(File.pathSeparator,new LinkedHashSet<>(cp)),UpdaterLeaseFixture600.class.getName(),mode,temp.toString());pb.environment().put("XDG_DATA_HOME",temp.resolve("data").toString());pb.environment().put("LOCALAPPDATA",temp.resolve("data").toString());return pb.redirectError(ProcessBuilder.Redirect.INHERIT).start();
  }
  private String run(String mode)throws Exception{Process p=start(mode);try{String line=UpdaterLeaseFixture600.line(p);assertTrue(p.waitFor(15,TimeUnit.SECONDS));assertEquals(0,p.exitValue());return line;}finally{UpdaterLeaseFixture600.finish(p);}}
}
