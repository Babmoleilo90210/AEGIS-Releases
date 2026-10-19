package org.securemail.client.ecosystem;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.jar.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.*;
import org.securemail.client.storage.*;

/** Optional exact published-binary rollback acceptance; configure aegis.legacy500.bundle. Never silently substitutes current classes. */
class Legacy500Rollback600Test {
  @TempDir Path temporary;
  @Test void exactReleased500CreatesRealIdentityLetterArchiveAndReadsVerifiedRestoredSnapshot()throws Exception{
    String input=System.getProperty("aegis.legacy500.bundle");Assumptions.assumeTrue(input!=null,"Exact 5.0.0 binary bundle not supplied; NOT_RUN");Path bundle=Path.of(input),oldCore=bundle.resolve("client-core-5.0.0.jar");assertEquals("6d263ef70f5b159aa4458125ffc75bf55c71346baf52b01db3b7db00e155ebe2",ComponentInstallation.sha256(oldCore),"This test must use the reviewed published AppImage JAR");
    String prior=System.getProperty("aegis.profile");Path profile=temporary.resolve("profile");System.setProperty("aegis.profile",profile.toString());
    try{ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());Path jar=temporary.resolve("probe.jar");String name=Legacy500VaultProbe.class.getName().replace('.','/')+".class";try(var out=new JarOutputStream(Files.newOutputStream(jar));var in=Legacy500VaultProbe.class.getClassLoader().getResourceAsStream(name)){out.putNextEntry(new JarEntry(name));in.transferTo(out);out.closeEntry();}
      String baseline=probe(bundle,jar,profile,"init");Files.createDirectories(profile.resolve("appearance"));Files.writeString(profile.resolve("appearance/custom.json"),"public theme preservation fixture");Files.writeString(profile.resolve("tor-mode.txt"),"snowflake\n");
      Path snapshot=ClientUpgrade.beforeVersionOpen("6.0.0",config,temporary.resolve("backups"));assertNotNull(snapshot);ProfileSnapshot.verify(snapshot,config);
      try(var mail=new LocalStore(config.storagePath(),Legacy500VaultProbe.MAIL_PASSWORD.toCharArray(),Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage());var recovery=MailRecoveryKey600.loadOrCreate(mail)){assertTrue(baseline.startsWith(mail.identity().userId()));new MailNotificationCounter600(mail).add(List.of(UUID.randomUUID().toString()));mail.writeExtension("mail6-draft-v1","public synthetic draft bytes".getBytes(java.nio.charset.StandardCharsets.US_ASCII),400000);}
      assertTrue(probe(bundle,jar,profile,"rekey").startsWith("PASS:"));ProfileSnapshot.restore(snapshot,config);assertEquals(baseline,probe(bundle,jar,profile,"verify"));assertEquals("public theme preservation fixture",Files.readString(profile.resolve("appearance/custom.json")));assertEquals("snowflake\n",Files.readString(profile.resolve("tor-mode.txt")));assertFalse(Files.exists(config.storagePath().resolve("lifecycle/identity6-recovery-root-v1.enc")));ProfileSnapshot.verify(snapshot,config);
      String sourceBefore=tree(config.storagePath());var migrated=MailProfileMigration600.beforeOpen(config,Legacy500VaultProbe.MAIL_PASSWORD.toCharArray(),Legacy500VaultProbe.ARCHIVE_PASSWORD.toCharArray(),()->false);assertNotEquals(config.storagePath(),migrated.storagePath());assertEquals(sourceBefore,tree(config.storagePath()),"Runtime migration changed the old Mail source");assertEquals(migrated.storagePath(),ClientConfig.load(AppPaths.config()).storagePath());try(var moved=new LocalStore(migrated.storagePath(),Legacy500VaultProbe.MAIL_PASSWORD.toCharArray(),Clock.systemUTC(),migrated.maxCiphertext(),migrated.maxLocalStorage())){assertTrue(baseline.startsWith(moved.identity().userId()));assertEquals(1,moved.inbox().size());assertEquals(1,moved.contacts().size());}assertEquals(baseline,probe(bundle,jar,profile,"verify"));assertFalse(MailProfileMigration600.required(migrated));assertEquals(migrated,MailProfileMigration600.beforeOpen(migrated,new char[0],new char[0],()->false));
    }finally{if(prior==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",prior);}
  }
  private static String tree(Path path)throws Exception{var digest=java.security.MessageDigest.getInstance("SHA-256");try(var files=Files.walk(path)){for(Path file:files.filter(Files::isRegularFile).sorted().toList()){digest.update(path.relativize(file).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update(Files.readAllBytes(file));}}return HexFormat.of().formatHex(digest.digest());}
  private static String probe(Path bundle,Path jar,Path profile,String mode)throws Exception{List<String> command=List.of(Path.of(System.getProperty("java.home"),"bin",AppPaths.windows()?"java.exe":"java").toString(),"-Daegis.profile="+profile,"-Daegis.native.root="+System.getProperty("aegis.native.root"),"-cp",jar+File.pathSeparator+bundle.resolve("*"),Legacy500VaultProbe.class.getName(),mode,profile.toString());Process p=new ProcessBuilder(command).redirectErrorStream(true).start();p.getOutputStream().close();try{assertTrue(p.waitFor(30,TimeUnit.SECONDS),"Exact old binary probe timed out");String output=new String(p.getInputStream().readNBytes(16384),java.nio.charset.StandardCharsets.UTF_8).strip();assertEquals(0,p.exitValue(),output);return output;}finally{if(p.isAlive())p.destroyForcibly();}}
}
