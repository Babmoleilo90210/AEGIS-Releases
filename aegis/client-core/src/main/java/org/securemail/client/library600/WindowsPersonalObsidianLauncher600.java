package org.securemail.client.library600;

import com.google.gson.*;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.client.safeweb.ObsidianWindowsBoundary600;
import java.io.*;
import java.net.URI;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Detached Windows manager. Free plugins execute only in their own personal VM.
 * Personal networking is ordinary third-party networking, not an AEGIS Tor claim. */
public final class WindowsPersonalObsidianLauncher600 {
 private final WindowsObsidianPackage600 official;private final Path vault,profile,control;private final List<Path>secrets;private Process own;
 public WindowsPersonalObsidianLauncher600(WindowsObsidianPackage600 official,Path vault,Path profile,Path control,Collection<Path>protectedPaths)throws Exception {
  this.official=official;this.vault=ObsidianDistribution600.directory(vault);this.profile=ObsidianDistribution600.directory(profile);AtomicFiles.directory(control);this.control=ObsidianDistribution600.directory(control);secrets=List.copyOf(protectedPaths);
  if(this.control.startsWith(this.vault)||this.control.startsWith(this.profile)||this.vault.startsWith(this.control)||this.profile.startsWith(this.control))throw new IOException("Контроллер нельзя передавать личным плагинам");
 }
 public synchronized void open()throws Exception {
  if(own!=null&&own.isAlive())return;official.verify();String nonce=UUID.randomUUID().toString();JsonObject j=new JsonObject();j.addProperty("nonce",nonce);j.addProperty("package",official.directory().toString());j.addProperty("version",official.release().version());j.addProperty("source",official.release().source().toASCIIString());j.addProperty("size",official.release().size());j.addProperty("sha256",official.release().sha256());j.addProperty("vault",vault.toString());j.addProperty("profile",profile.toString());JsonArray hidden=new JsonArray();for(Path p:secrets)hidden.add(p.toString());j.add("secrets",hidden);Path request=control.resolve("personal-windows-manager.json");AtomicFiles.write(request,j.toString().getBytes(StandardCharsets.UTF_8));
  Path java=Path.of(System.getProperty("java.home"),"bin/java.exe").toRealPath();ProcessBuilder builder=new ProcessBuilder(java.toString(),"-cp",System.getProperty("java.class.path"),WindowsPersonalObsidianLauncher600.class.getName(),"--manager",request.toString());builder.environment().keySet().removeIf(k->!Set.of("SystemRoot","windir","PATH","TEMP","TMP","LOCALAPPDATA","USERPROFILE","APPDATA").contains(k));builder.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);own=builder.start();own.getOutputStream().close();
  long end=System.nanoTime()+TimeUnit.MINUTES.toNanos(3);Path status=control.resolve("personal-windows-status.json");while(System.nanoTime()-end<0){if(Files.isRegularFile(status,LinkOption.NOFOLLOW_LINKS)&&Files.size(status)<2048){var s=JsonParser.parseString(Files.readString(status)).getAsJsonObject();if(nonce.equals(s.get("nonce").getAsString())){String state=s.get("state").getAsString();if(Set.of("RUNNING","ALREADY_RUNNING").contains(state))return;if(state.equals("FAILED"))throw new IOException("Личный Obsidian не запущен в Windows Sandbox");}}if(!own.isAlive())throw new IOException("Менеджер личной VM завершился; обычный запуск отключён");Thread.sleep(50);}throw new IOException("Создание собственной VM библиотеки ещё не подтверждено");
 }
 public synchronized boolean running(){return own!=null&&own.isAlive();}
 public static void main(String[]args)throws Exception {
        try(var installationLease=org.securemail.client.maintenance600.RuntimeLease600.running()){runManager(args);}
    }
    private static void runManager(String[]args)throws Exception {
  if(args.length!=2||!args[0].equals("--manager"))throw new IllegalArgumentException("Private manager request required");Path request=Path.of(args[1]).toAbsolutePath().normalize();if(!request.toRealPath().equals(request)||Files.size(request)>16384)throw new IOException("Некорректный запрос менеджера");Path control=ObsidianDistribution600.directory(request.getParent());var j=JsonParser.parseString(Files.readString(request)).getAsJsonObject();String nonce=j.get("nonce").getAsString();UUID.fromString(nonce);
  try(FileChannel channel=FileChannel.open(control.resolve("personal-windows-manager.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){FileLock lock=channel.tryLock();if(lock==null){status(control,nonce,"ALREADY_RUNNING");return;}try(lock){var release=new WindowsObsidianPackage600.Release(j.get("version").getAsString(),URI.create(j.get("source").getAsString()),j.get("size").getAsLong(),j.get("sha256").getAsString());var official=WindowsObsidianPackage600.reopen(release,Path.of(j.get("package").getAsString()));List<Path>hidden=new ArrayList<>();for(JsonElement e:j.getAsJsonArray("secrets"))hidden.add(Path.of(e.getAsString()));try(var driver=ObsidianWindowsBoundary600.personal(official,control,Path.of(j.get("vault").getAsString()),Path.of(j.get("profile").getAsString()),hidden)){Runtime.getRuntime().addShutdownHook(new Thread(()->{try{driver.close();}catch(Exception ignored){}}));driver.open(Path.of(j.get("vault").getAsString()));status(control,nonce,"RUNNING");while(driver.running())Thread.sleep(1000);status(control,nonce,"STOPPED");}}}catch(Exception error){status(control,nonce,"FAILED");throw error;}
 }
 private static void status(Path control,String nonce,String state)throws IOException {AtomicFiles.write(control.resolve("personal-windows-status.json"),("{\"nonce\":\""+nonce+"\",\"state\":\""+state+"\"}").getBytes(StandardCharsets.US_ASCII));}
}
