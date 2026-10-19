package org.securemail.client.library600;

import com.google.gson.*;
import org.securemail.client.AppPaths;
import org.securemail.client.storage.AtomicFiles;
import java.io.*;
import java.net.URI;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Detached trusted manager, never a bare host Obsidian launch. Personal code gets
 * only its own RW vault/profile inside bwrap+Xephyr+slirp. Free plugins remain
 * confined there. Personal Internet is ordinary third-party traffic, NOT an AEGIS
 * Tor-anonymity claim. Manager survives Core logout/close and owns its processes. */
public final class PersonalObsidianLauncher600 {
    private final ObsidianDistribution600 distribution;private final ObsidianProfile600.Plan plan;private final Path control;private final List<Path>secrets;private Process own;
    public PersonalObsidianLauncher600(ObsidianDistribution600 distribution,ObsidianProfile600.Plan plan)throws Exception {this(distribution,plan,AppPaths.root().resolve("library600/personal-control"),List.of(AppPaths.root(),AppPaths.config()));}
    public PersonalObsidianLauncher600(ObsidianDistribution600 distribution,ObsidianProfile600.Plan plan,Path managerControl,Collection<Path>protectedSecrets)throws Exception {
        if(plan.mode()!=ObsidianProfile600.Mode.PERSONAL||!plan.binary().equals(distribution.binary()))throw new IOException("Нужен отдельный личный профиль Obsidian");
        this.distribution=Objects.requireNonNull(distribution);this.plan=ObsidianProfile600.validate(plan.mode(),plan.binary(),ObsidianDistribution600.hash(distribution.binary()),plan.vault(),plan.configuration(),Map.of());
        AtomicFiles.directory(managerControl);control=ObsidianDistribution600.directory(managerControl);secrets=List.copyOf(protectedSecrets);
        if(control.startsWith(plan.vault())||control.startsWith(plan.configuration())||plan.vault().startsWith(control)||plan.configuration().startsWith(control))throw new IOException("Контроллер нельзя помещать в личный профиль");
    }
    public synchronized void open()throws Exception {
        distribution.verify();if(own!=null&&own.isAlive())return;
        String nonce=UUID.randomUUID().toString();JsonObject json=new JsonObject();json.addProperty("nonce",nonce);json.addProperty("distribution",distribution.root().toString());json.addProperty("receiptSha256",distribution.receiptSha256());json.addProperty("version",distribution.release().version());json.addProperty("source",distribution.release().source().toASCIIString());json.addProperty("size",distribution.release().size());json.addProperty("sha256",distribution.release().sha256());json.addProperty("vault",plan.vault().toString());json.addProperty("configuration",plan.configuration().toString());JsonArray hidden=new JsonArray();for(Path p:secrets)hidden.add(p.toAbsolutePath().normalize().toString());json.add("secrets",hidden);
        Path request=control.resolve("manager-request.json");AtomicFiles.write(request,json.toString().getBytes(StandardCharsets.UTF_8));
        Path java=Path.of(System.getProperty("java.home"),"bin/java").toRealPath();List<String>args=List.of(java.toString(),"-cp",System.getProperty("java.class.path"),PersonalObsidianLauncher600.class.getName(),"--manager",request.toString());
        ProcessBuilder builder=new ProcessBuilder(args);builder.environment().clear();builder.environment().put("PATH","/usr/bin:/bin");builder.environment().put("LANG","C.UTF-8");for(String key:List.of("DISPLAY","XAUTHORITY","XDG_SESSION_TYPE","XDG_DATA_HOME")){String value=System.getenv(key);if(value!=null)builder.environment().put(key,value);}builder.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);own=builder.start();own.getOutputStream().close();
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(35);Path result=control.resolve("manager-status.json");while(System.nanoTime()-end<0){if(Files.isRegularFile(result,LinkOption.NOFOLLOW_LINKS)&&Files.size(result)<4096){JsonObject status=JsonParser.parseString(Files.readString(result)).getAsJsonObject();if(nonce.equals(status.get("nonce").getAsString())){String state=status.get("state").getAsString();if(Set.of("RUNNING","ALREADY_RUNNING").contains(state))return;if(state.equals("FAILED"))throw new IOException("Личный Obsidian не запущен в изоляции: "+status.get("reason").getAsString());}}if(!own.isAlive())throw new IOException("Менеджер личной библиотеки завершился; небезопасный запуск отключён");Thread.sleep(40);}throw new IOException("Подготовка личного Obsidian ещё не подтверждена; обычный запуск отключён");
    }
    public synchronized boolean running(){return own!=null&&own.isAlive();}
    /** Own subprocess entry point. No account/root/device credentials are read or accepted. */
    public static void main(String[]args)throws Exception {
        try(var installationLease=org.securemail.client.maintenance600.RuntimeLease600.running()){runManager(args);}
    }
    private static void runManager(String[]args)throws Exception {
        if(args.length!=2||!args[0].equals("--manager"))throw new IllegalArgumentException("Private manager request required");Path request=Path.of(args[1]).toAbsolutePath().normalize();if(!request.toRealPath().equals(request)||Files.size(request)>16384)throw new IOException("Некорректный запрос менеджера");Path control=ObsidianDistribution600.directory(request.getParent());JsonObject j=JsonParser.parseString(Files.readString(request)).getAsJsonObject();String nonce=j.get("nonce").getAsString();UUID.fromString(nonce);
        try(FileChannel lockChannel=FileChannel.open(control.resolve("personal-manager.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
            FileLock lock=lockChannel.tryLock();if(lock==null){status(control,nonce,"ALREADY_RUNNING","");return;}
            try(lock){
                var release=new ObsidianDistribution600.Release(j.get("version").getAsString(),URI.create(j.get("source").getAsString()),j.get("size").getAsLong(),j.get("sha256").getAsString());
                var dist=ObsidianDistribution600.reopenLinux(Path.of(j.get("distribution").getAsString()),release,j.get("receiptSha256").getAsString());var profile=ObsidianProfile600.validate(ObsidianProfile600.Mode.PERSONAL,dist.binary(),ObsidianDistribution600.hash(dist.binary()),Path.of(j.get("vault").getAsString()),Path.of(j.get("configuration").getAsString()),Map.of());List<Path>hidden=new ArrayList<>();for(JsonElement e:j.getAsJsonArray("secrets"))hidden.add(Path.of(e.getAsString()));
                try(var boundary=new LinuxObsidianBoundary600(dist,profile,control,hidden)){Runtime.getRuntime().addShutdownHook(new Thread(()->{try{boundary.close();}catch(Exception ignored){}}));boundary.open(profile.vault());status(control,nonce,"RUNNING","");while(boundary.running())Thread.sleep(500);status(control,nonce,"STOPPED","");}
            }
        }catch(Exception failed){String reason=failed.getMessage();if(reason==null||reason.length()>500||reason.contains("\n"))reason="Проверьте системные компоненты и пространства имён";status(control,nonce,"FAILED",reason);throw failed;}
    }
    private static void status(Path control,String nonce,String state,String reason)throws IOException {JsonObject j=new JsonObject();j.addProperty("nonce",nonce);j.addProperty("state",state);j.addProperty("reason",reason);AtomicFiles.write(control.resolve("manager-status.json"),j.toString().getBytes(StandardCharsets.UTF_8));}
}
