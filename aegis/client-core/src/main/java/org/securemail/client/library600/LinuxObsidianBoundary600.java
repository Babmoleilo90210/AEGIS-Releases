package org.securemail.client.library600;

import org.securemail.client.safeweb.LinuxSafeWebSandbox;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Dedicated nested X display + bwrap user/PID/mount/network namespaces.
 * No network interface, host home/IPC/D-Bus/clipboard/audio/device mounts. Chromium's
 * own sandbox remains enabled: missing nested-userns support fails closed.
 * This confines this Obsidian process. A compromised host process under the same
 * OS account can still read host-owned files; that is not a mutual UID boundary. */
public final class LinuxObsidianBoundary600 implements AutoCloseable {
    private static final Path BWRAP=Path.of("/usr/bin/bwrap"),XEPHYR=Path.of("/usr/bin/Xephyr"),SLIRP=Path.of("/usr/bin/slirp4netns");
    private final ObsidianDistribution600 distribution;private final ObsidianProfile600.Plan profile;private final Path control;private final List<Path>secretPaths;
    private Process sandbox,display,network;private Path runtime;private final Set<ProcessHandle>children=new HashSet<>();private boolean closed;
    public LinuxObsidianBoundary600(ObsidianDistribution600 distribution,ObsidianProfile600.Plan profile,Path privateControl,Collection<Path>protectedSecrets)throws Exception {
        if(!profile.binary().equals(distribution.binary()))throw new IOException("Нужен отдельный проверенный защищённый профиль Obsidian");
        this.distribution=Objects.requireNonNull(distribution);this.profile=ObsidianProfile600.validate(profile.mode(),profile.binary(),ObsidianDistribution600.hash(distribution.binary()),profile.vault(),profile.configuration(),profile.approvedPlugins());control=ObsidianDistribution600.directory(privateControl);secretPaths=List.copyOf(protectedSecrets);
        if(profile.vault().startsWith(distribution.root())||distribution.root().startsWith(profile.vault())||control.startsWith(distribution.root())||control.startsWith(profile.vault()))throw new IOException("Каталоги профилей Obsidian пересекаются");
    }
    public synchronized void open(Path authorizedProjection)throws Exception {
        if(closed)throw new IOException("Защищённая библиотека заблокирована");if(profile.mode()==ObsidianProfile600.Mode.PERSONAL&&sandbox!=null&&sandbox.isAlive())return;
        if(sandbox!=null||display!=null)stopSession();distribution.verify();boolean personal=profile.mode()==ObsidianProfile600.Mode.PERSONAL;if(personal){if(!ObsidianDistribution600.directory(authorizedProjection).equals(profile.vault()))throw new IOException("Личный процесс получает только свой vault");for(Path secret:secretPaths){Path hidden=secret.toAbsolutePath().normalize();if(profile.vault().startsWith(hidden)||hidden.startsWith(profile.vault())||profile.configuration().startsWith(hidden)||hidden.startsWith(profile.configuration()))throw new IOException("Личный профиль пересекается с защищённым хранилищем");}}else validateProjection(authorizedProjection);LinuxSafeWebSandbox.checkHiddenPaths(secretPaths);
        if(!"Linux".equals(System.getProperty("os.name"))||!Set.of("amd64","x86_64").contains(System.getProperty("os.arch")))throw new IOException("Драйвер Obsidian требует Linux x86_64");
        trustedTool(BWRAP);trustedTool(XEPHYR);String host=System.getenv("DISPLAY");
        if(host==null||!host.matches(":[0-9]{1,5}(?:\\.[0-9]{1,3})?"))throw new IOException("Для защищённого Obsidian нужен локальный X11/Xwayland; прямой Wayland-доступ отключён");
        runtime=Files.createTempDirectory(control,"obsidian-session-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            Path settings=personal?profile.vault():prepareSettings(runtime,profile);if(personal){seedRegistry(profile.configuration().resolve("obsidian.json"),"/home/library/vault",true);trustedTool(SLIRP);Files.writeString(runtime.resolve("resolv.conf"),"nameserver 10.0.2.3\noptions timeout:2 attempts:2\n",StandardOpenOption.CREATE_NEW);}int number=100+new SecureRandom().nextInt(20000);Path socket=Path.of("/tmp/.X11-unix/X"+number);
            if(Files.exists(socket,LinkOption.NOFOLLOW_LINKS)||Files.exists(Path.of("/tmp/.X"+number+"-lock"),LinkOption.NOFOLLOW_LINKS))throw new IOException("Изолированный экран занят; повторите запуск");
            Path auth=runtime.resolve("Xauthority");cookie(auth,number);
            var screen=clean(List.of("/bin/sh","-c","exec 3<&0; \"$@\" 3<&- & child=$!; trap 'kill \"$child\" 2>/dev/null' HUP INT TERM; ( IFS= read -r value <&3; kill \"$child\" 2>/dev/null ) 0<&3 & monitor=$!; wait \"$child\"; result=$?; kill \"$monitor\" 2>/dev/null; exit \"$result\"","aegis-library-display",XEPHYR.toString(),":"+number,"-auth",auth.toString(),"-nolisten","tcp","-screen","1280x800","-resizeable","-terminate","-br","-title","АЕГИС — защищённая библиотека"));
            screen.environment().put("DISPLAY",host);String hostAuth=System.getenv("XAUTHORITY");Path hostCookie=hostAuth==null||hostAuth.isBlank()?Path.of(System.getProperty("user.home"),".Xauthority"):Path.of(hostAuth);if(Files.isRegularFile(hostCookie))screen.environment().put("XAUTHORITY",hostCookie.toRealPath().toString());screen.environment().put("HOME",runtime.toString());display=screen.start();
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);while(display.isAlive()&&!Files.exists(socket,LinkOption.NOFOLLOW_LINKS)&&System.nanoTime()-deadline<0)Thread.sleep(25);
            int uid=(Integer)Files.getAttribute(runtime,"unix:uid",LinkOption.NOFOLLOW_LINKS);
            if(!display.isAlive()||Files.isSymbolicLink(socket)||!Files.exists(socket,LinkOption.NOFOLLOW_LINKS)||((Integer)Files.getAttribute(socket,"unix:mode",LinkOption.NOFOLLOW_LINKS)&0170000)!=0140000||((Integer)Files.getAttribute(socket,"unix:uid",LinkOption.NOFOLLOW_LINKS))!=uid)throw new IOException("Xephyr не подтвердил собственный изолированный экран");
            ProcessBuilder app=clean(personal?personalCommand(distribution.root(),profile.vault(),profile.configuration(),auth,socket,number):command(distribution.root(),authorizedProjection.toRealPath(),settings,auth,socket,number));
            if(personal)app.redirectOutput(ProcessBuilder.Redirect.PIPE);sandbox=app.start();
            if(personal){long pid=readPid(sandbox);if(sandbox.descendants().noneMatch(child->child.pid()==pid))throw new IOException("Не подтверждён собственный PID пространства имён");network=clean(List.of(SLIRP.toString(),"--configure","--disable-host-loopback","--ready-fd=1","--exit-fd=0","--userns-path=/proc/"+pid+"/ns/user",Long.toString(pid),"tap0")).redirectOutput(ProcessBuilder.Redirect.PIPE).start();if(readByte(network,8)!='1'||!network.isAlive())throw new IOException("Личная сеть Obsidian не подготовлена; прямой fallback отключён");sandbox.getOutputStream().write(1);sandbox.getOutputStream().flush();}
            sandbox.getOutputStream().close();Thread.sleep(500);
            if(!sandbox.isAlive())throw new IOException("Obsidian не запустился в изоляции; проверьте namespaces и системные библиотеки. Ослабленный режим отключён");
            Process owned=sandbox;Thread.startVirtualThread(()->{try{owned.waitFor();synchronized(this){stopSession();}}catch(Exception ignored){/* close keeps ownership on failure */}});
        }catch(Exception failure){try{stopSession();}catch(Exception cleanup){failure.addSuppressed(cleanup);}throw failure;}
    }
    /** Fixed argv; no caller commands or shell interpolation. Namespace has no slirp/Tor/socket egress. */
    static List<String>command(Path bundle,Path projection,Path settings,Path auth,Path socket,int display){
        List<String>args=new ArrayList<>(List.of(BWRAP.toString(),"--die-with-parent","--new-session","--unshare-all","--cap-drop","ALL","--clearenv","--proc","/proc","--dev","/dev","--tmpfs","/tmp","--dir","/tmp/.X11-unix","--dir","/run","--dir","/home","--dir","/home/library","--dir","/home/library/vault","--dir","/home/library/config"));
        for(String system:List.of("/usr","/lib","/lib64","/etc/fonts","/etc/ssl/certs"))if(Files.exists(Path.of(system)))args.addAll(List.of("--ro-bind",system,system));
        args.addAll(List.of("--symlink","usr/bin","/bin","--symlink","usr/sbin","/sbin","--ro-bind",bundle.toString(),"/opt/obsidian","--ro-bind",projection.toString(),"/home/library/vault/"+projection.getFileName(),"--ro-bind",settings.toString(),"/home/library/vault/.obsidian","--ro-bind",auth.toString(),"/home/library/.Xauthority","--ro-bind",socket.toString(),"/tmp/.X11-unix/X"+display,"--setenv","HOME","/home/library","--setenv","XAUTHORITY","/home/library/.Xauthority","--setenv","DISPLAY",":"+display,"--setenv","PATH","/usr/bin:/bin","--setenv","LANG","C.UTF-8","--setenv","XDG_CONFIG_HOME","/home/library/config","--setenv","XDG_CACHE_HOME","/tmp/cache","--ro-bind",auth.getParent().resolve("obsidian.json").toString(),"/home/library/config/obsidian.json","--chdir","/home/library/vault","--","/opt/obsidian/obsidian","--user-data-dir=/home/library/config","obsidian://open?path=%2Fhome%2Flibrary%2Fvault%2F"+projection.getFileName()));return List.copyOf(args);
    }
    static List<String>personalCommand(Path bundle,Path vault,Path config,Path auth,Path socket,int display){
        List<String>base=new ArrayList<>(command(bundle,vault,vault,auth,socket,display));
        int metadata=base.indexOf("--proc");base.addAll(metadata,List.of("--info-fd","1","--block-fd","0"));
        int first=base.indexOf(vault.toString());base.set(first-1,"--bind");base.set(first+1,"/home/library/vault");
        // Remove the second readonly settings mount: the personal vault owns its .obsidian freely.
        int setting=base.indexOf("/home/library/vault/.obsidian");base.subList(setting-2,setting+1).clear();
        int registry=base.indexOf("/home/library/config/obsidian.json");base.subList(registry-2,registry+1).clear();int endpoint=base.indexOf("--setenv");base.addAll(endpoint,List.of("--bind",config.toString(),"/home/library/config","--ro-bind",auth.getParent().resolve("resolv.conf").toString(),"/etc/resolv.conf"));
        int execute=base.indexOf("--");List<String>app=List.copyOf(base.subList(execute+1,base.size()));base.subList(execute+1,base.size()).clear();base.addAll(List.of("/bin/sh","-c","exec \"$@\" </dev/null >/dev/null 2>&1","aegis-personal-obsidian"));base.addAll(app);base.set(base.size()-1,"obsidian://open?path=%2Fhome%2Flibrary%2Fvault");return List.copyOf(base);
    }
    private static long readPid(Process p)throws Exception {StringBuilder text=new StringBuilder();for(int n=0;n<8192;n++){int c=readByte(p,8);text.append((char)c);if(c=='}'){var m=java.util.regex.Pattern.compile("\\\"child-pid\\\"\\s*:\\s*([0-9]{1,10})").matcher(text);if(!m.find())throw new IOException("Нет PID namespace");return Long.parseLong(m.group(1));}}throw new IOException("Неверный ответ bwrap");}
    private static int readByte(Process p,int seconds)throws Exception {long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds);while(System.nanoTime()-deadline<0){if(p.getInputStream().available()>0)return p.getInputStream().read();if(!p.isAlive())throw new IOException("Процесс изоляции Obsidian завершился");Thread.sleep(20);}throw new IOException("Истекло время создания изоляции Obsidian");}
    static Path prepareSettings(Path run,ObsidianProfile600.Plan profile)throws Exception {
        seedRegistry(run.resolve("obsidian.json"),"/home/library/vault",false);Path settings=Files.createDirectory(run.resolve("settings"));List<String>plugins=new ArrayList<>(profile.approvedPlugins().keySet());Collections.sort(plugins);
        Files.writeString(settings.resolve("community-plugins.json"),new com.google.gson.Gson().toJson(plugins),StandardOpenOption.CREATE_NEW);
        Files.writeString(settings.resolve("core-plugins.json"),"[\"file-explorer\",\"global-search\",\"switcher\",\"graph\",\"backlink\",\"page-preview\",\"outline\"]",StandardOpenOption.CREATE_NEW);
        for(String name:plugins){Path source=profile.vault().resolve(".obsidian/plugins/"+name),dest=Files.createDirectories(settings.resolve("plugins/"+name));Files.copy(source.resolve("main.js"),dest.resolve("main.js"));if(!ObsidianDistribution600.hash(dest.resolve("main.js")).equals(profile.approvedPlugins().get(name)))throw new IOException("Изменён одобренный плагин");Path manifest=source.resolve("manifest.json");if(!Files.isRegularFile(manifest,LinkOption.NOFOLLOW_LINKS)||Files.size(manifest)>65536||!manifest.toRealPath().equals(manifest))throw new IOException("Небезопасный манифест плагина");Files.copy(manifest,dest.resolve("manifest.json"));}
        return settings;
    }
    static void seedRegistry(Path destination,String guestVault,boolean personal)throws Exception {
        com.google.gson.JsonObject root=new com.google.gson.JsonObject();if(personal&&Files.isRegularFile(destination,LinkOption.NOFOLLOW_LINKS)){try{root=com.google.gson.JsonParser.parseString(new String(org.securemail.client.storage.AtomicFiles.read(destination,1024*1024),StandardCharsets.UTF_8)).getAsJsonObject();}catch(Exception invalid){throw new IOException("Повреждён личный реестр Obsidian; исходный файл сохранён");}}
        com.google.gson.JsonObject entry=new com.google.gson.JsonObject();entry.addProperty("path",guestVault);entry.addProperty("ts",0);entry.addProperty("open",true);com.google.gson.JsonObject vaults=new com.google.gson.JsonObject();vaults.add("a600000000000001",entry);root.add("vaults",vaults);root.addProperty("language","ru");org.securemail.client.storage.AtomicFiles.write(destination,root.toString().getBytes(StandardCharsets.UTF_8));
    }
    private static void validateProjection(Path p)throws Exception {Path file=p.toAbsolutePath().normalize();if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||!file.toRealPath().equals(file)||Files.size(file)>1024*1024)throw new IOException("Нужна разрешённая отдельная проекция");String name=file.getFileName().toString();if(!name.endsWith(".md")||!UUID.fromString(name.substring(0,name.length()-3)).toString().concat(".md").equals(name)||!Files.isRegularFile(file.getParent().resolve(".aegis-projection-v1"),LinkOption.NOFOLLOW_LINKS))throw new IOException("Нужен отдельный управляемый UUID-файл");}
    static void trustedTool(Path path)throws IOException {if(!Files.isRegularFile(path)||!Files.isExecutable(path))throw new IOException("Отсутствует системный компонент: "+path.getFileName());Path real=path.toRealPath();for(Path leaf:List.of(path.toAbsolutePath().normalize(),real)){for(Path p=leaf;p!=null;p=p.getParent()){if((Integer)Files.getAttribute(p,"unix:uid",LinkOption.NOFOLLOW_LINKS)!=0||((Integer)Files.getAttribute(p,"unix:mode",LinkOption.NOFOLLOW_LINKS)&0022)!=0||Files.isSymbolicLink(p))throw new IOException("Небезопасные права системного компонента Obsidian");}}}
    private static ProcessBuilder clean(List<String>command){var builder=new ProcessBuilder(command);builder.environment().clear();builder.environment().put("PATH","/usr/bin:/bin");builder.environment().put("LANG","C.UTF-8");builder.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);return builder;}
    private static void cookie(Path file,int display)throws Exception {byte[]secret=new byte[16];new SecureRandom().nextBytes(secret);try(var out=new DataOutputStream(Files.newOutputStream(file,StandardOpenOption.CREATE_NEW))){out.writeShort(65535);field(out,new byte[0]);field(out,Integer.toString(display).getBytes(StandardCharsets.US_ASCII));field(out,"MIT-MAGIC-COOKIE-1".getBytes(StandardCharsets.US_ASCII));field(out,secret);}finally{Arrays.fill(secret,(byte)0);}Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-------"));}
    private static void field(DataOutputStream out,byte[]data)throws IOException{out.writeShort(data.length);out.write(data);}
    private synchronized void stopSession()throws Exception {
        Exception problem=null;for(Process owned:new Process[]{network,sandbox,display})if(owned!=null){owned.descendants().forEach(children::add);try{owned.destroy();if(!owned.waitFor(3,TimeUnit.SECONDS)){owned.destroyForcibly();owned.waitFor(3,TimeUnit.SECONDS);}owned.getOutputStream().close();}catch(Exception e){problem=e;}}
        for(ProcessHandle child:children)if(child.isAlive())child.destroy();for(ProcessHandle child:children)if(child.isAlive())child.destroyForcibly();
        if(network!=null&&network.isAlive()||sandbox!=null&&sandbox.isAlive()||display!=null&&display.isAlive()||children.stream().anyMatch(ProcessHandle::isAlive))throw new IOException("Собственные процессы Obsidian ещё завершаются",problem);
        if(problem!=null)throw problem;sandbox=null;display=null;network=null;children.clear();if(runtime!=null){ObsidianDistribution600.remove(runtime);runtime=null;}
    }
    public synchronized boolean running(){return sandbox!=null&&sandbox.isAlive()&&display!=null&&display.isAlive();}
    @Override public synchronized void close()throws Exception {closed=true;stopSession();}
}
