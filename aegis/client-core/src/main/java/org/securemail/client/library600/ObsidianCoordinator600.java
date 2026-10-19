package org.securemail.client.library600;

import com.google.gson.*;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.client.safeweb.ObsidianWindowsBoundary600;
import org.securemail.client.update.UpdateService;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;

/** Core assembler. Worker-thread API only; no account/root/device key enters any
 * third-party process. Personal manager is independent. Protected process owns
 * exactly ONE currently authorized file and is stopped on local lease deletion. */
public final class ObsidianCoordinator600 implements AutoCloseable {
    public static final ObsidianDistribution600.Release LINUX=new ObsidianDistribution600.Release("1.14.4",URI.create("https://github.com/obsidianmd/obsidian-releases/releases/download/v1.14.4/obsidian-1.14.4.tar.gz"),131209322,"e70b7cd63787e7f798a84fec453f5c446b91877bd3f612e8fb98e9b76cc81120");
    public static final WindowsObsidianPackage600.Release WINDOWS=new WindowsObsidianPackage600.Release("1.14.4",URI.create("https://github.com/obsidianmd/obsidian-releases/releases/download/v1.14.4/Obsidian-1.14.4.exe"),341331008,"28662520368d5956df7798076b8370ac730164a8863dcd4f678ced53f63faa00");
    private final Path profile,bundle,control,distributionRoot,personalRoot;private final int socks;private final List<Path>secrets;private final Object installMutex=new Object(),protectedMutex=new Object();private final AtomicLong epoch=new AtomicLong();
    private AutoCloseable protectedDriver;private Path protectedFile;private Object fileKey;private long modified;private ScheduledFuture<?>fileWatch;private volatile Exception cleanupFailure;
    private final ScheduledExecutorService watch=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-protected-obsidian-guard");t.setDaemon(true);return t;});
    public ObsidianCoordinator600(Path profile,Path bundle,int downloadSocksPort,List<Path>protectedRoots)throws Exception {
        if(downloadSocksPort<1||downloadSocksPort>65535)throw new IllegalArgumentException("Tor HTTPS SOCKS port required");AtomicFiles.directory(profile);this.profile=ObsidianDistribution600.directory(profile);this.bundle=bundle.toAbsolutePath().normalize();socks=downloadSocksPort;
        control=privateDir(this.profile.resolve("core600/obsidian-control"));List<Path>hidden=new ArrayList<>(protectedRoots);hidden.add(this.profile);hidden.add(this.profile.resolveSibling("aegis-library-projection600"));secrets=List.copyOf(hidden);
        Path data=platformData();distributionRoot=privateDir(data.resolve("AEGIS-Obsidian600"));personalRoot=privateDir(data.resolve("AEGIS-PersonalObsidian600"));for(Path secret:secrets)if(personalRoot.startsWith(secret.toAbsolutePath().normalize())||secret.toAbsolutePath().normalize().startsWith(personalRoot))throw new IOException("Личный Obsidian должен находиться вне защищённых каталогов АЕГИС");
    }
    public void openPersonal(UpdateService.Progress progress,BooleanSupplier cancel)throws Exception {
        Path vault=privateDir(personalRoot.resolve("vault")),configuration=privateDir(personalRoot.resolve("profile")),manager=privateDir(control.resolve("personal-manager"));
        if(windows()){var pkg=ensureWindows(progress,cancel);new WindowsPersonalObsidianLauncher600(pkg,vault,configuration,manager,secrets).open();}
        else{var d=ensureLinux(progress,cancel);var plan=ObsidianProfile600.validate(ObsidianProfile600.Mode.PERSONAL,d.binary(),ObsidianDistribution600.hash(d.binary()),vault,configuration,Map.of());new PersonalObsidianLauncher600(d,plan,manager,secrets).open();}
    }
    public void openProtected(Path authorizedFile,UpdateService.Progress progress,BooleanSupplier cancel)throws Exception {
        closeProtected();long generation=epoch.get();Path file=authorizedFile.toAbsolutePath().normalize(),expected=profile.resolveSibling("aegis-library-projection600").toAbsolutePath().normalize();
        if(!file.startsWith(expected)||file.getNameCount()-expected.getNameCount()!=3||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||!file.toRealPath().equals(file)||Files.size(file)>1024*1024||!Files.isRegularFile(file.getParent().resolve(".aegis-projection-v1"),LinkOption.NOFOLLOW_LINKS))throw new IOException("Защищённый Obsidian получает только отдельный файл действующего коннектора");
        BooleanSupplier aborted=()->cancel.getAsBoolean()||epoch.get()!=generation;AutoCloseable driver;
        if(windows()){var pkg=ensureWindows(progress,aborted);driver=new ObsidianWindowsBoundary600(pkg,privateDir(control.resolve("protected-windows")));}
        else{var d=ensureLinux(progress,aborted);Path vault=privateDir(control.resolve("protected-vault")),config=privateDir(control.resolve("protected-profile"));var plan=ObsidianProfile600.validate(ObsidianProfile600.Mode.PROTECTED,d.binary(),ObsidianDistribution600.hash(d.binary()),vault,config,Map.of());driver=new LinuxObsidianBoundary600(d,plan,privateDir(control.resolve("protected-linux")),secrets);}
        if(aborted.getAsBoolean()){driver.close();throw new InterruptedIOException("Открытие защищённой библиотеки отменено");}
        synchronized(protectedMutex){if(epoch.get()!=generation){driver.close();throw new InterruptedIOException("Доступ к библиотеке отозван");}protectedDriver=driver;protectedFile=file;BasicFileAttributes attributes=Files.readAttributes(file,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);fileKey=attributes.fileKey();modified=attributes.lastModifiedTime().toMillis();}
        try{if(driver instanceof LinuxObsidianBoundary600 linux)linux.open(file);else ((ObsidianWindowsBoundary600)driver).open(file);synchronized(protectedMutex){if(epoch.get()!=generation)throw new InterruptedIOException("Доступ отозван");fileWatch=watch.scheduleWithFixedDelay(this::guardProjection,1,1,TimeUnit.SECONDS);}}
        catch(Exception failure){try{closeProtected();}catch(Exception cleanup){failure.addSuppressed(cleanup);}throw failure;}
    }
    private void guardProjection(){try{synchronized(protectedMutex){if(protectedFile==null)return;var a=Files.readAttributes(protectedFile,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);if(!a.isRegularFile()||!Objects.equals(fileKey,a.fileKey())||modified!=a.lastModifiedTime().toMillis())throw new IOException("Проекция истекла или изменена");}}catch(Exception removed){try{closeProtected();}catch(Exception failed){cleanupFailure=failed;}}}
    /** Waits for actual own namespace/VM stop; failure is never acknowledged as successful cleanup. */
    public void closeProtected()throws Exception {epoch.incrementAndGet();synchronized(protectedMutex){if(fileWatch!=null){fileWatch.cancel(false);fileWatch=null;}if(protectedDriver!=null){protectedDriver.close();protectedDriver=null;}protectedFile=null;fileKey=null;if(cleanupFailure!=null){Exception prior=cleanupFailure;cleanupFailure=null;throw prior;}}}
    private ObsidianDistribution600 ensureLinux(UpdateService.Progress progress,BooleanSupplier cancel)throws Exception {
        synchronized(installMutex){progress.accept(0,-1);Path state=control.resolve("linux-distribution.json");if(Files.isRegularFile(state,LinkOption.NOFOLLOW_LINKS)){var j=JsonParser.parseString(new String(AtomicFiles.read(state,4096),StandardCharsets.UTF_8)).getAsJsonObject();Path root=distributionRoot.resolve(j.get("folder").getAsString()).normalize();if(!root.getParent().equals(distributionRoot))throw new IOException("Подмена каталога Obsidian");return ObsidianDistribution600.reopenLinux(root,LINUX,j.get("receiptSha256").getAsString());}
            Path target=distributionRoot.resolve("linux-"+LINUX.version()+"-"+UUID.randomUUID());var d=ObsidianDistribution600.installLinux(LINUX,target,socks,cancel,progress);JsonObject j=new JsonObject();j.addProperty("folder",target.getFileName().toString());j.addProperty("receiptSha256",d.receiptSha256());AtomicFiles.write(state,j.toString().getBytes(StandardCharsets.UTF_8));return d;}
    }
    private WindowsObsidianPackage600 ensureWindows(UpdateService.Progress progress,BooleanSupplier cancel)throws Exception {
        synchronized(installMutex){progress.accept(0,-1);Path target=distributionRoot.resolve("windows-"+WINDOWS.version());if(Files.exists(target,LinkOption.NOFOLLOW_LINKS))return WindowsObsidianPackage600.reopen(WINDOWS,target);return WindowsObsidianPackage600.install(WINDOWS,target,socks,cancel,progress);}
    }
    private static boolean windows(){return System.getProperty("os.name","").startsWith("Windows");}
    private static Path platformData()throws Exception {if(windows())return Path.of(com.sun.jna.platform.win32.Shell32Util.getKnownFolderPath(com.sun.jna.platform.win32.KnownFolders.FOLDERID_LocalAppData)).toRealPath();String x=System.getenv("XDG_DATA_HOME");Path path=x==null||x.isBlank()?Path.of(System.getProperty("user.home"),".local/share"):Path.of(x);Files.createDirectories(path);return ObsidianDistribution600.directory(path);}
    private static Path privateDir(Path path)throws Exception {AtomicFiles.directory(path);return ObsidianDistribution600.directory(path);}
    @Override public void close()throws Exception {try{closeProtected();}finally{watch.shutdownNow();}/* independent personal managers intentionally keep running */}
}
