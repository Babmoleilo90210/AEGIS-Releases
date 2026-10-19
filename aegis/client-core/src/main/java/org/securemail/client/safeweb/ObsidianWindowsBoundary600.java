package org.securemail.client.safeweb;

import org.securemail.client.library600.WindowsObsidianPackage600;
import org.securemail.client.storage.AtomicFiles;
import com.sun.jna.platform.win32.Advapi32Util;
import java.io.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Dedicated Microsoft Windows Sandbox VM. No host installer execution, network,
 * clipboard, microphone, printer or host profile mapping; own ID only. Home is
 * unsupported. Guest installs an already pinned official package without UAC on
 * the host. Native Windows/Obsidian acceptance remains a separate required gate. */
public final class ObsidianWindowsBoundary600 implements AutoCloseable {
    private final WindowsObsidianPackage600 official;private final Path control;private final WindowsSandboxCli cli;
    private final ScheduledExecutorService heartbeat=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-obsidian-vm-lease");t.setDaemon(true);return t;});
    private String id;private Process viewer;private Path personalVault,personalConfiguration;private ScheduledFuture<?>pulse;private Path runtime;private boolean closed,attempted;private long leaseCounter;private FileChannel lockChannel;private FileLock lock;
    public ObsidianWindowsBoundary600(WindowsObsidianPackage600 official,Path privateControl)throws Exception {
        var env=WindowsSafeWebSandbox.requireEnvironment();this.official=Objects.requireNonNull(official);official.verify();control=directory(privateControl);cli=new WindowsSandboxCli(env.windows(),env.local(),control);recoverOwned();
    }
    /** Personal plugins remain unrestricted inside their own VM, never on the host. */
    public static ObsidianWindowsBoundary600 personal(WindowsObsidianPackage600 official,Path control,Path vault,Path configuration,Collection<Path>secrets)throws Exception {
        Path v=directory(vault),c=directory(configuration);if(v.startsWith(c)||c.startsWith(v))throw new IOException("Личные профили пересекаются");
        for(Path secret:secrets){Path p=secret.toAbsolutePath().normalize();if(v.startsWith(p)||p.startsWith(v)||c.startsWith(p)||p.startsWith(c))throw new IOException("Личный vault пересекается с защищённым хранилищем");}
        var driver=new ObsidianWindowsBoundary600(official,control);if(driver.control.startsWith(v)||driver.control.startsWith(c)||v.startsWith(driver.control)||c.startsWith(driver.control))throw new IOException("Контроллер не должен быть доступен личным плагинам");driver.personalVault=v;driver.personalConfiguration=c;return driver;
    }
    public synchronized void open(Path authorizedProjection)throws Exception {
        if(closed)throw new IOException("Защищённая библиотека заблокирована");if(id!=null&&Boolean.TRUE.equals(cli.list().get(id)))return;
        stopSession();official.verify();Path projection=personalVault==null?projectionFile(authorizedProjection):directory(authorizedProjection);if(personalVault!=null&&!personalVault.equals(projection))throw new IOException("Разрешён только собственный личный vault");lockChannel=FileChannel.open(control.resolve("obsidian-wsb.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);
        try{lock=lockChannel.tryLock();}catch(OverlappingFileLockException e){lockChannel.close();lockChannel=null;throw new IOException("Библиотека уже управляет Windows Sandbox");}if(lock==null){lockChannel.close();lockChannel=null;throw new IOException("Библиотека уже управляет Windows Sandbox");}
        try {
            // Do not adopt or stop a user's unrelated Sandbox. The CLI's one-VM
            // compatibility limitation is explicit instead of an unsafe fallback.
            if(cli.list().values().stream().anyMatch(Boolean::booleanValue))throw new IOException("Уже открыт Windows Sandbox; посторонняя VM не изменяется");
            id=UUID.randomUUID().toString();runtime=Files.createTempDirectory(control,"obsidian-vm-");AtomicFiles.directory(runtime);if(personalVault==null){Path payload=Files.createDirectory(runtime.resolve("payload"));AtomicFiles.write(payload.resolve(".aegis-projection-v1"),"AEGIS projection copy\n".getBytes(StandardCharsets.US_ASCII));byte[]content=Files.readAllBytes(projection);try{AtomicFiles.write(payload.resolve(projection.getFileName()),content);}finally{Arrays.fill(content,(byte)0);}projection=payload;}Path settings=Files.createDirectory(runtime.resolve("settings"));AtomicFiles.write(settings.resolve("community-plugins.json"),"[]".getBytes(StandardCharsets.US_ASCII));AtomicFiles.write(settings.resolve("core-plugins.json"),"[\"file-explorer\",\"global-search\",\"graph\",\"backlink\",\"outline\"]".getBytes(StandardCharsets.US_ASCII));
            AtomicFiles.write(runtime.resolve("start.ps1"),("\uFEFF"+(personalVault==null?bootstrap(official.installer().getFileName().toString()):personalBootstrap(official.installer().getFileName().toString()))).getBytes(StandardCharsets.UTF_8));AtomicFiles.write(runtime.resolve("lease"),(id+":"+(leaseCounter++)).getBytes(StandardCharsets.US_ASCII));
            AtomicFiles.write(control.resolve("owned-obsidian-vm-id"),id.getBytes(StandardCharsets.US_ASCII));AtomicFiles.write(runtime.resolve(".owner-vm-id"),id.getBytes(StandardCharsets.US_ASCII));
            List<Path>mapped=new ArrayList<>(List.of(official.directory(),projection,runtime));if(personalConfiguration!=null)mapped.add(personalConfiguration);for(Path root:mapped){try(var walk=Files.walk(root)){for(Path p:walk.toList())grantSystem(p);}}
            String config=personalVault==null?configuration(official.directory(),projection,runtime):personalConfiguration(official.directory(),projection,personalConfiguration,runtime);attempted=true;var started=cli.run(List.of("start","--id",id,"--config",config,"--raw"),Duration.ofMinutes(2));
            if(started.exit()!=0||!Boolean.TRUE.equals(cli.list().get(id)))throw new IOException("Windows Sandbox не подтвердил собственную VM библиотеки");
            viewer=cli.builder(List.of("connect","--id",id,"--raw")).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();viewer.getOutputStream().close();
            pulse=heartbeat.scheduleWithFixedDelay(()->{synchronized(this){if(closed||runtime==null)return;try{AtomicFiles.write(runtime.resolve("lease"),(id+":"+(leaseCounter++)).getBytes(StandardCharsets.US_ASCII));}catch(Exception failed){try{stopSession();}catch(Exception ignored){/* retained ID and receipt keep cleanup honest */}}}},3,3,TimeUnit.SECONDS);
        }catch(Exception failed){try{stopSession();}catch(Exception cleanup){failed.addSuppressed(cleanup);}throw failed;}
    }
    static String configuration(Path installer,Path projection,Path runtime){return "<Configuration><VGpu>Disable</VGpu><Networking>Disable</Networking><AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput><PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection><ProtectedClient>Enable</ProtectedClient><MappedFolders>"+mapping(installer,"C:\\ApprovedPackage")+mapping(projection,"C:\\ApprovedProjection")+mapping(runtime,"C:\\LibraryRuntime")+"</MappedFolders><LogonCommand><Command>powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\LibraryRuntime\\start.ps1</Command></LogonCommand><MemoryInMB>4096</MemoryInMB></Configuration>";}
    static String personalConfiguration(Path installer,Path vault,Path profile,Path runtime){return configuration(installer,vault,runtime).replace("<Networking>Disable</Networking>","<Networking>Enable</Networking>").replace(mapping(vault,"C:\\ApprovedProjection"),writableMapping(vault,"C:\\PersonalVault")+writableMapping(profile,"C:\\PersonalProfile"));}
    private static String writableMapping(Path host,String guest){return mapping(host,guest).replace("<ReadOnly>true</ReadOnly>","<ReadOnly>false</ReadOnly>");}
    static String personalBootstrap(String filename){String source=bootstrap(filename);int start=source.indexOf("New-Item -ItemType Directory -Path 'C:\\AEGISLibrary'");int end=source.indexOf("$process = Start-Process",start);if(start<0||end<0)throw new IllegalStateException("Fixed bootstrap changed");return (source.substring(0,start)+source.substring(end)).replace("--user-data-dir=C:\\AEGISProfile","--user-data-dir=C:\\PersonalProfile").replace("C%3A%5CAEGISLibrary","C%3A%5CPersonalVault").replace("$process = Start-Process","@{vaults=@{'a600000000000001'=@{path='C:\\PersonalVault';ts=0;open=$true}};language='ru'} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'C:\\PersonalProfile\\obsidian.json' -Encoding UTF8\n$process = Start-Process");}
    private static String mapping(Path host,String guest){return "<MappedFolder><HostFolder>"+xml(host.toString())+"</HostFolder><SandboxFolder>"+xml(guest)+"</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>";}
    private static String xml(String x){return x.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&apos;");}
    static String bootstrap(String filename){if(!filename.matches("Obsidian-[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.exe"))throw new IllegalArgumentException("Official installer only");return """
        $ErrorActionPreference = 'Stop'
        $installer = 'C:\\ApprovedPackage\\%s'
        $installed = 'C:\\AEGISObsidian'
        $result = Start-Process -FilePath $installer -ArgumentList @('/S', '/D=C:\\AEGISObsidian') -Wait -PassThru
        if ($result.ExitCode -ne 0) { exit 31 }
        New-Item -ItemType Directory -Path 'C:\\AEGISLibrary' -Force | Out-Null
        New-Item -ItemType Directory -Path 'C:\\AEGISProfile' -Force | Out-Null
        # Junctions stay wholly inside the disposable guest. Host mappings are readonly.
        New-Item -ItemType Junction -Path 'C:\\AEGISLibrary\\Материалы' -Target 'C:\\ApprovedProjection' | Out-Null
        New-Item -ItemType Junction -Path 'C:\\AEGISLibrary\\.obsidian' -Target 'C:\\LibraryRuntime\\settings' | Out-Null
        @{vaults=@{'a600000000000001'=@{path='C:\\AEGISLibrary';ts=0;open=$true}};language='ru'} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'C:\\AEGISProfile\\obsidian.json' -Encoding UTF8
        $process = Start-Process -FilePath 'C:\\AEGISObsidian\\Obsidian.exe' -ArgumentList @('--user-data-dir=C:\\AEGISProfile','obsidian://open?path=C%%3A%%5CAEGISLibrary') -PassThru
        $lastLease = ''
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
          $lease = Get-Content -LiteralPath 'C:\\LibraryRuntime\\lease' -Raw
          if ($lease -ne $lastLease) { $lastLease = $lease; $clock.Restart() }
          if ($clock.Elapsed.TotalSeconds -gt 20) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue; exit 32 }
          Start-Sleep -Seconds 2
        }
        """.formatted(filename);}
    private static Path projectionFile(Path p)throws IOException {Path file=p.toAbsolutePath().normalize();if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||!file.toRealPath().equals(file)||Files.size(file)>1024*1024)throw new IOException("Нужен отдельный файл ACL-проекции");String n=file.getFileName().toString();try{if(!n.endsWith(".md")||!UUID.fromString(n.substring(0,n.length()-3)).toString().concat(".md").equals(n)||!Files.isRegularFile(file.getParent().resolve(".aegis-projection-v1"),LinkOption.NOFOLLOW_LINKS))throw new IOException("Нужен управляемый UUID-файл");}catch(IllegalArgumentException bad){throw new IOException("Некорректный UUID-файл");}return file;}
    private static Path directory(Path p)throws IOException {Path n=p.toAbsolutePath().normalize();if(!Files.isDirectory(n,LinkOption.NOFOLLOW_LINKS)||!n.toRealPath().equals(n))throw new IOException("Небезопасный каталог библиотеки");return n;}
    private static void grantSystem(Path path)throws IOException {var view=Files.getFileAttributeView(path,AclFileAttributeView.class,LinkOption.NOFOLLOW_LINKS);if(view==null)throw new IOException("Windows Sandbox требует NTFS ACL");var lookup=path.getFileSystem().getUserPrincipalLookupService();var owner=lookup.lookupPrincipalByName(System.getProperty("user.name"));var system=lookup.lookupPrincipalByName(Advapi32Util.getAccountBySid("S-1-5-18").fqn);List<AclEntry>entries=new ArrayList<>();for(var who:List.of(owner,system)){var e=AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(who).setPermissions(EnumSet.allOf(AclEntryPermission.class));if(Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))e.setFlags(AclEntryFlag.FILE_INHERIT,AclEntryFlag.DIRECTORY_INHERIT);entries.add(e.build());}view.setAcl(entries);}
    /** Reconciles only a host-private owned receipt after acquiring this controller's OS lock. */
    private void recoverOwned()throws Exception {
        Path receipt=control.resolve("owned-obsidian-vm-id");if(!Files.exists(receipt,LinkOption.NOFOLLOW_LINKS))return;
        if(Files.isSymbolicLink(receipt)||!receipt.toRealPath().equals(receipt)||Files.size(receipt)!=36)throw new IOException("Повреждена запись принадлежности VM библиотеки");String previous=Files.readString(receipt,StandardCharsets.US_ASCII);if(!UUID.fromString(previous).toString().equals(previous))throw new IOException("Недостоверный ID собственной VM");
        try(FileChannel channel=FileChannel.open(control.resolve("obsidian-wsb.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){FileLock held;try{held=channel.tryLock();}catch(OverlappingFileLockException busy){throw new IOException("Менеджер библиотеки уже работает");}if(held==null)throw new IOException("Менеджер библиотеки уже работает");try(held){if(Boolean.TRUE.equals(cli.list().get(previous)))cli.stop(previous);if(Boolean.TRUE.equals(cli.list().get(previous)))throw new IOException("Остановка прежней собственной VM не подтверждена");Files.delete(receipt);}}
    }
    public synchronized boolean running()throws IOException{return id!=null&&Boolean.TRUE.equals(cli.list().get(id));}
    private synchronized void stopSession()throws Exception {
        if(pulse!=null){pulse.cancel(false);pulse=null;}
        if(id!=null&&attempted){cli.stop(id);if(Boolean.TRUE.equals(cli.list().get(id)))throw new IOException("Остановка собственной VM Obsidian не подтверждена; файлы сохранены");}
        if(viewer!=null&&viewer.isAlive()){viewer.destroy();if(!viewer.waitFor(3,TimeUnit.SECONDS)){viewer.destroyForcibly();viewer.waitFor(3,TimeUnit.SECONDS);}if(viewer.isAlive())throw new IOException("Просмотр собственной VM ещё завершается");}viewer=null;
        if(runtime!=null){try(var paths=Files.walk(runtime)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}runtime=null;}
        Files.deleteIfExists(control.resolve("owned-obsidian-vm-id"));attempted=false;id=null;if(lock!=null){lock.release();lock=null;}if(lockChannel!=null){lockChannel.close();lockChannel=null;}
    }
    @Override public synchronized void close()throws Exception {closed=true;heartbeat.shutdownNow();stopSession();}
}
