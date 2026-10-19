package org.securemail.client.library600;

import org.securemail.client.storage.AtomicFiles;
import org.securemail.client.update.UpdateService;
import java.io.*;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import java.util.function.BooleanSupplier;

/** Verified official Windows installer, never executed on the host by this class.
 * The isolated guest installs it for one VM only. HTTPS+reviewed SHA trust, not an invented PGP signature. */
public final class WindowsObsidianPackage600 {
    public record Release(String version,URI source,long size,String sha256){public Release{
        if(version==null||!version.matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")||size<1||size>512L*1024*1024||sha256==null||!sha256.matches("[a-f0-9]{64}")||!URI.create("https://github.com/obsidianmd/obsidian-releases/releases/download/v"+version+"/Obsidian-"+version+".exe").equals(source))throw new IllegalArgumentException("Official reviewed Obsidian Windows release required");
    }}
    private final Release release;private final Path directory,installer;
    private WindowsObsidianPackage600(Release release,Path directory){this.release=release;this.directory=directory;installer=directory.resolve("Obsidian-"+release.version()+".exe");}
    public static WindowsObsidianPackage600 install(Release release,Path target,int socksPort,BooleanSupplier cancel,UpdateService.Progress progress)throws Exception {
        Path dest=target.toAbsolutePath().normalize(),parent=ObsidianDistribution600.directory(dest.getParent());if(Files.exists(dest,LinkOption.NOFOLLOW_LINKS))throw new IOException("Нужен новый каталог официального пакета");Path stage=Files.createTempDirectory(parent,".obsidian-windows-");AtomicFiles.directory(stage);
        try {Path exe=stage.resolve("Obsidian-"+release.version()+".exe");ObsidianHttps600.download(release.source(),exe,release.size(),socksPort,cancel,progress);if(!ObsidianDistribution600.hash(exe).equals(release.sha256()))throw new IOException("Подпись inventory/SHA-256 Obsidian не совпала");if(cancel.getAsBoolean())throw new InterruptedIOException("Установка Obsidian отменена");Files.move(stage,dest,StandardCopyOption.ATOMIC_MOVE);return new WindowsObsidianPackage600(release,dest);}finally{ObsidianDistribution600.remove(stage);}
    }
    /** Release itself must originate in owner-approved Core inventory. */
    public static WindowsObsidianPackage600 reopen(Release release,Path directory)throws Exception {var p=new WindowsObsidianPackage600(release,ObsidianDistribution600.directory(directory));p.verify();return p;}
    public void verify()throws Exception {ObsidianDistribution600.directory(directory);try(var files=Files.list(directory)){List<Path>all=files.toList();if(all.size()!=1||!all.getFirst().equals(installer))throw new IOException("Посторонние файлы в официальном пакете Obsidian");}if(Files.size(installer)!=release.size()||!ObsidianDistribution600.hash(installer).equals(release.sha256()))throw new IOException("Официальный пакет Obsidian изменён");}
    public Release release(){return release;}public Path directory(){return directory;}public Path installer(){return installer;}
}
