package org.securemail.client.library600;

import com.google.gson.*;
import org.apache.commons.compress.archivers.tar.*;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.securemail.client.update.*;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.BooleanSupplier;

/** Official HTTPS source + an independently reviewed release SHA-256 pin.
 * This is NOT a vendor OpenPGP signature. Owner signing of the release inventory
 * is external. No arbitrary URL, repository, installer execution or repackaging. */
public final class ObsidianDistribution600 {
    public record Release(String version,URI source,long size,String sha256) {
        public Release {
            if(version==null||!version.matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")||size<1||size>512L*1024*1024||sha256==null||!sha256.matches("[a-f0-9]{64}"))throw new IllegalArgumentException("Reviewed Obsidian release pin required");
            String expected="https://github.com/obsidianmd/obsidian-releases/releases/download/v"+version+"/obsidian-"+version+".tar.gz";
            if(!expected.equals(Objects.requireNonNull(source).toASCIIString()))throw new IllegalArgumentException("Official Linux Obsidian tarball required");
        }
    }
    @FunctionalInterface interface Fetch {void download(Release release,Path target,BooleanSupplier cancel)throws Exception;}
    private final Path root,binary;private final String version,receiptSha;private final Release release;private final Map<String,String>files;
    private ObsidianDistribution600(Path root,Path binary,Release release,String receiptSha,Map<String,String>files){this.root=root;this.binary=binary;this.version=release.version();this.release=release;this.receiptSha=receiptSha;this.files=Map.copyOf(files);}
    public Release release(){return release;}public Path root(){return root;}public Path binary(){return binary;}public String version(){return version;}public String receiptSha256(){return receiptSha;}
    /** Caller obtains release pins from the owner-approved signed inventory, not a file-selection dialogue. */
    public static ObsidianDistribution600 installLinux(Release release,Path destination,int socksPort,BooleanSupplier cancelled,UpdateService.Progress progress)throws Exception {
        return install(release,destination,cancelled,(r,target,cancel)->ObsidianHttps600.download(r.source(),target,r.size(),socksPort,cancel,progress));
    }
    static ObsidianDistribution600 install(Release release,Path destination,BooleanSupplier cancel,Fetch fetch)throws Exception {
        Path target=destination.toAbsolutePath().normalize(),parent=directory(target.getParent());
        if(!target.getParent().equals(parent)||Files.exists(target,LinkOption.NOFOLLOW_LINKS))throw new IOException("Установка Obsidian требует нового отдельного каталога");
        Path stage=Files.createTempDirectory(parent,".obsidian-install-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            Path archive=stage.resolve("official.tar.gz");fetch.download(release,archive,cancel);cancel(cancel);
            if(Files.size(archive)!=release.size()||!hash(archive).equals(release.sha256()))throw new IOException("Контрольная сумма официального Obsidian не совпала");
            Path payload=Files.createDirectory(stage.resolve("payload"));extract(archive,payload,cancel);Files.delete(archive);
            Path binary;
            try(var walk=Files.walk(payload)){List<Path>entries=walk.filter(p->p.getFileName().toString().equals("obsidian")&&Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)).toList();if(entries.size()!=1)throw new IOException("Не найден однозначный исполняемый файл Obsidian");binary=entries.getFirst();}
            Path bundle=binary.getParent();if(!Files.isRegularFile(bundle.resolve("resources/app.asar"),LinkOption.NOFOLLOW_LINKS))throw new IOException("Официальный пакет Obsidian неполон");
            Map<String,String>files=tree(bundle);JsonObject receipt=new JsonObject();receipt.addProperty("format","AEGIS-OBSIDIAN-DISTRIBUTION/v1");receipt.addProperty("version",release.version());receipt.addProperty("source",release.source().toASCIIString());receipt.addProperty("archiveSize",release.size());receipt.addProperty("archiveSha256",release.sha256());receipt.addProperty("trust","official HTTPS through Tor + owner-reviewed SHA-256");JsonObject hashes=new JsonObject();files.forEach(hashes::addProperty);receipt.add("files",hashes);
            byte[] bytes=receipt.toString().getBytes(StandardCharsets.UTF_8);Path marker=bundle.resolve(".aegis-official-distribution.json");Files.write(marker,bytes,StandardOpenOption.CREATE_NEW);Files.setPosixFilePermissions(marker,PosixFilePermissions.fromString("rw-------"));String receiptSha=hash(marker);
            cancel(cancel);Files.move(bundle,target,StandardCopyOption.ATOMIC_MOVE);return new ObsidianDistribution600(target,target.resolve("obsidian"),release,receiptSha,files);
        } finally {remove(stage);}
    }
    /** Restart requires the receipt digest pinned by trusted Core configuration. */
    public static ObsidianDistribution600 reopenLinux(Path root,Release release,String expectedReceiptSha)throws Exception {
        Path real=directory(root),marker=real.resolve(".aegis-official-distribution.json");
        if(expectedReceiptSha==null||!expectedReceiptSha.matches("[a-f0-9]{64}")||Files.size(marker)>4*1024*1024||!hash(marker).equals(expectedReceiptSha))throw new IOException("Не подтверждён pin установленного Obsidian");
        JsonObject json=JsonParser.parseString(Files.readString(marker)).getAsJsonObject();
        if(!"AEGIS-OBSIDIAN-DISTRIBUTION/v1".equals(json.get("format").getAsString())||!release.version().equals(json.get("version").getAsString())||!release.source().toASCIIString().equals(json.get("source").getAsString())||release.size()!=json.get("archiveSize").getAsLong()||!release.sha256().equals(json.get("archiveSha256").getAsString()))throw new IOException("Подмена происхождения Obsidian");
        Map<String,String>files=new TreeMap<>();for(var e:json.getAsJsonObject("files").entrySet())if(files.put(e.getKey(),e.getValue().getAsString())!=null)throw new IOException("Повторный файл");
        var result=new ObsidianDistribution600(real,real.resolve("obsidian"),release,expectedReceiptSha,files);result.verify();return result;
    }
    public void verify()throws Exception {
        if(!hash(root.resolve(".aegis-official-distribution.json")).equals(receiptSha)||!files.equals(tree(root)))throw new IOException("Установленный Obsidian изменён; запуск запрещён");
        if(!Files.isExecutable(binary))throw new IOException("Obsidian не является исполняемым файлом");
    }
    private static void extract(Path archive,Path root,BooleanSupplier cancel)throws Exception {
        long total=0;int entries=0;Set<Path>seen=new HashSet<>();
        try(var in=new TarArchiveInputStream(new GzipCompressorInputStream(Files.newInputStream(archive)))){
            for(TarArchiveEntry e;(e=in.getNextEntry())!=null;){cancel(cancel);if(++entries>20000||e.getName().length()>512||e.isSymbolicLink()||e.isLink()||(!e.isDirectory()&&!e.isFile())||!in.canReadEntryData(e))throw new IOException("Небезопасный элемент пакета Obsidian");
                String name=e.getName();Path relative=Path.of(name).normalize(),dest=root.resolve(relative).normalize();if(name.contains("\\")||name.indexOf('\0')>=0||relative.isAbsolute()||relative.startsWith("..")||!dest.startsWith(root)||dest.equals(root)||!seen.add(dest))throw new IOException("Выход за каталог пакета Obsidian");
                if(e.isDirectory()){Files.createDirectories(dest);continue;}long size=e.getSize();if(size<0||size>512L*1024*1024||(total+=size)>2L*1024*1024*1024)throw new IOException("Пакет Obsidian превышает лимит");Files.createDirectories(dest.getParent());try(var out=Files.newOutputStream(dest,StandardOpenOption.CREATE_NEW)){byte[]buf=new byte[65536];long n=0;for(int count;(count=in.read(buf))!=-1;){cancel(cancel);n+=count;if(n>size)throw new IOException("Неверный размер файла");out.write(buf,0,count);}if(n!=size)throw new EOFException();}Files.setPosixFilePermissions(dest,PosixFilePermissions.fromString((e.getMode()&0111)!=0?"rwx------":"rw-------"));
            }
        }
    }
    private static Map<String,String>tree(Path root)throws Exception {directory(root);Map<String,String>result=new TreeMap<>();long total=0;int entries=0;try(var walk=Files.walk(root)){var iterator=walk.iterator();while(iterator.hasNext()){Path p=iterator.next();if(++entries>20000)throw new IOException("Слишком много элементов пакета");if(Files.isSymbolicLink(p))throw new IOException("Ссылка в пакете Obsidian");if(Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS))continue;if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))throw new IOException("Необычный файл пакета Obsidian");long size=Files.size(p);if(size>512L*1024*1024||(total+=size)>2L*1024*1024*1024)throw new IOException("Размер дерева Obsidian превышает лимит");if(p.equals(root.resolve(".aegis-official-distribution.json")))continue;result.put(root.relativize(p).toString().replace('\\','/'),hash(p));}}return result;}
    static Path directory(Path p)throws IOException {Path n=p.toAbsolutePath().normalize();if(!Files.isDirectory(n,LinkOption.NOFOLLOW_LINKS)||!n.toRealPath().equals(n))throw new IOException("Небезопасный каталог Obsidian");return n;}
    static String hash(Path p)throws Exception {if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||!p.toRealPath().equals(p.toAbsolutePath().normalize()))throw new IOException("Небезопасный файл Obsidian");MessageDigest d=MessageDigest.getInstance("SHA-256");try(var in=Files.newInputStream(p)){byte[]b=new byte[65536];for(int n;(n=in.read(b))!=-1;)d.update(b,0,n);}return HexFormat.of().formatHex(d.digest());}
    static void remove(Path root)throws IOException {if(!Files.exists(root,LinkOption.NOFOLLOW_LINKS))return;try(var walk=Files.walk(root)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    private static void cancel(BooleanSupplier cancel)throws InterruptedIOException{if(cancel.getAsBoolean()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("Подготовка Obsidian отменена");}
}
