package org.securemail.client.safeweb;

import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.*;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import org.securemail.client.ClientConfig;
import org.securemail.client.storage.AtomicFiles;

/** Downloads authentic official Tor Browser packages through the messenger's Tor.
 * Metadata supplies a release candidate; the pinned OpenPGP signature authenticates
 * the actual package. No browser, archive, account password, or release key is read.
 * There is no direct-network fallback and no custom Tor Browser update feed.
 */
public final class TorBrowserDownloadService {
    public enum Platform {
        LINUX_X64("linux-x86_64", "linux-x86_64", ".tar.xz"),
        WINDOWS_X64("windows-x86_64", "windows-x86_64-portable", ".exe");
        final String endpoint, packagePlatform, extension;
        Platform(String endpoint, String packagePlatform, String extension) { this.endpoint=endpoint; this.packagePlatform=packagePlatform; this.extension=extension; }
        public URI metadataUri() { return URI.create("https://aus1.torproject.org/torbrowser/update_3/release/download-"+endpoint+".json"); }
        public static Platform current() throws IOException { return detect(System.getProperty("os.name", ""), System.getProperty("os.arch", "")); }
        static Platform detect(String os, String arch) throws IOException {
            if (!Set.of("amd64", "x86_64").contains(arch.toLowerCase(Locale.ROOT))) throw new IOException("Автоустановка Tor Browser поддерживает только x86_64");
            if (os.startsWith("Windows")) return WINDOWS_X64;
            if (os.equals("Linux")) return LINUX_X64;
            throw new IOException("Автоустановка Tor Browser доступна в Windows и Linux");
        }
    }
    public enum Stage { WAITING_FOR_TOR, RELEASE_METADATA, PACKAGE_DOWNLOAD, SIGNATURE_DOWNLOAD, VERIFYING, READY, CANCELLED, FAILED }
    public record Progress(Stage stage, long downloaded, long total, String message) { }
    @FunctionalInterface public interface ProgressListener { void update(Progress progress); }
    public record Release(Platform platform, String version, String gitTag, URI binary, URI signature) {
        public String filename() { return binary.getPath().substring(binary.getPath().lastIndexOf('/')+1); }
    }
    /** Cancel closes the active, owned HTTPS/SOCKS socket immediately; never another process. */
    public static final class Cancellation {
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final AtomicReference<Closeable> active = new AtomicReference<>();
        public void cancel() { cancelled.set(true); close(active.getAndSet(null)); }
        public boolean cancelled() { return cancelled.get() || Thread.currentThread().isInterrupted(); }
        void check() throws InterruptedIOException { if (cancelled()) throw new InterruptedIOException("Загрузка Tor Browser отменена"); }
        void attach(Closeable resource) throws IOException {
            check();
            if (!active.compareAndSet(null, resource)) { close(resource); throw new IOException("Одна отмена не может управлять параллельными загрузками"); }
            if (cancelled()) { close(active.getAndSet(null)); check(); }
        }
        void detach(Closeable resource) { active.compareAndSet(resource, null); }
        private static void close(Closeable resource) { if (resource!=null) try { resource.close(); } catch(IOException ignored) { } }
    }
    /** Files exist only in an owner-only directory outside every browser session.
     * Close after the existing authenticated installer has imported its own snapshot. */
    public static final class VerifiedPackage implements AutoCloseable {
        private final Path directory, archive, signature;
        private final Release release;
        private final TorBrowserSignature.Verified verification;
        private boolean closed;
        VerifiedPackage(Path directory,Path archive,Path signature,Release release,TorBrowserSignature.Verified verification) {
            this.directory=directory;this.archive=archive;this.signature=signature;this.release=release;this.verification=verification;
        }
        public synchronized Path archive() { ensureOpen(); return archive; }
        public synchronized Path signature() { ensureOpen(); return signature; }
        public Release release() { return release; }
        public TorBrowserSignature.Verified verification() { return verification; }
        private void ensureOpen() { if(closed)throw new IllegalStateException("Пакет Tor Browser уже очищен"); }
        @Override public synchronized void close() throws IOException { if(!closed){deleteOwnDirectory(directory);closed=true;} }
    }
    @FunctionalInterface interface BytesProgress { void update(long bytes,long total); }
    interface Fetcher { void fetch(URI uri, OutputStream destination, long limit, Cancellation cancel, BytesProgress progress) throws IOException; }
    @FunctionalInterface interface Verifier { TorBrowserSignature.Verified verify(Path archive,Path signature) throws IOException; }
    private static final long MAX_PACKAGE=1_000_000_000L;
    private static final int MAX_METADATA=16_384,MAX_SIGNATURE=65_536;
    private static final Object RELEASE_FLOOR_LOCK=new Object();
    private final BooleanSupplier torReady;
    private final Fetcher fetcher;
    private final Verifier verifier;
    public TorBrowserDownloadService(ClientConfig config, BooleanSupplier torReady) {
        this(torReady,new TorBrowserHttps(Objects.requireNonNull(config).torUpdateSocksPort()),TorBrowserSignature::verify);
    }
    TorBrowserDownloadService(BooleanSupplier torReady,Fetcher fetcher,Verifier verifier) { this.torReady=Objects.requireNonNull(torReady);this.fetcher=Objects.requireNonNull(fetcher);this.verifier=Objects.requireNonNull(verifier); }
    public VerifiedPackage downloadLatest(Path privateDownloadRoot,ProgressListener progress,Cancellation cancel) throws IOException {
        return downloadLatest(Platform.current(),privateDownloadRoot,progress,cancel);
    }
    public VerifiedPackage downloadLatest(Platform platform,Path privateDownloadRoot,ProgressListener progress,Cancellation cancel) throws IOException {
        Objects.requireNonNull(platform);Objects.requireNonNull(cancel);Objects.requireNonNull(progress);
        Path own=null;
        try {
            cancel.check();
            if(!torReady.getAsBoolean()) { emit(progress,Stage.WAITING_FOR_TOR,0,-1,"Ожидание Tor: подключите сеть АЕГИС и повторите загрузку");throw new TorRequiredException(); }
            emit(progress,Stage.RELEASE_METADATA,0,-1,"Получение сведений об официальном Tor Browser через Tor");
            ByteArrayOutputStream metadata=new ByteArrayOutputStream();
            fetcher.fetch(platform.metadataUri(),metadata,MAX_METADATA,cancel,(n,total)->emit(progress,Stage.RELEASE_METADATA,n,total,"Сведения об официальной версии"));
            Release release=parseMetadata(metadata.toByteArray(),platform);cancel.check();
            Path root=privateDownloadRoot.toAbsolutePath().normalize();rejectParentLinks(root);AtomicFiles.directory(root);rejectParentLinks(root);
            checkVersionFloor(root,release,false);
            own=Files.createTempDirectory(root,"tor-browser-download-");AtomicFiles.directory(own);
            Path archive=own.resolve(release.filename()),signature=own.resolve(release.filename()+".asc");
            downloadAtomic(release.binary(),archive,MAX_PACKAGE,Stage.PACKAGE_DOWNLOAD,"Загрузка официального Tor Browser",progress,cancel);
            downloadAtomic(release.signature(),signature,MAX_SIGNATURE,Stage.SIGNATURE_DOWNLOAD,"Загрузка подписи Tor Browser Developers",progress,cancel);
            AtomicFiles.write(own.resolve("release-metadata.json"),metadata.toByteArray());
            cancel.check();emit(progress,Stage.VERIFYING,0,-1,"Проверка подлинности пакета Tor Browser");
            TorBrowserSignature.Verified verified=verifier.verify(archive,signature);cancel.check();
            // The detached signature authenticates bytes, not the filename or discovery JSON.
            // Linux exposes signed version data without execution. Windows is checked after
            // its authenticated portable installer extracts the bundle, before publication.
            if(platform==Platform.LINUX_X64){TorBrowserPackageMetadata.require(TorBrowserPackageMetadata.linuxArchive(archive,cancel::cancelled),release.version(),false);checkVersionFloor(root,release,true);}
            emit(progress,Stage.READY,verified.size(),verified.size(),"Официальная подпись проверена; пакет готов к отдельной установке");
            return new VerifiedPackage(own,archive,signature,release,verified);
        } catch(IOException|RuntimeException error) {
            if(own!=null)try{deleteOwnDirectory(own);}catch(IOException cleanup){error.addSuppressed(cleanup);}
            if(cancel.cancelled()) { emit(progress,Stage.CANCELLED,0,-1,"Загрузка Tor Browser отменена; временные файлы очищены");InterruptedIOException stopped=new InterruptedIOException("Загрузка Tor Browser отменена");stopped.initCause(error);throw stopped; }
            if(!(error instanceof TorRequiredException))emit(progress,Stage.FAILED,0,-1,"Не удалось получить и проверить официальный Tor Browser");
            throw error;
        }
    }
    private void downloadAtomic(URI uri,Path destination,long limit,Stage stage,String message,ProgressListener progress,Cancellation cancel)throws IOException {
        cancel.check();emit(progress,stage,0,-1,message);Path partial=destination.resolveSibling(destination.getFileName()+".part");
        try {
            try(FileChannel channel=FileChannel.open(partial,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),AtomicFiles.attributes(partial.getParent()))) {
                OutputStream output=java.nio.channels.Channels.newOutputStream(channel);
                fetcher.fetch(uri,output,limit,cancel,(n,total)->emit(progress,stage,n,total,message));channel.force(true);
            }
            cancel.check();if(Files.size(partial)<=0||Files.size(partial)>limit)throw new IOException("Неверный размер официального пакета/подписи");
            Files.move(partial,destination,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(destination.getParent());
        } finally { Files.deleteIfExists(partial); }
    }
    /** JSON is discovery metadata, not a replacement for the package signature. */
    static Release parseMetadata(byte[] bytes,Platform platform)throws IOException {
        if(bytes.length==0||bytes.length>MAX_METADATA)throw new IOException("Некорректный размер metadata Tor Browser");
        Map<String,String> fields=new HashMap<>();
        try(JsonReader reader=new JsonReader(new InputStreamReader(new ByteArrayInputStream(bytes),StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)))) {
            reader.setStrictness(Strictness.STRICT);reader.beginObject();
            while(reader.hasNext()) {
                String key=reader.nextName();if(!Set.of("binary","sig","version","git_tag").contains(key)||fields.containsKey(key)||reader.peek()!=JsonToken.STRING)throw new IOException("Некорректные поля metadata Tor Browser");
                String value=reader.nextString();if(value.length()>2048)throw new IOException("Слишком длинное поле metadata Tor Browser");fields.put(key,value);
            }
            reader.endObject();if(reader.peek()!=JsonToken.END_DOCUMENT||fields.size()!=4)throw new IOException("Неполные metadata Tor Browser");
        }catch(IllegalStateException|IllegalArgumentException error){throw new IOException("Повреждены metadata Tor Browser",error);}
        String version=fields.get("version");if(!version.matches("[0-9]{1,3}(?:\\.[0-9]{1,4}){1,3}"))throw new IOException("Нужна стабильная числовая версия Tor Browser");
        if(!fields.get("git_tag").matches("tbb-"+java.util.regex.Pattern.quote(version)+"-build[1-9][0-9]{0,3}"))throw new IOException("Тег metadata не соответствует версии");
        String filename="tor-browser-"+platform.packagePlatform+"-"+version+platform.extension;
        String url="https://dist.torproject.org/torbrowser/"+version+"/"+filename;
        if(!fields.get("binary").equals(url)||!fields.get("sig").equals(url+".asc"))throw new IOException("URL/архитектура/подпись metadata не соответствуют официальному пакету");
        return new Release(platform,version,fields.get("git_tag"),URI.create(url),URI.create(url+".asc"));
    }
    private static void checkVersionFloor(Path root,Release release,boolean commit)throws IOException {
        synchronized(RELEASE_FLOOR_LOCK) {
            Path file=root.resolve("minimum-downloaded-"+release.platform.endpoint+".txt");
            if(Files.exists(file,LinkOption.NOFOLLOW_LINKS)) {
                String before=new String(AtomicFiles.read(file,64),StandardCharsets.US_ASCII).strip();
                if(!before.matches("[0-9]{1,3}(?:\\.[0-9]{1,4}){1,3}"))throw new IOException("Повреждена локальная отметка версии Tor Browser");
                if(compareVersions(release.version,before)<0)throw new IOException("Официальный источник предложил более старую версию Tor Browser; откат отключён");
            }
            if(commit)AtomicFiles.write(file,(release.version+"\n").getBytes(StandardCharsets.US_ASCII));
        }
    }
    static int compareVersions(String left,String right) {
        String[] a=left.split("\\."),b=right.split("\\.");
        for(int i=0;i<Math.max(a.length,b.length);i++){int difference=Integer.compare(i<a.length?Integer.parseInt(a[i]):0,i<b.length?Integer.parseInt(b[i]):0);if(difference!=0)return difference;}
        return 0;
    }
    private static void emit(ProgressListener listener,Stage stage,long bytes,long total,String message) { listener.update(new Progress(stage,bytes,total,message)); }
    static void rejectParentLinks(Path path)throws IOException { for(Path current=path;current!=null;current=current.getParent())if(Files.isSymbolicLink(current))throw new IOException("Ссылка в каталоге загрузки Tor Browser"); }
    private static void deleteOwnDirectory(Path directory)throws IOException {
        rejectParentLinks(directory.getParent());
        if(!Files.exists(directory,LinkOption.NOFOLLOW_LINKS))return;
        if(Files.isSymbolicLink(directory)||!Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS))throw new IOException("Каталог пакета Tor Browser заменён");
        // Only the finite files owned by this download; unexpected subdirectories fail closed.
        try(var entries=Files.list(directory)) { for(Path file:entries.toList()) { if(Files.isDirectory(file,LinkOption.NOFOLLOW_LINKS))throw new IOException("Неожиданный каталог в загрузке Tor Browser");Files.deleteIfExists(file); } }
        Files.delete(directory);
    }
    public static final class TorRequiredException extends IOException {
        private static final long serialVersionUID=1L;
        public TorRequiredException(){super("Для автоматической загрузки Tor Browser подключите Tor в АЕГИС. Прямой обход отключён.");}
    }
}
