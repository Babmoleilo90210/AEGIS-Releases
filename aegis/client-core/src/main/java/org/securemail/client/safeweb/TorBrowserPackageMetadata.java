package org.securemail.client.safeweb;

import com.google.gson.Strictness;
import com.google.gson.stream.*;
import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.apache.commons.compress.archivers.tar.*;
import org.tukaani.xz.XZInputStream;

/** The Tor Browser version is tbb_version.json, not Firefox's application.ini
 * Version. This data is authenticated only when its containing archive has
 * already passed TorBrowserSignature verification. Discovery labels remain untrusted. */
final class TorBrowserPackageMetadata {
    private TorBrowserPackageMetadata() { }
    record Version(String version,String architecture,String channel) { }
    static Version bundle(Path bundle) throws IOException {
        Path root=bundle.toRealPath(),file=root.resolve("Browser/tbb_version.json");
        if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(file)||!file.toRealPath().startsWith(root))throw new IOException("В официальном пакете отсутствует tbb_version.json");
        try(InputStream input=Files.newInputStream(file,LinkOption.NOFOLLOW_LINKS)){return parse(input.readNBytes(4097));}
    }
    static Version linuxArchive(Path archive,BooleanSupplier cancelled)throws IOException {
        Version found=null;int entries=0;
        try(InputStream file=Files.newInputStream(archive,LinkOption.NOFOLLOW_LINKS);
            InputStream bounded=new Bounded(new XZInputStream(file,131072),cancelled);
            TarArchiveInputStream tar=new TarArchiveInputStream(bounded)) {
            for(TarArchiveEntry entry;(entry=tar.getNextEntry())!=null;) {
                check(cancelled);if(++entries>20_000)throw new IOException("Слишком много записей Tor Browser");
                if(entry.getName().matches("[^/]+/Browser/tbb_version\\.json")) {
                    if(found!=null||!entry.isFile()||entry.isSymbolicLink()||entry.isLink()||entry.isSparse()||entry.getSize()>4096)throw new IOException("Неверная запись tbb_version.json");
                    found=parse(tar.readNBytes(4097));
                }
            }
        }
        if(found==null)throw new IOException("В официальном пакете отсутствует tbb_version.json");return found;
    }
    static void require(Version metadata,String expectedVersion,boolean windows)throws IOException {
        if(!metadata.version.equals(expectedVersion)||!metadata.architecture.equals(windows?"windows-x86_64":"linux-x86_64")||!metadata.channel.equals("release"))throw new IOException("Подписанное содержимое Tor Browser не соответствует версии, архитектуре или стабильному каналу пакета");
    }
    static Version parse(byte[] bytes)throws IOException {
        if(bytes.length==0||bytes.length>4096)throw new IOException("Неверный размер tbb_version.json");Map<String,String> fields=new HashMap<>();
        try(JsonReader reader=new JsonReader(new InputStreamReader(new ByteArrayInputStream(bytes),StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)))) {
            reader.setStrictness(Strictness.STRICT);reader.beginObject();
            while(reader.hasNext()) {
                String key=reader.nextName();if(!Set.of("version","architecture","channel","locale").contains(key)||fields.containsKey(key)||reader.peek()!=JsonToken.STRING)throw new IOException("Некорректные поля tbb_version.json");
                String value=reader.nextString();if(value.length()>64)throw new IOException("Слишком длинное поле tbb_version.json");fields.put(key,value);
            }
            reader.endObject();if(reader.peek()!=JsonToken.END_DOCUMENT||!fields.keySet().containsAll(Set.of("version","architecture","channel")))throw new IOException("Неполные сведения о версии Tor Browser");
        }catch(IllegalStateException|IllegalArgumentException error){throw new IOException("Повреждены сведения о версии Tor Browser",error);}
        if(!fields.get("version").matches("[0-9]{1,3}(?:\\.[0-9]{1,4}){1,3}")||!Set.of("linux-x86_64","windows-x86_64").contains(fields.get("architecture"))||!fields.get("channel").equals("release"))throw new IOException("Неподдерживаемая версия Tor Browser");
        return new Version(fields.get("version"),fields.get("architecture"),fields.get("channel"));
    }
    static void check(BooleanSupplier cancelled)throws InterruptedIOException { if(cancelled.getAsBoolean()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("Установка Tor Browser отменена"); }
    private static final class Bounded extends FilterInputStream {
        long left=3_000_000_000L;final BooleanSupplier cancelled;
        Bounded(InputStream input,BooleanSupplier cancelled){super(input);this.cancelled=cancelled;}
        private void count(long amount)throws IOException{if(amount>0&&(left-=amount)<0)throw new IOException("Превышен лимит распаковки Tor Browser");}
        @Override public int read()throws IOException{check(cancelled);int value=in.read();count(value<0?0:1);return value;}
        @Override public int read(byte[] b,int off,int len)throws IOException{check(cancelled);int read=in.read(b,off,(int)Math.min(len,Math.max(1,left+1)));count(read);return read;}
        @Override public long skip(long n)throws IOException{check(cancelled);long skipped=in.skip(Math.min(n,Math.max(1,left+1)));count(skipped);return skipped;}
    }
}
