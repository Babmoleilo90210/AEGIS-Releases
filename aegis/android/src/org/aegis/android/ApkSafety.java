package org.aegis.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.zip.*;

/** Bounded structural screening, separate from cryptographic APK signature verification. */
public final class ApkSafety {
    public static final long MAX_APK=128L*1024*1024, MAX_EXPANDED=512L*1024*1024, MAX_ENTRY=128L*1024*1024;
    public static final int MAX_ENTRIES=8192,MAX_MANIFEST=2*1024*1024;
    public final String sha256;public final int entries;public final boolean arm64,hasNative;
    private ApkSafety(String hash,int count,boolean arm64,boolean nativeCode){this.sha256=hash;this.entries=count;this.arm64=arm64;this.hasNative=nativeCode;}
    public static ApkSafety inspect(File file)throws IOException,GeneralSecurityException {
        long length=file.length();if(length<22||length>MAX_APK)throw new IOException("Размер APK должен быть не более 128 МиБ");
        MessageDigest hash=MessageDigest.getInstance("SHA-256");try(InputStream in=new FileInputStream(file)){byte[] buffer=new byte[65536];for(int n;(n=in.read(buffer))!=-1;)hash.update(buffer,0,n);}
        Set<String> names=new HashSet<>();int count=0;long total=0,actualTotal=0;long deadline=System.nanoTime()+10_000_000_000L;boolean manifest=false,dex=false,arm64=false,nativeCode=false;
        try(ZipFile zip=new ZipFile(file)){
            Enumeration<? extends ZipEntry> items=zip.entries();
            while(items.hasMoreElements()){
                ZipEntry item=items.nextElement();String name=item.getName();if(++count>MAX_ENTRIES||name.length()>1024||!names.add(name))throw new IOException("Слишком много записей ZIP или дубликат имени");
                if(name.startsWith("/")||name.indexOf('\\')>=0||name.indexOf('\0')>=0)throw new IOException("Небезопасное имя ZIP");
                for(String part:name.split("/",-1))if(part.equals("..")||part.equals("."))throw new IOException("Выход за пределы каталога ZIP");
                if(item.isDirectory())continue;
                long size=item.getSize(),compressed=item.getCompressedSize();if(size<0||compressed<0||size>MAX_ENTRY||size>0&&(compressed==0||size/Math.max(1,compressed)>200))throw new IOException("Неподдерживаемый размер или степень сжатия ZIP");
                total=Math.addExact(total,size);if(total>MAX_EXPANDED)throw new IOException("Слишком большой распакованный APK");
                if(name.equals("AndroidManifest.xml")){if(size>MAX_MANIFEST)throw new IOException("Манифест слишком велик");manifest=true;}
                if(name.matches("classes[0-9]*\\.dex"))dex=true;
                if(name.startsWith("lib/")){nativeCode=true;if(name.startsWith("lib/arm64-v8a/")&&name.endsWith(".so"))arm64=true;}
                if(name.endsWith(".dex")&&size<8)throw new IOException("Повреждённый DEX");
                long actual=0;CRC32 crc=new CRC32();
                try(InputStream expanded=zip.getInputStream(item)){byte[] buffer=new byte[65536];for(int n;(n=expanded.read(buffer))!=-1;){actual+=n;actualTotal+=n;if(actual>size||actual>MAX_ENTRY||actualTotal>MAX_EXPANDED||System.nanoTime()-deadline>=0)throw new IOException("Превышен реальный размер или срок проверки ZIP");crc.update(buffer,0,n);}}
                if(actual!=size||crc.getValue()!=item.getCrc())throw new IOException("Размер или CRC записи ZIP не совпадает");
            }
        }catch(ArithmeticException overflow){throw new IOException("Переполнение размера ZIP",overflow);}
        if(!manifest||!dex)throw new IOException("APK не содержит манифест и DEX");
        StringBuilder hex=new StringBuilder(64);for(byte b:hash.digest())hex.append(String.format(Locale.ROOT,"%02x",b&255));return new ApkSafety(hex.toString(),count,arm64,nativeCode);
    }
    public static void copyBounded(InputStream in,File file)throws IOException {
        long bytes=0;boolean complete=false;
        try(OutputStream out=new FileOutputStream(file)){byte[] buffer=new byte[65536];for(int n;(n=in.read(buffer))!=-1;){bytes+=n;if(bytes>MAX_APK)throw new IOException("APK больше 128 МиБ");out.write(buffer,0,n);}complete=true;}
        finally{if(!complete&&!file.delete()&&file.exists())throw new IOException("Не удалось удалить неполную копию APK");}
    }
}
