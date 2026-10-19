package org.securemail.client.library600;

import org.securemail.client.net.TorTransport;
import org.securemail.client.update.UpdateService;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.function.BooleanSupplier;

/** Narrow official Obsidian artifact HTTPS transport. Tor SOCKS remote DNS only. */
final class ObsidianHttps600 {
    private ObsidianHttps600(){}
    static void download(URI official,Path target,long size,int socksPort,BooleanSupplier cancel,UpdateService.Progress progress)throws IOException {
        URI current=official;long count=0;boolean complete=false;
        try {
            for(int redirects=0;redirects<4;redirects++) {
                validate(current,official,redirects==0);check(cancel);
                try(Socket tunnel=new TorTransport("127.0.0.1",socksPort).connectUpdate(current.getHost());SSLSocket tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(tunnel,current.getHost(),443,true)){
                    SSLParameters p=tls.getSSLParameters();p.setEndpointIdentificationAlgorithm("HTTPS");p.setServerNames(List.of(new SNIHostName(current.getHost())));tls.setSSLParameters(p);tls.setEnabledProtocols(new String[]{"TLSv1.3","TLSv1.2"});tls.setSoTimeout(20000);tls.startHandshake();
                    String path=current.getRawPath()+(current.getRawQuery()==null?"":"?"+current.getRawQuery());
                    tls.getOutputStream().write(("GET "+path+" HTTP/1.1\r\nHost: "+current.getHost()+"\r\nUser-Agent: AEGIS-Obsidian-Installer\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));tls.getOutputStream().flush();
                    InputStream in=new BufferedInputStream(tls.getInputStream());String status=line(in,1024);if(!status.matches("HTTP/1\\.[01] [0-9]{3}(?: [\\x20-\\x7e]*)?"))throw new IOException("Некорректный ответ источника Obsidian");int code=Integer.parseInt(status.substring(9,12));Map<String,String>headers=new HashMap<>();int total=0;
                    for(int n=0;n<64;n++){String row=line(in,8192);if((total+=row.length())>32768)throw new IOException("Заголовки слишком велики");if(row.isEmpty())break;int at=row.indexOf(':');if(at<1||!row.substring(0,at).matches("[A-Za-z0-9-]+")||headers.putIfAbsent(row.substring(0,at).toLowerCase(Locale.ROOT),row.substring(at+1).strip())!=null||n==63)throw new IOException("Некорректный HTTP Obsidian");}
                    if(Set.of(301,302,303,307,308).contains(code)){String location=headers.get("location");if(location==null)throw new IOException("Неполное перенаправление Obsidian");try{current=current.resolve(location);}catch(IllegalArgumentException failure){throw new IOException("Неверное перенаправление Obsidian");}validate(current,official,false);continue;}
                    if(code!=200||headers.containsKey("transfer-encoding")||headers.containsKey("content-encoding")&&!headers.get("content-encoding").equalsIgnoreCase("identity")||!Long.toString(size).equals(headers.get("content-length")))throw new IOException("Неподтверждённый размер/формат пакета Obsidian");
                    long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.MINUTES.toNanos(10);try(var out=Files.newOutputStream(target,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
                        byte[]buf=new byte[65536];for(int n;(n=in.read(buf))!=-1;){check(cancel);if(System.nanoTime()-deadline>=0)throw new IOException("Истекло время загрузки Obsidian");count+=n;if(count>size)throw new IOException("Пакет Obsidian превышает размер");out.write(buf,0,n);progress.accept(count,size);}if(count!=size)throw new EOFException("Пакет Obsidian загружен не полностью");}
                    complete=true;return;
                }
            }
            throw new IOException("Слишком много перенаправлений Obsidian");
        } finally {if(!complete)Files.deleteIfExists(target);}
    }
    static void validate(URI uri,URI official,boolean first)throws IOException {
        if(!"https".equals(uri.getScheme())||uri.getPort()!=-1&&uri.getPort()!=443||uri.getUserInfo()!=null||uri.getFragment()!=null||uri.toASCIIString().length()>8192||uri.toASCIIString().chars().anyMatch(c->c<32||c>126))throw new IOException("Небезопасный источник Obsidian");
        if(first||"github.com".equals(uri.getHost())){if(!uri.equals(official))throw new IOException("Подмена официального пакета Obsidian");}
        else if(!Set.of("release-assets.githubusercontent.com","objects.githubusercontent.com").contains(uri.getHost())||uri.getRawPath()==null||!uri.getRawPath().startsWith("/github-production-release-asset/"))throw new IOException("Перенаправление Obsidian вне официального хранилища");
    }
    private static String line(InputStream in,int max)throws IOException{ByteArrayOutputStream b=new ByteArrayOutputStream();for(int n=0;n<max;n++){int c=in.read();if(c<0)throw new EOFException();if(c==13){if(in.read()!=10)throw new IOException("HTTP framing");return b.toString(StandardCharsets.US_ASCII);}if(c<32||c>126)throw new IOException("HTTP framing");b.write(c);}throw new IOException("HTTP line limit");}
    private static void check(BooleanSupplier cancel)throws InterruptedIOException{if(cancel.getAsBoolean()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("Загрузка Obsidian отменена");}
}
