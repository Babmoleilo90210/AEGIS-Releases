package org.securemail.client.safeweb;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.net.ssl.*;
import org.securemail.client.net.TorTransport;

/** Vendor-scoped HTTPS over the explicit Tor SOCKS context. No direct networking,
 * local destination DNS, global proxy changes, cookies, credentials or browser IPC.
 * Every redirect is revalidated and must keep the same canonical vendor path.
 */
final class TorBrowserHttps implements TorBrowserDownloadService.Fetcher {
    private final TorTransport transport;
    TorBrowserHttps(int socksPort) { transport=new TorTransport("127.0.0.1",socksPort); }
    static void destination(URI uri) throws IOException {
        if(!"https".equals(uri.getScheme())||uri.getRawUserInfo()!=null||uri.getRawFragment()!=null||uri.getRawQuery()!=null
                ||uri.getPort()!=-1&&uri.getPort()!=443||uri.toASCIIString().length()>2048)throw new IOException("Небезопасный адрес загрузки Tor Browser");
        String path=uri.getRawPath(),host=uri.getHost();
        boolean allowed="aus1.torproject.org".equals(host)&&path!=null&&path.matches("/torbrowser/update_3/release/download-(?:linux|windows)-x86_64\\.json")
                ||"dist.torproject.org".equals(host)&&path!=null&&path.matches("/torbrowser/[0-9.]{3,24}/tor-browser-(?:linux-x86_64-[0-9.]{3,24}\\.tar\\.xz|windows-x86_64-portable-[0-9.]{3,24}\\.exe)(?:\\.asc)?");
        if(!allowed)throw new IOException("Загрузка разрешена только с официального сервера Tor Browser");
    }
    @Override public void fetch(URI initial,OutputStream destination,long limit,TorBrowserDownloadService.Cancellation cancel,TorBrowserDownloadService.BytesProgress progress)throws IOException {
        destination(initial);URI current=initial;
        for(int redirect=0;redirect<=4;redirect++) {
            destination(current);cancel.check();Socket[] held={null};
            try(Socket tunnel=transport.connectTorBrowserDownload(current.getHost(),socket->{held[0]=socket;cancel.attach(socket);});
                SSLSocket tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(tunnel,current.getHost(),443,true)) {
                SSLParameters parameters=tls.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");parameters.setServerNames(List.of(new SNIHostName(current.getHost())));tls.setSSLParameters(parameters);
                tls.setEnabledProtocols(new String[]{"TLSv1.3","TLSv1.2"});tls.setSoTimeout(20_000);tls.startHandshake();cancel.check();
                String request="GET "+current.getRawPath()+" HTTP/1.1\r\nHost: "+current.getHost()+"\r\nUser-Agent: AEGIS-TorBrowser-Installer\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
                tls.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));tls.getOutputStream().flush();
                URI next=readResponse(new BufferedInputStream(tls.getInputStream()),current,destination,limit,cancel,progress);
                if(next==null)return;
                if(redirect==4)throw new IOException("Слишком много перенаправлений Tor Browser");
                current=next;
            } finally { if(held[0]!=null)cancel.detach(held[0]); }
        }
        throw new IOException("Слишком много перенаправлений Tor Browser");
    }
    /** Serialized-response fixtures exercise the exact production parser. */
    static URI readResponse(InputStream input,URI requested,OutputStream output,long limit,TorBrowserDownloadService.Cancellation cancel,TorBrowserDownloadService.BytesProgress progress)throws IOException {
        cancel.check();String status=line(input,8192);
        if(!status.matches("HTTP/1\\.[01] [0-9]{3}(?: [\\x20-\\x7e]*)?"))throw new IOException("Некорректный HTTP-ответ сервера Tor Browser");
        int code=Integer.parseInt(status.substring(9,12));Map<String,String> headers=new HashMap<>();int bytes=status.length();boolean end=false;
        for(int count=0;count<100;count++) {
            cancel.check();String row=line(input,8192);bytes+=row.length()+2;if(bytes>65536)throw new IOException("Слишком большие HTTP-заголовки");
            if(row.isEmpty()){end=true;break;}
            int colon=row.indexOf(':');if(colon<=0)throw new IOException("Некорректный HTTP-заголовок");
            String name=row.substring(0,colon).toLowerCase(Locale.ROOT),value=row.substring(colon+1).strip();
            if(!name.matches("[a-z0-9!#$%&'*+.^_`|~-]+")||value.chars().anyMatch(c->c<32&&c!=9||c==127)||headers.putIfAbsent(name,value)!=null)throw new IOException("Некорректный или повторный HTTP-заголовок");
        }
        if(!end)throw new IOException("Слишком много HTTP-заголовков");
        if(Set.of(301,302,303,307,308).contains(code)) {
            String raw=headers.get("location");if(raw==null)throw new IOException("Перенаправление не содержит адрес");
            URI next;try{next=requested.resolve(raw);}catch(IllegalArgumentException error){throw new IOException("Некорректное перенаправление",error);}
            destination(next);
            if(!Objects.equals(requested.getHost(),next.getHost())||!Objects.equals(requested.getRawPath(),next.getRawPath()))throw new IOException("Сервер изменил источник/путь официального пакета");
            return next;
        }
        if(code!=200)throw new IOException("Официальный сервер Tor Browser вернул HTTP "+code);
        if(headers.containsKey("content-encoding")&&!headers.get("content-encoding").equalsIgnoreCase("identity"))throw new IOException("Сжатый HTTP-ответ не поддерживается");
        if(headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT).contains("text/html"))throw new IOException("Вместо пакета получена HTML-страница");
        long declared=-1;
        if(headers.containsKey("content-length"))try { String raw=headers.get("content-length");if(!raw.matches("[0-9]{1,12}"))throw new NumberFormatException();declared=Long.parseLong(raw); }catch(NumberFormatException error){throw new IOException("Некорректный размер HTTP-ответа",error);}
        if(declared>limit)throw new IOException("Ответ превышает лимит размера");
        boolean chunked=headers.containsKey("transfer-encoding");
        if(chunked&&(!headers.get("transfer-encoding").equalsIgnoreCase("chunked")||declared!=-1))throw new IOException("Неоднозначный HTTP-ответ");
        long count=0;byte[] buffer=new byte[65536];progress.update(0,declared);
        if(chunked) {
            while(true) {
                cancel.check();String row=line(input,256);if(!row.matches("[0-9a-fA-F]{1,12}"))throw new IOException("Некорректный HTTP chunk");
                long size=Long.parseLong(row,16);if(size>limit-count)throw new IOException("Ответ превышает лимит размера");
                if(size==0) {
                    // No trailers are needed by official package downloads. Reject unknown
                    // trailing metadata instead of accepting framing ambiguities.
                    if(!line(input,2).isEmpty())throw new IOException("HTTP trailers не поддерживаются");return null;
                }
                long left=size;
                while(left>0) { cancel.check();int read=input.read(buffer,0,(int)Math.min(left,buffer.length));if(read<0)throw new EOFException("Загрузка Tor Browser прервана");output.write(buffer,0,read);left-=read;count+=read;progress.update(count,-1); }
                if(!line(input,2).isEmpty())throw new IOException("Некорректное завершение HTTP chunk");
            }
        }
        while(declared<0||count<declared) {
            cancel.check();int wanted=(int)Math.min(buffer.length,declared<0?Math.max(1,limit-count+1):declared-count);
            int read=input.read(buffer,0,wanted);if(read<0){if(declared>=0&&count!=declared)throw new EOFException("Загрузка Tor Browser прервана");break;}
            if(read>limit-count)throw new IOException("Ответ превышает лимит размера");output.write(buffer,0,read);count+=read;progress.update(count,declared);
        }
        return null;
    }
    private static String line(InputStream input,int maximum)throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();int previous=-1;
        while(bytes.size()<=maximum) {
            int value=input.read();if(value<0)throw new EOFException("HTTP-ответ Tor Browser прерван");
            if(previous==13&&value==10){byte[] data=bytes.toByteArray();return new String(data,0,data.length-1,StandardCharsets.US_ASCII);}
            if(value==10||previous==13)throw new IOException("Некорректные окончания строк HTTP");
            bytes.write(value);previous=value;
        }
        throw new IOException("Слишком длинная HTTP-строка");
    }
}
