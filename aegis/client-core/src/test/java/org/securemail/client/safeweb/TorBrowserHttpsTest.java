package org.securemail.client.safeweb;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.securemail.client.net.TorTransport;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class TorBrowserHttpsTest {
    static final URI URL=URI.create("https://dist.torproject.org/torbrowser/15.0.25/tor-browser-linux-x86_64-15.0.25.tar.xz");
    static byte[] ascii(String value){return value.getBytes(StandardCharsets.US_ASCII);}
    static byte[] body(String response,long maximum)throws Exception {
        var bytes=new ByteArrayOutputStream();assertNull(TorBrowserHttps.readResponse(new ByteArrayInputStream(ascii(response)),URL,bytes,maximum,new TorBrowserDownloadService.Cancellation(),(n,t)->{}));return bytes.toByteArray();
    }
    @Test void supportsFixedChunkedAndCloseFramingWithMonotonicProgress()throws Exception {
        for(String message:List.of("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello","HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n","HTTP/1.0 200 OK\r\n\r\nhello")){
            var output=new ByteArrayOutputStream();var counts=new ArrayList<Long>();TorBrowserHttps.readResponse(new ByteArrayInputStream(ascii(message)),URL,output,5,new TorBrowserDownloadService.Cancellation(),(n,t)->counts.add(n));assertEquals("hello",output.toString(StandardCharsets.US_ASCII));for(int i=1;i<counts.size();i++)assertTrue(counts.get(i)>=counts.get(i-1));assertEquals(5L,counts.getLast());
        }
    }
    @Test void refusesAmbiguityTruncationHtmlCompressionOversizeAndHeaderInjection() {
        for(String message:List.of(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\nhe",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nSiteUnavailable",
            "HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello!\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=x\r\na\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: a\r\n\r\n",
            "HTTP/1.1 200 OK\nContent-Length: 2\n\nhe",
            "HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\nhe",
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\nhello!"))assertThrows(IOException.class,()->body(message,5),message);
    }
    @Test void redirectsMustRetainCanonicalHttpsHostAndExactPackagePath()throws Exception {
        var okay=new ByteArrayInputStream(ascii("HTTP/1.1 302 Found\r\nLocation: "+URL.getRawPath()+"\r\n\r\n"));assertEquals(URL,TorBrowserHttps.readResponse(okay,URL,new ByteArrayOutputStream(),50,new TorBrowserDownloadService.Cancellation(),(n,t)->{}));
        for(String address:List.of("http://dist.torproject.org"+URL.getPath(),"https://evil.example"+URL.getPath(),"https://dist.torproject.org/torbrowser/15.0.24/tor-browser-linux-x86_64-15.0.24.tar.xz",URL+"?secret=x",URL+"#fragment","https://u:p@dist.torproject.org"+URL.getPath(),"file:///etc/passwd"))assertThrows(IOException.class,()->body("HTTP/1.1 302 Found\r\nLocation: "+address+"\r\n\r\n",50),address);
    }
    @Test void vendorPolicyRejectsLocalAndArbitraryDestinationsBeforeSocketConnect()throws Exception {
        for(String address:List.of("https://localhost/x","https://127.0.0.1/x","https://dist.torproject.org/","https://dist.torproject.org:444"+URL.getPath(),"https://aus1.torproject.org/torbrowser/update_3/release/downloads.json","https://dist.torproject.org/torbrowser/15.0.25/%2e%2e/evil"))assertThrows(IOException.class,()->TorBrowserHttps.destination(URI.create(address)));
        assertThrows(IOException.class,()->new TorTransport("127.0.0.1",9).connectTorBrowserDownload("example.com"));
    }
    @Test void actualLoopbackSocksHandshakeSendsDomainAndPortWithoutLocalDestinationDns()throws Exception {
        TorTransport.requireAvailability(()->true);
        try(var server=new ServerSocket(0,1,InetAddress.getByAddress(new byte[]{127,0,0,1}));var executor=Executors.newVirtualThreadPerTaskExecutor()) {
            Future<String> observed=executor.submit(()->{try(var socket=server.accept()){socket.setSoTimeout(3000);var input=new DataInputStream(socket.getInputStream());var output=socket.getOutputStream();assertArrayEquals(new byte[]{5,1,0},input.readNBytes(3));output.write(new byte[]{5,0});output.flush();assertArrayEquals(new byte[]{5,1,0,3},input.readNBytes(4));String host=new String(input.readNBytes(input.readUnsignedByte()),StandardCharsets.US_ASCII);assertEquals(443,input.readUnsignedShort());output.write(new byte[]{5,0,0,1,127,0,0,1,0,0});output.flush();return host;}});
            try(var connection=new TorTransport("127.0.0.1",server.getLocalPort()).connectTorBrowserDownload("dist.torproject.org")){assertTrue(connection.isConnected());}
            assertEquals("dist.torproject.org",observed.get(4,TimeUnit.SECONDS));
        }
    }
    @Test void cancellationInterruptsRealSocketWhileSocksHandshakeIsWaiting()throws Exception {
        TorTransport.requireAvailability(()->true);var token=new TorBrowserDownloadService.Cancellation();var accepted=new CountDownLatch(1);
        try(var server=new ServerSocket(0,1,InetAddress.getByAddress(new byte[]{127,0,0,1}));var executor=Executors.newVirtualThreadPerTaskExecutor()){
            Future<?> peer=executor.submit(()->{try(var socket=server.accept()){accepted.countDown();while(socket.getInputStream().read()!=-1){}return null;}});
            Future<?> connect=executor.submit(()->{assertThrows(IOException.class,()->new TorTransport("127.0.0.1",server.getLocalPort()).connectTorBrowserDownload("aus1.torproject.org",token::attach));return null;});
            assertTrue(accepted.await(2,TimeUnit.SECONDS));token.cancel();connect.get(2,TimeUnit.SECONDS);peer.get(2,TimeUnit.SECONDS);assertTrue(token.cancelled());
        }
    }
}
