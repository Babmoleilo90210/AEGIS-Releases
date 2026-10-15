package org.securemail.client.update;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.securemail.client.net.TorTransport;

class UpdateTransportTest {
 @AfterEach void reset(){TorTransport.requireAvailability(()->true);}
 @Test void arbitraryHostsIpsCredentialsHttpAndPortsAreRejected(){for(String uri:new String[]{"http://github.com/file","https://evil.invalid/file","https://127.0.0.1/file","https://user:password@github.com/file","https://github.com:444/file","https://github.com/file#fragment"})assertThrows(IOException.class,()->TorHttpsClient.destination(URI.create(uri)));}
 @Test void explicitDistributionAndRedirectHostsOnly()throws Exception{for(String host:new String[]{"github.com","raw.githubusercontent.com","release-assets.githubusercontent.com","objects.githubusercontent.com"})TorHttpsClient.destination(URI.create("https://"+host+"/file"));assertThrows(IOException.class,()->new TorTransport("127.0.0.1",19050).connectUpdate("example.invalid"));assertThrows(IllegalArgumentException.class,()->new TorTransport("0.0.0.0",19050));}
 @Test void torFailurePreventsUpdateRequestAndClearnetFallback(){TorTransport.requireAvailability(()->false);IOException failure=assertThrows(IOException.class,()->new TorHttpsClient(19050).bytes(URI.create("https://github.com/file"),65536));assertTrue(failure.getMessage().contains("Прямое подключение отключено"));}
 @Test void updateHostnameUsesLoopbackSocksRemoteDnsOnly()throws Exception{TorTransport.requireAvailability(()->true);try(ServerSocket server=new ServerSocket(0,1,InetAddress.getByAddress(new byte[]{127,0,0,1}))){CompletableFuture<String> observed=new CompletableFuture<>();Thread proxy=new Thread(()->{try(Socket socket=server.accept()){socket.setSoTimeout(3000);var in=new DataInputStream(socket.getInputStream());var out=socket.getOutputStream();assertArrayEquals(new byte[]{5,1,0},in.readNBytes(3));out.write(new byte[]{5,0});out.flush();assertArrayEquals(new byte[]{5,1,0,3},in.readNBytes(4));String host=new String(in.readNBytes(in.readUnsignedByte()),StandardCharsets.US_ASCII);assertEquals(443,in.readUnsignedShort());out.write(new byte[]{5,0,0,1,127,0,0,1,0,0});out.flush();observed.complete(host);}catch(Throwable e){observed.completeExceptionally(e);}},"test-only-socks");proxy.setDaemon(true);proxy.start();try(Socket socket=new TorTransport("127.0.0.1",server.getLocalPort()).connectUpdate("raw.githubusercontent.com")){assertTrue(socket.getInetAddress().isLoopbackAddress());assertEquals("raw.githubusercontent.com",observed.get(3,TimeUnit.SECONDS));}proxy.join(3000);}}
}
