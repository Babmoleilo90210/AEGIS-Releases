package org.aegis.android;

import java.net.*;import java.io.*;import java.util.*;import java.util.concurrent.*;
import org.securemail.client.net.TorTransport;

/** Actual loopback SOCKS5 handshake fixture. It is not a Tor node, DNS-leak test, or native test. */
public final class OnionTransportTest {
    private static final String ONION="a".repeat(56)+".onion";
    public static void main(String[] args)throws Exception {
        for(boolean reject:new boolean[]{false,true}){
            try(ServerSocket server=new ServerSocket(0,2,InetAddress.getByAddress(new byte[]{127,0,0,1}))){server.setSoTimeout(2000);ExecutorService worker=Executors.newSingleThreadExecutor();Future<?> proof=worker.submit(()->{try(Socket peer=server.accept()){peer.setSoTimeout(2000);DataInputStream in=new DataInputStream(peer.getInputStream());if(!Arrays.equals(in.readNBytes(3),new byte[]{5,1,0}))throw new AssertionError();peer.getOutputStream().write(new byte[]{5,0});if(!Arrays.equals(in.readNBytes(4),new byte[]{5,1,0,3}))throw new AssertionError();int length=in.readUnsignedByte();String domain=new String(in.readNBytes(length),java.nio.charset.StandardCharsets.US_ASCII);if(!domain.equals(ONION)||in.readUnsignedShort()!=80)throw new AssertionError();peer.getOutputStream().write(new byte[]{5,(byte)(reject?5:0),0,1,127,0,0,1,0,80});if(!reject){if(in.read()!=123)throw new AssertionError();peer.getOutputStream().write(124);}}catch(Exception e){throw new RuntimeException(e);}});
                try{TorTransport tor=new TorTransport("127.0.0.1",server.getLocalPort());if(reject){try(Socket unexpected=tor.connectPeer(ONION,80)){throw new AssertionError("SOCKS refusal ignored");}catch(IOException expected){}}else try(Socket socket=tor.connectPeer(ONION,80)){socket.getOutputStream().write(123);if(socket.getInputStream().read()!=124)throw new AssertionError();}proof.get(3,TimeUnit.SECONDS);System.out.println("PASS "+(reject?"SOCKS-refusal-no-fallback":"onion-domain-sent-to-loopback-SOCKS"));}finally{worker.shutdownNow();if(!worker.awaitTermination(3,TimeUnit.SECONDS))throw new AssertionError("Worker leak");}
            }
        }
        try{new TorTransport("192.168.1.1",9050);throw new AssertionError("Remote proxy accepted");}catch(IllegalArgumentException expected){System.out.println("PASS remote-SOCKS-host-denied");}
        try{new TorTransport("127.0.0.1",9050).connectPeer("example.com",80);throw new AssertionError("Clearnet accepted");}catch(IllegalArgumentException expected){System.out.println("PASS clearnet-identity-host-denied-before-connect");}
        System.out.println("RESULT 4 PASS; real Tor/DNS/native tests NOT_RUN");
    }
}
