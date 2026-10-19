package org.securemail.ecosystem.rpc600;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Bounded internal transport: literal loopback, exact Identity response signature, no proxy/DNS/redirect.
 * Caller supplies/parses strict JSON. A total socket deadline also bounds a slow-drip response. */
public final class PinnedIdentityLoopback600 implements AutoCloseable {
  public static final class Response {
    public final int status;private final byte[] body;
    Response(int status,byte[] body){this.status=status;this.body=body.clone();}
    public byte[] body(){return body.clone();}
  }
  private final int port;private final byte[] key;private final String audience;
  private final Set<Socket> sockets=ConcurrentHashMap.newKeySet();private final Semaphore slots=new Semaphore(2);
  private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-identity-loopback-deadline");t.setDaemon(true);return t;});
  private volatile boolean closed;
  public PinnedIdentityLoopback600(int port,byte[] identityPin){if(port<1||port>65535)throw new IllegalArgumentException("Порт Identity");IdentityProtocol.publicKey(identityPin);this.port=port;key=identityPin.clone();audience=IdentityProtocol.id(key);deadlines.setRemoveOnCancelPolicy(true);}
  public Response post(byte[] exactRequest,String nonce)throws IOException {
    IdentityProtocol.nonceValue(nonce);if(exactRequest==null||exactRequest.length<2||exactRequest.length>IdentityProtocol.MAX_BODY||closed||!slots.tryAcquire())throw denied();
    Socket socket=new Socket(Proxy.NO_PROXY);ScheduledFuture<?> timeout=null;
    try {
      sockets.add(socket);if(closed)throw denied();timeout=deadlines.schedule(()->{try{socket.close();}catch(IOException ignored){}},6,TimeUnit.SECONDS);
      socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),port),2000);socket.setSoTimeout(3000);
      OutputStream output=socket.getOutputStream();output.write(("POST /identity/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+exactRequest.length+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));output.write(exactRequest);output.flush();
      DataInputStream input=new DataInputStream(socket.getInputStream());String status=line(input,256);if(!status.matches("HTTP/1\\.[01] [1-5][0-9]{2}(?: [\\x20-\\x7e]*)?"))throw denied();
      Map<String,String> headers=new HashMap<>();boolean complete=false;int total=0;
      for(int count=0;count<24;count++){String header=line(input,2048);total+=header.length();if(total>8192)throw denied();if(header.isEmpty()){complete=true;break;}int colon=header.indexOf(':');if(colon<1||!header.substring(0,colon).matches("[A-Za-z0-9-]+"))throw denied();String name=header.substring(0,colon).toLowerCase(Locale.ROOT);if(headers.putIfAbsent(name,header.substring(colon+1).trim())!=null)throw denied();}
      if(!complete||!headers.getOrDefault("content-type","").matches("(?i)application/json(?:;\\s*charset=utf-8)?")||headers.containsKey("transfer-encoding")||headers.containsKey("content-encoding")||!headers.getOrDefault("content-length","").matches("[0-9]{1,6}"))throw denied();int length=Integer.parseInt(headers.get("content-length"));if(length<2||length>IdentityProtocol.MAX_BODY)throw denied();
      byte[] body=new byte[length];input.readFully(body);byte[] signature=IdentityProtocol.unb64(headers.getOrDefault("aegis-signature",""),64);
      if(!IdentityProtocol.verify(key,IdentityProtocol.response(audience,nonce,exactRequest,body),signature)||closed)throw denied();return new Response(Integer.parseInt(status.substring(9,12)),body);
    }catch(IllegalArgumentException|RejectedExecutionException invalid){throw denied();}
    finally{if(timeout!=null)timeout.cancel(false);sockets.remove(socket);try{socket.close();}finally{slots.release();}}
  }
  private static String line(DataInputStream input,int maximum)throws IOException {ByteArrayOutputStream bytes=new ByteArrayOutputStream();for(int n=0;n<maximum;n++){int c=input.read();if(c<0)throw new EOFException();if(c=='\r'){if(input.read()!='\n')throw denied();return new String(bytes.toByteArray(),StandardCharsets.US_ASCII);}if(c<32||c>126)throw denied();bytes.write(c);}throw denied();}
  @Override public void close(){closed=true;for(Socket socket:sockets)try{socket.close();}catch(IOException ignored){}deadlines.shutdownNow();}
  private static IOException denied(){return new IOException("Не удалось проверить действующую сессию Identity");}
}
