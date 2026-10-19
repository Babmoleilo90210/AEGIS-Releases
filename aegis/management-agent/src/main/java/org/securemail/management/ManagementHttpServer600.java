package org.securemail.management;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** The production bounded HTTP boundary. Only the fixed broker independently authorizes commands. */
public final class ManagementHttpServer600 implements AutoCloseable {
  @FunctionalInterface public interface Processor { JsonObject process(byte[] exactEnvelope) throws Exception; }
  private final HttpServer server;
  private final ThreadPoolExecutor workers = new ThreadPoolExecutor(2,2,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(8),r->{Thread t=new Thread(r,"aegis-management-http");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final ScheduledThreadPoolExecutor timer = new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-management-deadline");t.setDaemon(true);return t;});
  private final long[] rate = {System.nanoTime(),0};
  public ManagementHttpServer600(InetSocketAddress address, KeyPair signingKey, Processor processor) throws IOException {
    if(address.isUnresolved()||!address.getAddress().getHostAddress().equals("127.0.0.1"))throw new IOException("Только loopback управления");
    Objects.requireNonNull(signingKey);Objects.requireNonNull(processor);timer.setRemoveOnCancelPolicy(true);server=HttpServer.create(address,8);server.setExecutor(workers);
    server.createContext("/",exchange->{
      byte[] body=new byte[0];String nonce=IdentityProtocol.nonce();var timeout=timer.schedule(exchange::close,60,TimeUnit.SECONDS);
      try {
        if(!exchange.getRequestMethod().equals("POST")||!exchange.getRequestURI().getRawPath().equals("/management/v1")||exchange.getRequestURI().getRawQuery()!=null)throw new IOException("Недоступно");
        Headers h=exchange.getRequestHeaders();List<String> lengths=h.get("Content-Length");String length=lengths!=null&&lengths.size()==1?lengths.getFirst():null;
        if(h.containsKey("Content-Encoding")||h.containsKey("Transfer-Encoding")||length==null||!length.matches("[0-9]{1,5}"))throw new IOException("Формат запроса");int n=Integer.parseInt(length);if(n<2||n>16384)throw new IOException("Размер запроса");
        body=exchange.getRequestBody().readNBytes(n+1);if(body.length!=n)throw new EOFException();var decoded=ManagementMain.decode(body);nonce=decoded.proofs().getFirst().nonce();
        // Even rate refusals bind the exact bounded request and caller nonce; never report
        // an unverified result as success, and never consume the app proof in the broker.
        synchronized(rate){long now=System.nanoTime();if(now-rate[0]>60_000_000_000L){rate[0]=now;rate[1]=0;}if(++rate[1]>30)throw new RateLimited();}
        respond(exchange,200,body,nonce,processor.process(body),signingKey);
      }catch(Exception denied){try{JsonObject error=new JsonObject();error.addProperty("error","Серверная операция не разрешена");respond(exchange,denied instanceof RateLimited?429:403,body,nonce,error,signingKey);}catch(Exception ignored){}}
      finally{Arrays.fill(body,(byte)0);timeout.cancel(false);exchange.close();}
    });
  }
  private static void respond(HttpExchange exchange,int code,byte[] request,String nonce,JsonObject data,KeyPair key)throws IOException {
    JsonObject envelope=new JsonObject();envelope.addProperty("ok",code==200);envelope.add("data",data);byte[] bytes=envelope.toString().getBytes(StandardCharsets.UTF_8);Headers h=exchange.getResponseHeaders();h.set("Content-Type","application/json; charset=utf-8");h.set("Cache-Control","no-store");h.set("Connection","close");h.set("AEGIS-Signature",IdentityProtocol.b64(IdentityProtocol.sign(key.getPrivate(),IdentityProtocol.response(IdentityProtocol.id(key.getPublic().getEncoded()),nonce,request,bytes))));exchange.sendResponseHeaders(code,bytes.length);exchange.getResponseBody().write(bytes);
  }
  public int port(){return server.getAddress().getPort();}
  private static final class RateLimited extends IOException {}
  public void start(){server.start();}
  @Override public void close(){server.stop(0);workers.shutdownNow();timer.shutdownNow();}
}
