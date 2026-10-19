package org.securemail.glas.signaling;

import com.google.gson.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.attachments.IdentityRemoteAuthority;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;

/** Loopback-only bounded public-metadata origin. There is no media transport operation. */
public final class GlasSignalingHttp600 implements AutoCloseable {
  private final HttpServer server;private final GlasRegistry600 registry;private final KeyPair key;
  private final ThreadPoolExecutor workers=new ThreadPoolExecutor(2,2,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(8),r->{Thread t=new Thread(r,"aegis-glas-signaling");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final ScheduledThreadPoolExecutor timer=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-glas-signaling-deadline");t.setDaemon(true);return t;});
  private long rateAt=System.nanoTime();private int count;
  public GlasSignalingHttp600(InetSocketAddress bind,GlasRegistry600 registry,KeyPair serviceKey)throws IOException {
    if(bind.isUnresolved()||!bind.getAddress().isLoopbackAddress())throw new IOException("Только onion origin через loopback");this.registry=Objects.requireNonNull(registry);key=Objects.requireNonNull(serviceKey);IdentityProtocol.publicKey(key.getPublic().getEncoded());
    byte[] test="AEGIS GLAS service consistency".getBytes(StandardCharsets.US_ASCII);if(!IdentityProtocol.verify(key.getPublic().getEncoded(),test,IdentityProtocol.sign(key.getPrivate(),test)))throw new IOException("Ключ сервиса");
    System.setProperty("jdk.httpserver.maxConnections","32");System.setProperty("sun.net.httpserver.maxReqHeaders","16");System.setProperty("sun.net.httpserver.maxReqTime","15");System.setProperty("sun.net.httpserver.maxRspTime","15");
    server=HttpServer.create(bind,16);server.setExecutor(workers);server.createContext("/",this::handle);timer.setRemoveOnCancelPolicy(true);timer.scheduleWithFixedDelay(()->{try{registry.cleanup(128);}catch(Exception ignored){}},30,30,TimeUnit.SECONDS);
  }
  public void start(){server.start();}public int port(){return server.getAddress().getPort();}
  private synchronized boolean rate(){long now=System.nanoTime();if(now-rateAt>60_000_000_000L){rateAt=now;count=0;}return ++count<=300;}
  private void handle(HttpExchange exchange){byte[] body=new byte[0];String nonce=IdentityProtocol.nonce();var deadline=timer.schedule(exchange::close,15,TimeUnit.SECONDS);
    try{
      if(!rate()||!exchange.getRequestMethod().equals("POST")||!exchange.getRequestURI().getRawPath().equals("/glas/v1")||exchange.getRequestURI().getRawQuery()!=null)throw new IOException("Недоступно");Headers h=exchange.getRequestHeaders();String length=single(h,"Content-Length");
      if(h.containsKey("Transfer-Encoding")||h.containsKey("Content-Encoding")||!"application/octet-stream".equals(single(h,"Content-Type"))||length==null||!length.matches("[0-9]{1,5}"))throw new IOException("Формат запроса");int n=Integer.parseInt(length);if(n<1||n>GlasProtocol600.MAX_REQUEST)throw new IOException("Размер запроса");body=exchange.getRequestBody().readNBytes(n+1);if(body.length!=n)throw new EOFException();var request=GlasProtocol600.decode(body);nonce=IdentityProtocol.nonceValue(single(h,"AEGIS-Nonce"));String time=single(h,"AEGIS-Time");if(time==null||!time.matches("[0-9]{1,17}"))throw new IOException("Время запроса");
      var proof=new IdentityRemoteAuthority.Proof(single(h,"AEGIS-Capability"),Long.parseLong(time),nonce,IdentityProtocol.unb64(single(h,"AEGIS-Proof"),64));respond(exchange,200,body,nonce,registry.execute(request,proof));
    }catch(Exception denied){try{JsonObject data=new JsonObject();data.addProperty("error","Голосовое соединение недоступно");respond(exchange,403,body,nonce,data);}catch(Exception ignored){}}
    finally{Arrays.fill(body,(byte)0);deadline.cancel(false);exchange.close();}
  }
  private void respond(HttpExchange exchange,int code,byte[] request,String nonce,JsonObject data)throws IOException{JsonObject response=new JsonObject();response.addProperty("ok",code==200);response.add("data",data);byte[] body=response.toString().getBytes(StandardCharsets.UTF_8);Headers h=exchange.getResponseHeaders();h.set("Content-Type","application/json; charset=utf-8");h.set("Cache-Control","no-store");h.set("Connection","close");h.set("X-Content-Type-Options","nosniff");h.set("AEGIS-Signature",IdentityProtocol.b64(IdentityProtocol.sign(key.getPrivate(),IdentityProtocol.response(IdentityProtocol.id(key.getPublic().getEncoded()),nonce,request,body))));exchange.sendResponseHeaders(code,body.length);exchange.getResponseBody().write(body);}
  private static String single(Headers h,String k){List<String>v=h.get(k);return v!=null&&v.size()==1?v.getFirst():null;}
  @Override public void close(){server.stop(0);workers.shutdownNow();timer.shutdownNow();}
}
