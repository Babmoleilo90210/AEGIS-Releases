package org.securemail.community.library600;

import com.sun.net.httpserver.*;
import org.securemail.community.access.AccessControl;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.*;
import org.securemail.community.http.StrictJson;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.library.protocol600.LibraryWire600;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.*;

/** Actual loopback HTTP origin for an operator-provisioned onion service. Nothing deploys production. */
public final class LibraryHttpServer600 implements AutoCloseable {
    private final HttpServer server;
    private final LibraryController600 controller;
    private final LibraryIdentityBridge600 bridge;
    private final KeyPair key;
    private final String audience;
    private final ThreadPoolExecutor workers=new ThreadPoolExecutor(2,2,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(16),r->{Thread t=new Thread(r,"aegis-library-http");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-library-http-deadline");t.setDaemon(true);return t;});
    private long window=System.nanoTime();private int count;
    public LibraryHttpServer600(InetSocketAddress bind,CommunityStore store,AccessControl access,ContentService content,KeyPair libraryKey,LibraryIdentityBridge600 bridge)throws Exception {
        if(bind.isUnresolved()||!bind.getAddress().isLoopbackAddress())throw new IOException("Библиотека доступна только через loopback за onion service");
        this.key=Objects.requireNonNull(libraryKey);this.bridge=Objects.requireNonNull(bridge);audience=IdentityProtocol.id(libraryKey.getPublic().getEncoded());
        if(!audience.equals(bridge.libraryAudience()))throw new IOException("Подмена ключа Library");
        controller=new LibraryController600(store,access,content,bridge);deadlines.setRemoveOnCancelPolicy(true);
        System.setProperty("jdk.httpserver.maxConnections","32");System.setProperty("sun.net.httpserver.maxReqHeaders","16");System.setProperty("sun.net.httpserver.maxReqTime","30");System.setProperty("sun.net.httpserver.maxRspTime","30");
        server=HttpServer.create(bind,16);server.setExecutor(workers);server.createContext("/",this::handle);
    }
    public void start(){server.start();}
    public int port(){return server.getAddress().getPort();}
    private synchronized boolean rate(){long now=System.nanoTime();if(now-window>=60_000_000_000L){window=now;count=0;}return ++count<=600;}
    private void handle(HttpExchange x){
        byte[]body=new byte[0];String nonce=IdentityProtocol.nonce();ScheduledFuture<?>deadline=deadlines.schedule(x::close,30,TimeUnit.SECONDS);
        try {
            if(!x.getRequestMethod().equals("POST")||!x.getRequestURI().getRawPath().equals("/library/v1")||x.getRequestURI().getRawQuery()!=null)throw new IOException("Endpoint");
            Headers h=x.getRequestHeaders();String length=one(h,"Content-Length"),type=one(h,"Content-Type");
            if(length==null||!length.matches("[0-9]{1,8}")||type==null||!type.matches("(?i)application/json(?:;\\s*charset=utf-8)?")||h.containsKey("Transfer-Encoding")||h.containsKey("Content-Encoding"))throw new IOException("Framing");
            int n=Integer.parseInt(length);if(n<2||n>LibraryWire600.MAX_BODY||!rate())throw new IOException("Limit");body=x.getRequestBody().readNBytes(n+1);if(body.length!=n)throw new IOException("Incomplete");
            Map<String,Object>request=StrictJson.object(body,LibraryWire600.MAX_BODY);
            if(!request.keySet().equals(Set.of("action","argsJson","authorization","nonce")))throw new IOException("Fields");
            nonce=IdentityProtocol.nonceValue(StrictJson.text(request,"nonce",43));String action=StrictJson.text(request,"action",96);LibraryWire600.identityAction(action);
            String exactArgs=StrictJson.text(request,"argsJson",LibraryWire600.MAX_ARGS);byte[]argsBytes=exactArgs.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Map<String,Object>args=StrictJson.object(argsBytes,LibraryWire600.MAX_ARGS);
            if(!(request.get("authorization") instanceof Map<?,?>raw))throw new IOException("Authorization");@SuppressWarnings("unchecked")Map<String,Object>authorization=(Map<String,Object>)raw;
            var evidence=bridge.evidence(action,exactArgs,args,authorization);bridge.authenticate(evidence); // consume app PoP once before Community tx
            Map<String,Object>result=bridge.withAuthority(evidence,ignored->controller.handle(evidence,action,args));
            respond(x,200,nonce,body,Map.of("ok",true,"data",result));
        }catch(CommunityException error){try{respond(x,error.code().equals("NOT_FOUND")?404:403,nonce,body,Map.of("ok",false,"error",Map.of("code",error.code(),"message","Материал или действие недоступны")));}catch(Exception ignored){}}
        catch(Exception error){try{respond(x,403,nonce,body,Map.of("ok",false,"error",Map.of("code","DENIED","message","Запрос библиотеки не разрешён")));}catch(Exception ignored){}}
        finally{Arrays.fill(body,(byte)0);deadline.cancel(false);x.close();}
    }
    private static String one(Headers h,String key){List<String>v=h.get(key);return v!=null&&v.size()==1?v.getFirst():null;}
    private void respond(HttpExchange x,int status,String nonce,byte[]request,Map<String,Object>value)throws IOException {
        byte[]body=StrictJson.bytes(value);try{
            if(body.length>LibraryWire600.MAX_BODY)throw new IOException("Response size");Headers h=x.getResponseHeaders();h.set("Content-Type","application/json; charset=utf-8");h.set("Connection","close");h.set("Cache-Control","no-store");h.set("X-Content-Type-Options","nosniff");
            h.set("AEGIS-Signature",IdentityProtocol.b64(IdentityProtocol.sign(key.getPrivate(),LibraryWire600.response(audience,nonce,request,body))));
            x.sendResponseHeaders(status,body.length);x.getResponseBody().write(body);
        }finally{Arrays.fill(body,(byte)0);}
    }
    @Override public void close(){server.stop(0);workers.shutdownNow();deadlines.shutdownNow();}
}
