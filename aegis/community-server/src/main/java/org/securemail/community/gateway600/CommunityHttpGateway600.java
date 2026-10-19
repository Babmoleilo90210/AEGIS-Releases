package org.securemail.community.gateway600;

import com.sun.net.httpserver.*;
import org.securemail.community.access.AccessControl;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.*;
import org.securemail.community.http.StrictJson;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.community.protocol600.CommunityWire600;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.*;

/** Actual loopback HTTP origin for an operator-provisioned onion service. Nothing deploys production. */
public final class CommunityHttpGateway600 implements AutoCloseable {
    private final HttpServer server;
    private final CommunityRouter600 controller;
    private final CommunityIdentityBridge600 bridge;
    private final org.securemail.community.agent.WorkerServiceGateway600 serviceWorkers;
    private final KeyPair key;
    private final String audience;
    private final ThreadPoolExecutor workers=new ThreadPoolExecutor(2,2,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(16),r->{Thread t=new Thread(r,"aegis-community6-http");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-community6-http-deadline");t.setDaemon(true);return t;});
    private long window=System.nanoTime();private int count;
    public CommunityHttpGateway600(InetSocketAddress bind,CommunityStore store,AccessControl access,ContentService content,org.securemail.community.org.OrgAdminService organizations,org.securemail.community.agent.AgentService agent,KeyPair communityKey,CommunityIdentityBridge600 bridge)throws Exception {
        if(bind.isUnresolved()||!bind.getAddress().isLoopbackAddress())throw new IOException("Сообщества доступны только через loopback за onion service");
        this.key=Objects.requireNonNull(communityKey);this.bridge=Objects.requireNonNull(bridge);audience=IdentityProtocol.id(communityKey.getPublic().getEncoded());
        if(!audience.equals(bridge.communityAudience()))throw new IOException("Подмена ключа Сообществ");
        controller=new CommunityRouter600(store,access,organizations,content,agent,bridge);serviceWorkers=new org.securemail.community.agent.WorkerServiceGateway600(store,access,agent,communityKey);deadlines.setRemoveOnCancelPolicy(true);
        System.setProperty("jdk.httpserver.maxConnections","32");System.setProperty("sun.net.httpserver.maxReqHeaders","16");System.setProperty("sun.net.httpserver.maxReqTime","30");System.setProperty("sun.net.httpserver.maxRspTime","30");
        server=HttpServer.create(bind,16);server.setExecutor(workers);server.createContext("/",this::handle);
    }
    public void start(){server.start();}
    public int port(){return server.getAddress().getPort();}
    private synchronized boolean rate(){long now=System.nanoTime();if(now-window>=60_000_000_000L){window=now;count=0;}return ++count<=600;}
    private void handle(HttpExchange x){
        byte[]body=new byte[0];String nonce=IdentityProtocol.nonce();ScheduledFuture<?>deadline=deadlines.schedule(x::close,30,TimeUnit.SECONDS);
        try {
            if(!rate())throw new IOException("Raw request limit");
            if(x.getRequestURI().getRawPath().equals(org.securemail.community.agent.WorkerWire600.PATH)){serviceWorkers.handle(x);return;}
            if(!x.getRequestMethod().equals("POST")||!x.getRequestURI().getRawPath().equals("/community/v6")||x.getRequestURI().getRawQuery()!=null)throw new IOException("Endpoint");
            Headers h=x.getRequestHeaders();String length=one(h,"Content-Length"),type=one(h,"Content-Type");
            if(length==null||!length.matches("[0-9]{1,8}")||type==null||!type.matches("(?i)application/json(?:;\\s*charset=utf-8)?")||h.containsKey("Transfer-Encoding")||h.containsKey("Content-Encoding"))throw new IOException("Framing");
            int n=Integer.parseInt(length);if(n<2||n>CommunityWire600.MAX_BODY)throw new IOException("Limit");body=x.getRequestBody().readNBytes(n+1);if(body.length!=n)throw new IOException("Incomplete");
            Map<String,Object>request=StrictJson.object(body,CommunityWire600.MAX_BODY);
            if(!request.keySet().equals(Set.of("action","argsJson","authorization","criticalProof","nonce")))throw new IOException("Fields");
            nonce=IdentityProtocol.nonceValue(StrictJson.text(request,"nonce",43));String action=StrictJson.text(request,"action",96);CommunityWire600.identityAction(action);
            String exactArgs=StrictJson.text(request,"argsJson",CommunityWire600.MAX_ARGS);byte[]argsBytes=exactArgs.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Map<String,Object>args=StrictJson.object(argsBytes,CommunityWire600.MAX_ARGS);
            if(!(request.get("authorization") instanceof Map<?,?>raw))throw new IOException("Authorization");@SuppressWarnings("unchecked")Map<String,Object>authorization=(Map<String,Object>)raw;
            var evidence=bridge.evidence(action,exactArgs,args,authorization);bridge.authenticate(evidence); // consume app PoP once before Community tx
            if(!(request.get("criticalProof") instanceof Map<?,?> criticalRaw))throw new IOException("Critical proof");@SuppressWarnings("unchecked")Map<String,Object> criticalProof=(Map<String,Object>)criticalRaw;
            Map<String,Object>result=controller.handle(evidence,action,args,criticalProof);
            respond(x,200,nonce,body,Map.of("ok",true,"data",result));
        }catch(CommunityException error){try{respond(x,error.code().equals("NOT_FOUND")?404:403,nonce,body,Map.of("ok",false,"error",Map.of("code",error.code(),"message","Материал или действие недоступны")));}catch(Exception ignored){}}
        catch(Exception error){try{respond(x,403,nonce,body,Map.of("ok",false,"error",Map.of("code","DENIED","message","Запрос Сообществ не разрешён")));}catch(Exception ignored){}}
        finally{Arrays.fill(body,(byte)0);deadline.cancel(false);x.close();}
    }
    private static String one(Headers h,String key){List<String>v=h.get(key);return v!=null&&v.size()==1?v.getFirst():null;}
    private void respond(HttpExchange x,int status,String nonce,byte[]request,Map<String,Object>value)throws IOException {
        byte[]body=StrictJson.bytes(value);try{
            if(body.length>CommunityWire600.MAX_BODY)throw new IOException("Response size");Headers h=x.getResponseHeaders();h.set("Content-Type","application/json; charset=utf-8");h.set("Connection","close");h.set("Cache-Control","no-store");h.set("X-Content-Type-Options","nosniff");
            h.set("AEGIS-Signature",IdentityProtocol.b64(IdentityProtocol.sign(key.getPrivate(),CommunityWire600.response(audience,nonce,request,body))));
            x.sendResponseHeaders(status,body.length);x.getResponseBody().write(body);
        }finally{Arrays.fill(body,(byte)0);}
    }
    @Override public void close(){server.stop(0);workers.shutdownNow();deadlines.shutdownNow();}
}
