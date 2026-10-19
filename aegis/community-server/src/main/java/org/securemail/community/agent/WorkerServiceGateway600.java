package org.securemail.community.agent;

import com.sun.net.httpserver.*;
import org.securemail.community.access.AccessControl;
import org.securemail.community.core.*;
import org.securemail.community.http.StrictJson;
import org.securemail.community.protocol.CommunityAuth;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;

/** Operator-allowlisted service keys only. No user root, Identity capability or administrative route. */
public final class WorkerServiceGateway600 {
  private final CommunityStore store;private final AccessControl access;private final AgentService agent;private final KeyPair key;private final String audience;
  public WorkerServiceGateway600(CommunityStore store,AccessControl access,AgentService agent,KeyPair key)throws Exception {
    this.store=store;this.access=access;this.agent=agent;this.key=key;audience=CommunityAuth.id(key.getPublic().getEncoded());
    initialize(store);
  }
  private static void initialize(CommunityStore store)throws Exception {store.tx(db->{try(var q=db.createStatement()){
    q.execute("CREATE TABLE IF NOT EXISTS agent600_worker_key(identity TEXT PRIMARY KEY REFERENCES identities(identity),enabled INTEGER NOT NULL,created INTEGER NOT NULL)");
    q.execute("CREATE TABLE IF NOT EXISTS agent600_worker_rate(identity TEXT PRIMARY KEY,window INTEGER NOT NULL,requests INTEGER NOT NULL)");
  }return null;});}
  public static void allow(CommunityStore store,AccessControl access,byte[]publicKey,String fingerprint)throws Exception {
    initialize(store);if(publicKey.length!=44||!CommunityAuth.id(publicKey).equals(fingerprint))throw CommunityException.denied();
    store.tx(db->{boolean existing=exists(db,"SELECT 1 FROM agent600_worker_key WHERE identity=?",fingerprint);
      if(!existing&&exists(db,"SELECT 1 FROM identities WHERE identity=?",fingerprint))throw CommunityException.denied();
      if(existing){checkScope(store,access,db,fingerprint);exec(db,"UPDATE agent600_worker_key SET enabled=1 WHERE identity=?",fingerprint);exec(db,"UPDATE agent_worker SET enabled=1 WHERE identity=?",fingerprint);}
      else {try(var q=db.createStatement();var r=q.executeQuery("SELECT count(*) FROM agent600_worker_key")){r.next();if(r.getInt(1)>=64)throw CommunityException.denied();}
        store.ensureIdentity(publicKey,"Служебный рабочий узел новостей");String role=UUID.randomUUID().toString();
        exec(db,"INSERT INTO roles(id,scope,name,clearance) VALUES(?,'GLOBAL',?,0)",role,"Служебный сборщик новостей "+fingerprint.substring(0,12));
        exec(db,"INSERT INTO role_permissions VALUES(?,'AGENT_WORK')",role);exec(db,"INSERT INTO assignments VALUES(?,?)",fingerprint,role);
        exec(db,"INSERT INTO agent_worker(identity,enabled) VALUES(?,1)",fingerprint);exec(db,"INSERT INTO agent600_worker_key VALUES(?,1,?)",fingerprint,store.clock().millis());
      }
      checkScope(store,access,db,fingerprint);store.audit(db,"LOCAL_OPERATOR","AGENT600_WORKER_ALLOW",fingerprint,"Separate public service identity only");return null;
    });
  }
  public static void revoke(CommunityStore store,String fingerprint)throws Exception {initialize(store);Values.identity(fingerprint);store.tx(db->{exec(db,"UPDATE agent600_worker_key SET enabled=0 WHERE identity=?",fingerprint);exec(db,"UPDATE agent_worker SET enabled=0 WHERE identity=?",fingerprint);store.audit(db,"LOCAL_OPERATOR","AGENT600_WORKER_REVOKE",fingerprint,"Service allowlist revoked");return null;});}
  private static void checkScope(CommunityStore store,AccessControl access,Connection db,String actor)throws Exception {
    if(!access.permissions(actor,"GLOBAL").equals(Set.of("AGENT_WORK"))||access.isGlobalAdmin(actor)||exists(db,"SELECT 1 FROM memberships WHERE identity=?",actor)||exists(db,"SELECT 1 FROM assignments a JOIN roles r ON r.id=a.role WHERE a.identity=? AND r.scope<>'GLOBAL'",actor))throw CommunityException.denied();
  }
  private void active(Connection db,String actor)throws Exception {if(!exists(db,"SELECT 1 FROM agent600_worker_key WHERE identity=? AND enabled=1",actor))throw CommunityException.denied();checkScope(store,access,db,actor);}
  private static void rate(Connection db,String identity,long now,int limit)throws Exception {
    long window=Math.floorDiv(now,60000);long prior=0;int count=0;try(var q=db.prepareStatement("SELECT window,requests FROM agent600_worker_rate WHERE identity=?")){q.setString(1,identity);try(var r=q.executeQuery()){if(r.next()){prior=r.getLong(1);count=r.getInt(2);}}}
    if(prior>window||prior==window&&count>=limit)throw new CommunityException("RATE_LIMIT","Служебный лимит");
    exec(db,"INSERT INTO agent600_worker_rate VALUES(?,?,?) ON CONFLICT(identity) DO UPDATE SET window=excluded.window,requests=excluded.requests",identity,window,prior==window?count+1:1);
  }
  public void handle(HttpExchange x) {
    byte[]body=new byte[0];String nonce="a".repeat(43),actor="0".repeat(64);byte[]requestProof=new byte[0];
    try {
      if(!x.getRequestMethod().equals("POST")||!x.getRequestURI().getRawPath().equals(WorkerWire600.PATH)||x.getRequestURI().getRawQuery()!=null)throw CommunityException.denied();
      Headers h=x.getRequestHeaders();String length=one(h,"Content-Length"),type=one(h,"Content-Type");
      if(length==null||!length.matches("[0-9]{1,7}")||type==null||!type.matches("(?i)application/json(?:;\\s*charset=utf-8)?")||h.containsKey("Transfer-Encoding")||h.containsKey("Content-Encoding"))throw CommunityException.denied();
      int size=Integer.parseInt(length);if(size<2||size>WorkerWire600.MAX_BODY)throw CommunityException.denied();body=x.getRequestBody().readNBytes(size+1);if(body.length!=size)throw CommunityException.denied();
      byte[]publicKey=decode(one(h,"AEGIS-Key"),44),signature=decode(one(h,"AEGIS-Signature"),64);actor=CommunityAuth.id(publicKey);
      nonce=one(h,"AEGIS-Nonce");String timeText=one(h,"AEGIS-Time");if(timeText==null||!timeText.matches("[0-9]{1,15}")||nonce==null||!nonce.matches("[A-Za-z0-9_-]{43}"))throw CommunityException.denied();
      long time=Long.parseLong(timeText),now=store.clock().millis();if(time<now-60000||time>now+60000)throw CommunityException.denied();
      requestProof=WorkerWire600.requestBytes(audience,time,nonce,body);if(!CommunityAuth.verify(publicKey,requestProof,signature))throw CommunityException.denied();
      Map<String,Object>request=StrictJson.object(body,WorkerWire600.MAX_BODY);if(!request.keySet().equals(Set.of("action","data"))||!(request.get("data") instanceof Map<?,?>raw))throw CommunityException.denied();
      String action=StrictJson.text(request,"action",64);if(!WorkerWire600.ACTIONS.contains(action))throw CommunityException.denied();@SuppressWarnings("unchecked")Map<String,Object>data=(Map<String,Object>)raw;
      String authenticatedActor=actor,authenticatedNonce=nonce;
      // Commit authenticated replay/rate guards even if the subsequent operation is invalid.
      store.tx(db->{active(db,authenticatedActor);rate(db,"*",now,120);rate(db,authenticatedActor,now,30);store.consumeNonce(authenticatedActor,authenticatedNonce,now+120000);return null;});
      Map<String,Object>result=store.tx(db->{active(db,authenticatedActor);agent.enforceWorkerBoundary(authenticatedActor,action);return agent.handle(authenticatedActor,action,data);});
      respond(x,200,nonce,actor,requestProof,body,Map.of("ok",true,"data",result));
    }catch(CommunityException error){try{respond(x,error.code().equals("RATE_LIMIT")?429:403,nonce,actor,requestProof,body,Map.of("ok",false,"error",error.code().equals("RATE_LIMIT")?"RATE_LIMIT":"DENIED"));}catch(Exception ignored){}}
    catch(Exception error){try{respond(x,403,nonce,actor,requestProof,body,Map.of("ok",false,"error","DENIED"));}catch(Exception ignored){}}
    finally{Arrays.fill(body,(byte)0);Arrays.fill(requestProof,(byte)0);x.close();}
  }
  private void respond(HttpExchange x,int status,String nonce,String actor,byte[]requestProof,byte[]requestBody,Map<String,Object>value)throws Exception {
    Map<String,Object>envelope=new LinkedHashMap<>(value);envelope.put("requestIdentity",actor);envelope.put("requestSha256",CommunityAuth.id(requestProof));byte[]body=AgentJson.bytes(envelope);
    try{if(body.length>WorkerWire600.MAX_BODY)throw new IOException("Worker response bound");x.getResponseHeaders().set("Content-Type","application/json");x.getResponseHeaders().set("Cache-Control","no-store");x.getResponseHeaders().set("Connection","close");x.getResponseHeaders().set("AEGIS-Signature",Base64.getEncoder().encodeToString(CommunityAuth.sign(key.getPrivate(),WorkerWire600.responseBytes(audience,nonce,requestBody,body))));x.sendResponseHeaders(status,body.length);x.getResponseBody().write(body);}finally{Arrays.fill(body,(byte)0);}
  }
  private static String one(Headers h,String key){List<String>values=h.get(key);return values!=null&&values.size()==1?values.getFirst():null;}
  private static byte[]decode(String text,int size)throws Exception{if(text==null||text.length()>128)throw CommunityException.denied();byte[]bytes=Base64.getDecoder().decode(text);if(bytes.length!=size||!Base64.getEncoder().encodeToString(bytes).equals(text))throw CommunityException.denied();return bytes;}
  private static boolean exists(Connection db,String sql,Object...args)throws Exception{try(var q=db.prepareStatement(sql)){for(int i=0;i<args.length;i++)q.setObject(i+1,args[i]);try(var r=q.executeQuery()){return r.next();}}}
  private static void exec(Connection db,String sql,Object...args)throws Exception{try(var q=db.prepareStatement(sql)){for(int i=0;i<args.length;i++)q.setObject(i+1,args[i]);q.executeUpdate();}}
}
