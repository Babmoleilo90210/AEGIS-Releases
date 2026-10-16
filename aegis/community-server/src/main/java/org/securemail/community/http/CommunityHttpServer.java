package org.securemail.community.http;

import com.sun.net.httpserver.*;
import org.securemail.community.core.*;
import org.securemail.community.access.AccessControl;
import org.securemail.community.org.OrgAdminService;
import org.securemail.community.content.ContentService;
import org.securemail.community.agent.AgentService;
import org.securemail.community.protocol.CommunityAuth;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

/** Loopback RPC origin for an independently configured Tor onion service.
 * No public listening interface, network discovery or production deployment is performed.
 * Every exact request and response body is bound to the configured service identity.
 */
public final class CommunityHttpServer implements AutoCloseable {
  private final HttpServer http;
  private final CommunityStore store;private final AccessControl access;
  private final OrgAdminService organizations;private final ContentService content;private final AgentService agent;
  private final KeyPair serviceKey;private final String audience;
  private final ThreadPoolExecutor workers=new ThreadPoolExecutor(2,2,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(16),daemon("aegis-community-http"),new ThreadPoolExecutor.AbortPolicy());
  private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,daemon("aegis-community-deadline"));
  private final LinkedHashMap<String,Bucket> rates=new LinkedHashMap<>();private long globalWindow;private int globalCount;
  private volatile boolean closed;
  private static ThreadFactory daemon(String name){return task->{Thread t=new Thread(task,name);t.setDaemon(true);return t;};}
  public CommunityHttpServer(InetSocketAddress bind,CommunityStore store,AccessControl access,OrgAdminService organizations,ContentService content,AgentService agent,KeyPair serviceKey)throws IOException,GeneralSecurityException {
    if(bind.isUnresolved()||!bind.getAddress().isLoopbackAddress())throw new IOException("Сервер АЕГИС должен слушать только loopback за Tor onion service");
    this.store=Objects.requireNonNull(store);this.access=Objects.requireNonNull(access);this.organizations=Objects.requireNonNull(organizations);this.content=Objects.requireNonNull(content);this.agent=Objects.requireNonNull(agent);this.serviceKey=Objects.requireNonNull(serviceKey);
    CommunityAuth.publicKey(serviceKey.getPublic().getEncoded());byte[] challenge="AEGIS service key consistency".getBytes(StandardCharsets.US_ASCII);
    if(!CommunityAuth.verify(serviceKey.getPublic().getEncoded(),challenge,CommunityAuth.sign(serviceKey.getPrivate(),challenge)))throw new GeneralSecurityException("Service key pair mismatch");audience=CommunityAuth.id(serviceKey.getPublic().getEncoded());store.bindServiceIdentity(audience);
    // JDK HTTP parser limits apply before our handler receives an exchange.
    System.setProperty("jdk.httpserver.maxConnections","64");System.setProperty("sun.net.httpserver.maxReqHeaders","32");System.setProperty("sun.net.httpserver.maxIdleConnections","16");System.setProperty("sun.net.httpserver.idleInterval","10");System.setProperty("sun.net.httpserver.maxReqTime","20");System.setProperty("sun.net.httpserver.maxRspTime","20");
    http=HttpServer.create(bind,32);http.setExecutor(workers);http.createContext("/",this::handle);deadlines.setRemoveOnCancelPolicy(true);
  }
  public void start(){if(closed)throw new IllegalStateException("Сервер закрыт");http.start();}
  public int port(){return http.getAddress().getPort();}
  public String serviceFingerprint(){return audience;}
  private void handle(HttpExchange exchange){
    String nonce=CommunityAuth.nonce();Binding binding=new Binding();ScheduledFuture<?> timeout=deadlines.schedule(exchange::close,20,TimeUnit.SECONDS);
    try {
      if(!exchange.getRequestMethod().equals("POST")||!exchange.getRequestURI().getRawPath().equals("/api/v1")||exchange.getRequestURI().getRawQuery()!=null){reject(exchange,binding,404,nonce,"NOT_FOUND","Материал недоступен");return;}
      Headers headers=exchange.getRequestHeaders();String candidate=single(headers,"AEGIS-Nonce");if(validNonce(candidate))nonce=candidate;
      String length=single(headers,"Content-Length"),type=single(headers,"Content-Type");
      if(headers.containsKey("Transfer-Encoding")||headers.containsKey("Content-Encoding")||length==null||!length.matches("[0-9]{1,8}")||type==null||!type.matches("(?i)application/json(?:;\\s*charset=utf-8)?")){reject(exchange,binding,400,nonce,"INVALID","Некорректный запрос");return;}
      long expected=Long.parseLong(length);if(expected<1||expected>CommunityAuth.MAX_BODY){reject(exchange,binding,413,nonce,"LIMIT","Размер запроса превышен");return;}
      if(!consumeRate(null)){reject(exchange,binding,429,nonce,"RATE_LIMIT","Слишком много запросов");return;}
      byte[] body=exchange.getRequestBody().readNBytes((int)expected+1);
      try {
        if(body.length!=expected)throw CommunityException.invalid();
        String timeText=single(headers,"AEGIS-Time"),keyText=single(headers,"AEGIS-Key"),signatureText=single(headers,"AEGIS-Signature");
        byte[] key=decode(keyText,44),signature=decode(signatureText,64);long now=store.clock().millis();long time=timeText!=null&&timeText.matches("[0-9]{1,17}")?Long.parseLong(timeText):-1;
        if(candidate==null||!candidate.equals(nonce)||key==null||signature==null||time<Math.max(0,now-60000)||time>now+60000||!CommunityAuth.verify(key,CommunityAuth.requestBytes(audience,time,nonce,body),signature)){
          reject(exchange,binding,401,nonce,"AUTH","Запрос не подтверждён");return;
        }
        String actor=CommunityAuth.id(key);binding.identity=actor;binding.requestSha256=CommunityAuth.id(CommunityAuth.requestBytes(audience,time,nonce,body));if(!consumeRate(actor)){reject(exchange,binding,429,nonce,"RATE_LIMIT","Слишком много запросов");return;}
        // Only an authenticated key may create an identity. Nonces are persisted before JSON parsing.
        store.ensureIdentity(key,"Пользователь");store.consumeNonce(actor,nonce,now+120000);
        Map<String,Object> request=StrictJson.object(body,CommunityAuth.MAX_BODY);
        if(!request.keySet().equals(Set.of("action","data")))throw CommunityException.invalid();
        String action=StrictJson.text(request,"action",128);if(!action.matches("[a-z][a-z0-9_.]{0,95}"))throw CommunityException.invalid();
        if(!(request.get("data") instanceof Map<?,?> raw))throw CommunityException.invalid();
        @SuppressWarnings("unchecked") Map<String,Object> data=(Map<String,Object>)raw;
        if(action.equals("session.capabilities"))action="community.me";
        final String selectedAction=action;Map<String,Object> document;
        if(selectedAction.startsWith("agent.")){
          // Agent model/evidence network operations must run outside the database monitor.
          // The service rechecks ACL, epochs and source revisions; never stamp its result
          // with a different authorization epoch that the client could cache as fresh.
          long epoch=access.authorizationEpoch(actor);Map<String,Object> result=dispatch(actor,selectedAction,data);
          if(access.authorizationEpoch(actor)!=epoch)throw CommunityException.missing();
          document=Map.of("ok",true,"data",result,"authorizationEpoch",epoch,"serverTime",store.clock().millis());
        }else document=store.tx(db->{Map<String,Object> result=dispatch(actor,selectedAction,data);return Map.of("ok",true,"data",result,"authorizationEpoch",access.authorizationEpoch(actor),"serverTime",store.clock().millis());});
        respond(exchange,binding,200,nonce,document);
      } finally {Arrays.fill(body,(byte)0);}
    } catch(CommunityException failure){
      try{String code=failure.code();int status=switch(code){case "NOT_FOUND"->404;case "DENIED","REAUTH_REQUIRED","FACTOR_UNAVAILABLE","FACTOR_INVALID"->403;case "REPLAY","CONFLICT","INITIALIZED"->409;case "RATE_LIMIT"->429;default->400;};reject(exchange,binding,status,nonce,code,safeMessage(failure.safeRussianMessage()));}catch(IOException ignored){}
    } catch(IOException|IllegalArgumentException failure){try{reject(exchange,binding,400,nonce,"INVALID","Некорректный запрос");}catch(IOException ignored){}}
    catch(Exception failure){try{reject(exchange,binding,503,nonce,"UNAVAILABLE","Сервис временно недоступен");}catch(IOException ignored){}}
    finally{timeout.cancel(false);exchange.close();}
  }
  private static final class Binding {String identity,requestSha256;}
  private Map<String,Object> dispatch(String actor,String action,Map<String,Object> data)throws Exception {
    agent.enforceWorkerBoundary(actor,action);
    if(organizations.supports(action))return organizations.handle(actor,action,data);
    if(content.supports(action))return content.handle(actor,action,data);
    if(agent.supports(action))return agent.handle(actor,action,data);
    throw CommunityException.invalid();
  }
  private static boolean validNonce(String value){try{return value!=null&&value.matches("[A-Za-z0-9_-]{43}")&&Base64.getUrlDecoder().decode(value).length==32&&Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(value)).equals(value);}catch(IllegalArgumentException invalid){return false;}}
  private static String single(Headers headers,String name){List<String> values=headers.get(name);return values!=null&&values.size()==1?values.getFirst():null;}
  private static byte[] decode(String value,int size){try{if(value==null||value.length()>128)return null;byte[] bytes=Base64.getDecoder().decode(value);return bytes.length==size&&Base64.getEncoder().encodeToString(bytes).equals(value)?bytes:null;}catch(IllegalArgumentException invalid){return null;}}
  private synchronized boolean consumeRate(String actor){
    long now=System.nanoTime();if(globalWindow==0||now-globalWindow>=60_000_000_000L){globalWindow=now;globalCount=0;}if(actor==null)return ++globalCount<=600;
    Bucket bucket=rates.get(actor);if(bucket==null||now-bucket.window>=60_000_000_000L){bucket=new Bucket(now);rates.put(actor,bucket);}while(rates.size()>4096)rates.remove(rates.keySet().iterator().next());return ++bucket.count<=120;
  }
  private static final class Bucket {final long window;int count;Bucket(long window){this.window=window;}}
  private static String safeMessage(String value){if(value==null||value.length()>200||value.codePoints().anyMatch(Character::isISOControl))return "Запрос отклонён";return value;}
  private void reject(HttpExchange exchange,Binding binding,int status,String nonce,String code,String message)throws IOException {if(!code.matches("[A-Z0-9_]{1,64}"))code="DENIED";respond(exchange,binding,status,nonce,Map.of("ok",false,"error",Map.of("code",code,"message",message),"serverTime",store.clock().millis()));}
  private void respond(HttpExchange exchange,Binding binding,int status,String nonce,Map<String,Object> document)throws IOException {
    Map<String,Object> envelope=new LinkedHashMap<>(document);if(binding.identity!=null){envelope.put("requestIdentity",binding.identity);envelope.put("requestSha256",binding.requestSha256);}
    byte[] bytes=StrictJson.bytes(envelope);if(bytes.length>CommunityAuth.MAX_BODY){Arrays.fill(bytes,(byte)0);envelope.clear();envelope.put("ok",false);envelope.put("error",Map.of("code","LIMIT","message","Размер ответа превышен"));if(binding.identity!=null){envelope.put("requestIdentity",binding.identity);envelope.put("requestSha256",binding.requestSha256);}bytes=StrictJson.bytes(envelope);status=413;}
    try {
      String signature=Base64.getEncoder().encodeToString(CommunityAuth.sign(serviceKey.getPrivate(),CommunityAuth.responseBytes(audience,nonce,bytes)));
      Headers headers=exchange.getResponseHeaders();headers.set("Content-Type","application/json; charset=utf-8");headers.set("Cache-Control","no-store");headers.set("Connection","close");headers.set("X-Content-Type-Options","nosniff");headers.set("AEGIS-Signature",signature);exchange.sendResponseHeaders(status,bytes.length);exchange.getResponseBody().write(bytes);
    }catch(GeneralSecurityException failure){throw new IOException("Подпись ответа недоступна");}finally{Arrays.fill(bytes,(byte)0);}
  }
  @Override public void close(){closed=true;http.stop(0);deadlines.shutdownNow();workers.shutdownNow();}
}
