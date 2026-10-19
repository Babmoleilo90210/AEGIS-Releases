package org.securemail.client.ecosystemauth;

import com.google.gson.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.community.CommunityJson;
import org.securemail.client.net.TorTransport;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.protocol.Limits;

/** Identity transport using only the existing onion-only SOCKS connector.
 * Holds no account identity key; application proof keys are used for one typed call.
 * A signed live status is a recheck, never a replacement for proof-of-possession.
 */
public final class IdentityClient600 implements AutoCloseable {
  @FunctionalInterface interface Connector {
    Socket open(String host,int port,TorTransport.SocketObserver observer)throws IOException;
  }
  public static final class Rejected extends IOException {
    private final String code;
    Rejected(String code){super("Сервер Identity отклонил запрос");this.code=code;}
    public String code(){return code;}
  }
  private final String onion,audience;
  private final int port;
  private final byte[] serverKey;
  private final Connector connector;
  private final Clock clock;
  private final Semaphore slots=new Semaphore(2);
  private final Set<Socket> active=ConcurrentHashMap.newKeySet();
  private final ScheduledExecutorService deadlines=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-identity-deadline");t.setDaemon(true);return t;});
  private volatile boolean closed;

  public IdentityClient600(String onion,int port,byte[] serverKey,TorTransport tor) {
    this(onion,port,serverKey,Objects.requireNonNull(tor)::connectPeer,Clock.systemUTC());
  }
  IdentityClient600(String onion,int port,byte[] serverKey,Connector connector,Clock clock) {
    Limits.onion(onion);
    if(port<1||port>65535)throw new IllegalArgumentException("Identity port");
    IdentityProtocol.publicKey(serverKey);
    this.onion=onion;this.port=port;this.serverKey=serverKey.clone();this.audience=IdentityProtocol.id(serverKey);
    this.connector=Objects.requireNonNull(connector);this.clock=Objects.requireNonNull(clock);
  }
  public String audience(){return audience;}

  public JsonObject rpc(String operation,JsonObject data)throws IOException {
    if(closed)throw new IOException("Соединение Identity закрыто");
    if(operation==null||!operation.matches("[a-z][A-Za-z0-9.]{0,63}"))throw new IOException("Некорректная операция Identity");
    String nonce=IdentityProtocol.nonce();
    JsonObject request=new JsonObject();request.addProperty("operation",operation);request.addProperty("nonce",nonce);request.add("data",data==null?new JsonObject():data.deepCopy());
    byte[] exact=request.toString().getBytes(StandardCharsets.UTF_8);
    if(exact.length>IdentityProtocol.MAX_BODY)throw new IOException("Запрос Identity слишком велик");
    if(!slots.tryAcquire())throw new IOException("Дождитесь завершения проверки Identity");
    Socket[] observed={null};ScheduledFuture<?>[] timeout={null};
    try {
      try(Socket socket=connector.open(onion,port,opened->{
        observed[0]=opened;active.add(opened);
        if(closed)throw new IOException("Соединение Identity закрыто");
        try{timeout[0]=deadlines.schedule(()->{try{opened.close();}catch(IOException ignored){}},30,TimeUnit.SECONDS);}
        catch(RejectedExecutionException stopped){throw new IOException("Соединение Identity закрыто",stopped);}
      })) {
        if(closed)throw new IOException("Соединение Identity закрыто");socket.setSoTimeout(20_000);
        OutputStream out=socket.getOutputStream();
        out.write(("POST /identity/v1 HTTP/1.1\r\nHost: "+onion+"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+exact.length+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(exact);out.flush();
        DataInputStream in=new DataInputStream(socket.getInputStream());String status=line(in,1024);
        if(!status.matches("HTTP/1\\.[01] [1-5][0-9]{2}(?: [\\x20-\\x7e]*)?"))throw new IOException("Некорректный ответ Identity");
        Map<String,String> headers=new HashMap<>();boolean complete=false;int total=0;
        for(int i=0;i<32;i++){
          String h=line(in,4096);total+=h.length();if(total>8192)throw new IOException("Заголовки Identity слишком велики");
          if(h.isEmpty()){complete=true;break;}
          int colon=h.indexOf(':');if(colon<1||!h.substring(0,colon).matches("[A-Za-z0-9-]+"))throw new IOException("Некорректный заголовок Identity");
          String key=h.substring(0,colon).toLowerCase(Locale.ROOT),value=h.substring(colon+1).strip();
          if(headers.putIfAbsent(key,value)!=null)throw new IOException("Повторный заголовок Identity");
        }
        if(!complete||headers.containsKey("transfer-encoding")||headers.containsKey("content-encoding"))throw new IOException("Недопустимое кодирование Identity");
        String len=headers.getOrDefault("content-length","");if(!len.matches("[0-9]{1,6}"))throw new IOException("Нет корректного размера Identity");
        int size=Integer.parseInt(len);if(size<1||size>IdentityProtocol.MAX_BODY)throw new IOException("Ответ Identity слишком велик");
        byte[] received=in.readNBytes(size);
        try {
          if(received.length!=size)throw new EOFException("Неполный ответ Identity");
          byte[] signature=IdentityProtocol.unb64(headers.getOrDefault("aegis-signature",""),64);
          if(!IdentityProtocol.verify(serverKey,IdentityProtocol.response(audience,nonce,exact,received),signature))throw new IOException("Подпись Identity не подтверждена");
          JsonObject response=CommunityJson.parse(received);
          JsonElement ok=response.get("ok");if(ok==null||!ok.isJsonPrimitive()||!ok.getAsJsonPrimitive().isBoolean())throw new IOException("Некорректный статус Identity");
          if(!ok.getAsBoolean()){
            JsonElement error=response.get("error");String code="DENIED";
            if(error!=null&&error.isJsonObject()){
              JsonElement value=error.getAsJsonObject().get("code");
              if(value!=null&&value.isJsonPrimitive()&&value.getAsJsonPrimitive().isString()&&value.getAsString().matches("[A-Z_]{1,40}"))code=value.getAsString();
            }
            throw new Rejected(code);
          }
          if(!status.startsWith("HTTP/1.1 200")&&!status.startsWith("HTTP/1.0 200"))throw new IOException("Недопустимый статус HTTP Identity");
          JsonElement result=response.get("data");if(result==null||!result.isJsonObject())throw new IOException("Некорректные данные Identity");
          if(closed)throw new IOException("Соединение Identity закрыто");return result.getAsJsonObject();
        }finally{Arrays.fill(received,(byte)0);}
      }
    }catch(Rejected e){throw e;}
    catch(IllegalArgumentException|IllegalStateException e){throw new IOException("Не удалось проверить ответ Identity",e);}
    finally {
      if(timeout[0]!=null)timeout[0].cancel(false);
      if(observed[0]!=null){active.remove(observed[0]);try{observed[0].close();}catch(IOException ignored){}}
      Arrays.fill(exact,(byte)0);slots.release();
    }
  }

  /** Hashes the exact actual service operation, not an unverified client supplied hash. */
  public JsonObject authorizeDigest(String token,PrivateKey appKey,String action,byte[] actualOperationBody)throws IOException,GeneralSecurityException {
    IdentityProtocol.Capability cap=IdentityProtocol.decodeCapability(token);
    if(!audience.equals(cap.audience)||!IdentityProtocol.verifyCapability(cap,serverKey,clock.millis()))throw new IOException("Разрешение приложения недействительно");
    byte[] digest=MessageDigest.getInstance("SHA-256").digest(Objects.requireNonNull(actualOperationBody));
    String nonce=IdentityProtocol.nonce();long time=clock.millis();
    byte[] proof=IdentityProtocol.sign(appKey,IdentityProtocol.requestDigest(cap,action,digest,time,nonce));
    return authorizeDigestProof(token,action,actualOperationBody,time,nonce,proof);
  }
  /** A separate service forwards an app's proof. It never receives the app private key. */
  public JsonObject authorizeDigestProof(String token,String action,byte[] actualOperationBody,long time,String nonce,byte[] proof)throws IOException,GeneralSecurityException {
    IdentityProtocol.Capability cap=IdentityProtocol.decodeCapability(token);
    if(!audience.equals(cap.audience)||!IdentityProtocol.verifyCapability(cap,serverKey,clock.millis()))throw new IOException("Разрешение приложения недействительно");
    byte[] digest=MessageDigest.getInstance("SHA-256").digest(Objects.requireNonNull(actualOperationBody));
    if(!IdentityProtocol.verify(cap.proofKey,IdentityProtocol.requestDigest(cap,action,digest,time,nonce),proof))throw new IOException("Запрос не соответствует разрешению приложения");
    JsonObject args=new JsonObject();args.addProperty("capability",token);args.addProperty("action",action);args.addProperty("bodySha256",IdentityProtocol.b64(digest));args.addProperty("time",time);args.addProperty("nonce",nonce);args.addProperty("proof",IdentityProtocol.b64(proof));
    JsonObject result=rpc("authorizeDigest",args);
    try {
      if(!cap.accountId.equals(text(result,"accountId"))||!cap.deviceId.equals(text(result,"deviceId"))||!cap.appId.name().equals(text(result,"appId"))||cap.generation!=number(result,"generation"))throw new IOException("Identity вернул другое разрешение");
      long until=number(result,"leaseUntil");if(until>cap.expiresAt||until<=clock.millis())throw new IOException("Разрешение Identity истекло");
      JsonArray list=result.getAsJsonArray("capabilities");if(list==null||list.size()!=cap.capabilities.size())throw new IOException("Некорректные полномочия Identity");
      Set<String> scopes=new HashSet<>();for(JsonElement item:list){if(!item.isJsonPrimitive()||!item.getAsJsonPrimitive().isString()||!scopes.add(item.getAsString()))throw new IOException("Некорректные полномочия Identity");}
      for(IdentityProtocol.Scope scope:cap.capabilities)if(!scopes.contains(scope.name()))throw new IOException("Полномочия Identity не совпадают");
    }catch(IllegalArgumentException|IllegalStateException e){throw new IOException("Некорректная привязка Identity",e);}
    return result;
  }
  /** Revalidates a capability already authorized with a proof by its holder. */
  public boolean isActive(String token)throws IOException {
    JsonObject data=new JsonObject();data.addProperty("capability",token);JsonObject result=rpc("isActive",data);JsonElement active=result.get("active");
    if(active==null||!active.isJsonPrimitive()||!active.getAsJsonPrimitive().isBoolean())throw new IOException("Некорректный ответ проверки сессии");
    return active.getAsBoolean();
  }
  private static String text(JsonObject object,String key)throws IOException {JsonElement e=object.get(key);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isString())throw new IOException("Некорректный ответ Identity");return e.getAsString();}
  private static long number(JsonObject object,String key)throws IOException {JsonElement e=object.get(key);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isNumber()||!e.getAsString().matches("[0-9]{1,19}"))throw new IOException("Некорректный ответ Identity");try{return Long.parseLong(e.getAsString());}catch(NumberFormatException invalid){throw new IOException("Некорректное число Identity",invalid);}}
  private static String line(DataInputStream in,int limit)throws IOException {
    ByteArrayOutputStream text=new ByteArrayOutputStream();
    for(int n=0;n<limit;n++){
      int c=in.read();if(c<0)throw new EOFException();
      if(c=='\r'){if(in.read()!='\n')throw new IOException("Некорректный HTTP Identity");return text.toString(StandardCharsets.US_ASCII);}
      if(c<32||c>126)throw new IOException("Некорректный HTTP Identity");text.write(c);
    }
    throw new IOException("Строка Identity слишком велика");
  }
  @Override public void close(){closed=true;for(Socket s:active)try{s.close();}catch(IOException ignored){}deadlines.shutdownNow();}
}
