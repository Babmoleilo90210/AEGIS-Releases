package org.securemail.client.community;

import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Clock;
import java.util.*;
import org.securemail.client.ClientConfig;
import org.securemail.client.net.TorTransport;
import org.securemail.client.storage.LocalStore;
import org.securemail.community.protocol.CommunityAuth;
import org.securemail.protocol.Limits;

/** A separate authenticated service channel. The only production connector is onion Tor SOCKS.
 * No mail, archive, password or private identity bytes are serialized to this service.
 */
public final class CommunityClient implements AutoCloseable {
  public record Settings(String onion,int port,String serverPublicKey){}
  @FunctionalInterface interface Connector{Socket connect(String onion,int port)throws IOException;}
  @FunctionalInterface private interface OpeningConnector{Socket connect(String onion,int port,TorTransport.SocketObserver observer)throws IOException;}
  public static final class Rejected extends IOException{
    private static final long serialVersionUID=1L;private final String code;
    Rejected(String code,String message){super(message);this.code=code;}public String code(){return code;}
  }
  private static final int CACHE_LIMIT=3*1024*1024,STATE_LIMIT=4*1024*1024;
  private static final long OFFLINE_MILLIS=5*60_000L;
  private final LocalStore local;private final Clock clock;private final OpeningConnector connector;
  private final java.util.concurrent.Semaphore slots=new java.util.concurrent.Semaphore(4);
  private final java.util.concurrent.ScheduledThreadPoolExecutor deadlines=new java.util.concurrent.ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-community-deadline");t.setDaemon(true);return t;});
  private final Object stateLock=new Object();private final Set<Socket> active=java.util.concurrent.ConcurrentHashMap.newKeySet();
  private final LinkedHashMap<String,JsonObject> cache=new LinkedHashMap<>();
  private volatile String announcedDisplay="";
  private Settings settings=new Settings("",80,"");private long epoch=-1;private volatile boolean closed,damaged;
  public CommunityClient(ClientConfig config,LocalStore local){this(local,Clock.systemUTC(),(OpeningConnector)new TorTransport(config.torSocksAddress(),config.torSocksPort())::connectPeer);}
  CommunityClient(LocalStore local,Clock clock,Connector connector){this(local,clock,(OpeningConnector)(onion,port,observer)->{Socket socket=connector.connect(onion,port);try{observer.opened(socket);return socket;}catch(IOException|RuntimeException failure){socket.close();throw failure;}});}
  private CommunityClient(LocalStore local,Clock clock,OpeningConnector connector){deadlines.setRemoveOnCancelPolicy(true);this.local=Objects.requireNonNull(local);this.clock=clock;this.connector=connector;
    try{byte[] raw=local.readExtension("community-v1",STATE_LIMIT);if(raw!=null){try{JsonObject root=CommunityJson.parse(raw);JsonObject s=root.getAsJsonObject("settings");if(s!=null&&!s.get("onion").getAsString().isEmpty())settings=checked(s.get("onion").getAsString(),s.get("port").getAsInt(),s.get("serverPublicKey").getAsString());if(root.has("epoch"))epoch=root.get("epoch").getAsLong();JsonObject entries=root.getAsJsonObject("cache");if(entries!=null&&entries.size()<=100)for(var entry:entries.entrySet())cache.put(entry.getKey(),entry.getValue().getAsJsonObject());prune();}finally{Arrays.fill(raw,(byte)0);}}}catch(Exception invalid){damaged=true;cache.clear();}
  }
  public Settings settings(){synchronized(stateLock){return settings;}}
  public boolean configured(){Settings s=settings();return !damaged&&!s.onion().isEmpty()&&!closed;}
  public boolean damaged(){return damaged;}
  public long authorizationEpoch(){synchronized(stateLock){return epoch;}}
  public void configure(String onion,int port,String encodedKey)throws IOException,GeneralSecurityException{
    Settings value=checked(onion,port,encodedKey);synchronized(stateLock){check();Settings old=settings;settings=value;cache.clear();epoch=-1;damaged=false;try{persist();}catch(IOException|GeneralSecurityException e){settings=old;throw e;}}
  }
  private static Settings checked(String onion,int port,String encoded)throws IOException,GeneralSecurityException{
    try{onion=onion.strip().toLowerCase(Locale.ROOT);Limits.onion(onion);if(port<1||port>65535)throw new IllegalArgumentException();byte[] key=Base64.getDecoder().decode(encoded.strip());CommunityAuth.publicKey(key);return new Settings(onion,port,Base64.getEncoder().encodeToString(key));}catch(IllegalArgumentException e){throw new IOException("Проверьте onion-адрес и открытый ключ сервера");}
  }
  /** Own signed display name only. This never asserts a verified badge or account authority. */
  public void publishDisplayName()throws IOException {
    if(!configured())return;String nickname=local.nickname();if(nickname==null||nickname.isBlank())return;String originalNickname=nickname;try{nickname=Limits.nickname(nickname);}catch(IllegalArgumentException invalid){throw new IOException("Проверьте nickname профиля",invalid);}
    Settings selected=settings();String marker=selected.onion()+":"+selected.port()+":"+selected.serverPublicKey()+":"+nickname;
    if(marker.equals(announcedDisplay))return;JsonObject args=new JsonObject();args.addProperty("nickname",nickname);
    JsonObject result=rpc("community.profile.update",args);
    if(!nickname.equals(stringField(result,"nickname")))throw new IOException("Не удалось подтвердить отображаемое имя");
    if(selected.equals(settings())&&originalNickname.equals(local.nickname()))announcedDisplay=marker;
  }
  public JsonObject rpc(String action,JsonObject data)throws IOException{
    check();if(!configured())throw new IOException(damaged?"Настройки общей системы повреждены. Настройте доверенный сервер повторно":"Укажите доверенный onion-сервер общей системы в настройках");
    if(action==null||!action.matches("[a-z][a-z0-9_.]{0,95}"))throw new IOException("Некорректное действие");
    Settings selected=settings();JsonObject body=new JsonObject();body.addProperty("action",action);body.add("data",data==null?new JsonObject():data.deepCopy());byte[] exact=body.toString().getBytes(StandardCharsets.UTF_8);if(exact.length>CommunityAuth.MAX_BODY)throw new IOException("Запрос слишком велик");
    String nonce=CommunityAuth.nonce();long time=clock.millis();byte[] key=Base64.getDecoder().decode(selected.serverPublicKey());String audience=CommunityAuth.id(key);
    if(!slots.tryAcquire()){Arrays.fill(exact,(byte)0);throw new IOException("Дождитесь завершения предыдущих запросов");}
    final Socket[] connecting={null};final java.util.concurrent.ScheduledFuture<?>[] deadline={null};
    try{
      byte[] proof=local.identity().sign(CommunityAuth.requestBytes(audience,time,nonce,exact));
      try(Socket socket=connector.connect(selected.onion(),selected.port(),opened->{connecting[0]=opened;active.add(opened);if(closed)throw new IOException("Соединение закрыто");try{deadline[0]=deadlines.schedule(()->{try{opened.close();}catch(IOException ignored){}},30,java.util.concurrent.TimeUnit.SECONDS);}catch(java.util.concurrent.RejectedExecutionException stopped){throw new IOException("Соединение закрыто",stopped);}})){socket.setSoTimeout(20_000);
        try{OutputStream out=socket.getOutputStream();String headers="POST /api/v1 HTTP/1.1\r\nHost: "+selected.onion()+"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+exact.length+"\r\nAEGIS-Key: "+Base64.getEncoder().encodeToString(local.identity().publicKey())+"\r\nAEGIS-Time: "+time+"\r\nAEGIS-Nonce: "+nonce+"\r\nAEGIS-Signature: "+Base64.getEncoder().encodeToString(proof)+"\r\n\r\n";out.write(headers.getBytes(StandardCharsets.US_ASCII));out.write(exact);out.flush();
          DataInputStream in=new DataInputStream(socket.getInputStream());String status=line(in,1024);if(!status.matches("HTTP/1\\.[01] [1-5][0-9]{2}(?: .*)?"))throw new IOException("Некорректный ответ сервера");Map<String,String> hs=new HashMap<>();int total=0;for(int n=0;n<64;n++){String header=line(in,8192);total+=header.length();if(total>16384)throw new IOException("Заголовок слишком велик");if(header.isEmpty())break;int colon=header.indexOf(':');if(colon<1)throw new IOException("Некорректный заголовок");String name=header.substring(0,colon).toLowerCase(Locale.ROOT),value=header.substring(colon+1).strip();if(hs.putIfAbsent(name,value)!=null)throw new IOException("Повторный заголовок");if(n==63)throw new IOException("Слишком много заголовков");}
          if(hs.containsKey("transfer-encoding")||hs.containsKey("content-encoding"))throw new IOException("Неподдерживаемое кодирование ответа");String length=hs.getOrDefault("content-length","");if(!length.matches("[0-9]{1,8}"))throw new IOException("Нет размера ответа");int size=Integer.parseInt(length);if(size>CommunityAuth.MAX_BODY)throw new IOException("Ответ слишком велик");byte[] received=in.readNBytes(size);if(received.length!=size)throw new EOFException("Неполный ответ");byte[] signature=Base64.getDecoder().decode(hs.getOrDefault("aegis-signature",""));if(!CommunityAuth.verify(key,CommunityAuth.responseBytes(audience,nonce,received),signature))throw new IOException("Подпись сервера не подтверждена");
          JsonObject response;try{response=CommunityJson.parse(received);}finally{Arrays.fill(received,(byte)0);}if(!local.identity().userId().equals(stringField(response,"requestIdentity"))||!CommunityAuth.id(CommunityAuth.requestBytes(audience,time,nonce,exact)).equals(stringField(response,"requestSha256")))throw new IOException("Ответ не соответствует подписанному запросу");if(!response.has("ok")||!response.get("ok").isJsonPrimitive()||!response.get("ok").getAsJsonPrimitive().isBoolean())throw new IOException("Некорректный статус ответа");if(!response.get("ok").getAsBoolean()){JsonObject e=response.getAsJsonObject("error");throw new Rejected(e==null?"DENIED":safe(e.get("code"),64),e==null?"Запрос отклонён":safe(e.get("message"),200));}
          JsonObject result=response.getAsJsonObject("data");if(result==null)throw new IOException("Некорректные данные ответа");synchronized(stateLock){check();if(!selected.equals(settings))throw new IOException("Настройки сервера изменены");JsonElement epochValue=response.get("authorizationEpoch");if(epochValue==null||!epochValue.isJsonPrimitive()||!epochValue.getAsJsonPrimitive().isNumber()||!epochValue.getAsString().matches("[0-9]{1,18}"))throw new IOException("Некорректная версия разрешений");long newEpoch=epochValue.getAsLong();if(epoch>newEpoch)throw new IOException("Разрешения изменились. Повторите запрос");if(epoch!=newEpoch){cache.clear();epoch=newEpoch;}cacheIfPermitted(action,data,result);persist();}return result;
        }finally{active.remove(socket);}
      }
    }catch(Rejected e){synchronized(stateLock){cache.clear();try{persist();}catch(Exception ignored){}}throw e;}catch(GeneralSecurityException|RuntimeException e){throw new IOException("Не удалось проверить защищённый ответ общей системы",e);}finally{if(deadline[0]!=null)deadline[0].cancel(false);if(connecting[0]!=null)active.remove(connecting[0]);Arrays.fill(exact,(byte)0);slots.release();}
  }
  private static String stringField(JsonObject object,String key)throws IOException{JsonElement e=object.get(key);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isString())throw new IOException("Некорректная привязка ответа");return e.getAsString();}
  private static String safe(JsonElement e,int limit){if(e==null||!e.isJsonPrimitive())return "Запрос отклонён";String s=e.getAsString();return s.codePoints().filter(c->!Character.isISOControl(c)).limit(limit).collect(StringBuilder::new,StringBuilder::appendCodePoint,StringBuilder::append).toString();}
  public JsonObject offline(String action,JsonObject args)throws IOException{synchronized(stateLock){check();prune();JsonObject item=cache.get(cacheKey(action,args));if(item==null)throw new IOException("Нет разрешённой офлайн-копии");JsonObject result=item.getAsJsonObject("data").deepCopy();result.addProperty("offlineCopy",true);return result;}}
  private void cacheIfPermitted(String action,JsonObject args,JsonObject data){
    if(!Set.of("content.library.get","content.news.get").contains(action))return;
    JsonObject policy=data.has("policy")&&data.get("policy").isJsonObject()?data.getAsJsonObject("policy"):null;
    if(policy==null||!policy.has("offlineAllowed")||!policy.get("offlineAllowed").isJsonPrimitive()||!policy.get("offlineAllowed").getAsJsonPrimitive().isBoolean()||!policy.get("offlineAllowed").getAsBoolean())return;
    JsonObject item=new JsonObject();item.addProperty("expires",clock.millis()+OFFLINE_MILLIS);item.add("data",data.deepCopy());cache.put(cacheKey(action,args),item);prune();while(cacheBytes()>CACHE_LIMIT&&!cache.isEmpty())cache.remove(cache.keySet().iterator().next());
  }
  private static String cacheKey(String action,JsonObject args){return action+":"+CommunityAuth.id((args==null?"{}":args.toString()).getBytes(StandardCharsets.UTF_8));}
  private int cacheBytes(){return cache.toString().getBytes(StandardCharsets.UTF_8).length;}
  private void prune(){long now=clock.millis();cache.entrySet().removeIf(e->{try{long expires=e.getValue().get("expires").getAsLong();return expires<=now||expires>now+OFFLINE_MILLIS;}catch(RuntimeException invalid){return true;}});while(cache.size()>100)cache.remove(cache.keySet().iterator().next());}
  public void clearCache()throws IOException{synchronized(stateLock){cache.clear();try{persist();}catch(GeneralSecurityException e){throw new IOException("Не удалось сохранить кэш",e);}}}
  private void persist()throws IOException,GeneralSecurityException{JsonObject root=new JsonObject(),s=new JsonObject(),items=new JsonObject();s.addProperty("onion",settings.onion());s.addProperty("port",settings.port());s.addProperty("serverPublicKey",settings.serverPublicKey());root.add("settings",s);root.addProperty("epoch",epoch);cache.forEach(items::add);root.add("cache",items);byte[] bytes=root.toString().getBytes(StandardCharsets.UTF_8);try{local.writeExtension("community-v1",bytes,STATE_LIMIT);}finally{Arrays.fill(bytes,(byte)0);}}
  private static String line(DataInputStream in,int maximum)throws IOException{ByteArrayOutputStream b=new ByteArrayOutputStream();boolean cr=false;for(int n=0;n<maximum;n++){int c=in.read();if(c<0)throw new EOFException();if(cr){if(c!='\n')throw new IOException("Некорректный HTTP");return b.toString(StandardCharsets.US_ASCII);}if(c=='\r')cr=true;else{if(c<32||c>126)throw new IOException("Некорректный HTTP");b.write(c);}}throw new IOException("Строка HTTP слишком длинная");}
  private void check()throws IOException{if(closed)throw new IOException("Общая система закрыта");}
  @Override public void close(){synchronized(stateLock){if(closed)return;closed=true;cache.clear();try{persist();}catch(Exception ignored){}}for(Socket s:active)try{s.close();}catch(IOException ignored){}deadlines.shutdownNow();}
}
