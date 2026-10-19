package org.securemail.client.voice600;

import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.AppPaths;
import org.securemail.client.community.CommunityJson;
import org.securemail.client.ecosystemauth.CorePublicConfig600;
import org.securemail.client.net.TorTransport;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;

/** Bounded pinned-response signaling over onion-only SOCKS. No audio traverses this service. */
public final class GlasSignalingClient600 implements AutoCloseable {
  public record Config(String onion,int port,byte[] servicePublic){
    public Config{org.securemail.protocol.Limits.onion(onion);if(port<1||port>65535)throw new IllegalArgumentException("Порт Гласа");IdentityProtocol.publicKey(servicePublic);servicePublic=servicePublic.clone();}
    @Override public byte[] servicePublic(){return servicePublic.clone();}
    public static Config load()throws IOException{
      Path file=AppPaths.root().resolve("core600/glas600.properties");for(Path p=file.toAbsolutePath();p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылка в настройках Гласа запрещена");
      if(!Files.isRegularFile(file)||Files.size(file)>4096)throw new IOException("Не настроен доверенный сервер сигнализации Гласа");Properties p=new Properties();try(var in=Files.newInputStream(file)){p.load(in);}if(!p.stringPropertyNames().equals(Set.of("onion","port","servicePublicKey")))throw new IOException("Некорректные настройки сервера Гласа");
      try{return new Config(p.getProperty("onion"),Integer.parseInt(p.getProperty("port")),IdentityProtocol.unb64(p.getProperty("servicePublicKey"),44));}catch(IllegalArgumentException e){throw new IOException("Некорректные настройки сервера Гласа",e);}
    }
  }
  public record Resolved(GlasProtocol600.Delegation delegation,GlasProtocol600.Endpoint endpoint){}
  @FunctionalInterface interface Connector{Socket open(String onion,int port,TorTransport.SocketObserver observer)throws IOException;}
  private final Config config;private final String wire,identityAudience;private final PrivateKey appKey;private final IdentityProtocol.Capability cap;private final Connector connector;
  private final Semaphore slots=new Semaphore(2);private final Set<Socket> sockets=ConcurrentHashMap.newKeySet();private final ScheduledExecutorService deadlines=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"glas-signaling-deadlines");t.setDaemon(true);return t;});private volatile boolean closed;
  public GlasSignalingClient600(Config config,CorePublicConfig600 identity,String wire,PrivateKey appKey,TorTransport tor){this(config,identity,wire,appKey,tor::connectPeer);}
  GlasSignalingClient600(Config config,CorePublicConfig600 identity,String wire,PrivateKey appKey,Connector connector){
    this.config=Objects.requireNonNull(config);this.wire=Objects.requireNonNull(wire);this.appKey=Objects.requireNonNull(appKey);this.connector=Objects.requireNonNull(connector);cap=IdentityProtocol.decodeCapability(wire);identityAudience=IdentityProtocol.id(identity.identityPublicKey());
    if(cap.appId!=IdentityProtocol.App.GLAS||!IdentityProtocol.verifyCapability(cap,identity.identityPublicKey(),System.currentTimeMillis())||!cap.capabilities.contains(IdentityProtocol.Scope.VOICE_CALL))throw new IllegalArgumentException("Разрешение Гласа недействительно");
    byte[] probe=IdentityProtocol.digest(GlasGrant600.CONSENT_BODY);if(!IdentityProtocol.verify(cap.proofKey,probe,IdentityProtocol.sign(appKey,probe)))throw new IllegalArgumentException("Ключ Гласа не соответствует допуску");
  }
  public String audience(){return IdentityProtocol.id(config.servicePublic());}
  public void register(GlasProtocol600.Delegation delegation,GlasProtocol600.Endpoint endpoint,Set<String> incoming,Set<String> outgoing)throws IOException{JsonObject data=call(GlasProtocol600.Request.register(delegation,endpoint,incoming,outgoing));JsonElement ok=data.get("registered");if(ok==null||!ok.isJsonPrimitive()||!ok.getAsJsonPrimitive().isBoolean()||!ok.getAsBoolean())throw new IOException("Адрес Гласа не зарегистрирован");}
  public Resolved lookup(byte[] pinnedContactRoot)throws IOException{return lookup(pinnedContactRoot,false);}
  public Resolved lookup(byte[] pinnedContactRoot,boolean incoming)throws IOException{
    JsonObject result=call(GlasProtocol600.Request.lookup(pinnedContactRoot,incoming));try{var d=GlasProtocol600.decodeDelegation(IdentityProtocol.unb64(text(result,"delegation"),1024));var e=GlasProtocol600.decodeEndpoint(IdentityProtocol.unb64(text(result,"endpoint"),1024));long now=System.currentTimeMillis();if(!GlasProtocol600.verifyDelegation(d,pinnedContactRoot,identityAudience,now)||!e.verify(audience(),d,now))throw new IOException("Адрес контакта не подтверждён");return new Resolved(d,e);}catch(IllegalArgumentException invalid){throw new IOException("Некорректный ответ Гласа",invalid);}
  }
  public void unregister()throws IOException{call(GlasProtocol600.Request.unregister());}
  private JsonObject call(GlasProtocol600.Request request)throws IOException{
    if(closed||!slots.tryAcquire())throw new IOException("Сигнализация Гласа сейчас недоступна");byte[] body=request.encode();long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] proof=IdentityProtocol.sign(appKey,IdentityProtocol.requestDigest(cap,"glas.call",IdentityProtocol.digest(body),time,nonce));Socket[] opened={null};ScheduledFuture<?>[] timeout={null};
    try(Socket socket=connector.open(config.onion(),config.port(),s->{opened[0]=s;sockets.add(s);if(closed)throw new IOException("Глас закрыт");try{timeout[0]=deadlines.schedule(()->close(s),20,TimeUnit.SECONDS);}catch(RejectedExecutionException stopped){throw new IOException("Глас закрыт",stopped);}})){
      socket.setSoTimeout(15000);OutputStream out=socket.getOutputStream();String headers="POST /glas/v1 HTTP/1.1\r\nHost: "+config.onion()+"\r\nContent-Type: application/octet-stream\r\nConnection: close\r\nAEGIS-Capability: "+wire+"\r\nAEGIS-Time: "+time+"\r\nAEGIS-Nonce: "+nonce+"\r\nAEGIS-Proof: "+IdentityProtocol.b64(proof)+"\r\nContent-Length: "+body.length+"\r\n\r\n";out.write(headers.getBytes(StandardCharsets.US_ASCII));out.write(body);out.flush();DataInputStream in=new DataInputStream(socket.getInputStream());String status=line(in,1024);if(!status.matches("HTTP/1\\.[01] [1-5][0-9]{2}(?: [\\x20-\\x7e]*)?"))throw new IOException("Некорректный ответ Гласа");Map<String,String> h=new HashMap<>();boolean ended=false;int total=0;
      for(int n=0;n<32;n++){String l=line(in,4096);total+=l.length();if(total>8192)throw new IOException("Размер заголовков Гласа");if(l.isEmpty()){ended=true;break;}int colon=l.indexOf(':');if(colon<1||!l.substring(0,colon).matches("[A-Za-z0-9-]+")||h.putIfAbsent(l.substring(0,colon).toLowerCase(Locale.ROOT),l.substring(colon+1).strip())!=null)throw new IOException("Заголовок Гласа");}
      String length=h.getOrDefault("content-length","");if(!ended||h.containsKey("transfer-encoding")||h.containsKey("content-encoding")||!length.matches("[0-9]{1,6}"))throw new IOException("Кодирование ответа Гласа");int size=Integer.parseInt(length);if(size<1||size>16384)throw new IOException("Размер ответа Гласа");byte[] received=in.readNBytes(size);if(received.length!=size)throw new EOFException();
      if(!IdentityProtocol.verify(config.servicePublic(),IdentityProtocol.response(audience(),nonce,body,received),IdentityProtocol.unb64(h.getOrDefault("aegis-signature",""),64)))throw new IOException("Подпись сервера Гласа не подтверждена");JsonObject result=CommunityJson.parse(received);JsonElement ok=result.get("ok"),data=result.get("data");if(!status.matches("HTTP/1\\.[01] 200(?: .*)?")||ok==null||!ok.isJsonPrimitive()||!ok.getAsJsonPrimitive().isBoolean()||!ok.getAsBoolean()||data==null||!data.isJsonObject())throw new IOException("Контакт недоступен или звонок не разрешён");if(closed)throw new IOException("Глас закрыт");return data.getAsJsonObject();
    }catch(IllegalArgumentException|IllegalStateException invalid){throw new IOException("Ответ Гласа не прошёл проверку",invalid);}finally{if(timeout[0]!=null)timeout[0].cancel(false);if(opened[0]!=null){sockets.remove(opened[0]);close(opened[0]);}slots.release();}
  }
  private static String text(JsonObject o,String name)throws IOException{JsonElement v=o.get(name);if(v==null||!v.isJsonPrimitive()||!v.getAsJsonPrimitive().isString()||v.getAsString().length()>4096)throw new IOException("Поле ответа Гласа");return v.getAsString();}
  private static String line(DataInputStream in,int max)throws IOException{ByteArrayOutputStream b=new ByteArrayOutputStream();for(int i=0;i<max;i++){int c=in.read();if(c<0)throw new EOFException();if(c=='\r'){if(in.read()!='\n')throw new IOException("HTTP Гласа");return b.toString(StandardCharsets.US_ASCII);}if(c<32||c>126)throw new IOException("HTTP Гласа");b.write(c);}throw new IOException("Строка Гласа слишком велика");}
  private static void close(Socket s){try{s.close();}catch(IOException ignored){}}
  @Override public void close(){closed=true;for(Socket s:sockets)close(s);sockets.clear();deadlines.shutdownNow();}
}
