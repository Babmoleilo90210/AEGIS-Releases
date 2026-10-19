package org.securemail.client.management600;

import com.google.gson.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.AppPaths;
import org.securemail.client.community.CommunityJson;
import org.securemail.client.net.TorTransport;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.protocol.Limits;

/** Tor-only management client. Client choices never replace the broker's live authorization. */
public final class ManagementClient600 implements AutoCloseable {
  public enum Service {
    MAIL_RELAY("Почтовый Relay 6"),IDENTITY("Идентификация"),ATTACHMENTS("Вложения"),GLAS_SIGNALING("Глас: сигнализация"),COMMUNITY("Общая система"),NEWS_WORKER("Новостной агент"),LIBRARY("Библиотека"),MONITORING("Мониторинг");
    private final String label;Service(String label){this.label=label;}@Override public String toString(){return label;}
  }
  public enum Action {
    STATUS("management.status"),RESTART("management.service.restart"),BACKUP_CREATE("management.backup.create"),BACKUP_RESTORE("management.backup.restore");
    private final String permission;Action(String permission){this.permission=permission;}public String permission(){return permission;}public boolean critical(){return this==BACKUP_RESTORE;}
  }
  public record Request(String id,Action action,Service service,String snapshot) {
    public Request {
      if(id==null||!UUID.fromString(id).toString().equals(id))throw new IllegalArgumentException("Идентификатор операции");Objects.requireNonNull(action);snapshot=snapshot==null?"":snapshot;
      if(action==Action.STATUS||action==Action.RESTART){Objects.requireNonNull(service);if(!snapshot.isEmpty())throw new IllegalArgumentException("Аргументы службы");}
      else if(service!=null||(action.critical()?!snapshot.matches("[a-f0-9]{64}"):!snapshot.isEmpty()))throw new IllegalArgumentException("Аргументы резервной копии");
    }
    public static Request status(Service service){return new Request(UUID.randomUUID().toString(),Action.STATUS,service,"");}
    public static Request restart(Service service){return new Request(UUID.randomUUID().toString(),Action.RESTART,service,"");}
    public static Request backup(){return new Request(UUID.randomUUID().toString(),Action.BACKUP_CREATE,null,"");}
    public static Request restore(String snapshot){return new Request(UUID.randomUUID().toString(),Action.BACKUP_RESTORE,null,snapshot);}
    /** Exact server ManagementPolicy format, covered by cross-module compatibility tests. */
    public byte[] encode(){try{var bytes=new ByteArrayOutputStream();try(var out=new DataOutputStream(bytes)){out.writeUTF("AEGIS-MANAGEMENT-REQUEST/v1");out.writeUTF(id);out.writeUTF(action.name());out.writeUTF(service==null?"":service.name());out.writeUTF(snapshot);}return bytes.toByteArray();}catch(IOException impossible){throw new IllegalStateException(impossible);}}
  }
  public record Grant(String capability,PrivateKey proof) {
    public Grant {Objects.requireNonNull(capability);Objects.requireNonNull(proof);}
    @Override public String toString(){return "ManagementGrant[redacted]";}
  }
  @FunctionalInterface public interface GrantProvider {Grant acquire(Request exactRequest)throws Exception;}
  public record Approval(String capability,long time,String nonce,byte[] signature) {
    public Approval {Objects.requireNonNull(capability);Objects.requireNonNull(nonce);if(signature==null||signature.length!=64)throw new IllegalArgumentException("Подтверждение операции");signature=signature.clone();}
    @Override public byte[] signature(){return signature.clone();}
    @Override public String toString(){return "ManagementApproval[redacted]";}
  }
  public record Result(int exitCode,String output) {
    public Result {if(output==null||output.length()>8192)throw new IllegalArgumentException("Размер результата");}
    public boolean queued(){return output.equals("Системное задание поставлено в очередь; результат проверьте отдельно");}
  }
  public record Config(String onion,int port,byte[] publicKey) {
    public Config {Limits.onion(onion);if(port<1||port>65535)throw new IllegalArgumentException("Порт управления");IdentityProtocol.publicKey(publicKey);publicKey=publicKey.clone();}
    @Override public byte[] publicKey(){return publicKey.clone();}
    public static Path defaultFile(){return AppPaths.root().resolve("core600/management.properties");}
    public static Config load(Path file)throws IOException {
      for(Path p=file.toAbsolutePath().normalize();p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылки в конфигурации управления запрещены");
      Properties properties=new Properties(){@Override public synchronized Object put(Object key,Object value){if(containsKey(key))throw new IllegalArgumentException("Повтор поля конфигурации");return super.put(key,value);}};
      try(var in=new ByteArrayInputStream(AtomicFiles.read(file,8192))){properties.load(in);if(!properties.stringPropertyNames().equals(Set.of("onion","port","publicKey")))throw new IOException("Поля конфигурации управления");return new Config(properties.getProperty("onion"),Integer.parseInt(properties.getProperty("port")),IdentityProtocol.unb64(properties.getProperty("publicKey"),44));}
      catch(IllegalArgumentException failure){throw new IOException("Не настроен доверенный сервер управления",failure);}
    }
  }
  public static final class Rejected extends IOException {public Rejected(){super("Серверная операция не разрешена. Обновите полномочия и подтверждение личности.");}}
  public static final class Busy extends IOException {public Busy(){super("Слишком много операций управления. Подождите перед повторной проверкой.");}}
  private final TorTransport tor;private final String onion;private final int port;private final byte[] servicePublic,identityPublic;
  private final Set<Socket> sockets=ConcurrentHashMap.newKeySet();private final Semaphore slots=new Semaphore(1);private volatile boolean closed;
  private final ScheduledThreadPoolExecutor timer=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-management-client-deadline");t.setDaemon(true);return t;});
  public ManagementClient600(TorTransport tor,String onion,int port,byte[] servicePublicKey,byte[] identityPublicKey){this.tor=Objects.requireNonNull(tor);this.onion=Limits.onion(onion);if(port<1||port>65535)throw new IllegalArgumentException("Порт управления");this.port=port;IdentityProtocol.publicKey(servicePublicKey);IdentityProtocol.publicKey(identityPublicKey);servicePublic=servicePublicKey.clone();identityPublic=identityPublicKey.clone();timer.setRemoveOnCancelPolicy(true);}
  public ManagementClient600(TorTransport tor,Config config,byte[] identityPublicKey){this(tor,config.onion(),config.port(),config.publicKey(),identityPublicKey);}
  public Approval approve(Request request,Grant grant)throws IOException {
    var cap=verifyGrant(grant.capability());long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] bytes=IdentityProtocol.requestDigest(cap,request.action().permission(),IdentityProtocol.digest(request.encode()),time,nonce);byte[] signature=IdentityProtocol.sign(grant.proof(),bytes);
    if(!IdentityProtocol.verify(cap.proofKey,bytes,signature))throw new IOException("Ключ приложения не совпадает с разрешением");return new Approval(grant.capability(),time,nonce,signature);
  }
  public Result execute(Request request,Grant grant)throws IOException {if(request.action().critical())throw new IOException("Нужны два независимых администратора");return executeApproved(request,List.of(approve(request,grant)));}
  public Result executeApproved(Request request,List<Approval> approvals)throws IOException {
    if(closed)throw new IOException("Управление закрыто");if(approvals==null||approvals.size()!=(request.action().critical()?2:1))throw new IOException("Число подтверждений операции");
    JsonArray proofArray=new JsonArray();Set<String> accounts=new HashSet<>();long now=System.currentTimeMillis();byte[] metadata=request.encode();
    for(Approval proof:approvals){var cap=verifyGrant(proof.capability());if(!accounts.add(cap.accountId)||proof.time()<Math.max(0,now-120000)||proof.time()>now+30000||!proof.nonce().matches("[A-Za-z0-9_-]{43}")||!IdentityProtocol.verify(cap.proofKey,IdentityProtocol.requestDigest(cap,request.action().permission(),IdentityProtocol.digest(metadata),proof.time(),proof.nonce()),proof.signature()))throw new IOException("Подтверждение не соответствует операции");JsonObject item=new JsonObject();item.addProperty("capability",proof.capability());item.addProperty("time",proof.time());item.addProperty("nonce",proof.nonce());item.addProperty("proof",IdentityProtocol.b64(proof.signature()));proofArray.add(item);}
    JsonObject envelope=new JsonObject();envelope.addProperty("metadata",IdentityProtocol.b64(metadata));envelope.add("proofs",proofArray);byte[] body=envelope.toString().getBytes(StandardCharsets.UTF_8);if(body.length>16384)throw new IOException("Размер запроса управления");
    if(!slots.tryAcquire())throw new IOException("Дождитесь завершения текущей операции");Socket[] observed={null};ScheduledFuture<?>[] deadline={null};
    try(Socket socket=tor.connectPeer(onion,port,opened->{if(closed)throw new IOException("Управление закрыто");observed[0]=opened;sockets.add(opened);deadline[0]=timer.schedule(()->{try{opened.close();}catch(IOException ignored){}},60,TimeUnit.SECONDS);})){
      if(closed)throw new IOException("Управление закрыто");socket.setSoTimeout(55000);OutputStream out=socket.getOutputStream();out.write(("POST /management/v1 HTTP/1.1\r\nHost: "+onion+"\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: "+body.length+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.write(body);out.flush();DataInputStream in=new DataInputStream(socket.getInputStream());String status=line(in,1024);if(!status.matches("HTTP/1\\.[01] [1-5][0-9]{2}(?: [\\x20-\\x7e]*)?"))throw new IOException("Ответ управления");
      Map<String,String> headers=new HashMap<>();boolean complete=false;int size=0;for(int i=0;i<24;i++){String value=line(in,4096);size+=value.length();if(size>8192)throw new IOException("Размер заголовков");if(value.isEmpty()){complete=true;break;}int colon=value.indexOf(':');if(colon<1||!value.substring(0,colon).matches("[A-Za-z0-9-]+")||headers.putIfAbsent(value.substring(0,colon).toLowerCase(Locale.ROOT),value.substring(colon+1).strip())!=null)throw new IOException("Заголовки управления");}
      String length=headers.getOrDefault("content-length","");if(!complete||!length.matches("[0-9]{1,5}")||headers.containsKey("transfer-encoding")||headers.containsKey("content-encoding"))throw new IOException("Кодирование ответа запрещено");int count=Integer.parseInt(length);if(count<2||count>16384)throw new IOException("Размер ответа управления");byte[] response=in.readNBytes(count);
      if(response.length!=count||!IdentityProtocol.verify(servicePublic,IdentityProtocol.response(IdentityProtocol.id(servicePublic),approvals.getFirst().nonce(),body,response),IdentityProtocol.unb64(headers.getOrDefault("aegis-signature",""),64)))throw new IOException("Подпись сервера управления не подтверждена");
      JsonObject reply=CommunityJson.parse(response);if(!reply.keySet().equals(Set.of("ok","data"))||!reply.get("ok").isJsonPrimitive()||!reply.getAsJsonPrimitive("ok").isBoolean()||!reply.get("data").isJsonObject())throw new IOException("Формат ответа управления");if(status.matches("HTTP/1\\.[01] 429(?: .*)?"))throw new Busy();if(!status.matches("HTTP/1\\.[01] 200(?: .*)?")||!reply.get("ok").getAsBoolean())throw new Rejected();JsonObject data=reply.getAsJsonObject("data");
      if(!data.keySet().equals(Set.of("exitCode","output"))||!data.getAsJsonPrimitive("exitCode").isNumber()||!data.getAsJsonPrimitive("output").isString())throw new IOException("Результат управления");if(closed)throw new IOException("Управление закрыто");return new Result(data.get("exitCode").getAsBigDecimal().intValueExact(),data.get("output").getAsString());
    }catch(RuntimeException failure){throw new IOException("Операция управления не завершена",failure);}
    finally{Arrays.fill(body,(byte)0);slots.release();if(deadline[0]!=null)deadline[0].cancel(false);if(observed[0]!=null){sockets.remove(observed[0]);try{observed[0].close();}catch(IOException ignored){}}}
  }
  private IdentityProtocol.Capability verifyGrant(String wire)throws IOException {try{var cap=IdentityProtocol.decodeCapability(wire);if(!IdentityProtocol.verifyCapability(cap,identityPublic,System.currentTimeMillis())||cap.appId!=IdentityProtocol.App.AEGIS||!cap.capabilities.containsAll(EnumSet.of(IdentityProtocol.Scope.ADMIN,IdentityProtocol.Scope.ACCOUNT_READ)))throw new Rejected();return cap;}catch(IllegalArgumentException failure){throw new Rejected();}}
  private static String line(DataInputStream in,int max)throws IOException {var bytes=new ByteArrayOutputStream();for(int i=0;i<max;i++){int c=in.read();if(c<0)throw new EOFException();if(c=='\r'){if(in.read()!='\n')throw new IOException("HTTP framing");return bytes.toString(StandardCharsets.US_ASCII);}if(c<32||c>126)throw new IOException("HTTP framing");bytes.write(c);}throw new IOException("HTTP line too long");}
  @Override public void close(){closed=true;for(Socket socket:sockets)try{socket.close();}catch(IOException ignored){}sockets.clear();timer.shutdownNow();}
}
