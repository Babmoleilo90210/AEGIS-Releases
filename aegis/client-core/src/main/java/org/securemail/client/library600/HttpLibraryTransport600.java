package org.securemail.client.library600;

import com.google.gson.*;
import org.securemail.client.community.CommunityJson;
import org.securemail.client.net.TorTransport;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.library.protocol600.LibraryWire600;
import org.securemail.protocol.Limits;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;

/** Actual onion-only Library HTTP client. Holds only the LIBRARY child's proof key, never the account root key. */
public final class HttpLibraryTransport600 implements LibraryConnector600.Transport,AutoCloseable {
    public static final class Rejected extends IOException {private final String code;Rejected(String code){super("Сервер библиотеки отклонил запрос");this.code=code;}public String code(){return code;}}
    private final String onion,audience,token;
    private final int port;
    private final byte[]libraryKey,identityKey;
    private final IdentityProtocol.Capability cap;
    private final TorTransport tor;
    private final Clock clock;
    private volatile PrivateKey appKey;
    private volatile boolean closed;
    private final Semaphore slots=new Semaphore(2);
    private final Set<Socket>active=ConcurrentHashMap.newKeySet();
    private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-library-client-deadline");t.setDaemon(true);return t;});
    public HttpLibraryTransport600(String onion,int port,byte[]libraryServiceKey,byte[]identityServiceKey,String capability,PrivateKey libraryAppProofKey,TorTransport tor) {
        this(onion,port,libraryServiceKey,identityServiceKey,capability,libraryAppProofKey,tor,Clock.systemUTC());
    }
    HttpLibraryTransport600(String onion,int port,byte[]libraryServiceKey,byte[]identityServiceKey,String capability,PrivateKey libraryAppProofKey,TorTransport tor,Clock clock) {
        Limits.onion(onion);if(port<1||port>65535)throw new IllegalArgumentException("Library port");IdentityProtocol.publicKey(libraryServiceKey);IdentityProtocol.publicKey(identityServiceKey);
        this.onion=onion;this.port=port;libraryKey=libraryServiceKey.clone();identityKey=identityServiceKey.clone();audience=IdentityProtocol.id(libraryKey);
        if(audience.equals(IdentityProtocol.id(identityKey)))throw new IllegalArgumentException("Separate service keys required");
        token=capability;cap=IdentityProtocol.decodeCapability(capability);
        if(cap.appId!=IdentityProtocol.App.LIBRARY||!IdentityProtocol.verifyCapability(cap,identityKey,clock.millis()))throw new IllegalArgumentException("Недействительный допуск Library");
        appKey=Objects.requireNonNull(libraryAppProofKey);this.tor=Objects.requireNonNull(tor);this.clock=Objects.requireNonNull(clock);deadlines.setRemoveOnCancelPolicy(true);
    }
    @Override public Map<String,Object>verifiedRequest(String action,Map<String,Object>args)throws Exception {
        long requestStarted=System.nanoTime();
        if(closed)throw new IOException("Library закрыта");PrivateKey proofKey=appKey;if(proofKey==null)throw new IOException("Library закрыта");
        if(!IdentityProtocol.verifyCapability(cap,identityKey,clock.millis()))throw new IOException("Допуск Library истёк");
        String identityAction=LibraryWire600.identityAction(action),argsJson=new GsonBuilder().disableHtmlEscaping().create().toJson(args);
        byte[]operation=LibraryWire600.operation(audience,action,argsJson.getBytes(StandardCharsets.UTF_8));String nonce=IdentityProtocol.nonce(),proofNonce=IdentityProtocol.nonce();long time=clock.millis();
        byte[]proof=IdentityProtocol.sign(proofKey,IdentityProtocol.requestDigest(cap,identityAction,IdentityProtocol.digest(operation),time,proofNonce));
        JsonObject auth=new JsonObject();auth.addProperty("capability",token);auth.addProperty("time",time);auth.addProperty("nonce",proofNonce);auth.addProperty("proof",IdentityProtocol.b64(proof));
        JsonObject request=new JsonObject();request.addProperty("action",action);request.addProperty("argsJson",argsJson);request.addProperty("nonce",nonce);request.add("authorization",auth);
        byte[]exact=request.toString().getBytes(StandardCharsets.UTF_8);if(exact.length>LibraryWire600.MAX_BODY)throw new IOException("Размер запроса Library");
        if(!slots.tryAcquire())throw new IOException("Дождитесь завершения запроса Library");Socket[]observed={null};ScheduledFuture<?>[]deadline={null};
        try {
            try(Socket socket=tor.connectPeer(onion,port,opened->{observed[0]=opened;active.add(opened);if(closed)throw new IOException("Library закрыта");try{deadline[0]=deadlines.schedule(()->{try{opened.close();}catch(IOException ignored){}},30,TimeUnit.SECONDS);}catch(RejectedExecutionException stopped){throw new IOException("Library закрыта",stopped);}})) {
                if(closed)throw new IOException("Library закрыта");socket.setSoTimeout(15000);OutputStream out=socket.getOutputStream();
                out.write(("POST /library/v1 HTTP/1.1\r\nHost: "+onion+"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+exact.length+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.write(exact);out.flush();
                DataInputStream in=new DataInputStream(socket.getInputStream());String status=line(in,1024);Map<String,String>headers=headers(in);String length=headers.getOrDefault("content-length","");
                if(!status.matches("HTTP/1\\.[01] [1-5][0-9]{2}(?: [\\x20-\\x7e]*)?")||!length.matches("[0-9]{1,8}"))throw new IOException("HTTP Library");
                int size=Integer.parseInt(length);if(size<2||size>LibraryWire600.MAX_BODY)throw new IOException("Размер ответа Library");byte[]body=in.readNBytes(size);
                try {
                    if(body.length!=size||!IdentityProtocol.verify(libraryKey,LibraryWire600.response(audience,nonce,exact,body),IdentityProtocol.unb64(headers.getOrDefault("aegis-signature",""),64)))throw new IOException("Подпись Library не подтверждена");
                    JsonObject reply=CommunityJson.parse(body);Map<String,Object>value=map(reply);
                    if(!(value.get("ok")instanceof Boolean ok))throw new IOException("Некорректный ответ Library");
                    if(!ok){String code="DENIED";if(value.get("error")instanceof Map<?,?>e&&e.get("code")instanceof String c&&c.matches("[A-Z_]{1,40}"))code=c;throw new Rejected(code);}
                    if(!status.startsWith("HTTP/1.1 200")||!(value.get("data")instanceof Map<?,?>raw))throw new IOException("Некорректный HTTP статус Library");
                    @SuppressWarnings("unchecked")Map<String,Object>result=(Map<String,Object>)raw;
                    if(!cap.accountId.equals(result.get("accountId"))||!cap.deviceId.equals(result.get("deviceId"))||number(result,"generation")!=cap.generation
                            ||number(result,"leaseUntil")>cap.expiresAt||number(result,"leaseUntil")<=clock.millis())throw new IOException("Подмена контекста Library");
                    if(closed)throw new IOException("Library закрыта");long elapsed=System.nanoTime()-requestStarted;if(elapsed<0)throw new IOException("Время запроса Library");result.put("_localRoundTripMillis600",(elapsed+999999L)/1000000L);return result;
                }finally{Arrays.fill(body,(byte)0);}
            }
        }finally{if(deadline[0]!=null)deadline[0].cancel(false);if(observed[0]!=null){active.remove(observed[0]);try{observed[0].close();}catch(IOException ignored){}}slots.release();Arrays.fill(exact,(byte)0);Arrays.fill(operation,(byte)0);Arrays.fill(proof,(byte)0);}
    }
    private static long number(Map<String,Object>m,String key)throws IOException {Object raw=m.get(key);if(!(raw instanceof Number))throw new IOException("Неверное число Library");try{return new java.math.BigDecimal(raw.toString()).longValueExact();}catch(RuntimeException e){throw new IOException("Неверное число Library",e);}}
    private static Map<String,Object>map(JsonObject object){Map<String,Object>out=new LinkedHashMap<>();for(var entry:object.entrySet())out.put(entry.getKey(),value(entry.getValue()));return out;}
    private static Object value(JsonElement element){if(element.isJsonNull())return null;if(element.isJsonObject())return map(element.getAsJsonObject());if(element.isJsonArray()){List<Object>out=new ArrayList<>();for(JsonElement e:element.getAsJsonArray())out.add(value(e));return out;}var p=element.getAsJsonPrimitive();if(p.isBoolean())return p.getAsBoolean();if(p.isNumber())return p.getAsBigDecimal();return p.getAsString();}
    private static Map<String,String>headers(DataInputStream in)throws IOException {Map<String,String>out=new HashMap<>();int total=0;for(int i=0;i<32;i++){String h=line(in,4096);total+=h.length();if(total>8192)throw new IOException("Размер заголовков Library");if(h.isEmpty()){if(out.containsKey("content-encoding")||out.containsKey("transfer-encoding"))throw new IOException("HTTP Library encoding");return out;}int p=h.indexOf(':');if(p<1||!h.substring(0,p).matches("[A-Za-z0-9-]+")||out.putIfAbsent(h.substring(0,p).toLowerCase(Locale.ROOT),h.substring(p+1).strip())!=null)throw new IOException("HTTP Library headers");}throw new IOException("HTTP Library headers");}
    private static String line(DataInputStream in,int limit)throws IOException {ByteArrayOutputStream out=new ByteArrayOutputStream();for(int n=0;n<limit;n++){int c=in.read();if(c<0)throw new EOFException();if(c=='\r'){if(in.read()!='\n')throw new IOException("HTTP Library framing");return out.toString(StandardCharsets.US_ASCII);}if(c<32||c>126)throw new IOException("HTTP Library framing");out.write(c);}throw new IOException("HTTP Library line limit");}
    @Override public void close(){closed=true;appKey=null;for(Socket s:active)try{s.close();}catch(IOException ignored){}deadlines.shutdownNow();}
}
