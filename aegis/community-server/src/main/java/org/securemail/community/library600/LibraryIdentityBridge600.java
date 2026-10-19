package org.securemail.community.library600;

import org.securemail.community.access.AccessControl;
import org.securemail.community.core.CommunityStore;
import org.securemail.community.http.StrictJson;
import org.securemail.community.gateway600.TrustedContext600;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.library.protocol600.LibraryWire600;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/** Internal operator-configured Identity connection. Literal loopback ONLY; no DNS/proxy or desktop dependency. */
public final class LibraryIdentityBridge600 implements LibraryController600.Authority,AutoCloseable {
    public static final class Evidence {
        private final String capability,action,proofNonce;
        private final long time;
        private final byte[] proof,operation;
        private final Map<String,Object> args;
        private IdentityProtocol.Capability cap;
        private long leaseUntil;
        private long stepUpUntil;
        private boolean administrator;
        private boolean authenticated;
        private Evidence(String capability,String action,long time,String nonce,byte[]proof,byte[]operation,Map<String,Object>args){this.capability=capability;this.action=action;this.time=time;this.proofNonce=nonce;this.proof=proof.clone();this.operation=operation.clone();this.args=Map.copyOf(args);}
    }
    private final int port;
    private final byte[] identityKey;
    private final String audience,libraryAudience;
    private final AccessControl access;
    private final CommunityStore store;
    private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-library-identity-deadline");t.setDaemon(true);return t;});
    private final Set<Socket>active=ConcurrentHashMap.newKeySet();
    private volatile boolean closed;
    public LibraryIdentityBridge600(int identityLoopbackPort,byte[]identityServiceKey,byte[]libraryServiceKey,AccessControl access,CommunityStore store){
        if(identityLoopbackPort<1||identityLoopbackPort>65535)throw new IllegalArgumentException("Identity port");
        IdentityProtocol.publicKey(identityServiceKey);IdentityProtocol.publicKey(libraryServiceKey);
        identityKey=identityServiceKey.clone();audience=IdentityProtocol.id(identityKey);libraryAudience=IdentityProtocol.id(libraryServiceKey);
        if(audience.equals(libraryAudience))throw new IllegalArgumentException("Separate service keys required");
        port=identityLoopbackPort;this.access=Objects.requireNonNull(access);this.store=Objects.requireNonNull(store);deadlines.setRemoveOnCancelPolicy(true);
    }
    public String libraryAudience(){return libraryAudience;}
    public Evidence evidence(String action,String exactArgsJson,Map<String,Object>args,Map<String,Object>authorization)throws IOException {
        if(!authorization.keySet().equals(Set.of("capability","time","nonce","proof")))throw new IOException("Некорректная авторизация");
        String cap=StrictJson.text(authorization,"capability",4096),nonce=IdentityProtocol.nonceValue(StrictJson.text(authorization,"nonce",43));
        long time=StrictJson.number(authorization,"time",0,Long.MAX_VALUE);byte[]proof=IdentityProtocol.unb64(StrictJson.text(authorization,"proof",86),64);
        return new Evidence(cap,action,time,nonce,proof,LibraryWire600.operation(libraryAudience,action,exactArgsJson.getBytes(StandardCharsets.UTF_8)),args);
    }
    /** Initial proof consumes its nonce once, outside the Community transaction. */
    public synchronized void authenticate(Evidence e)throws Exception {
        if(e.authenticated)throw new IOException("Повторная проверка доказательства");
        IdentityProtocol.Capability cap=IdentityProtocol.decodeCapability(e.capability);
        String action=LibraryWire600.identityAction(e.action);byte[]digest=IdentityProtocol.digest(e.operation);
        if(cap.appId!=IdentityProtocol.App.LIBRARY||!IdentityProtocol.verifyCapability(cap,identityKey,System.currentTimeMillis())
                ||!IdentityProtocol.verify(cap.proofKey,IdentityProtocol.requestDigest(cap,action,digest,e.time,e.proofNonce),e.proof))
            throw new IOException("Недействительное разрешение библиотеки");
        Map<String,Object>response=rpc("authorizeDigest",Map.of("capability",e.capability,"action",action,"bodySha256",IdentityProtocol.b64(digest),"time",e.time,"nonce",e.proofNonce,"proof",IdentityProtocol.b64(e.proof)));
        if(!cap.accountId.equals(response.get("accountId"))||!cap.deviceId.equals(response.get("deviceId"))||!cap.appId.name().equals(response.get("appId"))
                ||StrictJson.number(response,"generation",1,Long.MAX_VALUE)!=cap.generation)throw new IOException("Identity вернул другое разрешение");
        long until=StrictJson.number(response,"leaseUntil",1,Long.MAX_VALUE);if(until>cap.expiresAt||until<=System.currentTimeMillis())throw new IOException("Разрешение истекло");
        if(!(response.get("capabilities")instanceof List<?> scopes)||scopes.size()!=cap.capabilities.size())throw new IOException("Неверные полномочия");
        Set<String>actual=new HashSet<>();for(Object scope:scopes)if(!(scope instanceof String value)||!actual.add(value))throw new IOException("Неверные полномочия");
        for(IdentityProtocol.Scope scope:cap.capabilities)if(!actual.contains(scope.name()))throw new IOException("Неверные полномочия");
        byte[] accountKey=IdentityProtocol.unb64(StrictJson.text(response,"accountPublicKey",86),44);IdentityProtocol.publicKey(accountKey);
        String nickname=StrictJson.text(response,"nickname",80);
        if(!IdentityProtocol.id(accountKey).equals(cap.accountId)||nickname.isBlank()||nickname.codePoints().anyMatch(Character::isISOControl))throw new IOException("Подмена публичной identity");
        if(!(response.get("authorityAdministrator") instanceof Boolean administrator)
                ||!(response.get("authorityOwner") instanceof Boolean owner))throw new IOException("Отсутствует серверный контекст полномочий");
        long stepUpUntil=StrictJson.number(response,"stepUpUntil",0,Long.MAX_VALUE);
        if(owner&&!administrator)throw new IOException("Некорректный серверный контекст полномочий");
        mirror(cap.accountId,accountKey,nickname);
        e.cap=cap;e.leaseUntil=until;e.administrator=administrator;e.stepUpUntil=stepUpUntil;e.authenticated=true;
    }
    /** Only server-signed account public identity/nickname. Never copies client roles, badges or clearance. */
    private void mirror(String accountId,byte[] publicKey,String nickname)throws Exception {
        store.tx(db->{
            try(var q=db.prepareStatement("SELECT public_key,nickname FROM identities WHERE identity=?")){q.setString(1,accountId);try(var r=q.executeQuery()){
                if(r.next()) {
                    if(!java.security.MessageDigest.isEqual(publicKey,r.getBytes(1)))throw new IOException("Изменение identity запрещено");
                    if(!nickname.equals(r.getString(2)))try(var update=db.prepareStatement("UPDATE identities SET nickname=? WHERE identity=?")){update.setString(1,nickname);update.setString(2,accountId);update.executeUpdate();}
                    return null;
                }
            }}
            if(CommunityStore.count(db,"identities")>=1_000_000)throw new IOException("Лимит identity");
            try(var q=db.prepareStatement("INSERT INTO identities(identity,public_key,nickname) VALUES(?,?,?)")){q.setString(1,accountId);q.setBytes(2,publicKey);q.setString(3,nickname);q.executeUpdate();}
            store.audit(db,accountId,"IDENTITY_PUBLIC_MIRRORED",accountId,"Pinned Identity service: public key and nickname only");return null;
        });
    }
    @Override public LibraryController600.Verified verify(Object evidence,String action,Map<String,Object>args)throws Exception {
        if(!(evidence instanceof Evidence e)||!e.authenticated||!e.action.equals(action)||!e.args.equals(args))throw new IOException("Запрос не аутентифицирован");
        if(System.currentTimeMillis()>=e.leaseUntil||!Boolean.TRUE.equals(rpc("isActive",Map.of("capability",e.capability)).get("active")))throw new IOException("Сессия отозвана");
        return new LibraryController600.Verified(e.cap.accountId,e.cap.deviceId,e.cap.generation,e.leaseUntil,access.authorizationEpoch(e.cap.accountId));
    }
    /** Server-only scoped authority. Flags originate in the pinned Identity response,
     * never the Library request, nickname, badge or a local global_admins mirror. */
    public <T>T withAuthority(Evidence e,CommunityStore.SqlWork<T> work)throws Exception {
        if(e==null||!e.authenticated)throw new IOException("Запрос не аутентифицирован");
        return TrustedContext600.withServerAuthority(new TrustedContext600.ServerAuthority(){
            public String accountId(){return e.cap.accountId;}
            public boolean administrator(){return e.administrator;}
            public long stepUpUntil(){return e.stepUpUntil;}
            public void recheck()throws Exception{verify(e,e.action,e.args);}
            public void requireStepUp()throws Exception{if(e.stepUpUntil<=System.currentTimeMillis()||!Boolean.TRUE.equals(rpc("isStepUpActive",Map.of("capability",e.capability)).get("active")))throw new IOException("Повторно подтвердите личность");recheck();}
        },work);
    }
    private Map<String,Object>rpc(String operation,Map<String,Object>data)throws Exception {
        if(closed)throw new IOException("Identity bridge закрыт");String nonce=IdentityProtocol.nonce();byte[]request=StrictJson.bytes(Map.of("operation",operation,"nonce",nonce,"data",data));
        if(request.length>IdentityProtocol.MAX_BODY)throw new IOException("Размер Identity");Socket socket=new Socket(Proxy.NO_PROXY);active.add(socket);
        ScheduledFuture<?>deadline=deadlines.schedule(()->{try{socket.close();}catch(IOException ignored){}},15,TimeUnit.SECONDS);
        try(socket){socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),port),3000);socket.setSoTimeout(5000);
            OutputStream out=socket.getOutputStream();out.write(("POST /identity/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+request.length+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.write(request);out.flush();
            DataInputStream in=new DataInputStream(socket.getInputStream());String status=line(in,1024);Map<String,String>headers=headers(in);String length=headers.getOrDefault("content-length","");
            if(!status.matches("HTTP/1\\.[01] [1-5][0-9]{2}(?: [\\x20-\\x7e]*)?")||!length.matches("[0-9]{1,6}"))throw new IOException("Некорректный HTTP Identity");
            int size=Integer.parseInt(length);if(size<2||size>IdentityProtocol.MAX_BODY)throw new IOException("Размер Identity");byte[]body=in.readNBytes(size);
            if(body.length!=size||!IdentityProtocol.verify(identityKey,IdentityProtocol.response(audience,nonce,request,body),IdentityProtocol.unb64(headers.getOrDefault("aegis-signature",""),64)))throw new IOException("Подпись Identity не подтверждена");
            Map<String,Object>reply=StrictJson.object(body,IdentityProtocol.MAX_BODY);if(!Boolean.TRUE.equals(reply.get("ok"))||!status.startsWith("HTTP/1.1 200")||!(reply.get("data")instanceof Map<?,?> result))throw new IOException("Identity отклонил запрос");
            @SuppressWarnings("unchecked")Map<String,Object>typed=(Map<String,Object>)result;return typed;
        }finally{active.remove(socket);deadline.cancel(false);Arrays.fill(request,(byte)0);}
    }
    static Map<String,String>headers(DataInputStream in)throws IOException {
        Map<String,String>result=new HashMap<>();int total=0;for(int i=0;i<32;i++){String line=line(in,4096);total+=line.length();if(total>8192)throw new IOException("Заголовки слишком велики");if(line.isEmpty()){if(result.containsKey("transfer-encoding")||result.containsKey("content-encoding"))throw new IOException("Кодирование запрещено");return result;}int p=line.indexOf(':');if(p<1||!line.substring(0,p).matches("[A-Za-z0-9-]+")||result.putIfAbsent(line.substring(0,p).toLowerCase(Locale.ROOT),line.substring(p+1).strip())!=null)throw new IOException("Некорректный заголовок");}throw new IOException("Заголовки слишком велики");
    }
    static String line(DataInputStream in,int limit)throws IOException {ByteArrayOutputStream out=new ByteArrayOutputStream();for(int n=0;n<limit;n++){int c=in.read();if(c<0)throw new EOFException();if(c=='\r'){if(in.read()!='\n')throw new IOException("HTTP framing");return out.toString(StandardCharsets.US_ASCII);}if(c<32||c>126)throw new IOException("HTTP framing");out.write(c);}throw new IOException("HTTP line limit");}
    @Override public void close(){closed=true;for(Socket s:active)try{s.close();}catch(IOException ignored){}deadlines.shutdownNow();}
}
