package org.securemail.community.gateway600;

import org.securemail.community.access.AccessControl;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.CommunityStore;
import org.securemail.community.http.StrictJson;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/** Additive Core Community operator entry point. Fresh roles/admin tables remain empty; Identity owns Owner authorization. */
public final class CommunityMain600 {
    private static final String MARKER="AEGIS-COMMUNITY-600\n";
    private CommunityMain600() { }
    public static void main(String[]args){int result=run(args,System.out,System.err);if(result!=0)System.exit(result);}
    public static int run(String[]args,PrintStream out,PrintStream error) {
        try {
            if(args.length<2||!Set.of("--init","--inspect","--serve","--worker-allow","--worker-revoke").contains(args[0])){usage(error);return 2;}
            Path home=Path.of(args[1]).toAbsolutePath().normalize();Map<String,String>options=new LinkedHashMap<>();
            if((args.length-2)%2!=0)throw new IOException("Параметры");for(int i=2;i<args.length;i+=2)if(options.putIfAbsent(args[i],args[i+1])!=null)throw new IOException("Повторный параметр");
            if(args[0].equals("--init")){initialize(home,options,out);return 0;}
            if(args[0].equals("--worker-allow")||args[0].equals("--worker-revoke")){configureWorker(home,options,args[0].equals("--worker-allow"));out.println("Служебная allowlist рабочего узла обновлена локальным оператором.");return 0;}
            if(!options.isEmpty())throw new IOException("Неподдерживаемый параметр");
            if(args[0].equals("--inspect")){verifyHome(home);show(out,readKey(home));return 0;}
            try(Running running=start(home)) {
                out.println("Community Gateway 6.0 слушает только 127.0.0.1:"+running.port()+". Onion service настраивается отдельно оператором.");
                CountDownLatch stopped=new CountDownLatch(1);Thread hook=new Thread(()->{running.close();stopped.countDown();},"aegis-community6-shutdown");Runtime.getRuntime().addShutdownHook(hook);
                try{stopped.await();}finally{running.close();try{Runtime.getRuntime().removeShutdownHook(hook);}catch(IllegalStateException shuttingDown){}}
            }
            return 0;
        }catch(Exception failure){error.println("Community Gateway 6.0 не подготовлен или не запущен. Проверьте параметры, права файлов и закреплённые ключи; секреты и исключения не выводятся.");return 1;}
    }
    private static void usage(PrintStream out){out.println("--init DIR --identity-public FILE --identity-fingerprint SHA256 --identity-port PORT --port PORT");out.println("--inspect DIR | --serve DIR");out.println("--worker-allow DIR --public FILE --fingerprint SHA256 | --worker-revoke DIR --fingerprint SHA256");out.println("Только локальная подготовка отдельного сервиса; production Relay, update feed и release-signing key не используются.");}
    private static void configureWorker(Path home,Map<String,String>options,boolean allow)throws Exception {
        if(!options.keySet().equals(allow?Set.of("--public","--fingerprint"):Set.of("--fingerprint")))throw new IOException("Параметры службы");
        verifyHome(home);String fingerprint=options.get("--fingerprint");if(!fingerprint.matches("[a-f0-9]{64}"))throw new IOException("Отпечаток службы");
        byte[]kek=exactPrivate(home.resolve("factor-kek.bin"),32);
        try(CommunityStore store=new CommunityStore(home.resolve("community.sqlite"));AccessControl access=new AccessControl(store,kek)) {
            if(allow){byte[]pub=read(Path.of(options.get("--public")),256);if(pub.length!=44){String encoded=new String(pub,StandardCharsets.US_ASCII).strip();try{pub=Base64.getUrlDecoder().decode(encoded);}catch(IllegalArgumentException invalid){pub=Base64.getDecoder().decode(encoded);}}IdentityProtocol.publicKey(pub);org.securemail.community.agent.WorkerServiceGateway600.allow(store,access,pub,fingerprint);}
            else org.securemail.community.agent.WorkerServiceGateway600.revoke(store,fingerprint);
        }finally{Arrays.fill(kek,(byte)0);}
    }
    public static void initialize(Path home,Map<String,String>options,PrintStream out)throws Exception {
        if(!options.keySet().equals(Set.of("--identity-public","--identity-fingerprint","--identity-port","--port")))throw new IOException("Аргументы");
        home=home.toAbsolutePath().normalize();Path parent=home.getParent();if(parent==null||!parent.toRealPath().equals(parent)||Files.exists(home,LinkOption.NOFOLLOW_LINKS))throw new IOException("Нужен новый каталог");
        byte[]identityPublic=read(Path.of(options.get("--identity-public")),256);if(identityPublic.length!=44){String b64=new String(identityPublic,StandardCharsets.US_ASCII).strip();try{identityPublic=Base64.getUrlDecoder().decode(b64);}catch(IllegalArgumentException url){identityPublic=Base64.getDecoder().decode(b64);}}
        IdentityProtocol.publicKey(identityPublic);if(!IdentityProtocol.id(identityPublic).equals(options.get("--identity-fingerprint")))throw new IOException("Отпечаток Identity");int identityPort=port(options.get("--identity-port")),communityPort=port(options.get("--port"));if(identityPort==communityPort)throw new IOException("Разные порты обязательны");
        byte[]kek=new byte[32];new SecureRandom().nextBytes(kek);Path staging=home.resolveSibling("."+home.getFileName()+"-setup-"+UUID.randomUUID());
        try {
            Files.createDirectory(staging,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));KeyPair service=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            write(staging.resolve("service-private.pkcs8"),service.getPrivate().getEncoded());write(staging.resolve("service-public.x509"),service.getPublic().getEncoded());write(staging.resolve("factor-kek.bin"),kek.clone());
            try(CommunityStore store=new CommunityStore(staging.resolve("community.sqlite"));AccessControl access=new AccessControl(store,kek)){ContentService content=new ContentService(store,access);try(var agent=new org.securemail.community.agent.AgentService(store,access,content::ingestAi)){store.setNotificationSink(content::notifyAccount);if(!store.verifyAudit())throw new IOException("Audit");}}
            write(staging.resolve("config.json"),StrictJson.bytes(Map.of("version",1,"identityPublicKey",IdentityProtocol.b64(identityPublic),"identityPort",identityPort,"communityPort",communityPort)));
            write(staging.resolve("INITIALIZED"),"AEGIS-COMMUNITY-v1\n".getBytes(StandardCharsets.US_ASCII));write(staging.resolve("INITIALIZED600"),MARKER.getBytes(StandardCharsets.US_ASCII));Files.move(staging,home,StandardCopyOption.ATOMIC_MOVE);
            out.println("Community 6.0 подготовлен без пользовательских ролей и legacy bootstrap. Владелец подтверждается только Identity.");show(out,service);
        }finally{Arrays.fill(kek,(byte)0);if(Files.exists(staging,LinkOption.NOFOLLOW_LINKS))try(var paths=Files.walk(staging)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
    public static Running start(Path home)throws Exception {
        home=home.toAbsolutePath().normalize();verifyHome(home);KeyPair service=readKey(home);Map<String,Object>config=StrictJson.object(exactPrivate(home.resolve("config.json"),-1),8192);
        if(!config.keySet().equals(Set.of("version","identityPublicKey","identityPort","communityPort"))||StrictJson.number(config,"version",1,1)!=1)throw new IOException("Версия конфигурации");
        byte[]identityPublic=IdentityProtocol.unb64(StrictJson.text(config,"identityPublicKey",86),44);IdentityProtocol.publicKey(identityPublic);
        Path database=home.resolve("community.sqlite");privateDirectory(database.getParent());verifyPrivateFile(database);
        byte[]auditKey=exactPrivate(home.resolve("factor-kek.bin"),32);
        CommunityStore store=null;AccessControl access=null;CommunityIdentityBridge600 bridge=null;org.securemail.community.agent.AgentService agent=null;
        try {
            store=new CommunityStore(database);access=new AccessControl(store,auditKey);ContentService content=new ContentService(store,access);store.setNotificationSink(content::notifyAccount);store.bindServiceIdentity(IdentityProtocol.id(service.getPublic().getEncoded()));
            var organizations=new org.securemail.community.org.OrgAdminService(store,access,store.clock());agent=new org.securemail.community.agent.AgentService(store,access,content::ingestAi);
            bridge=new CommunityIdentityBridge600((int)StrictJson.number(config,"identityPort",1,65535),identityPublic,service.getPublic().getEncoded(),access,store);
            var server=new CommunityHttpGateway600(new InetSocketAddress("127.0.0.1",(int)StrictJson.number(config,"communityPort",1,65535)),store,access,content,organizations,agent,service,bridge);
            Running running=new Running(store,access,bridge,server,agent);server.start();agent.start();return running;
        }catch(Exception failure){if(bridge!=null)bridge.close();if(agent!=null)agent.close();if(access!=null)access.close();if(store!=null)store.close();throw failure;}
        finally{Arrays.fill(auditKey,(byte)0);}
    }
    public static final class Running implements AutoCloseable {
        private final CommunityStore store;private final AccessControl access;private final CommunityIdentityBridge600 bridge;private final CommunityHttpGateway600 server;private final org.securemail.community.agent.AgentService agent;private final AtomicBoolean closed=new AtomicBoolean();
        private Running(CommunityStore s,AccessControl a,CommunityIdentityBridge600 b,CommunityHttpGateway600 h,org.securemail.community.agent.AgentService agent){store=s;access=a;bridge=b;server=h;this.agent=agent;}
        public int port(){return server.port();}
        public void close(){if(closed.compareAndSet(false,true)){server.close();agent.close();bridge.close();access.close();try{store.close();}catch(Exception ignored){}}}
    }
    private static int port(String text)throws IOException {try{int value=Integer.parseInt(text);if(value<1||value>65535)throw new NumberFormatException();return value;}catch(RuntimeException invalid){throw new IOException("Неверный порт");}}
    private static void verifyHome(Path home)throws Exception {privateDirectory(home);if(!new String(exactPrivate(home.resolve("INITIALIZED600"),MARKER.length()),StandardCharsets.US_ASCII).equals(MARKER))throw new IOException("Маркер");}
    private static void show(PrintStream out,KeyPair key){out.println("Community public key (Base64URL): "+IdentityProtocol.b64(key.getPublic().getEncoded()));out.println("Community key SHA-256: "+IdentityProtocol.id(key.getPublic().getEncoded()));}
    private static KeyPair readKey(Path home)throws Exception {byte[]privateBytes=exactPrivate(home.resolve("service-private.pkcs8"),48);try{PrivateKey secret=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(privateBytes));byte[]pub=exactPrivate(home.resolve("service-public.x509"),44),challenge="AEGIS-COMMUNITY-600-KEY-CHECK/v1".getBytes(StandardCharsets.US_ASCII);if(!IdentityProtocol.verify(pub,challenge,IdentityProtocol.sign(secret,challenge)))throw new IOException("Ключи не согласованы");return new KeyPair(IdentityProtocol.publicKey(pub),secret);}finally{Arrays.fill(privateBytes,(byte)0);}}
    private static void privateDirectory(Path p)throws IOException {if(!Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS)||!p.toRealPath().equals(p.toAbsolutePath().normalize()))throw new IOException("Каталог");permissions(p);}
    private static void permissions(Path p)throws IOException {try{for(var permission:Files.getPosixFilePermissions(p,LinkOption.NOFOLLOW_LINKS))if(permission.name().startsWith("GROUP_")||permission.name().startsWith("OTHERS_"))throw new IOException("Доступ только владельцу");}catch(UnsupportedOperationException unsupported){throw new IOException("Этот серверный комплект требует POSIX permissions",unsupported);}}
    private static void verifyPrivateFile(Path p)throws IOException {if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||!p.toRealPath().equals(p.toAbsolutePath().normalize()))throw new IOException("Файл БД");permissions(p);}
    private static byte[]exactPrivate(Path p,int size)throws IOException {permissions(p);byte[]bytes=read(p,size<0?16*1024*1024:size);if(size>=0&&bytes.length!=size)throw new IOException("Размер защищённого файла");return bytes;}
    private static byte[]read(Path p,int limit)throws IOException {p=p.toAbsolutePath().normalize();if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||!p.toRealPath().equals(p)||Files.size(p)>limit)throw new IOException("Файл");try(var in=Files.newInputStream(p,LinkOption.NOFOLLOW_LINKS)){byte[]bytes=in.readNBytes(limit+1);if(bytes.length>limit)throw new IOException("Размер файла");return bytes;}}
    private static void write(Path target,byte[]bytes)throws IOException {try{Files.createFile(target,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));try(var out=java.nio.channels.FileChannel.open(target,StandardOpenOption.WRITE)){var data=java.nio.ByteBuffer.wrap(bytes);while(data.hasRemaining())out.write(data);out.force(true);}}finally{Arrays.fill(bytes,(byte)0);}}
}
