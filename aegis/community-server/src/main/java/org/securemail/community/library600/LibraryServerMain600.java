package org.securemail.community.library600;

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

/** Separate operator CLI, additive tables in the existing Community DB. No deployment or Relay replacement.
 * This service shares the Community authorization/content trust boundary and audit subkey, NOT the TOTP KEK.
 * A separate Unix identity without access to that DB cannot run this adapter; deployment must state that boundary. */
public final class LibraryServerMain600 {
    private static final String MARKER="AEGIS-LIBRARY-600\n";
    private LibraryServerMain600() { }
    public static void main(String[]args){int result=run(args,System.out,System.err);if(result!=0)System.exit(result);}
    public static int run(String[]args,PrintStream out,PrintStream error) {
        try {
            if(args.length<2||!Set.of("--init","--inspect","--serve").contains(args[0])){usage(error);return 2;}
            Path home=Path.of(args[1]).toAbsolutePath().normalize();Map<String,String>options=new LinkedHashMap<>();
            if((args.length-2)%2!=0)throw new IOException("Параметры");for(int i=2;i<args.length;i+=2)if(options.putIfAbsent(args[i],args[i+1])!=null)throw new IOException("Повторный параметр");
            if(args[0].equals("--init")){initialize(home,options,out);return 0;}
            if(!options.isEmpty())throw new IOException("Неподдерживаемый параметр");
            if(args[0].equals("--inspect")){verifyHome(home);show(out,readKey(home));return 0;}
            try(Running running=start(home)) {
                out.println("Library Controller слушает только 127.0.0.1:"+running.port()+". Onion service настраивается отдельно оператором.");
                CountDownLatch stopped=new CountDownLatch(1);Thread hook=new Thread(()->{running.close();stopped.countDown();},"aegis-library-shutdown");Runtime.getRuntime().addShutdownHook(hook);
                try{stopped.await();}finally{running.close();try{Runtime.getRuntime().removeShutdownHook(hook);}catch(IllegalStateException shuttingDown){}}
            }
            return 0;
        }catch(Exception failure){error.println("Library Controller не подготовлен или не запущен. Проверьте параметры, права файлов и закреплённые ключи; секреты и исключения не выводятся.");return 1;}
    }
    private static void usage(PrintStream out){out.println("--init DIR --community-home DIR --identity-public FILE --identity-fingerprint SHA256 --identity-port PORT --port PORT");out.println("--inspect DIR | --serve DIR");out.println("Только локальная подготовка отдельного сервиса; production Relay, update feed и release-signing key не используются.");}
    public static void initialize(Path home,Map<String,String>options,PrintStream out)throws Exception {
        if(!options.keySet().equals(Set.of("--community-home","--identity-public","--identity-fingerprint","--identity-port","--port")))throw new IOException("Аргументы");
        home=home.toAbsolutePath().normalize();Path parent=home.getParent();if(parent==null||!parent.toRealPath().equals(parent)||Files.exists(home,LinkOption.NOFOLLOW_LINKS))throw new IOException("Нужен новый каталог");
        Path community=Path.of(options.get("--community-home")).toAbsolutePath().normalize();privateDirectory(community);
        if(!new String(read(community.resolve("INITIALIZED"),64),StandardCharsets.US_ASCII).equals("AEGIS-COMMUNITY-v1\n"))throw new IOException("Community не инициализирован");
        verifyPrivateFile(community.resolve("community.sqlite"));
        byte[]identityPublic=read(Path.of(options.get("--identity-public")),256);if(identityPublic.length!=44){String b64=new String(identityPublic,StandardCharsets.US_ASCII).strip();try{identityPublic=Base64.getUrlDecoder().decode(b64);}catch(IllegalArgumentException url){identityPublic=Base64.getDecoder().decode(b64);}}
        IdentityProtocol.publicKey(identityPublic);if(!IdentityProtocol.id(identityPublic).equals(options.get("--identity-fingerprint")))throw new IOException("Отпечаток Identity не совпадает");
        int identityPort=port(options.get("--identity-port")),libraryPort=port(options.get("--port"));if(identityPort==libraryPort)throw new IOException("Разные порты обязательны");
        byte[]kek=exactPrivate(community.resolve("factor-kek.bin"),32),auditKey=null;Path staging=home.resolveSibling("."+home.getFileName()+"-setup-"+UUID.randomUUID());
        try {
            var mac=javax.crypto.Mac.getInstance("HmacSHA256");mac.init(new javax.crypto.spec.SecretKeySpec(kek,"HmacSHA256"));auditKey=mac.doFinal("AEGIS-COMMUNITY-AUDIT-SUBKEY-v1".getBytes(StandardCharsets.US_ASCII));
            Files.createDirectory(staging,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            KeyPair service=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            write(staging.resolve("service-private.pkcs8"),service.getPrivate().getEncoded());write(staging.resolve("service-public.x509"),service.getPublic().getEncoded());write(staging.resolve("community-audit-subkey.bin"),auditKey);
            write(staging.resolve("config.json"),StrictJson.bytes(Map.of("version",1,"communityDatabase",community.resolve("community.sqlite").toString(),"identityPublicKey",IdentityProtocol.b64(identityPublic),"identityPort",identityPort,"libraryPort",libraryPort)));
            write(staging.resolve("INITIALIZED"),MARKER.getBytes(StandardCharsets.US_ASCII));Files.move(staging,home,StandardCopyOption.ATOMIC_MOVE);
            out.println("Отдельный Library Controller подготовлен. Ключи аккаунтов и release signing не использованы. Community TOTP KEK не сохранялся в Library.");show(out,service);
        }finally {Arrays.fill(kek,(byte)0);if(auditKey!=null)Arrays.fill(auditKey,(byte)0);if(Files.exists(staging,LinkOption.NOFOLLOW_LINKS))try(var paths=Files.walk(staging)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
    public static Running start(Path home)throws Exception {
        home=home.toAbsolutePath().normalize();verifyHome(home);KeyPair service=readKey(home);Map<String,Object>config=StrictJson.object(exactPrivate(home.resolve("config.json"),-1),8192);
        if(!config.keySet().equals(Set.of("version","communityDatabase","identityPublicKey","identityPort","libraryPort"))||StrictJson.number(config,"version",1,1)!=1)throw new IOException("Версия конфигурации");
        byte[]identityPublic=IdentityProtocol.unb64(StrictJson.text(config,"identityPublicKey",86),44);IdentityProtocol.publicKey(identityPublic);
        Path database=Path.of(StrictJson.text(config,"communityDatabase",4096)).toAbsolutePath().normalize();privateDirectory(database.getParent());verifyPrivateFile(database);
        byte[]auditKey=exactPrivate(home.resolve("community-audit-subkey.bin"),32);
        CommunityStore store=null;AccessControl access=null;LibraryIdentityBridge600 bridge=null;
        try {
            store=new CommunityStore(database);store.setAuditKey(auditKey);access=new AccessControl(store);ContentService content=new ContentService(store,access);
            bridge=new LibraryIdentityBridge600((int)StrictJson.number(config,"identityPort",1,65535),identityPublic,service.getPublic().getEncoded(),access,store);
            var server=new LibraryHttpServer600(new InetSocketAddress("127.0.0.1",(int)StrictJson.number(config,"libraryPort",1,65535)),store,access,content,service,bridge);
            Running running=new Running(store,access,bridge,server);server.start();return running;
        }catch(Exception failure){if(bridge!=null)bridge.close();if(access!=null)access.close();if(store!=null)store.close();throw failure;}
        finally{Arrays.fill(auditKey,(byte)0);}
    }
    public static final class Running implements AutoCloseable {
        private final CommunityStore store;private final AccessControl access;private final LibraryIdentityBridge600 bridge;private final LibraryHttpServer600 server;private final AtomicBoolean closed=new AtomicBoolean();
        private Running(CommunityStore s,AccessControl a,LibraryIdentityBridge600 b,LibraryHttpServer600 h){store=s;access=a;bridge=b;server=h;}
        public int port(){return server.port();}
        public void close(){if(closed.compareAndSet(false,true)){server.close();bridge.close();access.close();try{store.close();}catch(Exception ignored){}}}
    }
    private static int port(String text)throws IOException {try{int value=Integer.parseInt(text);if(value<1||value>65535)throw new NumberFormatException();return value;}catch(RuntimeException invalid){throw new IOException("Неверный порт");}}
    private static void verifyHome(Path home)throws Exception {privateDirectory(home);if(!new String(exactPrivate(home.resolve("INITIALIZED"),MARKER.length()),StandardCharsets.US_ASCII).equals(MARKER))throw new IOException("Маркер");}
    private static void show(PrintStream out,KeyPair key){out.println("Library public key (Base64URL): "+IdentityProtocol.b64(key.getPublic().getEncoded()));out.println("Library key SHA-256: "+IdentityProtocol.id(key.getPublic().getEncoded()));}
    private static KeyPair readKey(Path home)throws Exception {byte[]privateBytes=exactPrivate(home.resolve("service-private.pkcs8"),48);try{PrivateKey secret=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(privateBytes));byte[]pub=exactPrivate(home.resolve("service-public.x509"),44),challenge="AEGIS-LIBRARY-KEY-CHECK/v1".getBytes(StandardCharsets.US_ASCII);if(!IdentityProtocol.verify(pub,challenge,IdentityProtocol.sign(secret,challenge)))throw new IOException("Ключи не согласованы");return new KeyPair(IdentityProtocol.publicKey(pub),secret);}finally{Arrays.fill(privateBytes,(byte)0);}}
    private static void privateDirectory(Path p)throws IOException {if(!Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS)||!p.toRealPath().equals(p.toAbsolutePath().normalize()))throw new IOException("Каталог");permissions(p);}
    private static void permissions(Path p)throws IOException {try{for(var permission:Files.getPosixFilePermissions(p,LinkOption.NOFOLLOW_LINKS))if(permission.name().startsWith("GROUP_")||permission.name().startsWith("OTHERS_"))throw new IOException("Доступ только владельцу");}catch(UnsupportedOperationException unsupported){throw new IOException("Этот серверный комплект требует POSIX permissions",unsupported);}}
    private static void verifyPrivateFile(Path p)throws IOException {if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||!p.toRealPath().equals(p.toAbsolutePath().normalize()))throw new IOException("Файл БД");permissions(p);}
    private static byte[]exactPrivate(Path p,int size)throws IOException {permissions(p);byte[]bytes=read(p,size<0?16*1024*1024:size);if(size>=0&&bytes.length!=size)throw new IOException("Размер защищённого файла");return bytes;}
    private static byte[]read(Path p,int limit)throws IOException {p=p.toAbsolutePath().normalize();if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||!p.toRealPath().equals(p)||Files.size(p)>limit)throw new IOException("Файл");try(var in=Files.newInputStream(p,LinkOption.NOFOLLOW_LINKS)){byte[]bytes=in.readNBytes(limit+1);if(bytes.length>limit)throw new IOException("Размер файла");return bytes;}}
    private static void write(Path target,byte[]bytes)throws IOException {try{Files.createFile(target,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));try(var out=java.nio.channels.FileChannel.open(target,StandardOpenOption.WRITE)){var data=java.nio.ByteBuffer.wrap(bytes);while(data.hasRemaining())out.write(data);out.force(true);}}finally{Arrays.fill(bytes,(byte)0);}}
}
