package org.securemail.community;

import org.securemail.community.core.*;
import org.securemail.community.access.AccessControl;
import org.securemail.community.org.OrgAdminService;
import org.securemail.community.content.ContentService;
import org.securemail.community.agent.*;
import org.securemail.community.http.CommunityHttpServer;
import org.securemail.community.protocol.CommunityAuth;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.security.spec.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/** Operator-only setup for a separate community service. Never deploys or changes Relay/Tor/feed. */
public final class CommunityMain {
  private CommunityMain(){}
  public static void main(String[] args){int status=run(args,System.out,System.err);if(status!=0)System.exit(status);}
  public static int run(String[] args,PrintStream out,PrintStream error){
    try {
      if(args.length<2||!Set.of("--init","--serve","--inspect").contains(args[0])){usage(error);return 2;}
      Path directory=Path.of(args[1]).toAbsolutePath().normalize();Map<String,String> options=options(args);
      if(args[0].equals("--init")){initialize(directory,options,out);return 0;}
      if(args[0].equals("--inspect")){if(!options.isEmpty())throw new IOException("Параметры не поддерживаются");verifyPrivateDirectory(directory);KeyPair key=readKey(directory);showPublic(out,key);return 0;}
      if(!options.keySet().stream().allMatch("--port"::equals))throw new IOException("Параметры не поддерживаются");
      int port=Integer.parseInt(options.getOrDefault("--port","38150"));if(port<1||port>65535)throw new IOException("Неверный порт");serve(directory,port,out);return 0;
    }catch(Exception failure){error.println("Операция не выполнена. Проверьте аргументы, полномочия владельца файлов и локальные параметры сервиса. Секреты и внутренние исключения не выводятся.");return 1;}
  }
  private static void usage(PrintStream out){out.println("АЕГИС — отдельный сервер организаций, новостей и библиотеки");out.println("--init DIR --first-public FILE --first-fingerprint SHA256 --first-totp FILE --second-public FILE --second-fingerprint SHA256 --second-totp FILE");out.println("--inspect DIR");out.println("--serve DIR [--port 38150]");out.println("TOTP: два независимо подготовленных файла по 32 байта с доступом только владельцу. Закрытые identity/release-signing ключи не требуются.");}
  private static Map<String,String> options(String[] args)throws IOException {if((args.length-2)%2!=0)throw new IOException("Параметры");Map<String,String> options=new LinkedHashMap<>();for(int i=2;i<args.length;i+=2){if(!args[i].startsWith("--")||options.putIfAbsent(args[i],args[i+1])!=null)throw new IOException("Параметры");}return options;}
  public static void initialize(Path directory,Map<String,String> options,PrintStream out)throws Exception {
    Set<String> expected=Set.of("--first-public","--first-fingerprint","--first-totp","--second-public","--second-fingerprint","--second-totp");if(!options.keySet().equals(expected))throw new IOException("Аргументы первоначальной настройки");
    byte[] first=readPublic(Path.of(options.get("--first-public"))),second=readPublic(Path.of(options.get("--second-public")));String firstFingerprint=options.get("--first-fingerprint"),secondFingerprint=options.get("--second-fingerprint");
    if(!CommunityAuth.id(first).equals(firstFingerprint)||!CommunityAuth.id(second).equals(secondFingerprint)||firstFingerprint.equals(secondFingerprint))throw new IOException("Независимые отпечатки не подтверждены");
    byte[] firstSeed=null,secondSeed=null,kek=new byte[32];
    try {
      firstSeed=readSecret(Path.of(options.get("--first-totp")),32);secondSeed=readSecret(Path.of(options.get("--second-totp")),32);
      if(MessageDigest.isEqual(firstSeed,secondSeed))throw new IOException("Независимые вторые факторы обязательны");
      directory=directory.toAbsolutePath().normalize();Path parent=directory.getParent();if(parent==null||!parent.toRealPath().equals(parent)||Files.exists(directory,LinkOption.NOFOLLOW_LINKS))throw new IOException("Нужен новый каталог без символических ссылок");
      Path destination=directory;directory=destination.resolveSibling("."+destination.getFileName()+".setup-"+UUID.randomUUID());createPrivateDirectory(directory);new SecureRandom().nextBytes(kek);KeyPair key=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      writePrivate(directory.resolve("service-private.pkcs8"),key.getPrivate().getEncoded());writePrivate(directory.resolve("service-public.x509"),key.getPublic().getEncoded());writePrivate(directory.resolve("factor-kek.bin"),kek);
      try(var store=new CommunityStore(directory.resolve("community.sqlite"),Clock.systemUTC())){
        var access=new AccessControl(store,kek);access.bootstrap(first,firstFingerprint,firstSeed,second,secondFingerprint,secondSeed);
        var content=new ContentService(store,access);store.setNotificationSink(content::notifyAccount);try(var agent=new AgentService(store,access,content::ingestAi)){agent.setLibraryLinks(new LocalLibraryLinks(store,access,(actor,id)->content.handle(actor,"content.library.get",Map.of("id",id)),content::proposeAi));}
      }
      writePrivate(directory.resolve("INITIALIZED"),"AEGIS-COMMUNITY-v1\n".getBytes(StandardCharsets.US_ASCII));Files.move(directory,destination,StandardCopyOption.ATOMIC_MOVE);out.println("Сервер подготовлен в отдельном каталоге. Существующий Relay и production feed не изменены.");showPublic(out,key);
    }finally{if(firstSeed!=null)Arrays.fill(firstSeed,(byte)0);if(secondSeed!=null)Arrays.fill(secondSeed,(byte)0);Arrays.fill(kek,(byte)0);}
  }
  private static void serve(Path directory,int port,PrintStream out)throws Exception {
    verifyPrivateDirectory(directory);byte[] marker=readSecret(directory.resolve("INITIALIZED"),19);try{if(!MessageDigest.isEqual(marker,"AEGIS-COMMUNITY-v1\n".getBytes(StandardCharsets.US_ASCII)))throw new IOException("Первоначальная настройка не подтверждена");}finally{Arrays.fill(marker,(byte)0);}
    KeyPair key=readKey(directory);byte[] kek=readSecret(directory.resolve("factor-kek.bin"),32);
    try(var store=new CommunityStore(directory.resolve("community.sqlite"),Clock.systemUTC())){
      AccessControl access;try{access=new AccessControl(store,kek);}finally{Arrays.fill(kek,(byte)0);}
      var content=new ContentService(store,access);store.setNotificationSink(content::notifyAccount);
      try(var agent=new AgentService(store,access,content::ingestAi)){
        agent.setLibraryLinks(new LocalLibraryLinks(store,access,(actor,id)->content.handle(actor,"content.library.get",Map.of("id",id)),content::proposeAi));
        var organizations=new OrgAdminService(store,access,store.clock());
        try(var server=new CommunityHttpServer(new InetSocketAddress("127.0.0.1",port),store,access,organizations,content,agent,key)){
          var stopped=new CountDownLatch(1);var closing=new AtomicBoolean();Runnable close=()->{if(closing.compareAndSet(false,true)){server.close();agent.close();try{store.close();}catch(Exception ignored){}}stopped.countDown();};Thread hook=new Thread(close,"aegis-community-shutdown");Runtime.getRuntime().addShutdownHook(hook);
          try{server.start();agent.start();showPublic(out,key);out.println("Сервис слушает только loopback:"+server.port()+". Tor onion service настраивается оператором отдельно; клиентский clearnet fallback не включён.");stopped.await();}
          finally{close.run();try{Runtime.getRuntime().removeShutdownHook(hook);}catch(IllegalStateException shuttingDown){}}
        }
      }
    }finally{Arrays.fill(kek,(byte)0);}
  }
  private static void showPublic(PrintStream out,KeyPair key){out.println("Открытый ключ сервера (Base64): "+Base64.getEncoder().encodeToString(key.getPublic().getEncoded()));out.println("SHA-256 ключа сервера: "+CommunityAuth.id(key.getPublic().getEncoded()));}
  private static KeyPair readKey(Path directory)throws Exception {
    byte[] secret=readSecret(directory.resolve("service-private.pkcs8"),48);try{PrivateKey key=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(secret));PublicKey pub=CommunityAuth.publicKey(readPublic(directory.resolve("service-public.x509")));byte[] challenge="AEGIS service key consistency".getBytes(StandardCharsets.US_ASCII);if(!CommunityAuth.verify(pub.getEncoded(),challenge,CommunityAuth.sign(key,challenge)))throw new IOException("Несогласованные ключи");return new KeyPair(pub,key);}finally{Arrays.fill(secret,(byte)0);}
  }
  private static byte[] readPublic(Path path)throws Exception {path=path.toAbsolutePath().normalize();if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)>128)throw new IOException("Открытый ключ");byte[] bytes=boundedRead(path,128);if(bytes.length!=44)bytes=Base64.getDecoder().decode(new String(bytes,StandardCharsets.US_ASCII).strip());CommunityAuth.publicKey(bytes);return bytes;}
  private static byte[] readSecret(Path path,int size)throws IOException {path=path.toAbsolutePath().normalize();if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)!=size)throw new IOException("Защищённый файл");verifyPrivate(path);byte[] bytes=boundedRead(path,size);if(bytes.length!=size){Arrays.fill(bytes,(byte)0);throw new IOException("Защищённый файл");}return bytes;}
  private static byte[] boundedRead(Path path,int maximum)throws IOException {
    try(var channel=Files.newByteChannel(path,Set.<OpenOption>of(StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS))){var buffer=java.nio.ByteBuffer.allocate(maximum+1);while(buffer.hasRemaining()&&channel.read(buffer)!=-1){}buffer.flip();if(buffer.remaining()>maximum){Arrays.fill(buffer.array(),(byte)0);throw new IOException("Размер файла превышен");}byte[] bytes=new byte[buffer.remaining()];buffer.get(bytes);Arrays.fill(buffer.array(),(byte)0);return bytes;}
  }
  private static void verifyPrivateDirectory(Path directory)throws IOException {if(!Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS)||!directory.toRealPath().equals(directory.toAbsolutePath().normalize()))throw new IOException("Защищённый каталог");verifyPrivate(directory);}
  private static void verifyPrivate(Path path)throws IOException {
    try{Set<PosixFilePermission> permissions=Files.getPosixFilePermissions(path,LinkOption.NOFOLLOW_LINKS);for(var permission:permissions)if(permission.name().startsWith("GROUP_")||permission.name().startsWith("OTHERS_"))throw new IOException("Доступ разрешён только владельцу");}
    catch(UnsupportedOperationException unavailable){AclFileAttributeView view=Files.getFileAttributeView(path,AclFileAttributeView.class,LinkOption.NOFOLLOW_LINKS);if(view==null)throw new IOException("Проверка полномочий недоступна");UserPrincipal owner=Files.getOwner(path,LinkOption.NOFOLLOW_LINKS);for(AclEntry entry:view.getAcl())if(entry.type()==AclEntryType.ALLOW&&!entry.principal().equals(owner))throw new IOException("Доступ разрешён только владельцу");}
  }
  private static void secure(Path path,boolean directory)throws IOException {
    try{Files.setPosixFilePermissions(path,PosixFilePermissions.fromString(directory?"rwx------":"rw-------"));}
    catch(UnsupportedOperationException unavailable){AclFileAttributeView view=Files.getFileAttributeView(path,AclFileAttributeView.class,LinkOption.NOFOLLOW_LINKS);if(view==null)throw new IOException("Защита файлов недоступна");UserPrincipal owner=Files.getOwner(path,LinkOption.NOFOLLOW_LINKS);view.setAcl(List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build()));}
  }
  private static void createPrivateDirectory(Path directory)throws IOException {try{Files.createDirectory(directory,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));}catch(UnsupportedOperationException unavailable){Files.createDirectory(directory);secure(directory,true);}}
  private static void writePrivate(Path target,byte[] value)throws IOException {
    byte[] owned=value.clone();Path temporary=target.resolveSibling(".setup-"+UUID.randomUUID());try{try{Files.createFile(temporary,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));}catch(UnsupportedOperationException unavailable){Files.createFile(temporary);secure(temporary,false);}try(var channel=java.nio.channels.FileChannel.open(temporary,StandardOpenOption.WRITE)){java.nio.ByteBuffer bytes=java.nio.ByteBuffer.wrap(owned);while(bytes.hasRemaining())channel.write(bytes);channel.force(true);}Files.move(temporary,target,StandardCopyOption.ATOMIC_MOVE);}
    finally{Files.deleteIfExists(temporary);Arrays.fill(owned,(byte)0);}
  }
}
