package org.securemail.glas.signaling;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import org.securemail.attachments.IdentityRemoteAuthority;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Separate staging service key only. Never loads user/account/release private keys. */
public final class GlasSignalingMain600 {
  private GlasSignalingMain600(){}
  public static void main(String[]args){try{
    if(args.length==2&&args[0].equals("init")){initialize(Path.of(args[1]));return;}
    if(args.length!=6||!args[0].equals("serve")||!args[3].equals("--identity"))throw new IOException("Параметры сервиса Гласа");
    Path state=Path.of(args[1]).toAbsolutePath().normalize();int port=Integer.parseInt(args[2]);if(port<1||port>65535||!state.toRealPath().equals(state))throw new IOException("Параметры сервиса Гласа");byte[] identityKey=IdentityRemoteAuthority.readPinnedKey(Path.of(args[5]));var identity=new IdentityRemoteAuthority(URI.create(args[4]),identityKey);KeyFactory f=KeyFactory.getInstance("Ed25519");byte[] secret=privateBytes(state.resolve("service-private.pkcs8"),48);KeyPair key;
    try{key=new KeyPair(f.generatePublic(new X509EncodedKeySpec(privateBytes(state.resolve("service-public.x509"),44))),f.generatePrivate(new PKCS8EncodedKeySpec(secret)));}finally{Arrays.fill(secret,(byte)0);}
    try(var registry=new GlasRegistry600(state,identity,identityKey,key.getPublic().getEncoded(),Clock.systemUTC(),10000);var server=new GlasSignalingHttp600(new InetSocketAddress("127.0.0.1",port),registry,key)){
      CountDownLatch stop=new CountDownLatch(1);Runtime.getRuntime().addShutdownHook(new Thread(stop::countDown,"aegis-glas-signaling-stop"));server.start();System.out.println("Сервис Гласа запущен на loopback. Публичный отпечаток: "+IdentityProtocol.id(key.getPublic().getEncoded()));stop.await();
    }
  }catch(Exception denied){System.err.println("Сервис Гласа не запущен: проверьте приватный каталог, закреплённый Identity и доступность loopback. Секретные данные в журнал не выводятся.");System.exit(1);}}
  private static void initialize(Path state)throws Exception{state=state.toAbsolutePath().normalize();if(Files.exists(state,LinkOption.NOFOLLOW_LINKS)||state.getParent()==null||!state.getParent().toRealPath().equals(state.getParent()))throw new IOException("Нужен отдельный новый каталог");Files.createDirectory(state,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));KeyPair key=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();byte[] secret=key.getPrivate().getEncoded();try{write(state.resolve("service-private.pkcs8"),secret);write(state.resolve("service-public.x509"),key.getPublic().getEncoded());}finally{Arrays.fill(secret,(byte)0);}System.out.println("Создан отдельный сервисный ключ Гласа. Приватные identity и release keys не используются.");}
  private static byte[] privateBytes(Path p,int n)throws IOException{if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||Files.size(p)!=n||Files.getPosixFilePermissions(p).stream().anyMatch(v->v.name().startsWith("GROUP_")||v.name().startsWith("OTHERS_")))throw new IOException("Приватный файл сервиса");return Files.readAllBytes(p);}
  private static void write(Path p,byte[] b)throws IOException{Files.createFile(p,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));Files.write(p,b);}
}
