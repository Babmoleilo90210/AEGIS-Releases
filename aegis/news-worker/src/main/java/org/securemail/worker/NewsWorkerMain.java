package org.securemail.worker;
import org.securemail.community.agent.NewsModel;
import org.securemail.community.agent.HttpNewsModel;
import org.securemail.community.agent.PublicSourceHttp;
import org.securemail.community.agent.SourceParser;
import org.securemail.community.agent.RobotsPolicy;

import org.securemail.community.agent.AgentJson;
import org.securemail.community.protocol.CommunityAuth;
import java.net.URI;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.*;
import java.util.*;

/** Separate server worker. Does not load client profile, archive, mail keys or an administrator key. */
public final class NewsWorkerMain {
  private NewsWorkerMain(){}
  public static void main(String[] args)throws Exception{
    Map<String,String>a=arguments(args);if(a.containsKey("generate-key")){generate(Path.of(a.get("generate-key")));return;}
    for(String key:List.of("server","server-key","worker-key","tor-socks"))if(!a.containsKey(key))throw new IllegalArgumentException("Укажите --server --server-key --worker-key --tor-socks; отдельная служебная identity обязательна");
    KeyPair worker=readKey(Path.of(a.get("worker-key")));byte[] serverKey=Base64.getDecoder().decode(a.get("server-key"));WorkerCoordinatorClient coordinator=new WorkerCoordinatorClient(URI.create(a.get("server")),serverKey,worker,Integer.parseInt(a.get("tor-socks")));
    try(NewsWorker service=new NewsWorker(coordinator::call,new PublicSourceHttp(),policy->{String provider=AgentJson.text(policy,"provider",32),model=AgentJson.text(policy,"model",128),endpoint=AgentJson.text(policy,"endpoint",2048),ref=AgentJson.text(policy,"credentialRef",80);if(!ref.isEmpty()&&!ref.matches("AEGIS_NEWS_API_KEY_[A-Z0-9_]{1,48}"))throw new IllegalArgumentException("Неверное имя секрета");String secret=ref.isEmpty()?"":System.getenv(ref);if(!ref.isEmpty()&&(secret==null||secret.isBlank()))throw new IllegalArgumentException("Секрет внешнего провайдера не настроен");return new HttpNewsModel(provider,model,URI.create(endpoint),secret,(int)AgentJson.number(policy,"maxOutputTokens",128,4096));})){
      System.out.println("Рабочий узел запущен. Публичные источники: HTTPS; координатор: только Tor. Секреты в журнал не выводятся.");
      do{try{service.runOnce();}catch(Exception e){if(Thread.currentThread().isInterrupted())break;System.err.println("Задание временно недоступно; повтор через ограниченный интервал.");}if(a.containsKey("once"))break;Thread.sleep(15000);}while(!Thread.currentThread().isInterrupted());
    }
  }
  private static Map<String,String>arguments(String[]args){Set<String> allowed=Set.of("server","server-key","worker-key","tor-socks","generate-key","once");Map<String,String>a=new HashMap<>();for(int n=0;n<args.length;n++){if(!args[n].startsWith("--"))throw new IllegalArgumentException("Неизвестный параметр");String k=args[n].substring(2);if(!allowed.contains(k)||a.containsKey(k))throw new IllegalArgumentException("Неизвестный или повторный параметр");String v=k.equals("once")?"true":++n<args.length?args[n]:null;if(v==null)throw new IllegalArgumentException("Не задан параметр");a.put(k,v);}return a;}
  private static void generate(Path directory)throws Exception{Path root=directory.toAbsolutePath().normalize();if(Files.exists(root))throw new IllegalArgumentException("Каталог уже существует");try{Files.createDirectory(root,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));}catch(UnsupportedOperationException e){throw new IllegalArgumentException("Служебный рабочий узел требует защищённую POSIX-систему файлов; Windows-сервер не заявлен",e);}KeyPair pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();byte[]privateBytes=pair.getPrivate().getEncoded();try{Files.createFile(root.resolve("worker.pk8"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));Files.write(root.resolve("worker.pk8"),privateBytes,StandardOpenOption.WRITE);Files.createFile(root.resolve("worker.pub"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));Files.write(root.resolve("worker.pub"),pair.getPublic().getEncoded(),StandardOpenOption.WRITE);}finally{Arrays.fill(privateBytes,(byte)0);}System.out.println("Служебная identity: "+CommunityAuth.id(pair.getPublic().getEncoded()));}
  private static KeyPair readKey(Path file)throws Exception{Path path=file.toAbsolutePath().normalize();if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||!path.toRealPath().equals(path)||Files.size(path)>1024)throw new IllegalArgumentException("Небезопасный файл служебного ключа");try{if(Files.getPosixFilePermissions(path).stream().anyMatch(p->p.name().startsWith("GROUP_")||p.name().startsWith("OTHERS_")))throw new IllegalArgumentException("Файл служебного ключа должен иметь права 0600");}catch(UnsupportedOperationException e){throw new IllegalArgumentException("Рабочий узел требует проверяемые POSIX-права ключа",e);}Path pub=path.resolveSibling("worker.pub");if(!Files.isRegularFile(pub,LinkOption.NOFOLLOW_LINKS)||Files.size(pub)!=44)throw new IllegalArgumentException("Нужен парный worker.pub");KeyFactory k=KeyFactory.getInstance("Ed25519");byte[] privateBytes=Files.readAllBytes(path);try{PrivateKey secret=k.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));PublicKey publicKey=k.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(pub)));byte[] test=new byte[32];new SecureRandom().nextBytes(test);if(!CommunityAuth.verify(publicKey.getEncoded(),test,CommunityAuth.sign(secret,test)))throw new IllegalArgumentException("Ключи рабочего узла не совпадают");return new KeyPair(publicKey,secret);}finally{Arrays.fill(privateBytes,(byte)0);}}
}
