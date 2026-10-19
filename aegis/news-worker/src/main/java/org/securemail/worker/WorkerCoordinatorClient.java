package org.securemail.worker;
import org.securemail.community.agent.PublicSourceHttp;
import org.securemail.community.agent.SourceParser;
import org.securemail.community.agent.RobotsPolicy;

import org.securemail.community.agent.AgentJson;
import org.securemail.community.protocol.CommunityAuth;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

/** Dedicated service identity. Coordinator requests are signed and onion-routed, never direct. */
public final class WorkerCoordinatorClient {
  public enum Mode { LEGACY5, SERVICE6 }
  @FunctionalInterface interface Connector{Socket connect(String host,int port)throws IOException;}
  private static final ScheduledThreadPoolExecutor DEADLINES=deadlines();
  private static ScheduledThreadPoolExecutor deadlines(){var timer=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-worker-rpc-deadline");t.setDaemon(true);return t;});timer.setRemoveOnCancelPolicy(true);return timer;}
  private static final class DeadlineSocket extends Socket{final ScheduledFuture<?>deadline=DEADLINES.schedule(()->{try{close();}catch(IOException ignored){}},30,TimeUnit.SECONDS);@Override public synchronized void close()throws IOException{if(deadline!=null)deadline.cancel(false);super.close();}}
  private final URI server;private final byte[] serverKey;private final KeyPair key;private final Connector connector;private final long deadlineMillis;private final Mode mode;
  public WorkerCoordinatorClient(URI server,byte[] serverKey,KeyPair key,int torSocksPort)throws IOException{
    this(server,serverKey,key,(host,port)->socks(host,port,torSocksPort),30000,Mode.LEGACY5);
  }
  public WorkerCoordinatorClient(URI server,byte[]serverKey,KeyPair key,int torSocksPort,Mode mode)throws IOException{this(server,serverKey,key,(host,port)->socks(host,port,torSocksPort),30000,mode);}
  WorkerCoordinatorClient(URI server,byte[] serverKey,KeyPair key,Connector connector)throws IOException{this(server,serverKey,key,connector,30000,Mode.LEGACY5);}
  WorkerCoordinatorClient(URI server,byte[]serverKey,KeyPair key,Connector connector,Mode mode)throws IOException{this(server,serverKey,key,connector,30000,mode);}
  WorkerCoordinatorClient(URI server,byte[]serverKey,KeyPair key,Connector connector,long deadlineMillis)throws IOException{this(server,serverKey,key,connector,deadlineMillis,Mode.LEGACY5);}
  WorkerCoordinatorClient(URI server,byte[] serverKey,KeyPair key,Connector connector,long deadlineMillis,Mode mode)throws IOException{this.mode=Objects.requireNonNull(mode);if(deadlineMillis<1||deadlineMillis>30000)throw new IOException("Некорректное ограничение времени");this.deadlineMillis=deadlineMillis;
    if(!"http".equals(server.getScheme())||server.getHost()==null||!server.getHost().matches("[a-z2-7]{56}\\.onion")||server.getRawUserInfo()!=null||server.getRawQuery()!=null||server.getRawFragment()!=null||!(mode==Mode.SERVICE6?server.getPath().equals(org.securemail.community.agent.WorkerWire600.PATH):Set.of("","/","/api/v1").contains(server.getPath()))||server.getPort()!=-1&&server.getPort()!=80)throw new IOException("Координатору нужен onion-адрес через Tor");
    if(serverKey.length!=44)throw new IOException("Некорректный ключ сервера");this.server=server;this.serverKey=serverKey.clone();this.key=key;this.connector=connector;
  }
  public Map<String,Object> call(String action,Map<String,Object> data)throws Exception{
    if(!Set.of("agent.worker.claim","agent.worker.complete","agent.worker.fail").contains(action))throw new IOException("Рабочему узлу запрещена административная операция");
    byte[] body=AgentJson.bytes(Map.of("action",action,"data",data));if(body.length>262144)throw new IOException("Результат задания слишком большой");byte[] nonceBytes=new byte[32];new SecureRandom().nextBytes(nonceBytes);String nonce=Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes),audience=CommunityAuth.id(serverKey);long time=System.currentTimeMillis();String signature=Base64.getEncoder().encodeToString(CommunityAuth.sign(key.getPrivate(),requestBytes(audience,time,nonce,body)));
    try(Socket socket=connector.connect(server.getHost(),80)){ScheduledFuture<?>deadline=DEADLINES.schedule(()->closeQuietly(socket),deadlineMillis,TimeUnit.MILLISECONDS);try{socket.setSoTimeout(15000);String headers="POST "+(mode==Mode.SERVICE6?org.securemail.community.agent.WorkerWire600.PATH:"/api/v1")+" HTTP/1.1\r\nHost: "+server.getHost()+"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+body.length+"\r\nAEGIS-Key: "+Base64.getEncoder().encodeToString(key.getPublic().getEncoded())+"\r\nAEGIS-Time: "+time+"\r\nAEGIS-Nonce: "+nonce+"\r\nAEGIS-Signature: "+signature+"\r\n\r\n";socket.getOutputStream().write(headers.getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().write(body);socket.getOutputStream().flush();var response=PublicSourceHttp.readResponse(socket.getInputStream(),server,262144);String signed=response.headers().get("aegis-signature");if(signed==null)throw new IOException("Ответ координатора не подписан");byte[] responseBody=response.body();byte[] sig;try{sig=Base64.getDecoder().decode(signed);}catch(IllegalArgumentException e){throw new IOException("Подпись координатора отклонена",e);}if(!CommunityAuth.verify(serverKey,(mode==Mode.SERVICE6?org.securemail.community.agent.WorkerWire600.responseBytes(audience,nonce,body,responseBody):CommunityAuth.responseBytes(audience,nonce,responseBody)),sig))throw new IOException("Подпись координатора отклонена");Map<String,Object> parsed=AgentJson.object(responseBody,262144);String expectedActor=CommunityAuth.id(key.getPublic().getEncoded()),expectedRequest=CommunityAuth.id(requestBytes(audience,time,nonce,body));if(!expectedActor.equals(parsed.get("requestIdentity"))||!expectedRequest.equals(parsed.get("requestSha256")))throw new IOException("Контекст ответа координатора не совпадает с запросом");if(!Boolean.TRUE.equals(parsed.get("ok")))throw new IOException("Координатор отклонил операцию");if(!(parsed.get("data") instanceof Map<?,?> map))throw new IOException("Некорректный ответ координатора");@SuppressWarnings("unchecked")Map<String,Object>result=(Map<String,Object>)map;return result;}finally{deadline.cancel(false);}}finally{Arrays.fill(body,(byte)0);}
  }
  private byte[]requestBytes(String audience,long time,String nonce,byte[]body)throws IOException{return mode==Mode.SERVICE6?org.securemail.community.agent.WorkerWire600.requestBytes(audience,time,nonce,body):CommunityAuth.requestBytes(audience,time,nonce,body);}
  private static void closeQuietly(Socket socket){try{socket.close();}catch(IOException ignored){}}
  static Socket socks(String host,int port,int socksPort)throws IOException{if(socksPort<1||socksPort>65535||!host.matches("[a-z2-7]{56}\\.onion"))throw new IOException("Неверный Tor-маршрут");Socket socket=new DeadlineSocket();try{socket.connect(new InetSocketAddress("127.0.0.1",socksPort),5000);socket.setSoTimeout(15000);InputStream in=socket.getInputStream();OutputStream out=socket.getOutputStream();out.write(new byte[]{5,1,0});out.flush();if(in.read()!=5||in.read()!=0)throw new IOException("Tor SOCKS недоступен");byte[] name=host.getBytes(StandardCharsets.US_ASCII);out.write(new byte[]{5,1,0,3,(byte)name.length});out.write(name);out.write(new byte[]{(byte)(port>>>8),(byte)port});out.flush();int version=in.read(),reply=in.read(),reserved=in.read(),type=in.read();if(version!=5||reply!=0||reserved!=0)throw new IOException("Tor не смог подключиться к координатору");int bytes=switch(type){case 1->4;case 4->16;case 3->in.read();default->throw new IOException("Некорректный Tor SOCKS-ответ");};if(bytes<0||in.readNBytes(bytes+2).length!=bytes+2)throw new EOFException("Неполный Tor SOCKS-ответ");return socket;}catch(IOException e){socket.close();throw e;}}
}
