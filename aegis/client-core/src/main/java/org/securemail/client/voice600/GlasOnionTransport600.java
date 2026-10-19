package org.securemail.client.voice600;

import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import org.securemail.client.net.*;
import org.securemail.client.voice.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;
import org.securemail.protocol.*;

/** A bounded loopback onion listener and Tor-only connector. Signaling grants are rechecked before either TLS role and during calls. */
public final class GlasOnionTransport600 implements AutoCloseable {
  private record Live(byte[] delegationSha,long checkedNanos){Live{delegationSha=delegationSha.clone();}}
  private final GlasState600 state;private final GlasGrant600 grant;private final PrivateKey appKey;private final GlasSignalingClient600 signaling;private final TorTransport tor;private final ServerSocket listener;
  private final ThreadPoolExecutor inbound=new ThreadPoolExecutor(0,2,30,TimeUnit.SECONDS,new SynchronousQueue<>(),r->{Thread t=new Thread(r,"glas-onion-inbound");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final ScheduledThreadPoolExecutor timer=new ScheduledThreadPoolExecutor(2,r->{Thread t=new Thread(r,"glas-route-check");t.setDaemon(true);return t;});private final Set<Socket> sockets=ConcurrentHashMap.newKeySet();private final ConcurrentHashMap<String,Live> peers=new ConcurrentHashMap<>();
  private volatile boolean closed,ready;private volatile TorControl control;private volatile VoiceCallService calls;private volatile String onion;private long lastRegister;private volatile Consumer<Boolean> status=ok->{};
  public GlasOnionTransport600(GlasState600 state,GlasGrant600 grant,PrivateKey appKey,GlasSignalingClient600 signaling,TorTransport tor)throws IOException{
    this.state=Objects.requireNonNull(state);this.grant=Objects.requireNonNull(grant);this.appKey=Objects.requireNonNull(appKey);this.signaling=Objects.requireNonNull(signaling);this.tor=Objects.requireNonNull(tor);listener=new ServerSocket();listener.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),0),2);timer.setRemoveOnCancelPolicy(true);state.remoteVerifier(this::verifyRemote,this::peerActive);
  }
  public void status(Consumer<Boolean> listener){status=Objects.requireNonNull(listener);}
  /** Runs on a worker; SAFECOOKIE owns an ephemeral onion removed when this control connection closes. */
  public void start(VoiceCallService service,int controlPort,Path cookie)throws IOException,GeneralSecurityException{
    if(closed||calls!=null)throw new IOException("Глас уже запускается или закрыт");calls=Objects.requireNonNull(service);TorControl own=new TorControl(controlPort,cookie);try{if(!own.bootstrapped())throw new IOException("Tor ещё подключается");onion=own.publish(listener.getLocalPort());if(!GlasProtocol600.validOnion(onion))throw new IOException("Tor вернул некорректный адрес");control=own;register();ready=true;service.networkAvailable(true);status.accept(true);}catch(IOException|RuntimeException failure){own.close();control=null;throw failure;}
    Thread accept=new Thread(this::accept,"glas-onion-accept");accept.setDaemon(true);accept.start();timer.scheduleWithFixedDelay(this::refresh,1,2,TimeUnit.SECONDS);
  }
  private void register()throws IOException{
    VoiceCallService service=calls;Set<String> incoming=new HashSet<>(),outgoing=new HashSet<>();for(UserInfo peer:state.contacts())if(!state.blocked(peer.userId())){if(service.incomingEnabled()&&service.callPolicy().incoming().allowsLocally(peer.userId()))incoming.add(peer.userId());if(service.callPolicy().outgoing().allowsLocally(peer.userId()))outgoing.add(peer.userId());}
    long now=System.currentTimeMillis(),until=Math.min(grant.delegation().expiresAt,now+GlasProtocol600.MAX_ENDPOINT_MILLIS);var unsigned=new GlasProtocol600.Endpoint(signaling.audience(),GlasProtocol600.sha256Delegation(grant.delegation()),onion,80,now,until,IdentityProtocol.nonce(),new byte[64]);signaling.register(grant.delegation(),unsigned.signed(IdentityProtocol.sign(appKey,unsigned.signingBytes())),incoming,outgoing);lastRegister=System.nanoTime();
  }
  private void refresh(){if(closed)return;sockets.removeIf(Socket::isClosed);try{VoiceCallService service=calls;if(service==null)return;var snapshot=service.snapshot();if(snapshot.busy()&&snapshot.contact()!=null){var remote=signaling.lookup(snapshot.contact().publicKey(),snapshot.direction()==VoiceCallService.Direction.INCOMING);Live previous=peers.get(snapshot.contact().userId());byte[] hash=GlasProtocol600.sha256Delegation(remote.delegation());if(previous!=null&&!MessageDigest.isEqual(previous.delegationSha(),hash))throw new IOException("Идентичность приложения собеседника изменилась");peers.put(snapshot.contact().userId(),new Live(hash,System.nanoTime()));}
      if(System.nanoTime()-lastRegister>10_000_000_000L)register();if(!ready){ready=true;service.networkAvailable(true);status.accept(true);}
    }catch(Exception failure){peers.clear();ready=false;if(calls!=null){calls.networkAvailable(false);calls.hangup();}status.accept(false);}}
  private void verifyRemote(VoiceTls.Offer offer)throws IOException{if(closed||!ready||offer.delegation()==null)throw new IOException("Маршрут Гласа недоступен");var resolved=signaling.lookup(offer.identityPublicKey(),offer.role()==VoiceTls.Role.CALLER);byte[] expected=GlasProtocol600.sha256Delegation(resolved.delegation()),actual=GlasProtocol600.sha256Delegation(offer.delegation());if(!MessageDigest.isEqual(expected,actual))throw new IOException("Голосовой ключ собеседника отозван или изменён");peers.put(IdentityProtocol.id(offer.identityPublicKey()),new Live(actual,System.nanoTime()));}
  public void verifyCurrentPeer(UserInfo peer,boolean incoming)throws IOException{if(closed||!ready)throw new IOException("Маршрут Гласа недоступен");var result=signaling.lookup(peer.publicKey(),incoming);byte[] hash=GlasProtocol600.sha256Delegation(result.delegation());Live existing=peers.get(peer.userId());if(existing==null||!MessageDigest.isEqual(existing.delegationSha(),hash))throw new IOException("Ключ собеседника изменился");peers.put(peer.userId(),new Live(hash,System.nanoTime()));}
  private boolean peerActive(UserInfo peer){Live active=peers.get(peer.userId());return !closed&&ready&&active!=null&&System.nanoTime()-active.checkedNanos()<5_000_000_000L;}
  public Socket connect(UserInfo contact)throws IOException{if(closed||!ready||sockets.size()>=8||state.blocked(contact.userId()))throw new IOException("Глас не подключён");var remote=signaling.lookup(contact.publicKey());peers.put(contact.userId(),new Live(GlasProtocol600.sha256Delegation(remote.delegation()),System.nanoTime()));return tor.connectPeer(remote.endpoint().onion,remote.endpoint().port,socket->{if(closed)throw new IOException("Глас закрыт");sockets.add(socket);});}
  private void accept(){while(!closed)try{Socket socket=listener.accept();socket.setSoTimeout(10000);sockets.add(socket);try{inbound.execute(()->{try(socket){var timeout=timer.schedule(()->close(socket),30,TimeUnit.SECONDS);try{DataInputStream in=new DataInputStream(socket.getInputStream());Binary.header(in);if(in.readUnsignedByte()!=101||!Binary.text(in,64).isEmpty())throw new IOException("Тип соединения Гласа");timeout.cancel(false);calls.handleIncoming(socket);}finally{timeout.cancel(false);}}catch(Exception ignored){}finally{sockets.remove(socket);}});}catch(RejectedExecutionException full){sockets.remove(socket);close(socket);}}catch(IOException lost){if(!closed){ready=false;if(calls!=null)calls.networkAvailable(false);}return;}}
  private static void close(Socket socket){try{socket.close();}catch(IOException ignored){}}
  public boolean ready(){return ready&&!closed;}
  @Override public void close(){if(closed)return;closed=true;ready=false;VoiceCallService service=calls;if(service!=null){service.networkAvailable(false);service.close();}timer.shutdownNow();inbound.shutdownNow();closeListener();for(Socket socket:sockets)close(socket);sockets.clear();peers.clear();TorControl own=control;control=null;if(own!=null)try{own.close();}catch(IOException ignored){}signaling.close();}
  private void closeListener(){try{listener.close();}catch(IOException ignored){}}
}
