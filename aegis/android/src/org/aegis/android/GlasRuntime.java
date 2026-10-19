package org.aegis.android;
import com.google.gson.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.community.CommunityJson;
import org.securemail.client.net.TorTransport;
import org.securemail.client.voice.*;
import org.securemail.client.voice600.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
/** Real call controller, signaling, pinned delegated TLS and bounded Opus pipeline, owned by one visible activity. */
final class GlasRuntime implements AutoCloseable {
  private static final ThreadPoolExecutor CLEANUP=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(4),r->{Thread t=new Thread(r,"glas-owned-cleanup");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final CoreBrokerClient broker;private final PrivateVault vault;private final IdentityProtocol.Capability cap;private final java.util.function.BooleanSupplier foreground;
  private AndroidGlasState state;private AndroidGlasSignalingClient600 signaling;private AndroidGlasOnionTransport600 route;private AndroidVoiceCallService calls;private volatile boolean closed;
  GlasRuntime(CoreBrokerClient broker,PrivateVault vault,GlasGrant600 grant,AndroidGlasSignalingClient600.Config config,java.util.function.BooleanSupplier foreground)throws Exception {
    this.foreground=java.util.Objects.requireNonNull(foreground);this.broker=broker;this.vault=vault;cap=broker.capability();JsonObject publicConfig=broker.publicConfig();byte[] server=IdentityProtocol.unb64(publicConfig.get("serverKey").getAsString(),44);String storage="voice-state-"+cap.accountId.substring(0,32);
    try{
      state=new AndroidGlasState(grant,cap,server,new AndroidGlasState.Storage(){public byte[] read()throws IOException{try{return vault.get(storage);}catch(Exception e){throw new IOException("История Гласа недоступна",e);}}public void write(byte[] b)throws IOException{try{vault.put(storage,b);}catch(Exception e){throw new IOException("История Гласа недоступна",e);}}},(id,role,peer)->{try{return vault.voiceTls(grant.delegation(),id,role,peer,cap.audience);}catch(java.security.GeneralSecurityException|IOException e){throw e;}catch(Exception e){throw new IOException("Ключ Гласа недоступен",e);}},this::authorized);
      TorTransport tor=new TorTransport("127.0.0.1",publicConfig.get("socksPort").getAsInt());AndroidGlasSignalingClient600.Signer signer=b->{if(!authorized())throw new IOException("Глас заблокирован");try{return vault.prove(b);}catch(Exception e){throw new IOException("Ключ приложения недоступен",e);}};
      signaling=new AndroidGlasSignalingClient600(config,server,IdentityProtocol.encodeCapability(cap),signer,tor,this::authorized);
      route=new AndroidGlasOnionTransport600(state,grant,signer,signaling,tor);calls=new AndroidVoiceCallService(state,route::connect);applyPolicy();
    }catch(Exception failure){close();throw failure;}
  }
  private boolean authorized(){try{return !closed&&foreground.getAsBoolean()&&broker.active()&&broker.capability().tokenId.equals(cap.tokenId)&&broker.capability().generation==cap.generation;}catch(RuntimeException e){return false;}}
  void connect()throws Exception {if(!authorized())throw new IOException("Допуск Гласа отозван");route.start(calls,new AndroidGlasOnionTransport600.Publisher(){public String publish(int port)throws IOException{try{if(!authorized())throw new IOException("Сессия заблокирована");return broker.publishVoice(port);}catch(Exception e){throw new IOException("Не удалось подготовить собственный onion: "+e.getMessage(),e);}}public void close()throws IOException{try{broker.dropVoice();}catch(Exception e){throw new IOException("Не удалось удалить собственный onion",e);}}});if(!authorized()){close();throw new IOException("Сессия завершена во время подключения");}}
  AndroidVoiceCallService calls(){if(!authorized())throw new SecurityException("Глас заблокирован");return calls;}
  List<org.securemail.protocol.UserInfo> contacts(){return state.contacts();}
  void applyPolicy()throws Exception {if(!authorized())throw new IOException("Глас заблокирован");byte[] b=vault.get("voice-policy");try{
    int incoming=0,outgoing=0;Set<String> selected=new HashSet<>();if(b!=null){String[] parts=new String(b,java.nio.charset.StandardCharsets.UTF_8).split("\n",3);if(parts.length<2)throw new IOException("Правила звонков повреждены");incoming=Integer.parseInt(parts[0]);outgoing=Integer.parseInt(parts[1]);if(parts.length==3)for(String id:parts[2].split("\\s+"))if(!id.isEmpty()){IdentityProtocol.idValue(id);if(!selected.add(id))continue;if(selected.size()>128)throw new IOException("Лимит контактов");}}
    calls.setCallPolicy(new AndroidVoiceCallPolicy(rule(incoming,selected),rule(outgoing,selected)));calls.setIncomingEnabled(incoming!=0);
  }finally{if(b!=null)Arrays.fill(b,(byte)0);}}
  private static AndroidVoiceCallPolicy.Rule rule(int value,Set<String> selected)throws IOException {AndroidVoiceCallPolicy.Mode mode=switch(value){case 0->AndroidVoiceCallPolicy.Mode.NONE;case 1->AndroidVoiceCallPolicy.Mode.ALL_CONTACTS;case 2->AndroidVoiceCallPolicy.Mode.SELECTED_CONTACTS;default->throw new IOException("Правила звонков повреждены");};return new AndroidVoiceCallPolicy.Rule(mode,selected,Set.of(),false);}
  public void close(){if(closed)return;closed=true;if(calls!=null)calls.close();if(state!=null)state.close();if(signaling!=null)signaling.close();AndroidGlasOnionTransport600.Publisher owned=route==null?null:route.closeLocal();if(owned!=null)try{CLEANUP.execute(()->{try{owned.close();}catch(IOException ignored){}});}catch(RejectedExecutionException busy){/* Local listener/timers/sockets already closed. Core lock/death/expiry independently removes any stale onion. */}}
}
