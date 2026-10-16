package org.securemail.client.community;

import com.google.gson.*;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.storage.LocalStore;
import org.securemail.client.voice.*;
import org.securemail.protocol.UserInfo;

/** Opt-in server grants with a maximum 20-second lease. Audio/control callbacks only read memory. */
public final class VoiceGrantCache implements VoiceOrganizationAuthorizer,AutoCloseable {
  private record Key(String peer,VoiceCallService.Direction direction){}
  private record Grant(Decision decision,CommunityClient.Settings server,long epoch,long startedNanos){}
  private final CommunityClient client;private final LocalStore local;private final VoiceCallService calls;
  private final ConcurrentMap<Key,Grant> grants=new ConcurrentHashMap<>();
  private final ScheduledExecutorService worker=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-call-permissions");t.setDaemon(true);return t;});
  private volatile boolean closed;
  public VoiceGrantCache(CommunityClient client,LocalStore local,VoiceCallService calls){this.client=client;this.local=local;this.calls=calls;worker.scheduleWithFixedDelay(this::refresh,1,8,TimeUnit.SECONDS);}
  @Override public Decision authorize(String actor,String peer,VoiceCallService.Direction direction){Grant g=grants.get(new Key(peer,direction));if(closed||g==null||!g.server.equals(client.settings())||g.epoch!=client.authorizationEpoch()||!leaseAlive(g.startedNanos,System.nanoTime())||!g.decision.permits(actor,peer,direction,local.now()))return null;return g.decision;}
  /** Explicit preflight, called on a UI worker before an outgoing call, never from an audio callback. */
  public void prepare(UserInfo contact,VoiceCallService.Direction direction)throws IOException{
    VoiceCallPolicy.Rule rule=calls.callPolicy().rule(direction);if(rule.allowsLocally(contact.userId()))return;
    if(!rule.permitsOrganizationCheck(contact.userId())||!known(contact.userId()))throw new IOException("Звонок не разрешён настройками доступа");
    CommunityClient.Settings server=client.settings();long issued=local.now(),startedNanos=System.nanoTime();JsonObject args=new JsonObject();JsonArray targets=new JsonArray();targets.add(contact.userId());args.add("targets",targets);args.addProperty("direction",direction.name());
    try{JsonObject result=client.rpc("org.calls.authorize_batch",args);JsonArray decisions=result.getAsJsonArray("decisions");if(decisions==null||decisions.size()!=1||!decisions.get(0).getAsJsonObject().get("target").getAsString().equals(contact.userId()))throw new IOException("Некорректное разрешение звонка");put(contact.userId(),direction,allowed(decisions.get(0).getAsJsonObject()),issued,startedNanos,20_000,server,epoch(result));if(authorize(local.identity().userId(),contact.userId(),direction)==null)throw new IOException("Звонок не разрешён действующими полномочиями");}
    catch(IOException|RuntimeException denied){grants.remove(new Key(contact.userId(),direction));if(denied instanceof IOException e)throw e;throw new IOException("Не удалось проверить разрешение на звонок",denied);}
  }
  /** Network I/O is permitted only in the bounded incoming-handshake worker. */
  public void prepare(String actor,String peer,VoiceCallService.Direction direction)throws IOException {
    if(!local.identity().userId().equals(actor))throw new IOException("Недействующая идентичность звонка");
    UserInfo contact=local.contacts().stream().filter(c->c.userId().equals(peer)).findFirst().orElseThrow(()->new IOException("Непроверенный контакт"));prepare(contact,direction);
  }
  private boolean known(String peer){return local.contacts().stream().anyMatch(c->c.userId().equals(peer));}
  private void put(String peer,VoiceCallService.Direction direction,boolean allowed,long issued,long startedNanos,long ttl,CommunityClient.Settings server,long epoch){
    if(closed||!server.equals(client.settings())||epoch!=client.authorizationEpoch()||!leaseAlive(startedNanos,System.nanoTime())||local.now()>=issued+ttl)return;
    grants.put(new Key(peer,direction),new Grant(new Decision(local.identity().userId(),peer,direction,issued,issued+ttl,allowed),server,epoch,startedNanos));
  }
  private void refresh(){
    if(closed)return;if(!client.configured()){grants.clear();return;}
    try{client.publishDisplayName();Set<Key> keep=new HashSet<>();for(var direction:VoiceCallService.Direction.values()){
      var rule=calls.callPolicy().rule(direction);List<String> targets=local.contacts().stream().map(UserInfo::userId).filter(p->!rule.allowsLocally(p)&&rule.permitsOrganizationCheck(p)).limit(VoiceCallPolicy.MAX_CONTACTS).toList();
      if(targets.isEmpty())continue;JsonObject args=new JsonObject();JsonArray list=new JsonArray();targets.forEach(list::add);args.add("targets",list);args.addProperty("direction",direction.name());CommunityClient.Settings server=client.settings();long issued=local.now(),startedNanos=System.nanoTime();JsonObject response=client.rpc("org.calls.authorize_batch",args);
      JsonArray decisions=response.getAsJsonArray("decisions");if(decisions==null||decisions.size()>256)throw new IOException("Некорректные разрешения звонков");Set<String> seen=new HashSet<>();for(var element:decisions){JsonObject result=element.getAsJsonObject();String peer=result.get("target").getAsString();if(!targets.contains(peer)||!seen.add(peer))throw new IOException("Некорректные разрешения звонков");Key key=new Key(peer,direction);keep.add(key);put(peer,direction,allowed(result),issued,startedNanos,20_000,server,epoch(response));}
    }grants.keySet().retainAll(keep);}catch(Exception unavailable){grants.clear();}
  }
  static boolean leaseAlive(long startedNanos,long nowNanos){long elapsed=nowNanos-startedNanos;return elapsed>=0&&elapsed<TimeUnit.SECONDS.toNanos(20);}
  private static boolean allowed(JsonObject object)throws IOException{JsonElement v=object.get("allowed");if(v==null||!v.isJsonPrimitive()||!v.getAsJsonPrimitive().isBoolean())throw new IOException("Некорректное разрешение звонка");return v.getAsBoolean();}
  private static long epoch(JsonObject object)throws IOException{JsonElement v=object.get("epoch");if(v==null||!v.isJsonPrimitive()||!v.getAsJsonPrimitive().isNumber()||!v.getAsString().matches("[0-9]{1,18}"))throw new IOException("Некорректная версия разрешения звонка");return v.getAsLong();}
  public void invalidate(){grants.clear();}
  @Override public void close(){closed=true;grants.clear();worker.shutdownNow();}
}
