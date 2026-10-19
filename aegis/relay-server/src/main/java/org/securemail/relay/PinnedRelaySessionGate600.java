package org.securemail.relay;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.*;
import java.nio.charset.*;
import java.security.*;
import java.util.*;
import org.securemail.ecosystem.protocol.*;
import org.securemail.ecosystem.rpc600.PinnedIdentityLoopback600;
import org.securemail.protocol.*;

/** Separate service key can query managed-account status only after explicit operator allowlisting.
 * All traffic is literal loopback, signed, nonce-bound and has a total deadline. No account private key. */
public final class PinnedRelaySessionGate600 implements RelaySessionGate600 {
  private final PinnedIdentityLoopback600 http;private final byte[] identityPin;private final KeyPair service;private final String identityAudience,serviceAudience;
  public PinnedRelaySessionGate600(int identityPort,byte[] identityPin,KeyPair relayService){
    IdentityProtocol.publicKey(identityPin);IdentityProtocol.publicKey(relayService.getPublic().getEncoded());byte[] probe=IdentityProtocol.digest("AEGIS-RELAY-SERVICE-CHECK/v1".getBytes(StandardCharsets.US_ASCII));if(!IdentityProtocol.verify(relayService.getPublic().getEncoded(),probe,IdentityProtocol.sign(relayService.getPrivate(),probe)))throw new IllegalArgumentException("Ключ сервиса Relay не соответствует открытому");
    this.identityPin=identityPin.clone();service=relayService;identityAudience=IdentityProtocol.id(identityPin);serviceAudience=IdentityProtocol.id(relayService.getPublic().getEncoded());http=new PinnedIdentityLoopback600(identityPort,identityPin);
  }
  private final Map<String,Long> fresh=new LinkedHashMap<>();
  private synchronized boolean cached(String key){Long until=fresh.get(key);return until!=null&&System.nanoTime()-until<0;}
  private synchronized void remember(String key,long checkedAt){long now=System.nanoTime();fresh.entrySet().removeIf(e->now-e.getValue()>=0);if(now-checkedAt<250_000_000L&&(fresh.size()<128||fresh.containsKey(key)))fresh.put(key,checkedAt+250_000_000L);}
  private synchronized void forget(String key){fresh.remove(key);}
  public String serviceAudience(){return serviceAudience;}
  @Override public Binding authenticate(UserInfo user,String nickname,byte[] password,DataInputStream input)throws IOException {
    return authenticateProof(user,nickname,password,input,false);
  }
  @Override public Binding register(UserInfo user,String nickname,byte[] password,DataInputStream input)throws IOException {return authenticateProof(user,nickname,password,input,true);}
  private Binding authenticateProof(UserInfo user,String nickname,byte[] password,DataInputStream input,boolean registration)throws IOException {
    try{
      String wire=Binary.text(input,4096);long time=input.readLong();String nonce=Binary.text(input,43);byte[] proof=Binary.bytes(input,64);var cap=IdentityProtocol.decodeCapability(wire);
      if(cap.appId!=IdentityProtocol.App.MAIL||!cap.accountId.equals(user.userId())||!IdentityProtocol.verifyCapability(cap,identityPin,System.currentTimeMillis())||!cap.capabilities.contains(IdentityProtocol.Scope.MAIL_READ))throw denied();
      String action=registration?"mail.send":"mail.read";if(registration&&!cap.capabilities.contains(IdentityProtocol.Scope.MAIL_SEND))throw denied();
      byte[] actual=registration?MailSessionProtocol600.registration(serviceAudience,user.userId(),nickname,password,user.publicKey()):MailSessionProtocol600.login(serviceAudience,user.userId(),nickname,password);byte[] sha=IdentityProtocol.digest(actual);
      if(!IdentityProtocol.verify(cap.proofKey,IdentityProtocol.requestDigest(cap,action,sha,time,nonce),proof))throw denied();
      JsonObject args=obj("capability",wire,"action",action,"bodySha256",IdentityProtocol.b64(sha),"time",time,"nonce",nonce,"proof",IdentityProtocol.b64(proof));JsonObject context=rpc("authorizeDigest",args);
      if(!text(context,"accountId").equals(user.userId())||!text(context,"deviceId").equals(cap.deviceId)||!text(context,"appId").equals("MAIL")||number(context,"generation")!=cap.generation||number(context,"leaseUntil")!=cap.expiresAt||!MessageDigest.isEqual(IdentityProtocol.unb64(text(context,"accountPublicKey"),44),user.publicKey()))throw denied();
      Binding binding=new Binding(wire);checkFresh(user,binding);return binding;
    }catch(IllegalArgumentException|IllegalStateException invalid){throw denied();}
  }
  @Override public void check(UserInfo user,Binding binding)throws IOException {check(user,binding,false);}
  @Override public void checkFresh(UserInfo user,Binding binding)throws IOException {check(user,binding,true);}
  @Override public void authorizeOperation(UserInfo user,Binding binding,Operation operation)throws IOException {
    check(user,binding);if(binding!=null&&!binding.capability().isEmpty())try{var cap=IdentityProtocol.decodeCapability(binding.capability());var required=switch(operation){case STORE,PROFILE_PUT,CONTACT_PUT->IdentityProtocol.Scope.MAIL_SEND;case CONTACT_GET->IdentityProtocol.Scope.CONTACTS_READ;default->IdentityProtocol.Scope.MAIL_READ;};if(!cap.capabilities.contains(required))throw denied();}catch(IllegalArgumentException invalid){throw denied();}
  }
  private void check(UserInfo user,Binding binding,boolean force)throws IOException {
    if(binding==null||binding.capability().isEmpty()){String cache="legacy:"+user.userId();if(!force&&cached(cache))return;forget(cache);long checkedAt=System.nanoTime();if(managed(user.userId()))throw denied();remember(cache,checkedAt);return;}
    String cache="token:"+IdentityProtocol.id(binding.capability().getBytes(StandardCharsets.US_ASCII));
    try{var cap=IdentityProtocol.decodeCapability(binding.capability());if(!cap.accountId.equals(user.userId())||cap.appId!=IdentityProtocol.App.MAIL||!cap.capabilities.contains(IdentityProtocol.Scope.MAIL_READ)||!IdentityProtocol.verifyCapability(cap,identityPin,System.currentTimeMillis()))throw denied();if(!force&&cached(cache))return;forget(cache);long checkedAt=System.nanoTime();JsonObject result=rpc("isActive",obj("capability",binding.capability()));if(!result.keySet().equals(Set.of("active"))||!bool(result,"active"))throw denied();remember(cache,checkedAt);}catch(IllegalArgumentException invalid){forget(cache);throw denied();}
  }
  private boolean managed(String account)throws IOException {
    long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] pub=service.getPublic().getEncoded();byte[] proof=IdentityProtocol.sign(service.getPrivate(),IdentityProtocol.managedAccountQuery(identityAudience,serviceAudience,account,time,nonce));
    JsonObject result=rpc("managedAccount",obj("serviceKey",IdentityProtocol.b64(pub),"accountId",account,"time",time,"nonce",nonce,"proof",IdentityProtocol.b64(proof)));if(!result.keySet().equals(Set.of("managed")))throw denied();return bool(result,"managed");
  }
  private JsonObject rpc(String operation,JsonObject data)throws IOException {
    String nonce=IdentityProtocol.nonce();JsonObject request=obj("operation",operation,"nonce",nonce);request.add("data",data);var receipt=http.post(request.toString().getBytes(StandardCharsets.UTF_8),nonce);JsonObject response=parse(receipt.body());if(receipt.status!=200||!bool(response,"ok")||!response.has("data")||!response.get("data").isJsonObject())throw denied();return response.getAsJsonObject("data");
  }
  private static JsonObject parse(byte[] encoded)throws IOException {
    try{CharsetDecoder decoder=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);JsonReader reader=new JsonReader(new StringReader(decoder.decode(java.nio.ByteBuffer.wrap(encoded)).toString()));reader.setStrictness(Strictness.STRICT);try(reader){JsonElement result=value(reader,0,new int[]{0});if(!result.isJsonObject()||reader.peek()!=JsonToken.END_DOCUMENT)throw denied();return result.getAsJsonObject();}}catch(IllegalArgumentException|IllegalStateException invalid){throw denied();}
  }
  private static JsonElement value(JsonReader in,int depth,int[] nodes)throws IOException {
    if(depth>12||++nodes[0]>4096)throw denied();return switch(in.peek()){
      case BEGIN_OBJECT->{JsonObject result=new JsonObject();in.beginObject();while(in.hasNext()){String name=in.nextName();if(name.length()>100||result.has(name))throw denied();result.add(name,value(in,depth+1,nodes));}in.endObject();yield result;}
      case BEGIN_ARRAY->{JsonArray result=new JsonArray();in.beginArray();while(in.hasNext())result.add(value(in,depth+1,nodes));in.endArray();yield result;}
      case STRING->{String text=in.nextString();if(text.length()>8192)throw denied();yield new JsonPrimitive(text);}
      case NUMBER->{String text=in.nextString();if(!text.matches("0|[1-9][0-9]{0,18}"))throw denied();yield new JsonPrimitive(new java.math.BigDecimal(text));}
      case BOOLEAN->new JsonPrimitive(in.nextBoolean());case NULL->{in.nextNull();yield JsonNull.INSTANCE;}default->throw denied();};
  }
  private static JsonObject obj(Object... pairs){JsonObject result=new JsonObject();for(int n=0;n<pairs.length;n+=2){if(pairs[n+1] instanceof Number number)result.addProperty((String)pairs[n],number);else result.addProperty((String)pairs[n],pairs[n+1].toString());}return result;}
  private static String text(JsonObject object,String name)throws IOException{JsonElement value=object.get(name);if(value==null||!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isString())throw denied();return value.getAsString();}
  private static boolean bool(JsonObject object,String name)throws IOException{JsonElement value=object.get(name);if(value==null||!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isBoolean())throw denied();return value.getAsBoolean();}
  private static long number(JsonObject object,String name)throws IOException{try{JsonElement value=object.get(name);if(value==null||!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isNumber())throw denied();return value.getAsBigDecimal().longValueExact();}catch(ArithmeticException invalid){throw denied();}}
  @Override public synchronized void close(){fresh.clear();http.close();}
  private static IOException denied(){return new IOException("Недействительная сессия Почты");}
}
