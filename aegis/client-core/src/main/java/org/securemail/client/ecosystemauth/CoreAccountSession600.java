package org.securemail.client.ecosystemauth;

import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.function.LongSupplier;
import org.securemail.client.ecosystem.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;

/** Device-authenticated Core session. Account root signatures are obtained by typed Mail consent only. */
public final class CoreAccountSession600 implements SessionAuthority,AutoCloseable {
  @FunctionalInterface public interface Rpc {JsonObject call(String operation,JsonObject data)throws IOException;}
  public static final class AppGrant implements AutoCloseable {
    private final Capability capability;private final String wire;private final KeyPair proof;
    private boolean closed;
    private AppGrant(Capability capability,String wire,KeyPair proof){this.capability=capability;this.wire=wire;this.proof=proof;}
    public Capability capability(){return capability;}
    public String wire(){return wire;}
    /** A narrow application proof key, NEVER the account or device private key. */
    public synchronized PrivateKey proofPrivate(){if(closed)throw new IllegalStateException("Приложение заблокировано");return proof.getPrivate();}
    public byte[] proofPublic(){return proof.getPublic().getEncoded();}
    synchronized byte[] proofEncoded(){if(closed)throw new IllegalStateException("Приложение заблокировано");return proof.getPrivate().getEncoded();}
    @Override public synchronized void close(){closed=true;try{proof.getPrivate().destroy();}catch(Exception ignored){/* JVM providers do not guarantee destruction. */}}
    @Override public String toString(){return "AppGrant["+capability.appId+", credentials redacted]";}
  }
  private final Rpc rpc;private final byte[] serverKey;private final String audience;
  private final Clock clock;private final LongSupplier nanoTime;
  private final EnumMap<App,KeyPair> appKeys=new EnumMap<>(App.class);
  private final List<AppGrant> grants=new ArrayList<>();
  private DeviceCredentials600 credentials;
  private final String accountId,deviceId;private volatile long generation,expiresAt,anchorWall,anchorNano;
  // Local lock must never wait for a remote request holding the session monitor.
  private volatile boolean closed,locked;private volatile AppGrant core,offlinePresence;
  public CoreAccountSession600(IdentityClient600 client,byte[] serverKey,DeviceCredentials600 credentials){this(client::rpc,serverKey,credentials,Clock.systemUTC(),System::nanoTime);}
  CoreAccountSession600(Rpc rpc,byte[] serverKey,DeviceCredentials600 credentials,Clock clock,LongSupplier nanoTime){
    IdentityProtocol.publicKey(serverKey);this.serverKey=serverKey.clone();this.audience=IdentityProtocol.id(serverKey);this.rpc=Objects.requireNonNull(rpc);this.credentials=Objects.requireNonNull(credentials);this.clock=Objects.requireNonNull(clock);this.nanoTime=Objects.requireNonNull(nanoTime);accountId=credentials.accountId();deviceId=credentials.deviceId();
  }
  /** All inputs signed by Mail are fixed-domain registration values; no root private key enters this process. */
  public synchronized void register(String nickname,long time,String nonce,byte[] accountProof)throws IOException {
    ensureNotStarted();byte[] body=IdentityProtocol.registration(audience,credentials.accountPublic(),credentials.devicePublic(),credentials.recoveryPublic(),nickname,time,nonce);
    if(!IdentityProtocol.verify(credentials.accountPublic(),body,accountProof))throw new IOException("Почта не подтвердила привязку аккаунта");
    JsonObject args=obj("accountKey",b64(credentials.accountPublic()),"deviceKey",b64(credentials.devicePublic()),"recoveryKey",b64(credentials.recoveryPublic()),"nickname",nickname,"time",time,"nonce",nonce,"accountProof",b64(accountProof),"deviceProof",b64(credentials.sign(body)));
    acceptSession(rpc.call("register",args));
  }
  /** A new trusted-device login atomically invalidates older generations on the Identity server. */
  public synchronized void login()throws IOException {
    ensureNotStarted();long now=clock.millis();String nonce=IdentityProtocol.nonce();
    acceptSession(rpc.call("login",obj("accountId",accountId,"deviceId",deviceId,"time",now,"nonce",nonce,"proof",b64(credentials.sign(IdentityProtocol.login(audience,accountId,deviceId,now,nonce))))));
  }
  private void acceptSession(JsonObject response)throws IOException {
    if(closed||locked)throw new IOException("Подтвердите вход в АЕГИС");
    if(!accountId.equals(text(response,"accountId"))||!deviceId.equals(text(response,"deviceId")))throw new IOException("Сервер вернул другую учётную запись");
    long gen=number(response,"generation"),issued=number(response,"issuedAt"),until=number(response,"expiresAt"),now=clock.millis();
    if(gen<1||issued>now+60_000||issued<now-60_000||until<=now||until-issued>IdentityProtocol.MAX_LEASE_MILLIS)throw new IOException("Недопустимый срок сессии");
    generation=gen;expiresAt=until;anchorWall=now;anchorNano=nanoTime.getAsLong();
    core=issue(App.AEGIS,EnumSet.of(Scope.ACCOUNT_READ,Scope.SESSION_MANAGE,Scope.DEVICE_MANAGE));
    // Management scopes deliberately have no offline validity. Presence uses a distinct,
    // previously server-signed read-only capability; it never authorizes a new action.
    offlinePresence=issue(App.AEGIS,Set.of(Scope.ACCOUNT_READ));
    ensureUnlocked();
  }
  public String accountId(){return accountId;}
  public String deviceId(){return deviceId;}
  public byte[] accountPublic(){return credentials.accountPublic();}
  public byte[] devicePublic(){return credentials.devicePublic();}
  public long generation(){return generation;}
  public AppGrant coreGrant()throws IOException {ensureLive();AppGrant value=core;if(value==null)throw new IOException("Вход ещё не завершён");return value;}
  public synchronized AppGrant grant(App app,Set<Scope> scopes)throws IOException {
    ensureUnlocked();for(AppGrant grant:grants)if(grant.capability.appId==app&&grant.capability.capabilities.equals(scopes)&&grant.capability.expiresAt>now()+30_000)return grant;
    return issue(app,scopes);
  }
  private AppGrant issue(App app,Set<Scope> scopes)throws IOException {
    ensureLive();long time=now(),ttl=Math.min(IdentityProtocol.MAX_LEASE_MILLIS,expiresAt-time);String nonce=IdentityProtocol.nonce();
    if(ttl<1)throw new IOException("Сессия истекла");
    KeyPair key;try{key=appKeys.computeIfAbsent(app,a->{try{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}catch(GeneralSecurityException e){throw new IllegalStateException(e);}});}catch(IllegalStateException invalid){throw new IOException("Не удалось создать ключ приложения",invalid);}
    byte[] body=IdentityProtocol.capabilityRequest(audience,accountId,deviceId,generation,app,key.getPublic().getEncoded(),scopes,ttl,time,nonce);
    JsonObject args=obj("accountId",accountId,"deviceId",deviceId,"generation",generation,"appId",app.name(),"proofKey",b64(key.getPublic().getEncoded()),"ttl",ttl,"time",time,"nonce",nonce,"deviceProof",b64(credentials.sign(body)),"appProof",b64(IdentityProtocol.sign(key.getPrivate(),body)));
    JsonArray list=new JsonArray();scopes.stream().map(Enum::name).sorted().forEach(list::add);args.add("capabilities",list);
    String wire=text(rpc.call("issueCapability",args),"capability");Capability cap;
    try{cap=IdentityProtocol.decodeCapability(wire);}catch(IllegalArgumentException invalid){throw new IOException("Некорректное разрешение приложения",invalid);}
    if(!IdentityProtocol.verifyCapability(cap,serverKey,now())||!accountId.equals(cap.accountId)||!deviceId.equals(cap.deviceId)||cap.generation!=generation||cap.appId!=app||!cap.capabilities.equals(scopes)||!MessageDigest.isEqual(key.getPublic().getEncoded(),cap.proofKey)||cap.expiresAt>expiresAt)throw new IOException("Разрешение выдано другому приложению");
    ensureUnlocked();AppGrant grant=new AppGrant(cap,wire,key);grants.add(grant);return grant;
  }
  @Override public synchronized ComponentLease authorize(ComponentId component)throws IOException {
    ensureUnlocked();App app;Set<Scope> scopes;
    switch(component){case MAIL->{app=App.MAIL;scopes=EnumSet.of(Scope.MAIL_READ,Scope.MAIL_SEND,Scope.CONTACTS_READ);}case GLAS->{app=App.GLAS;scopes=EnumSet.of(Scope.VOICE_CALL,Scope.CONTACTS_READ);}default->throw new IOException("Фоновая служба не имеет разрешённого обработчика");}
    AppGrant grant=grant(app,scopes);byte[] secret=grant.proofEncoded();
    try{ensureUnlocked();return new ComponentLease(component,accountId,generation,grant.wire().getBytes(StandardCharsets.US_ASCII),secret,grant.proofPublic());}
    finally{Arrays.fill(secret,(byte)0);}
  }
  @Override public synchronized void validate(ComponentLease lease)throws IOException {
    ensureLive();Capability cap;try{cap=IdentityProtocol.decodeCapability(new String(lease.capability(),StandardCharsets.US_ASCII));}catch(IllegalArgumentException invalid){throw new IOException("Некорректный допуск приложения",invalid);}
    App expected=switch(lease.component()){case MAIL->App.MAIL;case GLAS->App.GLAS;default->throw new IOException("Неизвестное приложение");};
    if(!IdentityProtocol.verifyCapability(cap,serverKey,now())||!accountId.equals(lease.accountId())||lease.generation()!=generation||!accountId.equals(cap.accountId)||!deviceId.equals(cap.deviceId)||generation!=cap.generation||cap.appId!=expected||!MessageDigest.isEqual(cap.proofKey,lease.proofPublicX509()))throw new IOException("Допуск приложения не соответствует текущей сессии");
    JsonObject result=rpc.call("isActive",obj("capability",IdentityProtocol.encodeCapability(cap)));JsonElement active=result.get("active");
    if(active==null||!active.isJsonPrimitive()||!active.getAsJsonPrimitive().isBoolean()||!active.getAsBoolean())throw new IOException("Сессия отозвана или истекла");
    ensureLive();
  }
  public synchronized JsonObject profile()throws IOException {ensureUnlocked();JsonObject result=accountRequest("profile",core,"account.read");ensureUnlocked();return result;}
  /** Step-up result may only come from Mail's independently checked, user-approved STEP-UP challenge. */
  public synchronized void completeStepUp(String challenge,long expires,byte[] accountProof)throws IOException {
    ensureUnlocked();if(expires<=now()||expires>now()+120_000)throw new IOException("Подтверждение личности истекло");
    byte[] payload=IdentityProtocol.stepUp(audience,accountId,deviceId,challenge,expires);
    if(!IdentityProtocol.verify(credentials.accountPublic(),payload,accountProof))throw new IOException("Почта не подтвердила личность");
    rpc.call("stepUp",obj("accountId",accountId,"deviceId",deviceId,"generation",generation,"challenge",challenge,"accountProof",b64(accountProof),"deviceProof",b64(credentials.sign(payload))));
    ensureUnlocked();
  }
  /** User must compare the full device fingerprint and explicitly approve. Server also requires fresh step-up. */
  public synchronized void approveDevice(DeviceApproval600 request)throws IOException {
    ensureUnlocked();request.verifyTarget(audience,accountId,now());byte[] body=IdentityProtocol.deviceApproval(audience,accountId,deviceId,request.challenge(),request.devicePublic(),request.expiresAt());
    JsonObject result=rpc.call("approveDevice",obj("accountId",accountId,"deviceId",deviceId,"generation",generation,"challenge",request.challenge(),"proof",b64(credentials.sign(body))));ensureUnlocked();JsonElement approved=result.get("approved");if(approved==null||!approved.isJsonPrimitive()||!approved.getAsJsonPrimitive().isBoolean()||!approved.getAsBoolean())throw new IOException("Устройство не подтверждено");
  }
  /** Fixed owner-transfer consent only. Neither a generic signing oracle nor a root-key operation. */
  public synchronized byte[] signOwnerTransferConsent(OwnerTransfer transfer,OwnerTransferRole role)throws IOException {
    ensureUnlocked();Objects.requireNonNull(transfer);Objects.requireNonNull(role);boolean owner=role==OwnerTransferRole.OWNER_APPROVE;
    if(!audience.equals(transfer.audience)||!accountId.equals(owner?transfer.ownerAccountId:transfer.targetAccountId)||!deviceId.equals(owner?transfer.ownerDeviceId:transfer.targetDeviceId)||generation!=(owner?transfer.ownerGeneration:transfer.targetGeneration)||transfer.expiresAt<=now()||transfer.expiresAt>now()+120_000)throw new IOException("Подтверждение относится к другой сессии");
    byte[] proof=credentials.sign(IdentityProtocol.ownerTransferConsent(transfer,role));ensureUnlocked();return proof;
  }
  /** One-time first administrator delegation is a separate fixed purpose, bound to both active devices. */
  public synchronized byte[] signFirstDelegationConsent(FirstDelegation delegation,FirstDelegateRole role)throws IOException {
    ensureUnlocked();Objects.requireNonNull(delegation);Objects.requireNonNull(role);boolean owner=role==FirstDelegateRole.OWNER_APPROVE;
    if(!audience.equals(delegation.audience)||!accountId.equals(owner?delegation.ownerAccountId:delegation.targetAccountId)||!deviceId.equals(owner?delegation.ownerDeviceId:delegation.targetDeviceId)||generation!=(owner?delegation.ownerGeneration:delegation.targetGeneration)||delegation.expiresAt<=now()||delegation.expiresAt>now()+120_000)throw new IOException("Делегирование относится к другой сессии");
    byte[] proof=credentials.sign(IdentityProtocol.firstDelegationBytes(delegation));ensureUnlocked();return proof;
  }
  private JsonObject accountRequest(String operation,AppGrant grant,String action)throws IOException {
    long time=now();String nonce=IdentityProtocol.nonce();byte[] proof=IdentityProtocol.sign(grant.proofPrivate(),IdentityProtocol.request(grant.capability,action,new byte[0],time,nonce));
    return rpc.call(operation,obj("capability",grant.wire(),"time",time,"nonce",nonce,"proof",b64(proof)));
  }
  /** Lock does not log out: existing narrowly authorized Glas may show its restricted call screen. */
  public void lock(){if(closed||locked)return;locked=true;credentials.close();}
  public boolean locked(){return locked;}
  /** Uncertainty never grants new rights: only the previously signed in-memory lease survives briefly offline.
   * There is no cold-start lease restoration. Material-specific READ/export leases are stricter. */
  public boolean canContinueOffline(){try{ensureUnlocked();AppGrant value=offlinePresence;long time=now();return value!=null&&value.capability.appId==App.AEGIS&&value.capability.capabilities.equals(Set.of(Scope.ACCOUNT_READ))&&accountId.equals(value.capability.accountId)&&deviceId.equals(value.capability.deviceId)&&generation==value.capability.generation&&IdentityProtocol.verifyCapability(value.capability,serverKey,time)&&time<Math.min(Math.addExact(anchorWall,IdentityProtocol.MAX_LEASE_MILLIS),Math.min(value.capability.expiresAt,value.capability.offlineUntil));}catch(IOException|ArithmeticException expired){return false;}}
  public synchronized void logout()throws IOException {
    if(closed)return;try{if(core!=null&&generation>0)accountRequest("revoke",core,"session.manage");}finally{destroy();}
  }
  private long now()throws IOException {
    long wall=clock.millis(),elapsed=nanoTime.getAsLong()-anchorNano;
    if(elapsed<0||wall<anchorWall-1000)throw new IOException("Системное время изменилось: подтвердите вход");
    long monotonic;try{monotonic=Math.addExact(anchorWall,elapsed/1_000_000);}catch(ArithmeticException overflow){throw new IOException("Недопустимое время сессии");}return Math.max(wall,monotonic);
  }
  private void ensureNotStarted()throws IOException {if(closed||locked||generation!=0)throw new IOException("Сессия уже открыта или заблокирована");}
  private void ensureLive()throws IOException {if(closed||generation<1||now()>=expiresAt)throw new IOException("Сессия закрыта или истекла");}
  private void ensureUnlocked()throws IOException {ensureLive();if(locked)throw new IOException("Подтвердите вход в АЕГИС");}
  private void destroy(){closed=true;locked=true;credentials.close();grants.forEach(AppGrant::close);appKeys.clear();}
  @Override public synchronized void close(){try{logout();}catch(IOException ignored){destroy();}}
  private static String b64(byte[] value){return IdentityProtocol.b64(value);}
  private static JsonObject obj(Object... pairs){JsonObject out=new JsonObject();for(int i=0;i<pairs.length;i+=2){Object value=pairs[i+1];if(value instanceof Number n)out.addProperty((String)pairs[i],n);else out.addProperty((String)pairs[i],value.toString());}return out;}
  private static String text(JsonObject value,String field)throws IOException {JsonElement item=value.get(field);if(item==null||!item.isJsonPrimitive()||!item.getAsJsonPrimitive().isString())throw new IOException("Некорректный ответ Identity");return item.getAsString();}
  private static long number(JsonObject value,String field)throws IOException {JsonElement item=value.get(field);if(item==null||!item.isJsonPrimitive()||!item.getAsJsonPrimitive().isNumber()||!item.getAsString().matches("[0-9]{1,19}"))throw new IOException("Некорректный ответ Identity");try{return Long.parseLong(item.getAsString());}catch(NumberFormatException bad){throw new IOException("Некорректное время Identity",bad);}}
}
