package org.securemail.community.access;

import org.securemail.community.core.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.*;
import java.util.*;

/** Server-only authority. No nickname, client flag or clearance alone grants permissions. */
public final class AccessControl implements AutoCloseable {
 private final CommunityStore store;private final byte[]factorKek;
 public static final Set<String> GLOBAL_ONLY=Set.of("ORG_APPROVE","NEWS_GLOBAL_PUBLISH","GLOBAL_ROLES_MANAGE","GLOBAL_ADMIN_MANAGE","VERIFICATION_MANAGE","AGENT_MANAGE","AGENT_WORK","SOURCE_MANAGE","WORKER_MANAGE","ADMIN_AUDIT","ADMIN_CONTENT","GLOBAL_CONFIG","LEVELS_MANAGE");
 public AccessControl(CommunityStore store){this.store=store;this.factorKek=null;}
 public AccessControl(CommunityStore store,byte[]factorKek)throws Exception{this.store=store;if(factorKek.length!=32)throw new IllegalArgumentException("TOTP KEK length");this.factorKek=factorKek.clone();var mac=javax.crypto.Mac.getInstance("HmacSHA256");mac.init(new javax.crypto.spec.SecretKeySpec(factorKek,"HmacSHA256"));byte[]auditSubkey=mac.doFinal("AEGIS-COMMUNITY-AUDIT-SUBKEY-v1".getBytes(StandardCharsets.US_ASCII));try{store.setAuditKey(auditSubkey);}finally{Arrays.fill(auditSubkey,(byte)0);}}
 public void bootstrap(byte[]first,String firstFingerprint,byte[]firstSeed,byte[]second,String secondFingerprint,byte[]secondSeed)throws Exception{
  if(factorKek==null||firstSeed.length!=32||secondSeed.length!=32||MessageDigest.isEqual(firstSeed,secondSeed))throw CommunityException.invalid();
  store.tx(c->{bootstrap(first,firstFingerprint,second,secondFingerprint);setFactor(c,firstFingerprint,firstSeed);setFactor(c,secondFingerprint,secondSeed);return null;});
 }
 private void setFactor(Connection c,String identity,byte[]seed)throws Exception{
  if(factorKek==null||seed.length!=32)throw CommunityException.denied();byte[]nonce=new byte[12];new SecureRandom().nextBytes(nonce);var cipher=javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,new javax.crypto.spec.SecretKeySpec(factorKek,"AES"),new javax.crypto.spec.GCMParameterSpec(128,nonce));cipher.updateAAD(("AEGIS-COMMUNITY-TOTP-v1:"+identity).getBytes(StandardCharsets.US_ASCII));byte[]encrypted=cipher.doFinal(seed);
  try(var q=c.prepareStatement("INSERT INTO second_factors(identity,nonce,ciphertext,last_counter) VALUES(?,?,?,-1) ON CONFLICT(identity) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,last_counter=-1,version=second_factors.version+1")){q.setString(1,identity);q.setBytes(2,nonce);q.setBytes(3,encrypted);q.executeUpdate();}finally{Arrays.fill(encrypted,(byte)0);}
 }

 public Map<String,Object> factorStatus(String actor)throws Exception{return store.tx(c->{authorizationEpoch(actor);boolean configured=exists(c,"SELECT 1 FROM second_factors WHERE identity=?",actor);return Map.of("configured",configured,"canEnroll",factorKek!=null&&!configured&&!isGlobalAdmin(actor));});}
 public Map<String,Object> beginFactorEnrollment(String actor)throws Exception{return store.tx(c->{
  authorizationEpoch(actor);checkStepUpRate(c,actor);if(factorKek==null||isGlobalAdmin(actor)||exists(c,"SELECT 1 FROM second_factors WHERE identity=?",actor))throw CommunityException.denied();String service=store.serviceIdentity();long expires=store.clock().millis()+300000;
  try(var q=c.prepareStatement("DELETE FROM factor_enrollment WHERE expires<?")){q.setLong(1,store.clock().millis());q.executeUpdate();}try(var q=c.createStatement();var r=q.executeQuery("SELECT count(*) FROM factor_enrollment")){r.next();if(r.getInt(1)>=10000&&!exists(c,"SELECT 1 FROM factor_enrollment WHERE identity=?",actor))throw new CommunityException("LIMIT","Повторите настройку позже");}
  byte[]seed=new byte[32],nonce=new byte[12],idBytes=new byte[32];SecureRandom rng=new SecureRandom();rng.nextBytes(seed);rng.nextBytes(nonce);rng.nextBytes(idBytes);String id=Base64.getUrlEncoder().withoutPadding().encodeToString(idBytes);
  try{var cipher=javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,new javax.crypto.spec.SecretKeySpec(factorKek,"AES"),new javax.crypto.spec.GCMParameterSpec(128,nonce));cipher.updateAAD(("AEGIS-COMMUNITY-FACTOR-ENROLL-v1:"+service+":"+actor+":"+id).getBytes(StandardCharsets.US_ASCII));byte[]encrypted=cipher.doFinal(seed);
   try(var q=c.prepareStatement("INSERT INTO factor_enrollment VALUES(?,?,?,?,?) ON CONFLICT(identity) DO UPDATE SET enrollment_id=excluded.enrollment_id,nonce=excluded.nonce,ciphertext=excluded.ciphertext,expires=excluded.expires")){q.setString(1,actor);q.setString(2,id);q.setBytes(3,nonce);q.setBytes(4,encrypted);q.setLong(5,expires);q.executeUpdate();}finally{Arrays.fill(encrypted,(byte)0);}
   String encoded=base32(seed),uri="otpauth://totp/AEGIS:"+actor.substring(0,16)+"?secret="+encoded+"&issuer=AEGIS&algorithm=SHA256&digits=8&period=30";store.audit(c,actor,"SECOND_FACTOR_ENROLL_STARTED",actor,"Pending first factor expires in five minutes");return Map.of("enrollmentId",id,"seedBase32",encoded,"otpauthUri",uri,"expires",expires,"algorithm","SHA256","digits",8,"period",30);
  }finally{Arrays.fill(seed,(byte)0);Arrays.fill(idBytes,(byte)0);}
 });}
 public void finishFactorEnrollment(String actor,String enrollmentId,String code)throws Exception{store.tx(c->{
  checkStepUpRate(c,actor);if(factorKek==null||isGlobalAdmin(actor)||exists(c,"SELECT 1 FROM second_factors WHERE identity=?",actor)||enrollmentId==null||!enrollmentId.matches("[A-Za-z0-9_-]{43}"))throw CommunityException.denied();byte[]nonce,encrypted;
  try(var q=c.prepareStatement("SELECT nonce,ciphertext FROM factor_enrollment WHERE identity=? AND enrollment_id=? AND expires>?")){q.setString(1,actor);q.setString(2,enrollmentId);q.setLong(3,store.clock().millis());try(var r=q.executeQuery()){if(!r.next())throw CommunityException.denied();nonce=r.getBytes(1);encrypted=r.getBytes(2);}}
  var cipher=javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");cipher.init(javax.crypto.Cipher.DECRYPT_MODE,new javax.crypto.spec.SecretKeySpec(factorKek,"AES"),new javax.crypto.spec.GCMParameterSpec(128,nonce));cipher.updateAAD(("AEGIS-COMMUNITY-FACTOR-ENROLL-v1:"+store.serviceIdentity()+":"+actor+":"+enrollmentId).getBytes(StandardCharsets.US_ASCII));byte[]seed=cipher.doFinal(encrypted);
  try{long counter=Totp.match(seed,code,store.clock().millis(),-1);if(counter<0)throw new CommunityException("REAUTH_REQUIRED","Код подтверждения неверен или истёк");setFactor(c,actor,seed);try(var q=c.prepareStatement("UPDATE second_factors SET last_counter=? WHERE identity=?")){q.setLong(1,counter);q.setString(2,actor);q.executeUpdate();}try(var q=c.prepareStatement("DELETE FROM factor_enrollment WHERE identity=?")){q.setString(1,actor);q.executeUpdate();}store.bumpEpoch(c,actor);store.revokeStepUp(c,actor);store.audit(c,actor,"SECOND_FACTOR_ENROLLED",actor,"First factor confirmed by actual one-time code");store.notifyAccount(actor,"SECURITY","Второй фактор успешно подключён");return null;}finally{Arrays.fill(seed,(byte)0);Arrays.fill(encrypted,(byte)0);}
 });}
 private static String base32(byte[]bytes){String alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";StringBuilder b=new StringBuilder();int buffer=0,bits=0;for(byte value:bytes){buffer=(buffer<<8)|(value&255);bits+=8;while(bits>=5){bits-=5;b.append(alphabet.charAt((buffer>>>bits)&31));}}if(bits>0)b.append(alphabet.charAt((buffer<<(5-bits))&31));return b.toString();}
 public void checkStepUpRate(Connection c,String actor)throws Exception{try(var q=c.prepareStatement("SELECT blocked_until FROM stepup_attempts WHERE identity=?")){q.setString(1,actor);try(var r=q.executeQuery()){if(r.next()&&r.getLong(1)>store.clock().millis())throw new CommunityException("RATE_LIMIT","Повторная проверка временно ограничена");}}}
 public void recordStepUpFailure(String actor)throws Exception{store.tx(c->{long now=store.clock().millis(),window=now;int fails=0;try(var q=c.prepareStatement("SELECT window,failures FROM stepup_attempts WHERE identity=?")){q.setString(1,actor);try(var r=q.executeQuery()){if(r.next()&&now-r.getLong(1)<300000){window=r.getLong(1);fails=r.getInt(2);}}}fails++;try(var q=c.prepareStatement("INSERT INTO stepup_attempts VALUES(?,?,?,?) ON CONFLICT(identity) DO UPDATE SET window=excluded.window,failures=excluded.failures,blocked_until=excluded.blocked_until")){q.setString(1,actor);q.setLong(2,window);q.setInt(3,fails);q.setLong(4,fails>=5?now+300000:0);q.executeUpdate();}return null;});}
 public void verifySecondFactor(Connection c,String actor,String code)throws Exception{
  if(factorKek==null)throw new CommunityException("FACTOR_UNCONFIGURED","Серверный второй фактор не настроен");
  byte[]nonce,encrypted;long last;
  try(var q=c.prepareStatement("SELECT nonce,ciphertext,last_counter FROM second_factors WHERE identity=?")){q.setString(1,actor);try(var r=q.executeQuery()){if(!r.next())throw new CommunityException("FACTOR_UNCONFIGURED","Подключите второй фактор в настройках безопасности");nonce=r.getBytes(1);encrypted=r.getBytes(2);last=r.getLong(3);}}
  var cipher=javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");cipher.init(javax.crypto.Cipher.DECRYPT_MODE,new javax.crypto.spec.SecretKeySpec(factorKek,"AES"),new javax.crypto.spec.GCMParameterSpec(128,nonce));cipher.updateAAD(("AEGIS-COMMUNITY-TOTP-v1:"+actor).getBytes(StandardCharsets.US_ASCII));byte[]seed=cipher.doFinal(encrypted);
  try{long counter=Totp.match(seed,code,store.clock().millis(),last);if(counter<0)throw new CommunityException("REAUTH_REQUIRED","Код подтверждения неверен, истёк или уже использован");try(var q=c.prepareStatement("UPDATE second_factors SET last_counter=? WHERE identity=? AND last_counter=?")){q.setLong(1,counter);q.setString(2,actor);q.setLong(3,last);if(q.executeUpdate()!=1)throw CommunityException.denied();}}finally{Arrays.fill(seed,(byte)0);Arrays.fill(encrypted,(byte)0);}
 }
 public void rotateFactor(String actor,String requestId,String user,byte[]seed)throws Exception{
  Values.identity(user);if(seed.length!=32)throw CommunityException.invalid();String seedHash=CommunityStore.hex(CommunityStore.hash(seed));String payload=CanonicalJson.encode(Map.of("user",user,"seedHash",seedHash));
  executeCritical(actor,requestId,"FACTOR_RESET",payload,c->{setFactor(c,user,seed);store.bumpEpoch(c,user);store.revokeStepUp(c,user);try(var q=c.prepareStatement("DELETE FROM factor_enrollment WHERE identity=?")){q.setString(1,user);q.executeUpdate();}store.audit(c,actor,"SECOND_FACTOR_ROTATED",user,"Independent administrator approval");return null;});
 }
 public boolean isServiceIdentity(String actor)throws Exception{return store.tx(c->permissions(actor,"GLOBAL").contains("AGENT_WORK")||(exists(c,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_worker'")&&exists(c,"SELECT 1 FROM agent_worker WHERE identity=?",actor)));}
 public boolean roleHasAdministratorAssignees(Connection c,String role)throws Exception{return exists(c,"WITH RECURSIVE descendants(id) AS (SELECT ? UNION SELECT p.role FROM role_parents p JOIN descendants d ON p.parent=d.id) SELECT 1 FROM assignments a JOIN descendants d ON d.id=a.role JOIN global_admins g ON g.identity=a.identity LIMIT 1",role);}
 public boolean isGlobalAdmin(String actor)throws Exception{return store.tx(c->exists(c,"SELECT 1 FROM global_admins WHERE identity=?",actor));}
 public boolean isMember(String actor,String org)throws Exception{return store.tx(c->exists(c,"SELECT 1 FROM memberships WHERE identity=? AND org=?",actor,org));}
 public long authorizationEpoch(String actor)throws Exception{return store.tx(c->{try(var q=c.prepareStatement("SELECT epoch FROM identities WHERE identity=?")){q.setString(1,actor);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.denied();return r.getLong(1);}}});}
 public Set<String> permissions(String actor,String scope)throws Exception{
  Values.identity(actor);Values.scope(scope);
  return store.tx(c->{if(!exists(c,"SELECT 1 FROM identities WHERE identity=?",actor))return Set.of();
   Set<String>result=new TreeSet<>();
   try(var q=c.prepareStatement("SELECT role FROM assignments a JOIN roles r ON r.id=a.role WHERE a.identity=? AND (r.scope='GLOBAL' OR r.scope=?)")){q.setString(1,actor);q.setString(2,scope);try(var r=q.executeQuery()){while(r.next()){RoleRights rights=roleRights(c,r.getString(1));result.addAll(rights.permissions());}}}
   if(scope.startsWith("ORG:")&&exists(c,"SELECT 1 FROM organizations WHERE id=? AND owner=?",scope.substring(4),actor)){
    result.addAll(Set.of("ORG_MANAGE","MEMBERS_MANAGE","ROLES_MANAGE"));
    try(var q=c.prepareStatement("SELECT permission FROM org_delegations WHERE org=?")){q.setString(1,scope.substring(4));try(var r=q.executeQuery()){while(r.next())result.add(r.getString(1));}}
   }
   if(!scope.equals("GLOBAL"))result.removeAll(GLOBAL_ONLY);
   return Set.copyOf(result);});
 }
 public boolean has(String actor,String permission,String scope)throws Exception{
  Values.permission(permission);Values.scope(scope);Values.identity(actor);
  return store.tx(c->{if(!exists(c,"SELECT 1 FROM identities WHERE identity=?",actor))return false;
   if(GLOBAL_ONLY.contains(permission)&&!scope.equals("GLOBAL"))return false;
   if(scope.startsWith("ORG:")&&!exists(c,"SELECT 1 FROM memberships WHERE identity=? AND org=?",actor,scope.substring(4))&&!isGlobalAdmin(actor))return false;
   return isGlobalAdmin(actor)||permissions(actor,scope).contains(permission);});
 }
 public void require(String actor,String permission,String scope)throws Exception{if(!has(actor,permission,scope))throw CommunityException.denied();}
 public int clearance(String actor,String scope)throws Exception{return store.tx(c->{int level=0;try(var q=c.prepareStatement("SELECT clearance FROM identities WHERE identity=?")){q.setString(1,actor);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.denied();level=r.getInt(1);}}
  try(var q=c.prepareStatement("SELECT role FROM assignments a JOIN roles r ON r.id=a.role WHERE a.identity=? AND (r.scope='GLOBAL' OR r.scope=?)")){q.setString(1,actor);q.setString(2,scope);try(var r=q.executeQuery()){while(r.next())level=Math.max(level,roleRights(c,r.getString(1)).clearance());}}return level;});}
 public boolean canRead(String actor,ResourcePolicy policy)throws Exception{
  return store.tx(c->{if(!exists(c,"SELECT 1 FROM identities WHERE identity=?",actor))return false;Values.scope(policy.scope());
   if(policy.scope().startsWith("ORG:")&&!isMember(actor,policy.scope().substring(4)))return false;
   if(clearance(actor,policy.scope())<policy.minLevel())return false;
   for(String p:policy.requiredPermissions())if(!has(actor,p,policy.scope()))return false;
   if(!policy.allowedOrgs().isEmpty()||!policy.allowedUsers().isEmpty()){
    boolean allow=policy.allowedUsers().contains(actor);for(String org:policy.allowedOrgs())allow|=isMember(actor,org);if(!allow)return false;
   }return true;});
 }
 public void requireRead(String actor,ResourcePolicy policy)throws Exception{if(!canRead(actor,policy))throw CommunityException.missing();}
 public record RoleRights(Set<String> permissions,int clearance){}
 public RoleRights roleRights(Connection c,String role)throws Exception{
  Set<String>visited=new HashSet<>(),active=new HashSet<>(),perms=new TreeSet<>();int[]level={0};walk(c,role,null,visited,active,perms,level);return new RoleRights(Set.copyOf(perms),level[0]);
 }
 private void walk(Connection c,String role,String expectedScope,Set<String>visited,Set<String>active,Set<String>perms,int[]level)throws Exception{
  if(active.contains(role))throw CommunityException.invalid();if(visited.contains(role))return;if(visited.size()>=128)throw CommunityException.invalid();active.add(role);visited.add(role);String scope;
  try(var q=c.prepareStatement("SELECT scope,clearance FROM roles WHERE id=?")){q.setString(1,role);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.invalid();scope=r.getString(1);if(expectedScope!=null&&!expectedScope.equals(scope))throw CommunityException.invalid();level[0]=Math.max(level[0],r.getInt(2));}}
  try(var q=c.prepareStatement("SELECT permission FROM role_permissions WHERE role=?")){q.setString(1,role);try(var r=q.executeQuery()){while(r.next())perms.add(r.getString(1));}}
  try(var q=c.prepareStatement("SELECT parent FROM role_parents WHERE role=?")){q.setString(1,role);try(var r=q.executeQuery()){while(r.next())walk(c,r.getString(1),scope,visited,active,perms,level);}}
  active.remove(role);
 }
 public void bootstrap(byte[]first,String firstFingerprint,byte[]second,String secondFingerprint)throws Exception{
  String a=CommunityStore.hex(CommunityStore.hash(first)),b=CommunityStore.hex(CommunityStore.hash(second));
  if(a.equals(b)||!a.equals(firstFingerprint)||!b.equals(secondFingerprint))throw CommunityException.invalid();
  store.tx(c->{if(exists(c,"SELECT 1 FROM global_admins LIMIT 1"))throw new CommunityException("INITIALIZED","Первоначальная настройка уже выполнена");
   store.ensureIdentity(first,"Первый администратор");store.ensureIdentity(second,"Второй администратор");
   try(var q=c.prepareStatement("INSERT INTO global_admins VALUES(?,?)")){for(String id:List.of(a,b)){q.setString(1,id);q.setLong(2,store.clock().millis());q.executeUpdate();}}
   store.audit(c,a,"BOOTSTRAP",b,"Two independently verified Ed25519 fingerprints");return null;});
 }
 public long secondFactorVersion(String actor)throws Exception{return store.tx(c->{try(var q=c.prepareStatement("SELECT version FROM second_factors WHERE identity=?")){q.setString(1,actor);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.denied();return r.getLong(1);}}});}
 public void requireStepUp(String actor,String token)throws Exception{
  if(token==null||!token.matches("[A-Za-z0-9_-]{43}"))throw new CommunityException("REAUTH_REQUIRED","Подтвердите вход повторно");
  String hash=CommunityStore.hex(CommunityStore.hash(token.getBytes(StandardCharsets.US_ASCII)));
  boolean valid=store.tx(c->{try(var q=c.prepareStatement("SELECT 1 FROM stepup_tokens t JOIN second_factors f ON f.identity=t.identity WHERE t.identity=? AND t.token_hash=? AND t.expires>? AND t.epoch=f.version")){q.setString(1,actor);q.setString(2,hash);q.setLong(3,store.clock().millis());try(var r=q.executeQuery()){return r.next();}}});
  if(!valid)throw new CommunityException("REAUTH_REQUIRED","Подтвердите вход повторно");
 }
 /** Approved requests bind exact payload and two current administrators. Callback and consumption are atomic. */
 public <T>T executeCritical(String actor,String id,String kind,String payload,CommunityStore.SqlWork<T> work)throws Exception{
  return store.tx(c->{if(!isGlobalAdmin(actor))throw CommunityException.denied();
   try(var q=c.prepareStatement("SELECT * FROM critical_requests WHERE id=?")){q.setString(1,id);try(var r=q.executeQuery()){
    if(!r.next()||!r.getString("state").equals("APPROVED")||r.getLong("expires")<=store.clock().millis()||!r.getString("kind").equals(kind)||!r.getString("payload").equals(payload)||!r.getString("initiator").equals(actor)||r.getString("approver").equals(actor)||!isGlobalAdmin(r.getString("approver")))throw CommunityException.denied();
   }}
   T value=work.run(c);try(var q=c.prepareStatement("UPDATE critical_requests SET state='EXECUTED',revision=revision+1 WHERE id=? AND state='APPROVED'")){q.setString(1,id);if(q.executeUpdate()!=1)throw CommunityException.conflict();}store.audit(c,actor,"CRITICAL_EXECUTED",id,kind);return value;});
 }
 @Override public void close(){if(factorKek!=null)Arrays.fill(factorKek,(byte)0);}
 public static boolean exists(Connection c,String sql,String...args)throws SQLException{try(var q=c.prepareStatement(sql)){for(int i=0;i<args.length;i++)q.setString(i+1,args[i]);try(var r=q.executeQuery()){return r.next();}}}
}
