package org.securemail.community.admin;

import org.securemail.community.core.*;
import org.securemail.community.access.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.time.Clock;
import java.util.*;

/** Administration is an authenticated RPC subsystem, never a nickname-based UI feature. */
public final class AdminService {
 private final CommunityStore store;private final AccessControl access;private final Clock clock;private final SecureRandom random=new SecureRandom();
 private static final Set<String>CRITICAL=Set.of("ROLE_DELETE","ROLE_CREATE","ROLE_UPDATE","ROLE_ASSIGN","ROLE_REVOKE","LEVEL_DEFINE","LEVEL_SET","ADMIN_GRANT","ADMIN_REVOKE","GLOBAL_CONFIG","TRUST_KEYS","VERIFY_POLICY","BULK_DELETE","AGENT_CONFIG","AGENT_MODEL","AGENT_BUDGET","AGENT_SOURCE","WORKER_MANAGE","FACTOR_RESET");
 public AdminService(CommunityStore store,AccessControl access,Clock clock){this.store=store;this.access=access;this.clock=clock;}
 public Map<String,Object>handle(String actor,String action,Map<String,Object>d)throws Exception{
  Values.identity(actor);
  try{return store.tx(c->switch(action){
   case "community.me"->me(c,actor);
   case "community.profile.update"->profile(c,actor,d);
   case "account.factor.status"->access.factorStatus(actor);
   case "account.factor.enroll.begin"->access.beginFactorEnrollment(actor);
   case "account.factor.enroll.finish"->{access.finishFactorEnrollment(actor,Values.string(d,"enrollmentId",86),Values.string(d,"code",8));yield Map.of("configured",true);}
   case "admin.stepup.begin"->begin(c,actor);
   case "admin.stepup.finish"->finish(c,actor,d);
   case "admin.factor.rotate"->rotateFactor(c,actor,d);
   case "admin.roles.list","org.roles.list"->roles(c,actor,d);
   case "admin.roles.create"->role(c,actor,d,false);
   case "admin.roles.update"->role(c,actor,d,true);
   case "admin.roles.delete"->deleteRole(c,actor,d);
   case "admin.roles.assign"->assign(c,actor,d,false);
   case "admin.roles.revoke"->assign(c,actor,d,true);
   case "admin.levels.list"->levels(c);
   case "admin.levels.create","admin.levels.update"->defineLevel(c,actor,d,action.endsWith("update"));
   case "admin.levels.assign"->setLevel(c,actor,d);
   case "admin.verifications.issue"->verify(c,actor,d);
   case "admin.verifications.revoke"->revokeVerification(c,actor,d);
   case "admin.verifications.list"->verifications(c,actor,d);
   case "admin.audit"->audit(c,actor,d);
   case "admin.critical.request"->request(c,actor,d);
   case "admin.critical.approve"->approve(c,actor,d);
   case "admin.critical.list"->criticalList(c,actor,d);
   case "admin.administrators.grant","admin.administrators.revoke"->administrator(c,actor,d,action.endsWith("revoke"));
   default->throw CommunityException.invalid();
  });}catch(CommunityException e){if((action.equals("admin.stepup.finish")||action.equals("account.factor.enroll.finish"))&&!e.code().equals("RATE_LIMIT"))store.persistAfterRollback(db->{access.recordStepUpFailure(actor);return null;});throw e;}
 }
 private Map<String,Object>profile(Connection c,String actor,Map<String,Object>d)throws Exception{
  if(!d.keySet().equals(Set.of("nickname")))throw CommunityException.invalid();access.authorizationEpoch(actor);String nickname;try{nickname=org.securemail.protocol.Limits.nickname(Values.string(d,"nickname",32));}catch(IllegalArgumentException invalid){throw CommunityException.invalid();}
  try(var q=c.prepareStatement("UPDATE identities SET nickname=? WHERE identity=? AND nickname<>?")){q.setString(1,nickname);q.setString(2,actor);q.setString(3,nickname);if(q.executeUpdate()!=0)store.audit(c,actor,"DISPLAY_NAME_UPDATED",actor,"Self-asserted display name; no authority assigned");}return Map.of("nickname",nickname);
 }
 private Map<String,Object>me(Connection c,String actor)throws Exception{
  try(var q=c.prepareStatement("SELECT nickname,clearance,epoch FROM identities WHERE identity=?")){q.setString(1,actor);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.denied();return Map.of("identity",actor,"nickname",r.getString(1),"clearance",r.getInt(2),"epoch",r.getLong(3),"isAdmin",access.isGlobalAdmin(actor),"permissions",access.permissions(actor,"GLOBAL"));}}
 }
 private String token(){byte[]b=new byte[32];random.nextBytes(b);return Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
 private Map<String,Object>begin(Connection c,String actor)throws Exception{
  access.checkStepUpRate(c,actor);
  try(var q=c.prepareStatement("DELETE FROM stepup_challenges WHERE expires<? OR identity=?")){q.setLong(1,clock.millis());q.setString(2,actor);q.executeUpdate();}
  String challenge=token();long expires=clock.millis()+60000;
  try(var q=c.prepareStatement("INSERT INTO stepup_challenges VALUES(?,?,?)")){q.setString(1,challenge);q.setString(2,actor);q.setLong(3,expires);q.executeUpdate();}
  String message="AEGIS-COMMUNITY-STEPUP-v2\n"+store.serviceIdentity()+"\n"+actor+"\n"+challenge+"\n"+expires;
  return Map.of("challenge",challenge,"expires",expires,"factorRequired",true,"signingBytesBase64",Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8)));
 }
 private Map<String,Object>finish(Connection c,String actor,Map<String,Object>d)throws Exception{
  access.checkStepUpRate(c,actor);
  String challenge=Values.string(d,"challenge",86);byte[]proof;try{proof=Base64.getDecoder().decode(Values.string(d,"signatureBase64",128));}catch(IllegalArgumentException e){throw CommunityException.invalid();}if(proof.length!=64)throw CommunityException.invalid();
  long expiry;byte[]pub;
  try(var q=c.prepareStatement("SELECT ch.expires,i.public_key FROM stepup_challenges ch JOIN identities i ON i.identity=ch.identity WHERE ch.challenge=? AND ch.identity=?")){q.setString(1,challenge);q.setString(2,actor);try(var r=q.executeQuery()){if(!r.next()||r.getLong(1)<=clock.millis())throw CommunityException.denied();expiry=r.getLong(1);pub=r.getBytes(2);}}
  Signature sig=Signature.getInstance("Ed25519");sig.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pub)));sig.update(("AEGIS-COMMUNITY-STEPUP-v2\n"+store.serviceIdentity()+"\n"+actor+"\n"+challenge+"\n"+expiry).getBytes(StandardCharsets.UTF_8));
  if(!sig.verify(proof))throw CommunityException.denied();
  access.verifySecondFactor(c,actor,Values.string(d,"code",8));
  try(var q=c.prepareStatement("DELETE FROM stepup_challenges WHERE challenge=?")){q.setString(1,challenge);q.executeUpdate();}
  try(var q=c.prepareStatement("DELETE FROM stepup_tokens WHERE identity=? OR expires<?")){q.setString(1,actor);q.setLong(2,clock.millis());q.executeUpdate();}
  String token=token();long expires=clock.millis()+300000;
  try(var q=c.prepareStatement("INSERT INTO stepup_tokens VALUES(?,?,?,?)")){q.setString(1,CommunityStore.hex(CommunityStore.hash(token.getBytes(StandardCharsets.US_ASCII))));q.setString(2,actor);q.setLong(3,expires);q.setLong(4,access.secondFactorVersion(actor));q.executeUpdate();}
  store.audit(c,actor,"STEP_UP",actor,"Fresh identity proof and server-enforced one-time TOTP");return Map.of("token",token,"expires",expires);
 }
 private void step(String actor,Map<String,Object>d)throws Exception{access.requireStepUp(actor,Values.string(d,"stepUp",86));}
 private Map<String,Object>roles(Connection c,String actor,Map<String,Object>d)throws Exception{
  String scope=Values.scope(Values.string(d,"scope",80));access.require(actor,scope.equals("GLOBAL")?"GLOBAL_ROLES_MANAGE":"ROLES_MANAGE",scope);
  String after=Values.optional(d,"after",36);long requestedLimit=d.containsKey("limit")?Values.number(d,"limit"):30;if(requestedLimit<1||requestedLimit>30)throw CommunityException.invalid();int limit=(int)requestedLimit;List<Map<String,Object>>out=new ArrayList<>();try(var q=c.prepareStatement("SELECT id,name,clearance,revision FROM roles WHERE scope=? AND id>? ORDER BY id LIMIT ?")){q.setString(1,scope);q.setString(2,after);q.setInt(3,limit);try(var r=q.executeQuery()){while(r.next()){String id=r.getString(1);List<String>parents=new ArrayList<>(),permissions=new ArrayList<>();try(var x=c.prepareStatement("SELECT parent FROM role_parents WHERE role=? ORDER BY parent")){x.setString(1,id);try(var z=x.executeQuery()){while(z.next())parents.add(z.getString(1));}}try(var x=c.prepareStatement("SELECT permission FROM role_permissions WHERE role=? ORDER BY permission")){x.setString(1,id);try(var z=x.executeQuery()){while(z.next())permissions.add(z.getString(1));}}out.add(Map.of("id",id,"scope",scope,"name",r.getString(2),"clearance",r.getInt(3),"revision",r.getLong(4),"parents",parents,"permissions",permissions));}}}return Map.of("items",out,"nextAfter",out.size()==limit?out.getLast().get("id"):"");
 }
 private Map<String,Object>role(Connection c,String actor,Map<String,Object>d,boolean update)throws Exception{
  step(actor,d);String scope=Values.scope(Values.string(d,"scope",80)),name=Values.string(d,"name",80),id=update?Values.string(d,"id",36):UUID.randomUUID().toString();
  access.require(actor,scope.equals("GLOBAL")?"GLOBAL_ROLES_MANAGE":"ROLES_MANAGE",scope);Set<String>permissions=Values.strings(d,"permissions",128),parents=Values.strings(d,"parents",32);long level=Values.number(d,"clearance");if(level<0||level>1000000)throw CommunityException.invalid();
  if(level!=0&&!AccessControl.exists(c,"SELECT 1 FROM access_levels WHERE rank=?",String.valueOf(level)))throw CommunityException.invalid();
  for(String p:permissions){Values.permission(p);if(!scope.equals("GLOBAL")&&AccessControl.GLOBAL_ONLY.contains(p))throw CommunityException.denied();}
  // Capture delegation authority before any role graph mutation. The actor may be
  // assigned this role or a descendant; reading their rights after the write would
  // otherwise let the requested grant authorize itself, including its clearance.
  boolean administrator=access.isGlobalAdmin(actor);AccessControl.RoleRights authority=new AccessControl.RoleRights(access.permissions(actor,scope),access.clearance(actor,scope));
  if(scope.equals("GLOBAL"))return access.executeCritical(actor,Values.string(d,"requestId",36),update?"ROLE_UPDATE":"ROLE_CREATE",CanonicalJson.encode(CanonicalJson.operationFields(d)),db->saveRole(db,actor,d,update,scope,name,id,permissions,parents,(int)level,administrator,authority));
  return saveRole(c,actor,d,update,scope,name,id,permissions,parents,(int)level,administrator,authority);
 }
 private Map<String,Object>saveRole(Connection c,String actor,Map<String,Object>d,boolean update,String scope,String name,String id,Set<String>permissions,Set<String>parents,int level,boolean administrator,AccessControl.RoleRights authority)throws Exception{
  if(update){try(var q=c.prepareStatement("UPDATE roles SET name=?,clearance=?,revision=revision+1 WHERE id=? AND scope=? AND revision=?")){q.setString(1,name);q.setInt(2,level);q.setString(3,id);q.setString(4,scope);q.setLong(5,Values.number(d,"revision"));if(q.executeUpdate()!=1)throw CommunityException.conflict();}}
  else{if(CommunityStore.count(c,"roles")>=10000)throw new CommunityException("LIMIT","Достигнут предел ролей");try(var q=c.prepareStatement("INSERT INTO roles(id,scope,name,clearance) VALUES(?,?,?,?)")){q.setString(1,id);q.setString(2,scope);q.setString(3,name);q.setInt(4,level);q.executeUpdate();}}
  for(String table:List.of("role_permissions","role_parents")){try(var q=c.prepareStatement("DELETE FROM "+table+" WHERE role=?")){q.setString(1,id);q.executeUpdate();}}
  for(String p:permissions)try(var q=c.prepareStatement("INSERT INTO role_permissions VALUES(?,?)")){q.setString(1,id);q.setString(2,p);q.executeUpdate();}
  for(String p:parents){if(!AccessControl.exists(c,"SELECT 1 FROM roles WHERE id=? AND scope=?",p,scope))throw CommunityException.denied();try(var q=c.prepareStatement("INSERT INTO role_parents VALUES(?,?)")){q.setString(1,id);q.setString(2,p);q.executeUpdate();}}
  AccessControl.RoleRights effective=access.roleRights(c,id);if(effective.permissions().contains("AGENT_WORK")&&access.roleHasAdministratorAssignees(c,id))throw new CommunityException("SERVICE_IDENTITY","Служебные полномочия рабочего узла нельзя назначать администратору");if(!administrator&&(!authority.permissions().containsAll(effective.permissions())||effective.clearance()>authority.clearance()))throw CommunityException.denied();
  store.bumpRoleEpoch(c,id);store.audit(c,actor,update?"ROLE_UPDATED":"ROLE_CREATED",id,scope);return Map.of("id",id,"revision",revision(c,"roles",id));
 }
 private Map<String,Object>deleteRole(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);String id=Values.string(d,"id",36),scope;try(var q=c.prepareStatement("SELECT scope FROM roles WHERE id=?")){q.setString(1,id);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.missing();scope=r.getString(1);}}
  access.require(actor,scope.equals("GLOBAL")?"GLOBAL_ROLES_MANAGE":"ROLES_MANAGE",scope);AccessControl.RoleRights rights=access.roleRights(c,id);if(!access.isGlobalAdmin(actor)&&(!access.permissions(actor,scope).containsAll(rights.permissions())||rights.clearance()>access.clearance(actor,scope)))throw CommunityException.denied();
  CommunityStore.SqlWork<Map<String,Object>>work=db->{List<String>users=new ArrayList<>();try(var q=db.prepareStatement("SELECT identity FROM assignments WHERE role=? LIMIT 100000")){q.setString(1,id);try(var r=q.executeQuery()){while(r.next())users.add(r.getString(1));}}store.bumpRoleEpoch(db,id);try(var q=db.prepareStatement("DELETE FROM roles WHERE id=? AND revision=?")){q.setString(1,id);q.setLong(2,Values.number(d,"revision"));if(q.executeUpdate()!=1)throw CommunityException.conflict();}for(String user:users)store.notifyAccount(user,"ROLE","Назначенная вам роль удалена");store.audit(db,actor,"ROLE_DELETED",id,scope);return Map.of("ok",true);};
  return scope.equals("GLOBAL")?access.executeCritical(actor,Values.string(d,"requestId",36),"ROLE_DELETE",CanonicalJson.encode(CanonicalJson.operationFields(d)),work):work.run(c);
 }
 private Map<String,Object>assign(Connection c,String actor,Map<String,Object>d,boolean revoke)throws Exception{
  step(actor,d);String role=Values.string(d,"role",36),user=Values.identity(Values.string(d,"user",64)),scope;
  try(var q=c.prepareStatement("SELECT scope FROM roles WHERE id=?")){q.setString(1,role);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.missing();scope=r.getString(1);}}
  access.require(actor,scope.equals("GLOBAL")?"GLOBAL_ROLES_MANAGE":"ROLES_MANAGE",scope);
  if(scope.startsWith("ORG:")&&!access.isMember(user,scope.substring(4)))throw CommunityException.denied();
  AccessControl.RoleRights rights=access.roleRights(c,role);if(!revoke&&rights.permissions().contains("AGENT_WORK")&&access.isGlobalAdmin(user))throw new CommunityException("SERVICE_IDENTITY","Служебные полномочия рабочего узла нельзя назначать администратору");if(!access.isGlobalAdmin(actor)&&(!access.permissions(actor,scope).containsAll(rights.permissions())||rights.clearance()>access.clearance(actor,scope)))throw CommunityException.denied();
  CommunityStore.SqlWork<Map<String,Object>>work=db->{try(var q=db.prepareStatement(revoke?"DELETE FROM assignments WHERE identity=? AND role=?":"INSERT OR IGNORE INTO assignments VALUES(?,?)")){q.setString(1,user);q.setString(2,role);q.executeUpdate();}store.bumpEpoch(db,user);store.notifyAccount(user,"ROLE",revoke?"Назначение роли отозвано":"Вам назначена роль");store.audit(db,actor,revoke?"ROLE_REVOKED":"ROLE_ASSIGNED",user,role);return Map.of("ok",true);};
  return scope.equals("GLOBAL")?access.executeCritical(actor,Values.string(d,"requestId",36),revoke?"ROLE_REVOKE":"ROLE_ASSIGN",CanonicalJson.encode(CanonicalJson.operationFields(d)),work):work.run(c);
 }
 private Map<String,Object>levels(Connection c)throws Exception{List<Map<String,Object>>out=new ArrayList<>();try(var q=c.createStatement();var r=q.executeQuery("SELECT id,name,rank,revision FROM access_levels ORDER BY rank LIMIT 128")){while(r.next())out.add(Map.of("id",r.getString(1),"name",r.getString(2),"rank",r.getInt(3),"revision",r.getLong(4)));}return Map.of("items",out);}
 private Map<String,Object>defineLevel(Connection c,String actor,Map<String,Object>d,boolean update)throws Exception{
  step(actor,d);access.require(actor,"LEVELS_MANAGE","GLOBAL");String name=Values.string(d,"name",80),id=update?Values.string(d,"id",36):UUID.randomUUID().toString();long rank=Values.number(d,"rank");if(rank<1||rank>1000000)throw CommunityException.invalid();
  return access.executeCritical(actor,Values.string(d,"requestId",36),"LEVEL_DEFINE",CanonicalJson.encode(CanonicalJson.operationFields(d)),db->{
   if(update){try(var old=db.prepareStatement("SELECT rank FROM access_levels WHERE id=?")){old.setString(1,id);try(var r=old.executeQuery()){if(!r.next())throw CommunityException.missing();int oldRank=r.getInt(1);if(oldRank!=rank&&(AccessControl.exists(db,"SELECT 1 FROM identities WHERE clearance=?",String.valueOf(oldRank))||AccessControl.exists(db,"SELECT 1 FROM roles WHERE clearance=?",String.valueOf(oldRank))))throw new CommunityException("CONFLICT","Используемый уровень нельзя перенумеровать без отдельной миграции");}}try(var q=db.prepareStatement("UPDATE access_levels SET name=?,rank=?,revision=revision+1 WHERE id=? AND revision=?")){q.setString(1,name);q.setLong(2,rank);q.setString(3,id);q.setLong(4,Values.number(d,"revision"));if(q.executeUpdate()!=1)throw CommunityException.conflict();}}
   else{try(var count=db.createStatement();var r=count.executeQuery("SELECT count(*) FROM access_levels")){r.next();if(r.getInt(1)>=128)throw CommunityException.invalid();}try(var q=db.prepareStatement("INSERT INTO access_levels VALUES(?,?,?,1)")){q.setString(1,id);q.setString(2,name);q.setLong(3,rank);q.executeUpdate();}}
   store.bumpEpoch(db);store.audit(db,actor,"LEVEL_DEFINED",id,name);return Map.of("id",id);});
 }
 private Map<String,Object>setLevel(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);access.require(actor,"LEVELS_MANAGE","GLOBAL");String user=Values.identity(Values.string(d,"user",64));long level=Values.number(d,"clearance");if(level<0||level>1000000||level!=0&&!AccessControl.exists(c,"SELECT 1 FROM access_levels WHERE rank=?",String.valueOf(level)))throw CommunityException.invalid();
  return access.executeCritical(actor,Values.string(d,"requestId",36),"LEVEL_SET",CanonicalJson.encode(CanonicalJson.operationFields(d)),db->{try(var q=db.prepareStatement("UPDATE identities SET clearance=? WHERE identity=?")){q.setLong(1,level);q.setString(2,user);if(q.executeUpdate()!=1)throw CommunityException.missing();}store.bumpEpoch(db,user);store.audit(db,actor,"LEVEL_ASSIGNED",user,String.valueOf(level));return Map.of("ok",true);});
 }
 private Map<String,Object>verify(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);access.require(actor,"VERIFICATION_MANAGE","GLOBAL");String user=Values.identity(Values.string(d,"user",64)),kind=Values.string(d,"kind",16),value=Values.string(d,"value",160),basis=Values.string(d,"basis",2000);if(!Set.of("IDENTITY","POSITION").contains(kind))throw CommunityException.invalid();String id=UUID.randomUUID().toString();
  try(var q=c.prepareStatement("INSERT INTO verifications(id,subject,kind,value,basis,issuer,created) VALUES(?,?,?,?,?,?,?)")){q.setString(1,id);q.setString(2,user);q.setString(3,kind);q.setString(4,value);q.setString(5,basis);q.setString(6,actor);q.setLong(7,clock.millis());q.executeUpdate();}store.audit(c,actor,"VERIFICATION_ISSUED",user,id+":"+kind);store.notifyAccount(user,"VERIFICATION","Администрация подтвердила сведения вашего профиля");return Map.of("id",id);
 }
 private Map<String,Object>revokeVerification(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);access.require(actor,"VERIFICATION_MANAGE","GLOBAL");String id=Values.string(d,"id",36),basis=Values.string(d,"basis",2000);try(var q=c.prepareStatement("UPDATE verifications SET revoked=?,revoker=?,revoke_basis=? WHERE id=? AND revoked IS NULL")){q.setLong(1,clock.millis());q.setString(2,actor);q.setString(3,basis);q.setString(4,id);if(q.executeUpdate()!=1)throw CommunityException.conflict();}store.audit(c,actor,"VERIFICATION_REVOKED",id,"Revocation recorded");return Map.of("ok",true);
 }
 private Map<String,Object>verifications(Connection c,String actor,Map<String,Object>d)throws Exception{
  String user=Values.identity(Values.string(d,"user",64));boolean privileged=access.has(actor,"VERIFICATION_MANAGE","GLOBAL")||actor.equals(user);List<Map<String,Object>>out=new ArrayList<>();try(var q=c.prepareStatement("SELECT * FROM verifications WHERE subject=? ORDER BY created DESC LIMIT 100")){q.setString(1,user);try(var r=q.executeQuery()){while(r.next()){Map<String,Object>v=new LinkedHashMap<>();v.put("id",r.getString("id"));v.put("kind",r.getString("kind"));v.put("value",r.getString("value"));v.put("created",r.getLong("created"));v.put("active",r.getObject("revoked")==null);v.put("issuer",r.getString("issuer"));if(privileged){v.put("basis",r.getString("basis"));v.put("revoked",r.getObject("revoked"));v.put("revokeBasis",r.getString("revoke_basis"));}out.add(v);}}}return Map.of("items",out);
 }
 private Map<String,Object>audit(Connection c,String actor,Map<String,Object>d)throws Exception{
  access.require(actor,"ADMIN_AUDIT","GLOBAL");long after=d.containsKey("after")?Values.number(d,"after"):0,limit=d.containsKey("limit")?Values.number(d,"limit"):50;if(after<0||limit<1||limit>100)throw CommunityException.invalid();List<Map<String,Object>>out=new ArrayList<>();try(var q=c.prepareStatement("SELECT * FROM audit WHERE seq>? ORDER BY seq LIMIT ?")){q.setLong(1,after);q.setLong(2,limit);try(var r=q.executeQuery()){while(r.next())out.add(Map.of("seq",r.getLong("seq"),"created",r.getLong("created"),"actor",r.getString("actor"),"action",r.getString("action"),"target",r.getString("target"),"details",r.getString("details"),"previous",r.getString("previous"),"digest",r.getString("digest")));}}return Map.of("items",out,"integrity",store.verifyAudit());
 }
 private Map<String,Object>request(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);if(!access.isGlobalAdmin(actor))throw CommunityException.denied();String kind=Values.string(d,"kind",40);if(!CRITICAL.contains(kind)||!(d.get("payload") instanceof Map<?,?>payload))throw CommunityException.invalid();String encoded=CanonicalJson.encode(payload),digest=CommunityStore.hex(CommunityStore.hash(encoded.getBytes(StandardCharsets.UTF_8))),id=UUID.randomUUID().toString();long expires=clock.millis()+600000;
  try(var q=c.prepareStatement("UPDATE critical_requests SET state='EXPIRED',revision=revision+1 WHERE state IN ('PENDING','APPROVED') AND expires<?")){q.setLong(1,clock.millis());q.executeUpdate();}
  try(var q=c.prepareStatement("SELECT count(*) FROM critical_requests WHERE initiator=? AND state IN ('PENDING','APPROVED')")){q.setString(1,actor);try(var r=q.executeQuery()){r.next();if(r.getInt(1)>=32)throw CommunityException.invalid();}}
  if(CommunityStore.count(c,"critical_requests")>=100000)throw new CommunityException("LIMIT","Требуется обслуживание журнала операций");
  try(var q=c.prepareStatement("INSERT INTO critical_requests(id,kind,payload,digest,initiator,expires,state) VALUES(?,?,?,?,?,?,'PENDING')")){q.setString(1,id);q.setString(2,kind);q.setString(3,encoded);q.setString(4,digest);q.setString(5,actor);q.setLong(6,expires);q.executeUpdate();}store.audit(c,actor,"CRITICAL_REQUESTED",id,kind+":"+digest);store.notifyAdministrators("SECURITY","Критическая операция ожидает независимого подтверждения");return Map.of("id",id,"expires",expires,"digest",digest,"revision",1);
 }
 private Map<String,Object>approve(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);if(!access.isGlobalAdmin(actor))throw CommunityException.denied();String id=Values.string(d,"id",36);try(var q=c.prepareStatement("UPDATE critical_requests SET approver=?,state='APPROVED',revision=revision+1 WHERE id=? AND revision=? AND state='PENDING' AND initiator<>? AND expires>? AND EXISTS(SELECT 1 FROM global_admins a WHERE a.identity=critical_requests.initiator)")){q.setString(1,actor);q.setString(2,id);q.setLong(3,Values.number(d,"revision"));q.setString(4,actor);q.setLong(5,clock.millis());if(q.executeUpdate()!=1)throw CommunityException.denied();}store.audit(c,actor,"CRITICAL_APPROVED",id,"Independent administrator");return Map.of("ok",true,"revision",2);
 }
 private Map<String,Object>criticalList(Connection c,String actor,Map<String,Object>d)throws Exception{
  if(!access.isGlobalAdmin(actor))throw CommunityException.denied();if(!Set.of("limit","after").containsAll(d.keySet()))throw CommunityException.invalid();long requestedLimit=d.containsKey("limit")?Values.number(d,"limit"):10;if(requestedLimit<1||requestedLimit>10)throw CommunityException.invalid();int limit=(int)requestedLimit;String after=Values.optional(d,"after",36);
  if(!after.isEmpty())try{if(!UUID.fromString(after).toString().equals(after))throw CommunityException.invalid();}catch(IllegalArgumentException invalid){throw CommunityException.invalid();}
  List<Map<String,Object>>out=new ArrayList<>();boolean more=false;try(var q=c.prepareStatement("SELECT * FROM critical_requests WHERE state IN ('PENDING','APPROVED') AND id>? ORDER BY id LIMIT ?")){q.setString(1,after);q.setInt(2,limit+1);try(var r=q.executeQuery()){while(r.next()){if(out.size()==limit){more=true;break;}out.add(Map.of("id",r.getString("id"),"kind",r.getString("kind"),"payload",r.getString("payload"),"digest",r.getString("digest"),"initiator",r.getString("initiator"),"requester",r.getString("initiator"),"expires",r.getLong("expires"),"state",r.getString("state"),"revision",r.getLong("revision")));}}}return Map.of("items",out,"requests",out,"nextAfter",more?out.getLast().get("id"):"");
 }
 private Map<String,Object>administrator(Connection c,String actor,Map<String,Object>d,boolean revoke)throws Exception{
  step(actor,d);access.require(actor,"GLOBAL_ADMIN_MANAGE","GLOBAL");String user=Values.identity(Values.string(d,"user",64));
  return access.executeCritical(actor,Values.string(d,"requestId",36),revoke?"ADMIN_REVOKE":"ADMIN_GRANT",CanonicalJson.encode(CanonicalJson.operationFields(d)),db->{if(revoke){try(var q=db.createStatement();var r=q.executeQuery("SELECT count(*) FROM global_admins")){r.next();if(r.getInt(1)<=2)throw new CommunityException("MIN_ADMINS","Должны остаться два независимых администратора");}try(var q=db.prepareStatement("DELETE FROM global_admins WHERE identity=?")){q.setString(1,user);q.executeUpdate();}}
   else {if(access.isServiceIdentity(user))throw new CommunityException("SERVICE_IDENTITY","Служебная identity рабочего узла не может стать администратором");if(!AccessControl.exists(db,"SELECT 1 FROM second_factors WHERE identity=?",user))throw new CommunityException("FACTOR_UNCONFIGURED","Сначала зарегистрируйте второй фактор администратора");try(var q=db.prepareStatement("INSERT OR IGNORE INTO global_admins VALUES(?,?)")){q.setString(1,user);q.setLong(2,clock.millis());q.executeUpdate();}}
   store.bumpEpoch(db,user);store.revokeStepUp(db,user);store.audit(db,actor,revoke?"ADMIN_REVOKED":"ADMIN_GRANTED",user,"Two administrator approval");return Map.of("ok",true);});
 }
 private Map<String,Object>rotateFactor(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);access.require(actor,"GLOBAL_ADMIN_MANAGE","GLOBAL");byte[]seed;try{seed=Base64.getDecoder().decode(Values.string(d,"seedBase64",64));}catch(IllegalArgumentException e){throw CommunityException.invalid();}try{access.rotateFactor(actor,Values.string(d,"requestId",36),Values.identity(Values.string(d,"user",64)),seed);}finally{Arrays.fill(seed,(byte)0);}return Map.of("ok",true);
 }
 private static long revision(Connection c,String table,String id)throws SQLException{if(!table.equals("roles"))throw new IllegalArgumentException();try(var q=c.prepareStatement("SELECT revision FROM roles WHERE id=?")){q.setString(1,id);try(var r=q.executeQuery()){r.next();return r.getLong(1);}}}
}
