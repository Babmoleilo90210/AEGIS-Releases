package org.securemail.community.org;

import org.securemail.community.core.*;
import org.securemail.community.access.*;
import java.sql.*;
import java.time.Clock;
import java.util.*;

/** Persisted approval, joining and membership management. No predefined organization roles. */
public final class OrganizationService {
 private final CommunityStore store;private final AccessControl access;private final Clock clock;
 public OrganizationService(CommunityStore store,AccessControl access,Clock clock){this.store=store;this.access=access;this.clock=clock;}
 public Map<String,Object>handle(String actor,String action,Map<String,Object>d)throws Exception{
  Values.identity(actor);return store.tx(c->switch(action){
   case "org.applications.create"->apply(c,actor,d);
   case "org.applications.list"->applications(c,actor,d);
   case "org.applications.decide"->decide(c,actor,d);
   case "org.list"->list(c,actor,d);
   case "org.get"->get(c,actor,d);
   case "org.update"->update(c,actor,d);
   case "org.join"->join(c,actor,d);
   case "org.join.request"->joinRequest(c,actor,d);
   case "org.join.requests"->joinRequests(c,actor,d);
   case "org.join.decide"->joinDecide(c,actor,d);
   case "org.invite"->invite(c,actor,d);
   case "org.leave"->leave(c,actor,d,false);
   case "org.members.remove"->leave(c,actor,d,true);
   case "org.members.list"->members(c,actor,d);
   case "org.members.roles"->memberRoles(c,actor,d);
   case "org.calls.authorize"->call(c,actor,d);
   case "org.calls.authorize_batch","org.calls.authorizeBatch"->callBatch(c,actor,d);
   default->throw CommunityException.invalid();
  });
 }
 private static String org(Map<String,Object>d)throws Exception{return Values.string(d,d.containsKey("org")?"org":"id",36);}
 private static String city(Map<String,Object>d)throws Exception{String s=Values.optional(d,"city",160);if(!s.isEmpty()&&!s.matches("[a-z]{2}/[a-z0-9_-]{1,64}/[a-z0-9_-]{1,80}"))throw CommunityException.invalid();return s;}
 private static String policy(Map<String,Object>d)throws Exception{String s=Values.string(d,"joinPolicy",12);if(!Set.of("OPEN","REQUEST","INVITE").contains(s))throw CommunityException.invalid();return s;}
 private void step(String actor,Map<String,Object>d)throws Exception{access.requireStepUp(actor,Values.string(d,"stepUp",86));}
 private Map<String,Object>apply(Connection c,String actor,Map<String,Object>d)throws Exception{
  String name=Values.string(d,"name",120),description=Values.string(d,"description",8000),purpose=Values.string(d,"purpose",2000),city=city(d),join=policy(d);byte[]emblem=ImageSanitizer.emblem(Values.optional(d,"emblemBase64",700000));
  try(var q=c.prepareStatement("SELECT count(*) FROM org_applications WHERE owner=? AND status='PENDING'")){q.setString(1,actor);try(var r=q.executeQuery()){r.next();if(r.getInt(1)>=5)throw new CommunityException("LIMIT","Дождитесь рассмотрения предыдущих заявок");}}
  if(CommunityStore.count(c,"org_applications")>=100000)throw new CommunityException("LIMIT","Достигнут предел заявок");String id=UUID.randomUUID().toString();
  try(var q=c.prepareStatement("INSERT INTO org_applications(id,owner,name,description,purpose,city,emblem,join_policy,status,created) VALUES(?,?,?,?,?,?,?,?,'PENDING',?)")){q.setString(1,id);q.setString(2,actor);q.setString(3,name);q.setString(4,description);q.setString(5,purpose);q.setString(6,city);q.setBytes(7,emblem);q.setString(8,join);q.setLong(9,clock.millis());q.executeUpdate();}
  store.audit(c,actor,"ORG_APPLIED",id,"Pending administrative approval");store.notifyAdministrators("ORGANIZATION","Поступила заявка на создание организации");return Map.of("id",id,"revision",1,"status","PENDING");
 }
 private Map<String,Object>applications(Connection c,String actor,Map<String,Object>d)throws Exception{
  boolean admin=access.has(actor,"ORG_APPROVE","GLOBAL");List<Map<String,Object>>items=new ArrayList<>();try(var q=c.prepareStatement("SELECT * FROM org_applications WHERE (?=1 OR owner=?) ORDER BY created DESC LIMIT 100")){q.setInt(1,admin?1:0);q.setString(2,actor);try(var r=q.executeQuery()){while(r.next())items.add(Map.of("id",r.getString("id"),"owner",r.getString("owner"),"name",r.getString("name"),"description",r.getString("description"),"purpose",r.getString("purpose"),"city",r.getString("city"),"joinPolicy",r.getString("join_policy"),"status",r.getString("status"),"revision",r.getLong("revision")));}}return Map.of("items",items);
 }
 private Map<String,Object>decide(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);access.require(actor,"ORG_APPROVE","GLOBAL");String id=Values.string(d,"id",36);boolean approve=Values.bool(d,"approve",false);Set<String>delegated=Values.strings(d,"delegatedPermissions",128);
  for(String p:delegated){Values.permission(p);if(AccessControl.GLOBAL_ONLY.contains(p))throw CommunityException.denied();if(!access.has(actor,p,"GLOBAL"))throw CommunityException.denied();}
  String owner,name,description,city,join;byte[]emblem;
  try(var q=c.prepareStatement("SELECT * FROM org_applications WHERE id=? AND revision=? AND status='PENDING'")){q.setString(1,id);q.setLong(2,Values.number(d,"revision"));try(var r=q.executeQuery()){if(!r.next())throw CommunityException.conflict();owner=r.getString("owner");name=r.getString("name");description=r.getString("description");city=r.getString("city");join=r.getString("join_policy");emblem=r.getBytes("emblem");}}
  if(approve){if(CommunityStore.count(c,"organizations")>=50000)throw CommunityException.invalid();
   try(var q=c.prepareStatement("INSERT INTO organizations(id,name,description,city,emblem,join_policy,owner) VALUES(?,?,?,?,?,?,?)")){q.setString(1,id);q.setString(2,name);q.setString(3,description);q.setString(4,city);q.setBytes(5,emblem);q.setString(6,join);q.setString(7,owner);q.executeUpdate();}
   addMember(c,id,owner);for(String p:delegated)try(var q=c.prepareStatement("INSERT INTO org_delegations VALUES(?,?)")){q.setString(1,id);q.setString(2,p);q.executeUpdate();}
  }
  try(var q=c.prepareStatement("UPDATE org_applications SET status=?,revision=revision+1 WHERE id=? AND status='PENDING'")){q.setString(1,approve?"APPROVED":"REJECTED");q.setString(2,id);if(q.executeUpdate()!=1)throw CommunityException.conflict();}
  store.bumpEpoch(c,owner);store.notifyAccount(owner,"ORGANIZATION",approve?"Заявка на создание организации одобрена":"Заявка на создание организации отклонена");store.audit(c,actor,approve?"ORG_APPROVED":"ORG_REJECTED",id,"Explicit delegated permissions: "+String.join(",",new TreeSet<>(delegated)));return Map.of("id",id,"status",approve?"APPROVED":"REJECTED","revision",2);
 }
 private Map<String,Object>list(Connection c,String actor,Map<String,Object>d)throws Exception{
  String after=Values.optional(d,"after",36);List<Map<String,Object>>items=new ArrayList<>();try(var q=c.prepareStatement("SELECT id,name,description,city,join_policy,revision FROM organizations WHERE id>? ORDER BY id LIMIT 100")){q.setString(1,after);try(var r=q.executeQuery()){while(r.next())items.add(Map.of("id",r.getString(1),"name",r.getString(2),"description",r.getString(3),"city",r.getString(4),"joinPolicy",r.getString(5),"revision",r.getLong(6),"member",access.isMember(actor,r.getString(1))));}}return Map.of("items",items);
 }
 private Map<String,Object>get(Connection c,String actor,Map<String,Object>d)throws Exception{
  String id=org(d);try(var q=c.prepareStatement("SELECT * FROM organizations WHERE id=?")){q.setString(1,id);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.missing();String scope="ORG:"+id;return Map.of("id",id,"name",r.getString("name"),"description",r.getString("description"),"city",r.getString("city"),"joinPolicy",r.getString("join_policy"),"emblemBase64",Base64.getEncoder().encodeToString(r.getBytes("emblem")),"revision",r.getLong("revision"),"member",access.isMember(actor,id),"permissions",access.permissions(actor,scope),"owner",r.getString("owner"));}}
 }
 private Map<String,Object>update(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);String id=org(d);access.require(actor,"ORG_MANAGE","ORG:"+id);String name=Values.string(d,"name",120),description=Values.string(d,"description",8000),city=city(d),join=policy(d);byte[]emblem=ImageSanitizer.emblem(Values.optional(d,"emblemBase64",700000));
  try(var q=c.prepareStatement("UPDATE organizations SET name=?,description=?,city=?,join_policy=?,emblem=?,revision=revision+1 WHERE id=? AND revision=?")){q.setString(1,name);q.setString(2,description);q.setString(3,city);q.setString(4,join);q.setBytes(5,emblem);q.setString(6,id);q.setLong(7,Values.number(d,"revision"));if(q.executeUpdate()!=1)throw CommunityException.conflict();}store.audit(c,actor,"ORG_UPDATED",id,"Organization description/settings");return Map.of("ok",true,"revision",Values.number(d,"revision")+1);
 }
 private String joinPolicy(Connection c,String id)throws Exception{try(var q=c.prepareStatement("SELECT join_policy FROM organizations WHERE id=?")){q.setString(1,id);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.missing();return r.getString(1);}}}
 private void addMember(Connection c,String id,String user)throws Exception{try(var q=c.prepareStatement("SELECT count(*) FROM memberships WHERE org=?")){q.setString(1,id);try(var r=q.executeQuery()){r.next();if(r.getInt(1)>=100000)throw CommunityException.invalid();}}try(var q=c.prepareStatement("INSERT OR IGNORE INTO memberships VALUES(?,?,?)")){q.setString(1,id);q.setString(2,user);q.setLong(3,clock.millis());q.executeUpdate();}}
 private Map<String,Object>join(Connection c,String actor,Map<String,Object>d)throws Exception{
  String id=org(d),policy=joinPolicy(c,id);if(access.isMember(actor,id))return Map.of("ok",true);boolean invited;try(var q=c.prepareStatement("SELECT 1 FROM org_invitations WHERE org=? AND identity=? AND expires>?")){q.setString(1,id);q.setString(2,actor);q.setLong(3,clock.millis());try(var r=q.executeQuery()){invited=r.next();}}
  if(!policy.equals("OPEN")&&!invited)throw CommunityException.denied();addMember(c,id,actor);try(var q=c.prepareStatement("DELETE FROM org_invitations WHERE org=? AND identity=?")){q.setString(1,id);q.setString(2,actor);q.executeUpdate();}store.bumpEpoch(c,actor);store.audit(c,actor,"ORG_JOINED",id,invited?"Invitation":"Open membership");return Map.of("ok",true);
 }
 private Map<String,Object>joinRequest(Connection c,String actor,Map<String,Object>d)throws Exception{
  String id=org(d);if(!joinPolicy(c,id).equals("REQUEST")||access.isMember(actor,id))throw CommunityException.denied();try(var q=c.prepareStatement("SELECT count(*) FROM org_join_requests WHERE org=?")){q.setString(1,id);try(var r=q.executeQuery()){r.next();if(r.getInt(1)>=10000)throw CommunityException.invalid();}}
  try(var q=c.prepareStatement("INSERT OR IGNORE INTO org_join_requests VALUES(?,?,?)")){q.setString(1,id);q.setString(2,actor);q.setLong(3,clock.millis());q.executeUpdate();}store.audit(c,actor,"ORG_JOIN_REQUESTED",id,"Awaiting authorized membership decision");return Map.of("ok",true);
 }
 private Map<String,Object>joinRequests(Connection c,String actor,Map<String,Object>d)throws Exception{
  String id=org(d);access.require(actor,"MEMBERS_MANAGE","ORG:"+id);List<Map<String,Object>>items=new ArrayList<>();try(var q=c.prepareStatement("SELECT j.identity,i.nickname,j.created FROM org_join_requests j JOIN identities i ON i.identity=j.identity WHERE j.org=? ORDER BY j.created LIMIT 100")){q.setString(1,id);try(var r=q.executeQuery()){while(r.next())items.add(Map.of("identity",r.getString(1),"nickname",r.getString(2),"created",r.getLong(3)));}}return Map.of("items",items);
 }
 private Map<String,Object>joinDecide(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);String id=org(d),user=Values.identity(Values.string(d,"user",64));access.require(actor,"MEMBERS_MANAGE","ORG:"+id);if(!AccessControl.exists(c,"SELECT 1 FROM org_join_requests WHERE org=? AND identity=?",id,user))throw CommunityException.missing();boolean approve=Values.bool(d,"approve",false);if(approve)addMember(c,id,user);try(var q=c.prepareStatement("DELETE FROM org_join_requests WHERE org=? AND identity=?")){q.setString(1,id);q.setString(2,user);q.executeUpdate();}store.bumpEpoch(c,user);store.notifyAccount(user,"ORGANIZATION",approve?"Заявка на вступление одобрена":"Заявка на вступление отклонена");store.audit(c,actor,approve?"ORG_MEMBER_APPROVED":"ORG_MEMBER_REJECTED",user,id);return Map.of("ok",true);
 }
 private Map<String,Object>invite(Connection c,String actor,Map<String,Object>d)throws Exception{
  step(actor,d);String id=org(d),user=Values.identity(Values.string(d,"user",64));access.require(actor,"MEMBERS_MANAGE","ORG:"+id);if(access.isMember(user,id))throw CommunityException.conflict();try(var q=c.prepareStatement("SELECT count(*) FROM org_invitations WHERE org=? AND expires>?")){q.setString(1,id);q.setLong(2,clock.millis());try(var r=q.executeQuery()){r.next();if(r.getInt(1)>=1000)throw CommunityException.invalid();}}
  try(var q=c.prepareStatement("INSERT INTO org_invitations VALUES(?,?,?) ON CONFLICT(org,identity) DO UPDATE SET expires=excluded.expires")){q.setString(1,id);q.setString(2,user);q.setLong(3,clock.millis()+7*86400000L);q.executeUpdate();}store.audit(c,actor,"ORG_MEMBER_INVITED",user,id);store.notifyAccount(user,"ORGANIZATION","Вы получили приглашение в организацию");return Map.of("ok",true);
 }
 private Map<String,Object>leave(Connection c,String actor,Map<String,Object>d,boolean remove)throws Exception{
  String id=org(d),user=remove?Values.identity(Values.string(d,"user",64)):actor;if(remove){step(actor,d);access.require(actor,"MEMBERS_MANAGE","ORG:"+id);}if(AccessControl.exists(c,"SELECT 1 FROM organizations WHERE id=? AND owner=?",id,user))throw new CommunityException("OWNER_REQUIRED","Перед выходом необходимо согласовать передачу управления");
  try(var q=c.prepareStatement("DELETE FROM memberships WHERE org=? AND identity=?")){q.setString(1,id);q.setString(2,user);q.executeUpdate();}try(var q=c.prepareStatement("DELETE FROM assignments WHERE identity=? AND role IN (SELECT id FROM roles WHERE scope=?)")){q.setString(1,user);q.setString(2,"ORG:"+id);q.executeUpdate();}store.bumpEpoch(c,user);store.notifyAccount(user,"ORGANIZATION",remove?"Ваше участие в организации прекращено":"Вы вышли из организации");store.audit(c,actor,remove?"ORG_MEMBER_REMOVED":"ORG_MEMBER_LEFT",user,id);return Map.of("ok",true);
 }
 private Map<String,Object>members(Connection c,String actor,Map<String,Object>d)throws Exception{
  String id=org(d);if(!access.isMember(actor,id))throw CommunityException.denied();String after=Values.optional(d,"after",64);List<Map<String,Object>>items=new ArrayList<>();try(var q=c.prepareStatement("SELECT m.identity,i.nickname FROM memberships m JOIN identities i ON i.identity=m.identity WHERE m.org=? AND m.identity>? ORDER BY m.identity LIMIT 25")){q.setString(1,id);q.setString(2,after);try(var r=q.executeQuery()){while(r.next()){String user=r.getString(1);List<Map<String,Object>>roles=new ArrayList<>();try(var x=c.prepareStatement("SELECT r.id,r.name FROM roles r JOIN assignments a ON a.role=r.id WHERE a.identity=? AND r.scope=? ORDER BY r.name LIMIT 33")){x.setString(1,user);x.setString(2,"ORG:"+id);try(var z=x.executeQuery()){while(z.next())roles.add(Map.of("id",z.getString(1),"name",z.getString(2)));}}boolean truncated=roles.size()>32;if(truncated)roles.removeLast();items.add(Map.of("identity",user,"nickname",r.getString(2),"roles",roles,"rolesTruncated",truncated));}}}return Map.of("items",items,"nextAfter",items.size()==25?items.getLast().get("identity"):"");
 }
 private Map<String,Object>memberRoles(Connection c,String actor,Map<String,Object>d)throws Exception{String id=org(d),user=Values.identity(Values.string(d,"user",64)),after=Values.optional(d,"after",36);if(!access.isMember(actor,id)||!access.isMember(user,id))throw CommunityException.missing();List<Map<String,Object>>items=new ArrayList<>();try(var q=c.prepareStatement("SELECT r.id,r.name FROM roles r JOIN assignments a ON a.role=r.id WHERE a.identity=? AND r.scope=? AND r.id>? ORDER BY r.id LIMIT 30")){q.setString(1,user);q.setString(2,"ORG:"+id);q.setString(3,after);try(var r=q.executeQuery()){while(r.next())items.add(Map.of("id",r.getString(1),"name",r.getString(2)));}}return Map.of("items",items,"nextAfter",items.size()==30?items.getLast().get("id"):"");}
 private Map<String,Object>callBatch(Connection c,String actor,Map<String,Object>d)throws Exception{
  Set<String>targets=Values.strings(d,"targets",256);String direction=Values.string(d,"direction",16);if(!Set.of("INCOMING","OUTGOING").contains(direction))throw CommunityException.invalid();List<Map<String,Object>>decisions=new ArrayList<>();for(String target:new TreeSet<>(targets)){Values.identity(target);if(actor.equals(target)){decisions.add(Map.of("target",target,"allowed",false));continue;}var result=call(c,actor,Map.of("target",target,"direction",direction));decisions.add(Map.of("target",target,"allowed",result.get("allowed")));}return Map.of("decisions",decisions,"epoch",access.authorizationEpoch(actor),"expires",clock.millis()+20000);
 }
 private Map<String,Object>call(Connection c,String actor,Map<String,Object>d)throws Exception{
  String target=Values.identity(Values.string(d,"target",64)),direction=Values.string(d,"direction",16);if(!Set.of("INCOMING","OUTGOING").contains(direction)||actor.equals(target))throw CommunityException.invalid();String sender=direction.equals("OUTGOING")?actor:target,recipient=direction.equals("OUTGOING")?target:actor;boolean allowed=false;
  try(var q=c.prepareStatement("SELECT a.org FROM memberships a JOIN memberships b ON b.org=a.org WHERE a.identity=? AND b.identity=? LIMIT 256")){q.setString(1,sender);q.setString(2,recipient);try(var r=q.executeQuery()){while(r.next()){String scope="ORG:"+r.getString(1);if(access.has(sender,"VOICE_CALL",scope)&&access.has(recipient,"VOICE_RECEIVE",scope)){allowed=true;break;}}}}
  return Map.of("allowed",allowed,"epoch",access.authorizationEpoch(actor),"expires",clock.millis()+5000);
 }
}
