package org.securemail.community.access;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.community.core.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
/** Real SQL/RPC allow+deny regression including legacy absent fields and mutation escape routes. */
class RoleDeny600Test {
 @TempDir Path home;AccessControlTest.Fixture f;
 @BeforeEach void setup()throws Exception{f=new AccessControlTest.Fixture(home.resolve("community.db"));}
 @AfterEach void close()throws Exception{f.access.close();f.store.close();}
 String role(String scope,String name,List<String> allow,List<String> deny,List<String> parents)throws Exception{
  Map<String,Object> data=Map.of("scope",scope,"name",name,"permissions",allow,"deniedPermissions",deny,"parents",parents,"clearance",0);
  return (String)(scope.equals("GLOBAL")?f.critical("admin.roles.create","ROLE_CREATE",data):f.call(f.u,"admin.roles.create",f.stepped(f.u,data))).get("id");
 }
 void assign(String role,String user)throws Exception{f.critical("admin.roles.assign","ROLE_ASSIGN",Map.of("role",role,"user",user));}
 @Test void globalDenyOverridesInheritedAndIndependentAssignedAllows()throws Exception{
  String grant=role("GLOBAL","Разрешено",List.of("NEWS_CREATE"),List.of(),List.of());
  String deny=role("GLOBAL","Запрещено",List.of(),List.of("NEWS_CREATE"),List.of());
  String child=role("GLOBAL","Наследник",List.of("NEWS_CREATE"),List.of(),List.of(deny));
  assign(grant,f.u.id);assertTrue(f.access.has(f.u.id,"NEWS_CREATE","GLOBAL"));assign(child,f.u.id);
  assertFalse(f.access.has(f.u.id,"NEWS_CREATE","GLOBAL"));assertEquals(Set.of("NEWS_CREATE"),f.store.tx(c->f.access.roleRights(c,child).deniedPermissions()));assertEquals(Set.of(),f.store.tx(c->f.access.roleRights(c,child).permissions()));
 }
 @Test void legacyUpdateWithoutDenialsPreservesSecurityPolicyAndListReturnsExplicitDenials()throws Exception{
  f.enroll(f.u);String org=f.org(f.u,"OPEN",Set.of("NEWS_CREATE")),scope="ORG:"+org;
  String deny=role(scope,"Ограничение",List.of(),List.of("NEWS_CREATE"),List.of());
  f.call(f.u,"admin.roles.update",f.stepped(f.u,Map.of("id",deny,"revision",1,"scope",scope,"name","Новое имя","permissions",List.of(),"parents",List.of(),"clearance",0)));
  assertEquals(Set.of("NEWS_CREATE"),f.store.tx(c->f.access.roleRights(c,deny).deniedPermissions()));
  Map<?,?> row=(Map<?,?>)((List<?>)f.call(f.u,"org.roles.list",Map.of("scope",scope)).get("items")).getFirst();assertEquals(List.of("NEWS_CREATE"),row.get("deniedPermissions"));
  f.call(f.u,"admin.roles.update",f.stepped(f.u,Map.of("id",deny,"revision",2,"scope",scope,"name","Очистить явно","permissions",List.of(),"deniedPermissions",List.of(),"parents",List.of(),"clearance",0)));
  assertEquals(Set.of(),f.store.tx(c->f.access.roleRights(c,deny).deniedPermissions()));
 }
 @Test void organizationDenyAlsoRestrictsImplicitOwnerDelegationsButNotAnotherScope()throws Exception{
  f.enroll(f.u);String org=f.org(f.u,"OPEN",Set.of("NEWS_CREATE")),other=f.org(f.u,"OPEN",Set.of("NEWS_CREATE"));String scope="ORG:"+org;
  String deny=role(scope,"Ограниченный владелец",List.of(),List.of("NEWS_CREATE"),List.of());f.call(f.u,"admin.roles.assign",f.stepped(f.u,Map.of("role",deny,"user",f.u.id)));
  assertFalse(f.access.has(f.u.id,"NEWS_CREATE",scope));assertTrue(f.access.has(f.u.id,"ROLES_MANAGE",scope));assertTrue(f.access.has(f.u.id,"NEWS_CREATE","ORG:"+other));
 }
 @Test void roleManagerCannotRemoveOwnDenyThroughUpdateDeleteRevokeOrInheritanceUnlink()throws Exception{
  f.enroll(f.u);f.enroll(f.v);String org=f.org(f.u,"OPEN",Set.of("NEWS_CREATE")),scope="ORG:"+org;f.call(f.v,"org.join",Map.of("id",org));
  String grant=role(scope,"Управление",List.of("ROLES_MANAGE","NEWS_CREATE"),List.of(),List.of()),deny=role(scope,"Ограничение",List.of(),List.of("NEWS_CREATE"),List.of());
  for(String r:List.of(grant,deny))f.call(f.u,"admin.roles.assign",f.stepped(f.u,Map.of("role",r,"user",f.v.id)));
  long epoch=f.access.authorizationEpoch(f.v.id);assertFalse(f.access.has(f.v.id,"NEWS_CREATE",scope));
  assertThrows(CommunityException.class,()->f.call(f.v,"admin.roles.update",f.stepped(f.v,Map.of("id",deny,"revision",1,"scope",scope,"name","Снять запрет","permissions",List.of(),"deniedPermissions",List.of(),"parents",List.of(),"clearance",0))));
  assertThrows(CommunityException.class,()->f.call(f.v,"admin.roles.delete",f.stepped(f.v,Map.of("id",deny,"revision",1))));
  assertThrows(CommunityException.class,()->f.call(f.v,"admin.roles.revoke",f.stepped(f.v,Map.of("role",deny,"user",f.v.id))));
  String inherited=role(scope,"Наследник",List.of("ROLES_MANAGE","NEWS_CREATE"),List.of(),List.of(deny));f.call(f.u,"admin.roles.assign",f.stepped(f.u,Map.of("role",inherited,"user",f.v.id)));
  assertThrows(CommunityException.class,()->f.call(f.v,"admin.roles.update",f.stepped(f.v,Map.of("id",inherited,"revision",1,"scope",scope,"name","Обход предка","permissions",List.of("ROLES_MANAGE","NEWS_CREATE"),"parents",List.of(),"clearance",0))));
  assertFalse(f.access.has(f.v.id,"NEWS_CREATE",scope));assertTrue(f.access.authorizationEpoch(f.v.id)>=epoch);
 }
 @Test void leavingAndRejoiningCannotClearScopedDenyOrRestorePreviousGrants()throws Exception{
  f.enroll(f.u);String org=f.org(f.u,"OPEN",Set.of("NEWS_CREATE","NEWS_EDIT")),other=f.org(f.u,"OPEN",Set.of("NEWS_CREATE")),scope="ORG:"+org;f.call(f.v,"org.join",Map.of("id",org));f.call(f.v,"org.join",Map.of("id",other));
  String global=role("GLOBAL","Глобальное создание",List.of("NEWS_CREATE"),List.of(),List.of());assign(global,f.v.id);
  String restricted=role(scope,"Сочетание",List.of("NEWS_EDIT"),List.of("NEWS_CREATE"),List.of());f.call(f.u,"admin.roles.assign",f.stepped(f.u,Map.of("role",restricted,"user",f.v.id)));
  assertFalse(f.access.has(f.v.id,"NEWS_CREATE",scope));assertTrue(f.access.has(f.v.id,"NEWS_EDIT",scope));long epoch=f.access.authorizationEpoch(f.v.id);
  f.call(f.v,"org.leave",Map.of("id",org));assertFalse(f.access.has(f.v.id,"NEWS_EDIT",scope));assertTrue(f.access.has(f.v.id,"NEWS_CREATE","GLOBAL"));assertTrue(f.access.has(f.v.id,"NEWS_CREATE","ORG:"+other));
  f.call(f.v,"org.join",Map.of("id",org));assertFalse(f.access.has(f.v.id,"NEWS_CREATE",scope));assertFalse(f.access.has(f.v.id,"NEWS_EDIT",scope));assertTrue(f.access.authorizationEpoch(f.v.id)>epoch);
  f.call(f.u,"admin.roles.revoke",f.stepped(f.u,Map.of("role",restricted,"user",f.v.id)));assertTrue(f.access.has(f.v.id,"NEWS_CREATE",scope));assertFalse(f.access.has(f.v.id,"NEWS_EDIT",scope));
 }
 @Test void persistentDenyChangesAdvanceAffectedEpochAfterMemberHasLeft()throws Exception{
  f.enroll(f.u);String org=f.org(f.u,"OPEN",Set.of("NEWS_CREATE")),scope="ORG:"+org;f.call(f.v,"org.join",Map.of("id",org));String restricted=role(scope,"Запрет",List.of(),List.of("NEWS_CREATE"),List.of());f.call(f.u,"admin.roles.assign",f.stepped(f.u,Map.of("role",restricted,"user",f.v.id)));f.call(f.v,"org.leave",Map.of("id",org));long epoch=f.access.authorizationEpoch(f.v.id);
  f.call(f.u,"admin.roles.update",f.stepped(f.u,Map.of("id",restricted,"revision",1,"scope",scope,"name","Уточнено","permissions",List.of(),"deniedPermissions",List.of("NEWS_CREATE"),"parents",List.of(),"clearance",0)));assertTrue(f.access.authorizationEpoch(f.v.id)>epoch);
 }
 @Test void authorizedDeletionClearsPersistentRestrictionAndAdvancesEpoch()throws Exception{
  f.enroll(f.u);String org=f.org(f.u,"OPEN",Set.of("NEWS_CREATE")),scope="ORG:"+org;f.call(f.v,"org.join",Map.of("id",org));String restricted=role(scope,"Удаляемый запрет",List.of(),List.of("NEWS_CREATE"),List.of());f.call(f.u,"admin.roles.assign",f.stepped(f.u,Map.of("role",restricted,"user",f.v.id)));f.call(f.v,"org.leave",Map.of("id",org));long epoch=f.access.authorizationEpoch(f.v.id);
  f.call(f.u,"admin.roles.delete",f.stepped(f.u,Map.of("id",restricted,"revision",1)));assertTrue(f.access.authorizationEpoch(f.v.id)>epoch);assertEquals(0,f.store.<Integer>tx(c->{try(var q=c.prepareStatement("SELECT count(*) FROM role_restrictions WHERE identity=?")){q.setString(1,f.v.id);try(var r=q.executeQuery()){r.next();return r.getInt(1);}}}));
 }
 @Test void administrativeOverrideDoesNotGrantRequiredClosedResourceReadPermission()throws Exception{
  assertTrue(f.access.isGlobalAdmin(f.a.id));ResourcePolicy policy=new ResourcePolicy("GLOBAL",0,Set.of("LIBRARY_READ"),Set.of(),Set.of(),false);
  assertFalse(f.access.canRead(f.a.id,policy));String grant=role("GLOBAL","Чтение",List.of("LIBRARY_READ"),List.of(),List.of());assign(grant,f.a.id);assertTrue(f.access.canRead(f.a.id,policy));
  String deny=role("GLOBAL","Закрыть чтение",List.of(),List.of("LIBRARY_READ"),List.of());assign(deny,f.a.id);assertFalse(f.access.canRead(f.a.id,policy));assertTrue(f.access.isGlobalAdmin(f.a.id));
 }
}
