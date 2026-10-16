package org.securemail.community.org;
import org.securemail.community.core.*;
import org.securemail.community.access.*;
import org.securemail.community.admin.AdminService;
import java.time.Clock;
import java.util.Map;
/** Router boundary. Transport authenticates an identity before dispatching actions. */
public final class OrgAdminService {
 private final OrganizationService organizations;private final AdminService admin;
 public OrgAdminService(CommunityStore store,AccessControl access,Clock clock){organizations=new OrganizationService(store,access,clock);admin=new AdminService(store,access,clock);}
 public boolean supports(String action){return action.equals("community.me")||action.equals("community.profile.update")||action.startsWith("account.factor.")||action.startsWith("org.")||action.startsWith("admin.");}
 public Map<String,Object> handle(String actor,String action,Map<String,Object>data)throws Exception{return action.startsWith("org.")&&!action.equals("org.roles.list")?organizations.handle(actor,action,data):admin.handle(actor,action,data);}
}
