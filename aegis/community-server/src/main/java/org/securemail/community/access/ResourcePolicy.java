package org.securemail.community.access;
import java.util.Set;
/** All constraints combine with AND. User/org allowlists combine with OR. Clearance grants no permission. */
public record ResourcePolicy(String scope,int minLevel,Set<String> requiredPermissions,Set<String> allowedOrgs,Set<String> allowedUsers,boolean offlineAllowed){
 public ResourcePolicy {if(scope==null||minLevel<0||minLevel>1000000)throw new IllegalArgumentException("policy");requiredPermissions=Set.copyOf(requiredPermissions);allowedOrgs=Set.copyOf(allowedOrgs);allowedUsers=Set.copyOf(allowedUsers);if(requiredPermissions.size()>128||allowedOrgs.size()>128||allowedUsers.size()>256)throw new IllegalArgumentException("policy bounds");}
 public static ResourcePolicy publicPolicy(){return new ResourcePolicy("GLOBAL",0,Set.of(),Set.of(),Set.of(),false);}
}
