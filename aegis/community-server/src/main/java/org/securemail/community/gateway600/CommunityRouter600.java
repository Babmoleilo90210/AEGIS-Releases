package org.securemail.community.gateway600;
import org.securemail.community.access.AccessControl;
import org.securemail.community.core.*;
import org.securemail.community.org.OrgAdminService;
import org.securemail.community.content.ContentService;
import org.securemail.community.agent.AgentService;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import java.util.*;
/** Existing implementations with a request-scoped verified ecosystem principal; no legacy root signing. */
public final class CommunityRouter600 {
    private final CommunityStore store;private final AccessControl access;private final OrgAdminService organizations;private final ContentService content;private final AgentService agent;private final CommunityIdentityBridge600 bridge;private final CommunityCritical600 critical;
    public CommunityRouter600(CommunityStore store,AccessControl access,OrgAdminService organizations,ContentService content,AgentService agent,CommunityIdentityBridge600 bridge)throws Exception {this.store=store;this.access=access;this.organizations=organizations;this.content=content;this.agent=agent;this.bridge=bridge;this.critical=new CommunityCritical600(store,bridge);}
    public Map<String,Object> handle(CommunityIdentityBridge600.Evidence evidence,String action,Map<String,Object> args,Map<String,Object> criticalProof)throws Exception {
        if(!evidence.authenticated||!evidence.action.equals(action)||!evidence.args.equals(args))throw CommunityException.denied();
        if(action.startsWith("account.factor.")||action.startsWith("admin.stepup.")||action.startsWith("admin.factor.")||action.startsWith("admin.administrators.")||action.startsWith("content.library.")||action.startsWith("library600.")||action.startsWith("agent.library.")||action.startsWith("agent.worker."))throw new CommunityException("SEPARATE_AUTHORITY","Используйте отдельное приложение или управление Identity");
        if(args.get("permissions") instanceof List<?> permissions&&permissions.contains("AGENT_WORK"))throw new CommunityException("SERVICE_IDENTITY","Рабочая служба подключается отдельно от пользовательских ролей");
        bridge.recheck(evidence,true);boolean administrator=evidence.cap.capabilities.contains(IdentityProtocol.Scope.ADMIN);
        CommunityCritical600.Receipt receipt=null;
        if(args.containsKey("requestId")&&!action.equals("admin.critical.request")&&!action.equals("admin.critical.approve"))receipt=critical.consume(evidence,args,criticalProof);
        final CommunityCritical600.Receipt selected=receipt;
        TrustedContext600 context=new TrustedContext600(evidence.cap.accountId,administrator,evidence.stepUpUntil,()->bridge.recheck(evidence,false),()->bridge.recheckStepUp(evidence),(actor,id,kind,payload,work)->critical.execute(evidence,selected,actor,id,kind,payload,work));
        return TrustedContext600.run(context,unused->{
            if(action.equals("admin.critical.request")){context.requireStepUp(evidence.cap.accountId);return critical.request(evidence,args,criticalProof);}
            if(action.equals("admin.critical.approve")){context.requireStepUp(evidence.cap.accountId);return critical.approve(evidence,args,criticalProof);}
            if(action.equals("admin.critical.list"))return critical.list(args);
            if(action.equals("community600.critical.get"))return critical.metadata(Values.string(args,"id",36));
            if(action.startsWith("agent.")){agent.enforceWorkerBoundary(evidence.cap.accountId,action);Map<String,Object> result=agent.handle(evidence.cap.accountId,action,args);bridge.recheck(evidence,true);return result;}
            return store.tx(db->{agent.enforceWorkerBoundary(evidence.cap.accountId,action);Map<String,Object> result;if(organizations.supports(action))result=organizations.handle(evidence.cap.accountId,action,args);else if(content.supports(action))result=content.handle(evidence.cap.accountId,action,args);else throw CommunityException.invalid();bridge.recheck(evidence,true);return result;});
        });
    }
}
