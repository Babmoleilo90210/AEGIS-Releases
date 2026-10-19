package org.securemail.community.gateway600;
import org.securemail.community.core.*;
/** Request-only capability context. Construction/installation confined to authenticated gateway package. */
public final class TrustedContext600 {
    @FunctionalInterface interface Check {void run()throws Exception;}
    @FunctionalInterface interface Critical {Object execute(String actor,String id,String kind,String payload,CommunityStore.SqlWork<?> work)throws Exception;}
    private static final ThreadLocal<TrustedContext600> LOCAL=new ThreadLocal<>();
    private final String account;private final boolean administrator;private final long stepUpUntil;private final Check recheck,step;private final Critical critical;
    TrustedContext600(String account,boolean administrator,long stepUpUntil,Check recheck,Check step,Critical critical){this.account=account;this.administrator=administrator;this.stepUpUntil=stepUpUntil;this.recheck=recheck;this.step=step;this.critical=critical;}
    /** Internal trusted server callback. It is not an HTTP, Binder or client role setter. */
    public interface ServerAuthority {String accountId();boolean administrator();long stepUpUntil();void recheck()throws Exception;void requireStepUp()throws Exception;}
    public static <T>T withServerAuthority(ServerAuthority authority,CommunityStore.SqlWork<T> work)throws Exception {authority.recheck();TrustedContext600 context=new TrustedContext600(authority.accountId(),authority.administrator(),authority.stepUpUntil(),authority::recheck,authority::requireStepUp,(actor,id,kind,payload,task)->{throw CommunityException.denied();});return run(context,db->{T result=work.run(db);authority.recheck();return result;});}
    public static TrustedContext600 current(){return LOCAL.get();}
    public boolean isAdministrator(String actor)throws Exception {recheck.run();return account.equals(actor)&&administrator;}
    public void requireStepUp(String actor)throws Exception {if(!account.equals(actor)||stepUpUntil<=System.currentTimeMillis())throw new CommunityException("REAUTH_REQUIRED","Повторно подтвердите личность");recheck.run();step.run();}
    public <T>T executeCritical(String actor,String id,String kind,String payload,CommunityStore.SqlWork<T> work)throws Exception {if(!account.equals(actor)||!administrator)throw CommunityException.denied();requireStepUp(actor);@SuppressWarnings("unchecked")T result=(T)critical.execute(actor,id,kind,payload,work);return result;}
    static <T>T run(TrustedContext600 context,CommunityStore.SqlWork<T> action)throws Exception {if(LOCAL.get()!=null)throw new IllegalStateException("Nested ecosystem context");LOCAL.set(context);try{return action.run(null);}finally{LOCAL.remove();}}
}
