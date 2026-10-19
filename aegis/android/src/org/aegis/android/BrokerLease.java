package org.aegis.android;
import org.securemail.ecosystem.protocol.IdentityProtocol;
/** A short independent lock for an immutable lease. Never held across Binder, sockets or callbacks. */
public final class BrokerLease {
  private IdentityProtocol.Capability current;private long deadline,epoch;
  public synchronized long epoch(){return epoch;}
  public synchronized IdentityProtocol.Capability peek(){return current;}
  public synchronized boolean active(long now){return current!=null&&now<deadline;}
  public synchronized IdentityProtocol.Capability capability(long now){if(current==null||now>=deadline)throw new SecurityException("Сессия заблокирована");return current;}
  public synchronized void install(long expected,IdentityProtocol.Capability cap,long until,long now){if(epoch!=expected||until<=now||until-now>AndroidPolicy.LOCAL_LEASE)throw new SecurityException("Ответ отозванной IPC сессии");if(current!=null&&(cap.generation<current.generation||!cap.accountId.equals(current.accountId)))throw new SecurityException("Недействительное поколение");current=cap;deadline=until;}
  public synchronized boolean expire(long now){if(current==null||now<deadline)return false;return clear();}
  public synchronized boolean clear(){boolean was=current!=null;current=null;deadline=0;epoch++;return was;}
}
