package org.aegis.android;

import android.app.Service;
import android.content.Intent;
import android.os.*;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Each transaction authenticates its kernel UID; no localhost secret API. */
public final class CoreBrokerService extends Service {
    static final String DESCRIPTOR="org.aegis.android.SessionBroker.v1";
    static final int CHALLENGE=1,LEASE=2,STATUS=3,EVENT=4,OBSERVE=5,TOUCH=6,PROPOSE=7,CONSENT=8,PUBLIC_CONFIG=9,VOICE_STAGE=10,VOICE_PENDING=11,VOICE_DELIVER=12,VOICE_RECEIVE=13,VOICE_PUBLISH=14,VOICE_DROP=15;
    private final java.util.concurrent.ScheduledExecutorService rechecks=java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-identity-recheck");t.setDaemon(true);return t;});
    private static CoreBrokerService running;
    private final android.content.BroadcastReceiver screen=new android.content.BroadcastReceiver(){public void onReceive(android.content.Context c,Intent i){if(Intent.ACTION_SCREEN_OFF.equals(i.getAction())){SessionLedger.get(c).lock();notifyRevoked(false);}}};
    private final VoiceHandoff voiceHandoff=new VoiceHandoff();
    private final Map<String,Challenge> challenges=new HashMap<>();private final Map<String,IBinder> observers=new HashMap<>();
    private static final class Challenge {final String value=IdentityProtocol.nonce();final long until=SystemClock.elapsedRealtime()+30_000;}
    public void onCreate(){super.onCreate();synchronized(CoreBrokerService.class){running=this;}registerReceiver(screen,new android.content.IntentFilter(Intent.ACTION_SCREEN_OFF),android.content.Context.RECEIVER_NOT_EXPORTED);rechecks.scheduleWithFixedDelay(()->CoreIdentity.get(this).recheck(),20,20,java.util.concurrent.TimeUnit.SECONDS);}
    public static void revoked(){notifyRunning(false);}
    public static void exited(){notifyRunning(true);}
    private static void notifyRunning(boolean exit){CoreBrokerService service;synchronized(CoreBrokerService.class){service=running;}if(service!=null)service.notifyRevoked(exit);}
    private synchronized void notifyRevoked(boolean exit){NetworkVpnService.stopLocked(this);voiceHandoff.clear();if(exit)CoreTor.get(this).stop();else try{rechecks.execute(()->{try{CoreTor.get(this).drop(null);}catch(Exception ignored){}});}catch(java.util.concurrent.RejectedExecutionException closing){}for(IBinder observer:new ArrayList<>(observers.values())){Parcel p=Parcel.obtain();try{p.writeInterfaceToken(DESCRIPTOR);p.writeInt(exit?1:0);observer.transact(1,p,null,IBinder.FLAG_ONEWAY);}catch(RemoteException dead){/* lease expiration remains authoritative */}finally{p.recycle();}}challenges.clear();}
    private final Binder binder=new Binder(){
        @Override protected boolean onTransact(int code,Parcel data,Parcel reply,int flags)throws RemoteException {
            if(code==INTERFACE_TRANSACTION){reply.writeString(DESCRIPTOR);return true;}
            if(code<CHALLENGE||code>VOICE_DROP)return super.onTransact(code,data,reply,flags);
            String pkg=PackageTrust.caller(CoreBrokerService.this);
            if(AndroidPolicy.CORE.equals(pkg))throw new SecurityException("Служебный вызов главного приложения не требуется");
            if(data.dataSize()>(code==VOICE_DELIVER?70000:16384))throw new SecurityException("Слишком большой IPC запрос");data.enforceInterface(DESCRIPTOR);
            try{
                SessionLedger ledger=SessionLedger.get(CoreBrokerService.this);
                if(code==CHALLENGE){data.enforceNoDataAvail();Challenge challenge=new Challenge();synchronized(CoreBrokerService.this){challenges.put(pkg,challenge);}reply.writeNoException();reply.writeString(challenge.value);return true;}
                if(code==STATUS){data.enforceNoDataAvail();reply.writeNoException();reply.writeInt(ledger.active()?1:0);return true;}
                if(code==PUBLIC_CONFIG){data.enforceNoDataAvail();String config=CoreIdentity.get(CoreBrokerService.this).publicConfig(pkg).toString();reply.writeNoException();reply.writeString(config);return true;}
                byte[] key=data.createByteArray(),signature=data.createByteArray();if(key==null||key.length!=44||signature==null||signature.length!=64)throw new SecurityException("Доказательство приложения отсутствует");Challenge challenge;synchronized(CoreBrokerService.this){challenge=challenges.remove(pkg);}if(challenge==null||SystemClock.elapsedRealtime()>=challenge.until||!IdentityProtocol.verify(key,AndroidPolicy.proof(pkg,challenge.value,key,code),signature))throw new SecurityException("Повторный или недействительный IPC запрос");
                // A known application may observe lock/exit even before it has a data grant.
                // This gives no account data and allows an explicit full exit to stop a local mic test.
                if(code==OBSERVE){IBinder observer=data.readStrongBinder();data.enforceNoDataAvail();if(observer==null)throw new SecurityException("Наблюдатель отсутствует");synchronized(CoreBrokerService.this){observers.put(pkg,observer);}observer.linkToDeath(()->{boolean removed;synchronized(CoreBrokerService.this){removed=observers.remove(pkg,observer);}if(removed&&AndroidPolicy.GLAS.equals(pkg))try{rechecks.execute(()->{try{CoreTor.get(CoreBrokerService.this).drop(null);}catch(Exception ignored){}});}catch(java.util.concurrent.RejectedExecutionException closing){}},0);reply.writeNoException();return true;}
                if(code==PROPOSE){data.enforceNoDataAvail();String proposal=CoreIdentity.get(CoreBrokerService.this).propose(pkg,key);reply.writeNoException();reply.writeString(proposal);return true;}
                if(code==CONSENT){String id=data.readString();byte[] consent=data.createByteArray();data.enforceNoDataAvail();if(id==null||id.length()!=43||consent==null||consent.length!=64)throw new SecurityException("Подтверждение допуска отсутствует");String wire=CoreIdentity.get(CoreBrokerService.this).consent(pkg,key,id,consent);reply.writeNoException();reply.writeString(wire);return true;}
                String token=ledger.lease(pkg,key);
                if(code==VOICE_PUBLISH||code==VOICE_DROP){
                    if(!AndroidPolicy.GLAS.equals(pkg))throw new SecurityException("Маршрут доступен только Гласу");IdentityProtocol.Capability cap=IdentityProtocol.decodeCapability(token);if(!cap.capabilities.contains(IdentityProtocol.Scope.VOICE_CALL))throw new SecurityException("Звонки не разрешены");
                    if(code==VOICE_DROP){data.enforceNoDataAvail();CoreTor.get(CoreBrokerService.this).drop(cap.tokenId);reply.writeNoException();return true;}
                    int port=data.readInt();data.enforceNoDataAvail();String onion=CoreTor.get(CoreBrokerService.this).publish(cap,port);if(!ledger.active()||!token.equals(ledger.lease(pkg,key))){CoreTor.get(CoreBrokerService.this).drop(null);throw new SecurityException("Сессия заблокирована или изменена");}reply.writeNoException();reply.writeString(onion);return true;
                }
                if(code>=VOICE_STAGE&&code<=VOICE_RECEIVE){
                    byte[] server=IdentityProtocol.unb64(ledger.publicPin(),44);IdentityProtocol.Capability current=IdentityProtocol.decodeCapability(token);long wall=System.currentTimeMillis(),elapsed=SystemClock.elapsedRealtime();
                    if(code==VOICE_STAGE){data.enforceNoDataAvail();if(!AndroidPolicy.GLAS.equals(pkg))throw new SecurityException("Запрос доступен только Гласу");String request=voiceHandoff.stage(token,IdentityProtocol.decodeCapability(ledger.coreToken()),server,wall,elapsed);rechecks.schedule(()->voiceHandoff.expire(SystemClock.elapsedRealtime()),VoiceHandoff.TTL,java.util.concurrent.TimeUnit.MILLISECONDS);reply.writeNoException();reply.writeString(request);return true;}
                    if(code==VOICE_PENDING){data.enforceNoDataAvail();if(!AndroidPolicy.MAIL.equals(pkg))throw new SecurityException("Подтверждение доступно только Почте");String pending=voiceHandoff.pending(current,server,wall,elapsed);reply.writeNoException();reply.writeString(pending);return true;}
                    if(code==VOICE_DELIVER){if(!AndroidPolicy.MAIL.equals(pkg))throw new SecurityException("Подтверждение доступно только Почте");String request=data.readString();byte[] grant=data.createByteArray();data.enforceNoDataAvail();try{voiceHandoff.deliver(request,grant,current,server,wall,elapsed);}finally{if(grant!=null)Arrays.fill(grant,(byte)0);}reply.writeNoException();return true;}
                    data.enforceNoDataAvail();if(!AndroidPolicy.GLAS.equals(pkg))throw new SecurityException("Допуск доступен только Гласу");byte[] grant=voiceHandoff.receive(current,server,wall,elapsed);reply.writeNoException();reply.writeByteArray(grant);Arrays.fill(grant,(byte)0);return true;
                }
                if(code==LEASE){data.enforceNoDataAvail();reply.writeNoException();reply.writeString(ledger.publicPin());reply.writeString(token);reply.writeLong(SystemClock.elapsedRealtime()+AndroidPolicy.LOCAL_LEASE);return true;}
                if(code==TOUCH){data.enforceNoDataAvail();ledger.touch();reply.writeNoException();return true;}
                String id=data.readString();int count=data.readInt();data.enforceNoDataAvail();EventQueue.get(CoreBrokerService.this).accept(pkg,id,count);reply.writeNoException();return true;
            }catch(SecurityException denied){throw denied;}catch(Exception failure){throw new SecurityException("Операция недоступна");}
        }
    };
    @Override public IBinder onBind(Intent intent){return binder;}
    @Override public void onTaskRemoved(Intent root){try{SessionLedger.get(this).logout();}catch(Exception ignored){}notifyRevoked(true);stopSelf();}
    @Override public void onDestroy(){SessionLedger.get(this).lock();notifyRevoked(true);unregisterReceiver(screen);rechecks.shutdownNow();CoreIdentity.get(this).closeNetwork();synchronized(CoreBrokerService.class){if(running==this)running=null;}super.onDestroy();}
}
