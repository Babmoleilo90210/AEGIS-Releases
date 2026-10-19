package org.aegis.android;
import android.app.*;
import android.content.*;
import android.os.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.torproject.jni.TorService;
/** Official Tor native service in its own Core UID process; raw control never crosses Binder. */
public final class CoreTorService extends TorService {
  static final String DESCRIPTOR="org.aegis.android.OwnedTor.v1";
  static final int STATUS=1,PUBLISH=2,DROP=3;
  private String onion;
  private final Binder typed=new Binder(){@Override protected boolean onTransact(int code,Parcel data,Parcel reply,int flags)throws RemoteException {
    if(Binder.getCallingUid()!=android.os.Process.myUid())throw new SecurityException("Tor доступен только главному АЕГИС");
    if(code==INTERFACE_TRANSACTION){reply.writeString(DESCRIPTOR);return true;}
    if(code<STATUS||code>DROP)return super.onTransact(code,data,reply,flags);
    if(data.dataSize()>512)throw new SecurityException("Размер команды Tor");data.enforceInterface(DESCRIPTOR);
    synchronized(CoreTorService.this){try{
      if(code==STATUS){data.enforceNoDataAvail();String boot=getInfo("status/bootstrap-phase"),ports=getInfo("net/listeners/socks");reply.writeNoException();reply.writeInt(android.os.Process.myPid());reply.writeString(boot==null?"Подготовка Tor":boot.substring(0,Math.min(1024,boot.length())));reply.writeString(ports==null?"":ports.substring(0,Math.min(512,ports.length())));return true;}
      if(code==DROP){data.enforceNoDataAvail();drop();reply.writeNoException();return true;}
      int port=data.readInt();data.enforceNoDataAvail();if(port<1||port>65535||getTorControlConnection()==null||TorRuntimePolicy.ports(getInfo("status/bootstrap-phase"),getInfo("net/listeners/socks")).length!=3)throw new IOException("Tor ещё не подключён");
      if(onion!=null)throw new IOException("Голосовой onion уже занят");
      Map<Integer,String> ports=new HashMap<>();ports.put(80,"127.0.0.1:"+port);Map<String,String> answer=getTorControlConnection().addOnion("NEW:ED25519-V3",ports,List.of("DiscardPK"));
      String id=answer.get("ServiceID");if(id==null)id=answer.get("serviceID");if(id==null||!id.matches("[a-z2-7]{56}"))throw new IOException("Tor вернул неверный onion");onion=id;
      reply.writeNoException();reply.writeString(id+".onion");return true;
    }catch(Exception unavailable){throw new SecurityException("Команда Tor недоступна: "+unavailable.getClass().getSimpleName());}}
  }};
  @Override public void onCreate(){
    NotificationManager manager=getSystemService(NotificationManager.class);manager.createNotificationChannel(new NotificationChannel("aegis-tor","Защищённый маршрут Tor",NotificationManager.IMPORTANCE_LOW));
    startForeground(60002,new Notification.Builder(this,"aegis-tor").setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("АЕГИС · Tor").setContentText("Отдельный защищённый маршрут приложений").setOngoing(true).build());
    try{File file=getTorrc(this);String fixed=TorRuntimePolicy.CONFIG;
      try(FileOutputStream out=new FileOutputStream(file)){out.write(fixed.getBytes(StandardCharsets.US_ASCII));out.getFD().sync();}android.system.Os.chmod(file.getAbsolutePath(),0600);
    }catch(Exception failure){stopForeground(STOP_FOREGROUND_REMOVE);stopSelf();throw new IllegalStateException("Не удалось подготовить приватный Tor",failure);}
    super.onCreate();
  }
  @Override public IBinder onBind(Intent i){return typed;}
  @Override public int onStartCommand(Intent i,int flags,int id){return START_NOT_STICKY;}
  private synchronized void drop()throws IOException{String old=onion;onion=null;if(old!=null&&getTorControlConnection()!=null)getTorControlConnection().delOnion(old);}
  @Override public void onDestroy(){try{drop();}catch(IOException ignored){}super.onDestroy();stopForeground(STOP_FOREGROUND_REMOVE);android.os.Process.killProcess(android.os.Process.myPid());}
}
