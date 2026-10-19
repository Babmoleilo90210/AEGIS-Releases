package org.aegis.android;
import android.content.*;
import android.os.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.protocol.Binary;
/** Core-only front end with bounded commands; no raw Tor cookie, key or control IPC. */
final class CoreTor {
  private static CoreTor instance;static synchronized CoreTor get(Context c){if(!AndroidPolicy.CORE.equals(c.getPackageName()))throw new SecurityException("Tor принадлежит АЕГИС");if(instance==null)instance=new CoreTor(c.getApplicationContext());return instance;}
  private final Context context;private final ThreadPoolExecutor commands=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(4),r->{Thread t=new Thread(r,"aegis-tor-command");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private volatile IBinder binder;private boolean bound;private int pid;private volatile String status="Встроенный Tor остановлен";private volatile int[] ports=new int[0];private volatile boolean started;private volatile long epoch;private String owner;
  private CoreTor(Context c){context=c;}
  private ServiceConnection connection;
  private ServiceConnection connection(long bindingEpoch){return new ServiceConnection(){
    public void onServiceConnected(ComponentName n,IBinder b){synchronized(CoreTor.this){if(bindingEpoch!=epoch||connection!=this||!started)return;binder=b;try{b.linkToDeath(()->{synchronized(CoreTor.this){if(bindingEpoch==epoch&&binder==b)failClosed();}},0);}catch(RemoteException dead){failClosed();}}}
    public void onServiceDisconnected(ComponentName n){synchronized(CoreTor.this){if(bindingEpoch==epoch&&connection==this)failClosed();}}
    public void onBindingDied(ComponentName n){onServiceDisconnected(n);}
  };}
  synchronized void start()throws IOException {
    if(started)return;if(bound&&connection!=null){context.unbindService(connection);bound=false;}started=true;long bindingEpoch=++epoch;ServiceConnection own=connection(bindingEpoch);connection=own;
    try{context.startForegroundService(new Intent(context,CoreTorService.class));bound=context.bindService(new Intent(context,CoreTorService.class),own,Context.BIND_AUTO_CREATE);if(!bound)throw new IOException("Служба Tor недоступна");status="Встроенный Tor подключается";}catch(RuntimeException|IOException e){failClosed();throw new IOException("Не удалось запустить службу Tor",e);}
  }
  private Parcel command(int code,int port)throws IOException {
    if(Looper.myLooper()==Looper.getMainLooper())throw new IOException("Команда Tor требует рабочего потока");long operationEpoch=epoch;IBinder service=binder;if(service==null)throw new IOException("Служба Tor ещё не подключена");
    Future<Parcel> f=commands.submit(()->{Parcel data=Parcel.obtain(),reply=Parcel.obtain();try{data.writeInterfaceToken(CoreTorService.DESCRIPTOR);if(code==CoreTorService.PUBLISH)data.writeInt(port);if(!service.transact(code,data,reply,0))throw new IOException("Версия Tor IPC");reply.readException();if(operationEpoch!=epoch)throw new IOException("Контекст Tor изменён");return reply;}catch(Exception failure){reply.recycle();throw failure;}finally{data.recycle();}});
    try{return f.get(12,TimeUnit.SECONDS);}catch(Exception failure){f.cancel(true);if(operationEpoch==epoch)failClosed();throw new IOException("Команда Tor не завершилась; собственный процесс остановлен",failure);}
  }
  void refresh()throws IOException {long observed=epoch;Parcel r=command(CoreTorService.STATUS,0);try{int process=r.readInt();String bootstrap=r.readString(),listeners=r.readString();r.enforceNoDataAvail();if(process<=0||process==android.os.Process.myPid())throw new IOException("Неверный процесс Tor");String phase=bootstrap==null?"Подготовка Tor":bootstrap;int[] current=TorRuntimePolicy.ports(phase,listeners);synchronized(this){if(observed!=epoch)throw new IOException("Ответ прежнего контекста Tor");pid=process;status=phase;ports=current;}}finally{r.recycle();}}
  int socks(String pkg)throws IOException {refresh();int[] p=ports;if(p.length!=3)throw new IOException("Tor ещё подключается: "+status);return p[AndroidPolicy.MAIL.equals(pkg)?1:AndroidPolicy.GLAS.equals(pkg)?2:0];}
  int awaitSocks(String pkg)throws IOException {start();long observed=epoch,deadline=SystemClock.elapsedRealtime()+120_000;while(SystemClock.elapsedRealtime()<deadline){if(observed!=epoch)throw new IOException("Подготовка Tor отменена");if(binder!=null){refresh();int[] current=ports;if(current.length==3)return current[AndroidPolicy.MAIL.equals(pkg)?1:AndroidPolicy.GLAS.equals(pkg)?2:0];}try{Thread.sleep(500);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("Подготовка Tor прервана",e);}}throw new IOException("Tor не подключился за две минуты: "+status);}
  String status(){return status;}
  String publish(IdentityProtocol.Capability cap,int port)throws IOException {
    synchronized(this){if(owner!=null)throw new IOException("Голосовой маршрут уже занят");owner=cap.tokenId;}try{socks(AndroidPolicy.GLAS);String nonce=IdentityProtocol.nonce();
    try(Socket s=new Socket()){s.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),port),3000);s.setSoTimeout(3000);DataOutputStream out=new DataOutputStream(s.getOutputStream());Binary.header(out);out.writeByte(VoiceEndpointProof.OPERATION);Binary.text(out,"");Binary.text(out,nonce);out.flush();DataInputStream in=new DataInputStream(s.getInputStream());Binary.header(in);byte[] proof=Binary.bytes(in,64);if(proof.length!=64||!IdentityProtocol.verify(cap.proofKey,VoiceEndpointProof.canonical(cap,port,nonce),proof))throw new IOException("Не подтверждено владение голосовым слушателем");}
    if(!SessionLedger.get(context).active())throw new IOException("Сессия заблокирована");Parcel reply=command(CoreTorService.PUBLISH,port);try{String onion=reply.readString();reply.enforceNoDataAvail();if(!org.securemail.glas.protocol600.GlasProtocol600.validOnion(onion))throw new IOException("Неверный onion");synchronized(this){if(!cap.tokenId.equals(owner))throw new IOException("Маршрут был отменён");}return onion;}finally{reply.recycle();}}catch(IOException|RuntimeException failure){try{drop(cap.tokenId);}catch(Exception ignored){}throw failure;}
  }
  void drop(String token)throws IOException {synchronized(this){if(owner==null)return;if(token!=null&&!owner.equals(token))throw new IOException("Голосовой маршрут принадлежит другому допуску");owner=null;}Parcel r=command(CoreTorService.DROP,0);r.recycle();}
  private synchronized void failClosed(){epoch++;int owned=pid;if(owned==0){android.app.ActivityManager manager=(android.app.ActivityManager)context.getSystemService(Context.ACTIVITY_SERVICE);List<android.app.ActivityManager.RunningAppProcessInfo> running=manager.getRunningAppProcesses();if(running!=null)for(var p:running)if(p.uid==android.os.Process.myUid()&&(context.getPackageName()+":tor").equals(p.processName))owned=p.pid;}pid=0;ports=new int[0];owner=null;status="Tor остановлен после ошибки";binder=null;if(owned>0)android.os.Process.killProcess(owned);context.stopService(new Intent(context,CoreTorService.class));if(bound&&connection!=null){ServiceConnection old=connection;bound=false;connection=null;context.unbindService(old);}started=false;}
  void stop(){failClosed();}
}
