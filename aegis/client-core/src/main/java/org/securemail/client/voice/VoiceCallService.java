package org.securemail.client.voice;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLSocket;
import org.securemail.client.crypto.Identity;
import org.securemail.client.net.NetworkService;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

/** One consented audio call, carried only by the existing Tor onion peer route.
 * Signalling is client-only; the production Relay protocol is unchanged.
 */
public final class VoiceCallService implements AutoCloseable {
  public enum State {IDLE,PREPARING,RINGING,WAITING,INCOMING,ENCRYPTING,SECURE,RECONNECTING,UNAVAILABLE,DECLINED,ENDED}
  public enum Direction {INCOMING,OUTGOING}
  public record Snapshot(State state,String callId,UserInfo contact,Direction direction,String status,boolean microphoneEnabled,long startedAt,long durationMillis,String fingerprint,String safetyCode,boolean historyEnabled){
    public boolean busy(){return switch(state){case PREPARING,RINGING,WAITING,INCOMING,ENCRYPTING,SECURE,RECONNECTING->true;default->false;};}
  }
  public record HistoryEntry(String callId,String peerId,boolean outgoing,long startedMinute,long durationSeconds,String outcome){}
  @FunctionalInterface interface Connector {Socket connect(UserInfo contact)throws IOException;}
  @FunctionalInterface interface EncodedSink {boolean offer(long sequence,long timestampMillis,byte[] opus);}
  interface Media extends AutoCloseable {
    void receive(long sequence,long timestampMillis,byte[] opus)throws IOException;
    void microphone(boolean enabled)throws IOException;
    void configure(GlasAudioSession.Config config)throws IOException;
    GlasAudioSession.Stats stats();
    void close();
  }
  @FunctionalInterface interface MediaFactory {Media open(GlasAudioSession.Config config,EncodedSink sink,java.util.function.Consumer<String> failure)throws IOException;}
  private static final long RING_MILLIS=60_000,RECONNECT_MILLIS=45_000;
  private final Object lock=new Object();
  private final LocalStore local;
  private final LocalFeatures features;
  private final Connector connector;
  private final MediaFactory mediaFactory;
  private final VoiceHistory history;
  private final ThreadPoolExecutor workers=new ThreadPoolExecutor(0,4,30,TimeUnit.SECONDS,new SynchronousQueue<>(),daemonFactory("glas-io"),new ThreadPoolExecutor.AbortPolicy());
  private final ThreadPoolExecutor audioActions=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(8),daemonFactory("glas-devices"),new ThreadPoolExecutor.AbortPolicy());
  private final ScheduledThreadPoolExecutor timer=new ScheduledThreadPoolExecutor(1,daemonFactory("glas-timer"));
  private final ExecutorService notifications=Executors.newSingleThreadExecutor(daemonFactory("glas-events"));
  private final CopyOnWriteArrayList<Runnable> listeners=new CopyOnWriteArrayList<>();
  private final AtomicBoolean notificationPending=new AtomicBoolean();
  private final Set<Socket> handshakes=ConcurrentHashMap.newKeySet();
  private final Semaphore authenticationSlots=new Semaphore(2);
  private final LinkedHashMap<UUID,Long> seenCalls=new LinkedHashMap<>();
  private volatile boolean closed,routeReady;
  private volatile boolean voiceStateDamaged;
  private volatile boolean cleanupPending;
  private Call current;
  private volatile Snapshot snapshot;

  private static ThreadFactory daemonFactory(String name){return task->{Thread thread=new Thread(task,name);thread.setDaemon(true);return thread;};}
  public VoiceCallService(LocalStore local,LocalFeatures features,NetworkService network)throws IOException,GeneralSecurityException {
    this(local,features,contact->{if(network==null)throw new IOException("Tor peer route unavailable");return network.connectVoice(contact);},VoiceCallService::openMedia);
  }
  /** Test seams replace network/device I/O only. Public construction always uses TorTransport and real audio. */
  VoiceCallService(LocalStore local,LocalFeatures features,Connector connector,MediaFactory mediaFactory)throws IOException,GeneralSecurityException {
    this.local=Objects.requireNonNull(local);this.features=Objects.requireNonNull(features);this.connector=Objects.requireNonNull(connector);this.mediaFactory=Objects.requireNonNull(mediaFactory);VoiceHistory loaded;
    try{loaded=new VoiceHistory(local);}catch(IOException|GeneralSecurityException damaged){loaded=VoiceHistory.empty(local);voiceStateDamaged=true;}
    history=loaded;snapshot=new Snapshot(voiceStateDamaged?State.UNAVAILABLE:State.IDLE,"",null,null,voiceStateDamaged?"Настройки звонков повреждены. Очистите историю звонков для восстановления":"Звонки через Tor · микрофон выключен",false,0,0,"","",history.enabled());
    timer.setRemoveOnCancelPolicy(true);timer.scheduleWithFixedDelay(this::tick,1,1,TimeUnit.SECONDS);
  }
  private static Media openMedia(GlasAudioSession.Config config,EncodedSink sink,java.util.function.Consumer<String> failure)throws IOException {
    var session=GlasAudioSession.start(config,sink::offer,new GlasAudioSession.Listener(){@Override public void failed(String ignored){failure.accept("Аудиоустройство недоступно");}});
    return new Media(){
      private GlasAudioSession.Config selected=config;
      public void receive(long sequence,long timestamp,byte[] opus)throws IOException{session.receive(sequence,timestamp,opus);}
      public void microphone(boolean enabled)throws IOException{session.setMicrophoneEnabled(enabled);}
      public void configure(GlasAudioSession.Config value)throws IOException{
        if(!selected.inputDeviceId().equals(value.inputDeviceId()))session.switchInput(value.inputDeviceId());
        if(!selected.outputDeviceId().equals(value.outputDeviceId()))session.switchOutput(value.outputDeviceId());
        session.setInputGain(value.inputGain());session.setSpeakerVolume(value.speakerVolume());selected=value;
        session.setProcessing(value.echoCancellation(),value.noiseSuppression());
      }
      public GlasAudioSession.Stats stats(){return session.stats();}
      public void close(){session.close();}
    };
  }
  public Snapshot snapshot(){return snapshot;}
  public boolean busy(){synchronized(lock){return current!=null||cleanupPending;}}
  public AutoCloseable listen(Runnable listener){listeners.add(Objects.requireNonNull(listener));return ()->listeners.remove(listener);}
  public GlasAudioSession.Config audioConfig(){return history.config();}
  public GlasAudioSession.Stats audioStats(){synchronized(lock){return current==null||current.media==null?null:current.media.stats();}}
  public List<HistoryEntry> history(){return history.entries();}
  public void setHistoryEnabled(boolean enabled)throws IOException,GeneralSecurityException {requireVoiceState();history.enabled(enabled);synchronized(lock){if(!enabled&&current!=null)current.recordHistory=false;publish();}}
  public void clearHistory()throws IOException,GeneralSecurityException {history.clear();boolean repaired=voiceStateDamaged;voiceStateDamaged=false;synchronized(lock){publish();}if(repaired)idleStatus("Настройки звонков восстановлены · история отключена");}
  public boolean incomingEnabled(){return !voiceStateDamaged&&history.incomingEnabled();}
  public void setIncomingEnabled(boolean enabled)throws IOException,GeneralSecurityException {requireVoiceState();history.incomingEnabled(enabled);Call call;synchronized(lock){call=current;publish();}if(!enabled&&call!=null&&call.state==State.INCOMING)decline(call.id.toString());}
  public boolean notificationsEnabled(){return history.notificationsEnabled();}
  public void setNotificationsEnabled(boolean enabled)throws IOException,GeneralSecurityException {requireVoiceState();history.notificationsEnabled(enabled);synchronized(lock){publish();}}
  private void requireVoiceState()throws IOException {if(voiceStateDamaged)throw new IOException("Очистите повреждённую историю звонков для восстановления");}
  public void configureAudio(GlasAudioSession.Config config){
    Objects.requireNonNull(config);for(String id:List.of(config.inputDeviceId(),config.outputDeviceId()))if(id.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>256||id.codePoints().anyMatch(Character::isISOControl))throw new IllegalArgumentException("Audio device identifier");submitAudio(()->{
      Call call;Media media;synchronized(lock){call=current;media=call==null?null:call.media;}
      try{requireVoiceState();if(media!=null)media.configure(config);history.config(config);synchronized(lock){publish();}}
      catch(IOException|GeneralSecurityException|RuntimeException failure){if(call!=null)finish(call,State.UNAVAILABLE,"Аудиоустройство недоступно","unavailable",true);else idleStatus("Не удалось сохранить настройки аудио");}
    });
  }
  public void start(UserInfo contact)throws IOException {
    requireVoiceState();UserInfo pinned=trusted(contact);Call call;
    synchronized(lock){if(closed)throw new IOException("Приложение закрывается");if(current!=null||cleanupPending)throw new IOException("Сначала завершите текущий звонок");if(!routeReady)throw new IOException("Дождитесь подключения Tor и P2P");
      call=new Call(UUID.randomUUID(),pinned,Direction.OUTGOING,local.now());call.recordHistory=history.enabled();current=call;call.state=State.PREPARING;call.status="Подготовка звонка через Tor";publish();}
    if(!submit(()->connect(call,false)))finish(call,State.UNAVAILABLE,"Звонок сейчас недоступен","unavailable",false);
  }
  public void accept(String callId){
    synchronized(lock){Call call=matching(callId);if(call==null||call.state!=State.INCOMING||call.link==null||!stillTrusted(call))return;
      call.accepted=true;call.state=State.ENCRYPTING;call.status="Подтверждение защищённого аудиоканала";call.deadline=local.now()+20_000;enqueueControl(call.link,VoiceFrames.ACCEPT);publish();}
  }
  public void decline(String callId){Call call;synchronized(lock){call=matching(callId);if(call==null||call.state!=State.INCOMING)return;}requestEnd(call,State.DECLINED,"Звонок отклонён","declined");}
  public void hangup(){Call call;synchronized(lock){call=current;}if(call!=null)requestEnd(call,State.ENDED,"Звонок завершён","ended");}
  private void requestEnd(Call call,State state,String message,String outcome){
    synchronized(lock){if(current!=call||call.ending)return;call.ending=true;call.microphone=false;call.state=state;call.status=message;clearAudio(call.link);publish();}
    if(!submit(()->finish(call,state,message,outcome,true)))try{timer.execute(()->finish(call,state,message,outcome,true));}catch(RejectedExecutionException closing){finish(call,state,message,outcome,false);}
  }
  public void setMicrophoneEnabled(boolean enabled){
    Call call;Media media;boolean schedule;
    synchronized(lock){call=current;if(call==null||call.state!=State.SECURE||call.media==null||!call.accepted)return;call.microphone=false;call.desiredMicrophone=enabled;call.microphoneGeneration++;clearAudio(call.link);media=call.media;schedule=!call.microphoneTaskPending;call.microphoneTaskPending=true;publish();}
    if(schedule&&!submitAudio(()->updateMicrophone(call,media)))finish(call,State.UNAVAILABLE,"Управление микрофоном недоступно","unavailable",true);
  }
  private void updateMicrophone(Call call,Media media){
    try{
      while(true){boolean enabled;long generation;
        synchronized(lock){if(current!=call||call.media!=media||call.state!=State.SECURE||call.ending)break;enabled=call.desiredMicrophone;generation=call.microphoneGeneration;}
        media.microphone(enabled);
        synchronized(lock){if(current!=call||call.media!=media||call.state!=State.SECURE||call.ending)break;if(generation==call.microphoneGeneration){call.microphone=enabled;call.microphoneTaskPending=false;clearAudio(call.link);if(!enabled)enqueueControl(call.link,VoiceFrames.MUTED);publish();return;}}
      }
      media.microphone(false);
    }catch(IOException|RuntimeException failure){finish(call,State.UNAVAILABLE,"Микрофон недоступен","unavailable",true);}
    finally{synchronized(lock){call.microphoneTaskPending=false;}}
  }
  /** Invoked by ClientSession after actual Tor bootstrap, not merely account login. */
  public void networkAvailable(boolean available){routeReady=available;if(!available){Call call;Link link;
    synchronized(lock){call=current;link=call==null?null:call.link;if(call!=null&&link!=null&&!call.ending){call.microphone=false;call.desiredMicrophone=false;call.microphoneGeneration++;clearAudio(link);if(call.accepted){long now=local.now();if(call.reconnectDeadline==0){call.reconnectDeadline=now+RECONNECT_MILLIS;call.reconnectAttempts=0;call.nextReconnect=now+2_000;}call.state=State.RECONNECTING;call.status="Tor недоступен · микрофон выключен";}publish();}}
    if(call!=null&&link!=null&&!submit(()->lost(call,link)))try{timer.execute(()->lost(call,link));}catch(RejectedExecutionException closing){closeSocket(link.raw);}
  }}

  /** Called only after PeerServer consumed the fixed client-only operation preface. */
  public void handleIncoming(Socket raw)throws Exception {
    if(closed||voiceStateDamaged||!authenticationSlots.tryAcquire()){raw.close();return;}
    handshakes.add(raw);ScheduledFuture<?> deadline=timer.schedule(()->closeSocket(raw),30,TimeUnit.SECONDS);Link link=null;Call call=null;
    try{
      raw.setSoTimeout(15_000);var in=new DataInputStream(raw.getInputStream());var out=new DataOutputStream(raw.getOutputStream());
      VoiceTls.Offer remote=VoiceTls.read(in);UserInfo contact=trustedKey(remote.identityPublicKey());
      remote.verify(contact.publicKey(),local.identity().publicKey(),remote.callId(),VoiceTls.Role.CALLER,local.now());
      synchronized(lock){pruneSeen();if(current==null&&seenCalls.containsKey(remote.callId()))throw new IOException("Call replay");}
      try(var pending=VoiceTls.create(local.identity(),remote.callId(),VoiceTls.Role.CALLEE,contact.publicKey())){
        pending.offer().write(out);out.flush();SSLSocket tls=pending.handshake(raw,remote,contact.publicKey(),false);
        link=new Link(raw,tls,VoiceTls.shortCode(pending.offer(),remote));VoiceFrames.Frame first=VoiceFrames.read(link.in);boolean resume;
        try{resume=VoiceFrames.start(first);}finally{first.wipe();}
        deadline.cancel(false);handshakes.remove(raw);
        int rejected=0;synchronized(lock){
          if(closed||!stillTrusted(contact))throw new IOException("Contact no longer trusted");
          if(resume){
            call=current;if(call==null||call.direction!=Direction.INCOMING||!call.id.equals(remote.callId())||!call.accepted||call.state!=State.RECONNECTING||!same(call.contact,contact)||call.reconnectDeadline<local.now())throw new IOException("No resumable call");
          }else{
            if(!history.incomingEnabled())rejected=VoiceFrames.DECLINE;
            else if(current!=null||cleanupPending||seenCalls.containsKey(remote.callId()))rejected=VoiceFrames.BUSY;
            else {call=new Call(remote.callId(),contact,Direction.INCOMING,local.now());call.recordHistory=history.enabled();current=call;remember(call.id);call.state=State.INCOMING;call.status="Входящий защищённый звонок";}
          }
          if(rejected==0){call.link=link;call.safetyCode=link.safetyCode;call.deadline=local.now()+(resume?20_000:RING_MILLIS);call.microphone=false;
            if(resume){call.state=State.ENCRYPTING;call.status="Восстановление защищённого канала";}publish();}
        }
        if(rejected!=0){VoiceFrames.write(link.out,VoiceFrames.control(rejected));return;}
        startWriter(call,link);enqueueControl(link,resume?VoiceFrames.ACCEPT:VoiceFrames.RINGING);readLoop(call,link);
      }
    }finally{
      deadline.cancel(false);handshakes.remove(raw);authenticationSlots.release();if(link!=null)closeLink(link);else closeSocket(raw);
      if(call!=null&&link!=null)lost(call,link);
    }
  }
  private void connect(Call call,boolean resume){
    Link link=null;Socket raw=null;
    try{
      synchronized(lock){if(current!=call||closed||!stillTrusted(call))return;}
      raw=connector.connect(call.contact);handshakes.add(raw);Socket owned=raw;var deadline=timer.schedule(()->closeSocket(owned),30,TimeUnit.SECONDS);
      try(var pending=VoiceTls.create(local.identity(),call.id,VoiceTls.Role.CALLER,call.contact.publicKey())){
        raw.setSoTimeout(15_000);var out=new DataOutputStream(raw.getOutputStream());var in=new DataInputStream(raw.getInputStream());
        Binary.header(out);out.writeByte(VoiceFrames.OPERATION);Binary.text(out,"");pending.offer().write(out);out.flush();
        VoiceTls.Offer remote=VoiceTls.read(in);remote.verify(call.contact.publicKey(),local.identity().publicKey(),call.id,VoiceTls.Role.CALLEE,local.now());
        synchronized(lock){if(current!=call||closed||!stillTrusted(call))return;call.state=State.ENCRYPTING;call.status="Проверка личности и шифрования";publish();}
        SSLSocket tls=pending.handshake(raw,remote,call.contact.publicKey(),true);deadline.cancel(false);handshakes.remove(raw);
        link=new Link(raw,tls,VoiceTls.shortCode(pending.offer(),remote));
        synchronized(lock){if(current!=call||closed)return;call.link=link;call.safetyCode=link.safetyCode;call.state=resume?State.ENCRYPTING:State.WAITING;call.status=resume?"Восстановление защищённого канала":"Ожидание ответа";call.deadline=local.now()+(resume?20_000:RING_MILLIS);publish();}
        VoiceFrames.write(link.out,VoiceFrames.start(resume));startWriter(call,link);readLoop(call,link);
      }finally{deadline.cancel(false);}
    }catch(IOException|GeneralSecurityException|RuntimeException failure){
      boolean accepted;synchronized(lock){accepted=current==call&&call.accepted;}
      if(!accepted)finish(call,State.UNAVAILABLE,"Контакт недоступен или не поддерживает Глас","unavailable",false);
    }finally{
      if(raw!=null)handshakes.remove(raw);if(link!=null){closeLink(link);lost(call,link);}else {closeSocket(raw);connectionAttemptFailed(call);}
    }
  }
  private void connectionAttemptFailed(Call call){
    synchronized(lock){if(current!=call||!call.accepted||closed)return;call.connecting=false;call.link=null;call.state=State.RECONNECTING;call.status="Соединение через Tor прервано · микрофон выключен";publish();}
  }
  private void readLoop(Call call,Link link)throws IOException {
    link.tls.setSoTimeout(15_000);
    while(!closed&&!link.closed){
      VoiceFrames.Frame frame=VoiceFrames.read(link.in);link.lastReceived=System.nanoTime();
      try{
        long now=System.nanoTime();if(now-link.rateWindow>=1_000_000_000L){link.rateWindow=now;link.framesInWindow=0;}if(++link.framesInWindow>250)throw new IOException("Voice frame rate limit");
        synchronized(lock){if(current!=call||call.link!=link)return;if(!stillTrusted(call))throw new IOException("Contact trust changed");}
        switch(frame.type()){
          case VoiceFrames.RINGING->{synchronized(lock){if(call.direction!=Direction.OUTGOING||call.accepted)throw new IOException("Unexpected ring");if(call.state==State.WAITING){call.state=State.RINGING;call.status="У контакта звонит";publish();}else if(call.state!=State.RINGING)throw new IOException("Unexpected ring state");}}
          case VoiceFrames.ACCEPT->{synchronized(lock){if(call.direction!=Direction.OUTGOING||call.state!=State.WAITING&&call.state!=State.RINGING&&call.state!=State.ENCRYPTING)throw new IOException("Unexpected acceptance");call.accepted=true;call.state=State.ENCRYPTING;call.status="Открытие защищённого аудиоканала";enqueueControl(link,VoiceFrames.READY);publish();}openAudio(call,link);}
          case VoiceFrames.READY->{synchronized(lock){if(call.direction!=Direction.INCOMING||!call.accepted||call.state!=State.ENCRYPTING)throw new IOException("Unexpected audio readiness");}openAudio(call,link);}
          case VoiceFrames.DECLINE->{finish(call,State.DECLINED,"Контакт отклонил звонок","declined",false);return;}
          case VoiceFrames.BUSY->{finish(call,State.UNAVAILABLE,"Контакт занят другим звонком","unavailable",false);return;}
          case VoiceFrames.END->{finish(call,State.ENDED,"Звонок завершён","ended",false);return;}
          case VoiceFrames.AUDIO->{Media media;synchronized(lock){if(call.state!=State.SECURE||!call.accepted||call.media==null)throw new IOException("Audio before consent");media=call.media;}
            VoiceFrames.Audio audio=VoiceFrames.audio(frame);try{if(audio.sequence()<=link.lastAudioSequence)throw new IOException("Voice frame replay");link.lastAudioSequence=audio.sequence();media.receive(audio.sequence(),audio.timestampMillis(),audio.opus());}finally{Arrays.fill(audio.opus(),(byte)0);}}
          case VoiceFrames.PING->enqueueControl(link,VoiceFrames.PONG);
          case VoiceFrames.PONG,VoiceFrames.MUTED->{}
          default->throw new IOException("Unexpected voice control");
        }
      }finally{frame.wipe();}
    }
  }
  private void openAudio(Call call,Link link)throws IOException {
    synchronized(lock){if(current!=call||call.link!=link||!call.accepted||call.media!=null||call.ending)return;}
    Media media;
    try{media=Objects.requireNonNull(mediaFactory.open(history.config(),(sequence,timestamp,opus)->offerAudio(call,link,sequence,timestamp,opus),reason->finish(call,State.UNAVAILABLE,"Аудиоустройство недоступно","unavailable",true)));}
    catch(IOException|RuntimeException unavailable){finish(call,State.UNAVAILABLE,"Аудиоустройство недоступно","unavailable",true);return;}
    boolean stale;synchronized(lock){stale=current!=call||call.link!=link||!call.accepted||closed||call.ending;if(!stale){call.media=media;call.microphone=false;call.desiredMicrophone=false;call.microphoneGeneration++;call.state=State.SECURE;call.status="Личность проверена · TLS 1.3 · Tor · микрофон выключен";if(call.startedAt==0){call.startedAt=local.now();call.startedNanos=System.nanoTime();}call.connecting=false;call.deadline=0;call.reconnectDeadline=0;publish();}}
    if(stale)media.close();
  }
  private boolean offerAudio(Call call,Link link,long sequence,long timestamp,byte[] opus){
    try{synchronized(lock){if(closed||current!=call||call.link!=link||call.state!=State.SECURE||!call.microphone||link.closed)return false;
      return link.audio.offer(sequence,timestamp,opus);}}finally{Arrays.fill(opus,(byte)0);}
  }
  private void startWriter(Call call,Link link)throws IOException {
    if(!submit(()->{try{
      while(!closed&&!link.closed){QueuedAudio audio=null;VoiceFrames.Frame frame=link.controls.poll();if(frame==null){audio=link.audio.poll(50,TimeUnit.MILLISECONDS);if(audio==null)continue;frame=audio.frame;}
        try{boolean allowed;synchronized(lock){allowed=frame.type()!=VoiceFrames.AUDIO||current==call&&call.link==link&&call.microphone&&call.state==State.SECURE&&!call.ending;}if(allowed){
          long now=System.nanoTime();if(now-link.lastKeyUpdate>600_000_000_000L||link.bytesSinceKeyUpdate>=64L*1024*1024){VoiceTls.requestKeyUpdate(link.tls);link.lastKeyUpdate=now;link.bytesSinceKeyUpdate=0;}
          if(audio==null)VoiceFrames.write(link.out,frame);else if(!link.audio.writeIfFresh(link.out,audio))continue;link.bytesSinceKeyUpdate+=frame.payload().length;
        }if(frame.type()==VoiceFrames.END||frame.type()==VoiceFrames.DECLINE)break;}finally{frame.wipe();}}
    }catch(IOException failure){lost(call,link);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}finally{closeLink(link);lost(call,link);}}))throw new IOException("Voice worker busy");
  }
  private void enqueueControl(Link link,int type){if(link==null||link.closed)return;VoiceFrames.Frame frame=VoiceFrames.control(type);if(!link.controls.offer(frame)){frame.wipe();closeLink(link);}}
  private void lost(Call call,Link link){
    Media media=null;
    synchronized(lock){if(current!=call||call.link!=link||closed||call.ending)return;call.link=null;media=call.media;call.media=null;call.microphone=false;call.desiredMicrophone=false;call.microphoneGeneration++;call.connecting=false;clearAudio(link);
      if(call.accepted){long now=local.now();if(call.reconnectDeadline==0){call.reconnectDeadline=now+RECONNECT_MILLIS;call.reconnectAttempts=0;call.nextReconnect=now+2_000;}call.state=State.RECONNECTING;call.status="Соединение через Tor прервано · микрофон выключен";call.deadline=0;publish();}
    }
    closeLink(link);if(media!=null)media.close();
    if(!call.accepted)finish(call,State.UNAVAILABLE,"Соединение с контактом прервано","unavailable",false);
  }
  private void tick(){
    try{
      Call call;Link link;boolean reconnect=false,renew=false;String ending=null;
      synchronized(lock){if(closed)return;pruneSeen();call=current;if(call==null||call.ending)return;link=call.link;
        if(!stillTrusted(call))ending="Доверие к контакту изменено · звонок завершён";
        else if(call.reconnectDeadline>0&&local.now()>=call.reconnectDeadline)ending="Не удалось восстановить соединение через Tor";
        else if(call.state==State.RECONNECTING){long now=local.now();if(now>=call.reconnectDeadline||call.direction==Direction.OUTGOING&&call.reconnectAttempts>=3&&!call.connecting)ending="Не удалось восстановить соединение через Tor";
          else if(call.direction==Direction.OUTGOING&&routeReady&&!call.connecting&&now>=call.nextReconnect){call.connecting=true;call.reconnectAttempts++;call.nextReconnect=now+(2_000L<<call.reconnectAttempts);reconnect=true;}}
        else if(call.deadline>0&&local.now()>=call.deadline)ending="Время ожидания звонка истекло";
        else if(call.state==State.PREPARING&&local.now()-call.createdAt>60_000)ending="Не удалось подготовить звонок через Tor";
        if(call.state==State.SECURE&&link!=null&&System.nanoTime()-link.createdNanos>=3_600_000_000_000L)renew=true;
        if(link!=null&&System.nanoTime()-link.lastPing>5_000_000_000L){link.lastPing=System.nanoTime();enqueueControl(link,VoiceFrames.PING);}publish();
      }
      if(ending!=null)finish(call,State.UNAVAILABLE,ending,call.direction==Direction.INCOMING&&!call.accepted?"missed":"unavailable",true);
      else if(renew)lost(call,link);
      else if(reconnect&&!submit(()->connect(call,true)))connectionAttemptFailed(call);
    }catch(RuntimeException failure){Call call;synchronized(lock){call=current;}if(call!=null)finish(call,State.UNAVAILABLE,"Звонок остановлен","unavailable",false);}
  }
  private void finish(Call call,State result,String message,String outcome,boolean notifyPeer){
    Link link;Media media;HistoryEntry entry;
    synchronized(lock){if(current!=call)return;cleanupPending=true;current=null;link=call.link;call.link=null;media=call.media;call.media=null;call.microphone=false;call.desiredMicrophone=false;call.microphoneGeneration++;remember(call.id);long duration=duration(call);
      entry=new HistoryEntry(call.id.toString(),call.contact.userId(),call.direction==Direction.OUTGOING,call.createdAt/60000*60000,Math.min(31L*86400,duration/1000),outcome);
      snapshot=new Snapshot(result,call.id.toString(),call.contact,call.direction,message,false,call.startedAt,duration,Identity.fingerprint(call.contact.publicKey()),call.safetyCode,history.enabled());notifyListeners();
    }
    clearAudio(link);
    if(link!=null){if(notifyPeer){enqueueControl(link,result==State.DECLINED?VoiceFrames.DECLINE:VoiceFrames.END);try{timer.schedule(()->closeLink(link),400,TimeUnit.MILLISECONDS);}catch(RejectedExecutionException closing){closeLink(link);}}else closeLink(link);}
    if(media!=null)media.close();
    try{if(call.recordHistory)history.add(entry);}catch(IOException|GeneralSecurityException failure){synchronized(lock){if(current==null){Snapshot previous=snapshot;snapshot=new Snapshot(previous.state(),previous.callId(),previous.contact(),previous.direction(),message+" · история не сохранена",false,previous.startedAt(),previous.durationMillis(),previous.fingerprint(),previous.safetyCode(),history.enabled());notifyListeners();}}}finally{cleanupPending=false;}
  }
  private Call matching(String id){return current!=null&&current.id.toString().equals(id)?current:null;}
  private UserInfo trusted(UserInfo candidate)throws IOException {if(candidate==null)throw new IOException("Выберите проверенный контакт");UserInfo pinned=local.contact(candidate.nickname());if(pinned==null||!same(pinned,candidate)||!stillTrusted(pinned)||pinned.userId().equals(local.identity().userId()))throw new IOException("Добавьте и проверьте контакт; заблокированные контакты не могут звонить");return pinned;}
  private UserInfo trustedKey(byte[] key)throws IOException {String id=Identity.id(key);UserInfo contact=local.contacts().stream().filter(person->person.userId().equals(id)&&MessageDigest.isEqual(person.publicKey(),key)).findFirst().orElseThrow(()->new IOException("Unknown voice identity"));return trusted(contact);}
  private boolean stillTrusted(Call call){return stillTrusted(call.contact);}
  private boolean stillTrusted(UserInfo contact){UserInfo pinned=local.contact(contact.nickname());return pinned!=null&&same(pinned,contact)&&!features.blockedSender(contact.userId());}
  private static boolean same(UserInfo first,UserInfo second){return first.userId().equals(second.userId())&&MessageDigest.isEqual(first.publicKey(),second.publicKey());}
  private void remember(UUID id){seenCalls.put(id,local.now()+300_000);pruneSeen();while(seenCalls.size()>256)seenCalls.remove(seenCalls.keySet().iterator().next());}
  private void pruneSeen(){long now=local.now();seenCalls.entrySet().removeIf(entry->entry.getValue()<=now);}
  private long duration(Call call){return call.startedNanos==0?0:Math.max(0,(System.nanoTime()-call.startedNanos)/1_000_000);}
  private void publish(){
    if(current==null){Snapshot previous=snapshot;snapshot=new Snapshot(previous.state(),previous.callId(),previous.contact(),previous.direction(),previous.status(),false,previous.startedAt(),previous.durationMillis(),previous.fingerprint(),previous.safetyCode(),history.enabled());}
    else {Call call=current;snapshot=new Snapshot(call.state,call.id.toString(),call.contact,call.direction,call.status,call.microphone,call.startedAt,duration(call),Identity.fingerprint(call.contact.publicKey()),call.safetyCode,history.enabled());}
    notifyListeners();
  }
  private void idleStatus(String message){synchronized(lock){if(current!=null)return;Snapshot previous=snapshot;snapshot=new Snapshot(previous.state(),previous.callId(),previous.contact(),previous.direction(),message,false,previous.startedAt(),previous.durationMillis(),previous.fingerprint(),previous.safetyCode(),history.enabled());notifyListeners();}}
  private void notifyListeners(){if(closed||!notificationPending.compareAndSet(false,true))return;try{notifications.execute(()->{notificationPending.set(false);for(Runnable listener:listeners)try{listener.run();}catch(RuntimeException ignored){}});}catch(RejectedExecutionException ignored){notificationPending.set(false);}}
  private boolean submit(Runnable work){if(closed)return false;try{workers.execute(work);return true;}catch(RejectedExecutionException full){return false;}}
  private boolean submitAudio(Runnable work){if(closed)return false;try{audioActions.execute(work);return true;}catch(RejectedExecutionException full){idleStatus("Аудиоустройства заняты");return false;}}
  private static void clearAudio(Link link){if(link!=null)link.audio.clear();}
  private static void closeSocket(Socket socket){if(socket!=null)try{socket.close();}catch(IOException ignored){}}
  private static void closeLink(Link link){if(link==null)return;link.closed=true;closeSocket(link.raw);closeSocket(link.tls);clearAudio(link);VoiceFrames.Frame frame;while((frame=link.controls.poll())!=null)frame.wipe();}
  @Override public void close(){
    Call call;synchronized(lock){if(closed)return;call=current;}if(call!=null)finish(call,State.ENDED,"Звонок завершён","ended",false);
    synchronized(lock){closed=true;routeReady=false;}for(Socket socket:handshakes)closeSocket(socket);handshakes.clear();timer.shutdownNow();workers.shutdownNow();audioActions.shutdownNow();notifications.shutdownNow();listeners.clear();
  }
  private static final class Call {
    final UUID id;final UserInfo contact;final Direction direction;final long createdAt;
    State state;String status="",safetyCode="";Link link;Media media;boolean accepted,microphone,desiredMicrophone,microphoneTaskPending,connecting,ending,recordHistory;long microphoneGeneration,startedAt,startedNanos,deadline,reconnectDeadline,nextReconnect;int reconnectAttempts;
    Call(UUID id,UserInfo contact,Direction direction,long createdAt){this.id=id;this.contact=contact;this.direction=direction;this.createdAt=createdAt;}
  }
  static final long AUDIO_TTL_NANOS=250_000_000L;
  static final class QueuedAudio {
    final VoiceFrames.Frame frame;final long enqueuedNanos;
    private QueuedAudio(VoiceFrames.Frame frame,long enqueuedNanos){this.frame=frame;this.enqueuedNanos=enqueuedNanos;}
  }
  /** Owns only audio payloads. A stalled writer must not replay its queued speech later.
   * The clock seam is local monotonic time, unrelated to peer/wire timestamps.
   */
  static final class AudioQueue {
    private final ArrayDeque<QueuedAudio> frames=new ArrayDeque<>();
    private final int capacity;private final long ttlNanos;private final java.util.function.LongSupplier nanoTime;
    private boolean pressurePending;
    AudioQueue(int capacity,long ttlNanos,java.util.function.LongSupplier nanoTime){if(capacity<1||ttlNanos<1)throw new IllegalArgumentException("Audio queue bounds");this.capacity=capacity;this.ttlNanos=ttlNanos;this.nanoTime=Objects.requireNonNull(nanoTime);}
    boolean offer(long sequence,long timestamp,byte[] opus){
      try{return offerOwned(VoiceFrames.audio(sequence,timestamp,opus));}catch(IOException invalid){return false;}finally{Arrays.fill(opus,(byte)0);}
    }
    synchronized boolean offerOwned(VoiceFrames.Frame frame){
      if(frame.type()!=VoiceFrames.AUDIO){frame.wipe();throw new IllegalArgumentException("Audio frame required");}
      long now=nanoTime.getAsLong();discardExpired(now);boolean pressure=pressurePending;pressurePending=false;
      if(frames.size()==capacity){frames.removeFirst().frame.wipe();pressure=true;}
      frames.addLast(new QueuedAudio(frame,now));notifyAll();return !pressure;
    }
    synchronized QueuedAudio poll(long timeout,TimeUnit unit)throws InterruptedException{
      long budget=unit.toNanos(timeout),began=System.nanoTime();
      while(true){discardExpired(nanoTime.getAsLong());if(!frames.isEmpty())return frames.removeFirst();long remaining=budget-(System.nanoTime()-began);if(remaining<=0)return null;TimeUnit.NANOSECONDS.timedWait(this,remaining);}
    }
    private boolean expired(QueuedAudio audio,long now){long age=now-audio.enqueuedNanos;return age<0||age>=ttlNanos;}
    private void discardExpired(long now){while(!frames.isEmpty()&&expired(frames.getFirst(),now)){frames.removeFirst().frame.wipe();pressurePending=true;}}
    boolean writeIfFresh(DataOutputStream out,QueuedAudio audio)throws IOException{
      try{
        synchronized(this){if(expired(audio,nanoTime.getAsLong())){pressurePending=true;return false;}}
        // Never hold the queue monitor while TLS blocks. A write already in
        // progress cannot be retracted; all later queued frames are rechecked.
        VoiceFrames.write(out,audio.frame);return true;
      }finally{audio.frame.wipe();}
    }
    synchronized void clear(){while(!frames.isEmpty())frames.removeFirst().frame.wipe();notifyAll();}
    synchronized int size(){return frames.size();}
  }
  private static final class Link {
    final Socket raw;final SSLSocket tls;final DataInputStream in;final DataOutputStream out;final String safetyCode;
    final ArrayBlockingQueue<VoiceFrames.Frame> controls=new ArrayBlockingQueue<>(8);
    final AudioQueue audio=new AudioQueue(12,AUDIO_TTL_NANOS,System::nanoTime);
    volatile boolean closed;final long createdNanos=System.nanoTime();volatile long lastReceived=System.nanoTime(),lastPing=System.nanoTime();long lastAudioSequence=-1,lastKeyUpdate=System.nanoTime(),bytesSinceKeyUpdate,rateWindow=System.nanoTime();int framesInWindow;
    Link(Socket raw,SSLSocket tls,String code)throws IOException{this.raw=raw;this.tls=tls;in=new DataInputStream(tls.getInputStream());out=new DataOutputStream(tls.getOutputStream());safetyCode=code;}
  }
}
