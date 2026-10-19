package org.securemail.client.ecosystem;

import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.securemail.client.ecosystemauth.CorePublicConfig600;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Temporary, explicitly consented Mail key operation; no ordinary component session is minted by this broker. */
public final class MailPairingBroker600 implements AutoCloseable {
  private final ComponentInstallation installation;private final CorePublicConfig600 config;
  private final ExecutorService worker=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"aegis-mail-consent-launch");t.setDaemon(true);return t;});
  private final AtomicBoolean busy=new AtomicBoolean(),closed=new AtomicBoolean();
  private volatile Process active;private volatile LocalIpc.Channel channel;private volatile ServerSocket listener;
  public MailPairingBroker600(ComponentInstallation installation)throws IOException{this(installation,CorePublicConfig600.fromDefaultFile());}
  public MailPairingBroker600(ComponentInstallation installation,CorePublicConfig600 config){this.installation=Objects.requireNonNull(installation);this.config=Objects.requireNonNull(config);}
  public CompletableFuture<MailPairing600.RegistrationResult> beginRegistration(byte[] devicePublic) {
    return submit(new MailPairing600.RegistrationRequest(devicePublic),bytes->{
      var result=MailPairing600.decodeRegistrationResult(bytes);
      if(Math.abs(System.currentTimeMillis()-result.time())>60000 || !IdentityProtocol.verify(result.accountPublic(),IdentityProtocol.registration(IdentityProtocol.id(config.identityPublicKey()),result.accountPublic(),devicePublic,result.recoveryPublic(),result.nickname(),result.time(),result.nonce()),result.accountProof()))throw new IOException("Подтверждение регистрации Почты не прошло проверку");
      return result;
    });
  }
  public CompletableFuture<MailPairing600.StepUpResult> beginStepUp(String capability,long time,String nonce,byte[] appProof) {
    var request=new MailPairing600.StepUpRequest(capability,time,nonce,appProof);
    return submit(request,bytes->{var result=MailPairing600.decodeStepUpResult(bytes);var cap=IdentityProtocol.decodeCapability(capability);
      if(!result.accountId().equals(cap.accountId)||!result.deviceId().equals(cap.deviceId)||result.generation()!=cap.generation||result.expiresAt()<=System.currentTimeMillis()||!IdentityProtocol.verify(result.accountPublic(),IdentityProtocol.stepUp(IdentityProtocol.id(config.identityPublicKey()),result.accountId(),result.deviceId(),result.challenge(),result.expiresAt()),result.accountProof()))throw new IOException("Подтверждение личности Почты не прошло проверку");return result;});
  }
  public CompletableFuture<org.securemail.client.voice600.GlasGrant600> beginVoiceDelegation(String capability,long time,String nonce,byte[] appProof) {
    var request=new MailPairing600.VoiceDelegationRequest(capability,time,nonce,appProof);
    return submit(request,bytes->{var result=org.securemail.client.voice600.GlasGrant600.decode(bytes);var cap=IdentityProtocol.decodeCapability(capability);var d=result.delegation();
      if(!org.securemail.glas.protocol600.GlasProtocol600.verifyDelegation(d,cap,config.identityPublicKey(),System.currentTimeMillis())||!result.verify(d.accountPublic(),IdentityProtocol.id(config.identityPublicKey()),System.currentTimeMillis()))throw new IOException("Допуск и контакты Гласа не прошли проверку");return result;});
  }
  public CompletableFuture<MailPairing600.OwnerTransferResult> beginOwnerTransfer(String capability,IdentityProtocol.OwnerTransfer transfer,IdentityProtocol.OwnerTransferRole intent,long time,String nonce,byte[] appProof) {
    var request=new MailPairing600.OwnerTransferRequest(capability,transfer,intent,time,nonce,appProof);
    return submit(request,bytes->{var result=MailPairing600.decodeOwnerTransferResult(bytes);long now=System.currentTimeMillis();if(result.intent()!=intent||transfer.expiresAt<=now||!transfer.audience.equals(IdentityProtocol.id(config.identityPublicKey()))||!java.security.MessageDigest.isEqual(IdentityProtocol.ownerTransferBytes(transfer),IdentityProtocol.ownerTransferBytes(result.transfer()))||!IdentityProtocol.verify(result.accountPublic(),IdentityProtocol.ownerTransferConsent(transfer,intent),result.accountProof()))throw new IOException("Подтверждение передачи владельца Почтой не прошло проверку");return result;});
  }
  public CompletableFuture<MailPairing600.FirstDelegateResult> beginFirstDelegate(String capability,IdentityProtocol.FirstDelegation delegation,IdentityProtocol.FirstDelegateRole intent,long time,String nonce,byte[] appProof) {
    var request=new MailPairing600.FirstDelegateRequest(capability,delegation,intent,time,nonce,appProof);
    return submit(request,bytes->{var result=MailPairing600.decodeFirstDelegateResult(bytes);long now=System.currentTimeMillis();if(result.intent()!=intent||delegation.expiresAt<=now||!delegation.audience.equals(IdentityProtocol.id(config.identityPublicKey()))||!java.security.MessageDigest.isEqual(IdentityProtocol.firstDelegationBytes(delegation),IdentityProtocol.firstDelegationBytes(result.delegation()))||!IdentityProtocol.verify(result.accountPublic(),IdentityProtocol.firstDelegationBytes(delegation),result.accountProof()))throw new IOException("Первое делегирование Почтой не прошло проверку");return result;});
  }
  public CompletableFuture<MailPairing600.OwnerBootstrapResult> beginOwnerBootstrap(String capability,IdentityProtocol.OwnerBootstrap bootstrap,long time,String nonce,byte[] appProof) {
    var request=new MailPairing600.OwnerBootstrapRequest(capability,bootstrap,time,nonce,appProof);
    return submit(request,bytes->{var result=MailPairing600.decodeOwnerBootstrapResult(bytes);long now=System.currentTimeMillis();if(bootstrap.expiresAt<=now||!bootstrap.audience.equals(IdentityProtocol.id(config.identityPublicKey()))||!java.security.MessageDigest.isEqual(IdentityProtocol.ownerBootstrapBytes(bootstrap),IdentityProtocol.ownerBootstrapBytes(result.bootstrap()))||!IdentityProtocol.verify(result.accountPublic(),IdentityProtocol.ownerBootstrapBytes(bootstrap),result.accountProof()))throw new IOException("Первоначальное назначение владельца Почтой не прошло проверку");return result;});
  }
  public CompletableFuture<MailPairing600.DeviceRecoveryResult> beginDeviceRecovery(IdentityProtocol.DeviceRecovery recovery,long time,String nonce,byte[] deviceProof) {
    var request=new MailPairing600.DeviceRecoveryRequest(recovery,time,nonce,deviceProof);
    return submit(request,bytes->{var result=MailPairing600.decodeDeviceRecoveryResult(bytes);long now=System.currentTimeMillis();byte[] body=IdentityProtocol.deviceRecoveryBytes(recovery);if(recovery.expiresAt<=now||!recovery.audience.equals(IdentityProtocol.id(config.identityPublicKey()))||!java.security.MessageDigest.isEqual(body,IdentityProtocol.deviceRecoveryBytes(result.recovery()))||!IdentityProtocol.verify(result.accountPublic(),body,result.accountProof())||!IdentityProtocol.verify(result.recoveryPublic(),body,result.recoveryProof()))throw new IOException("Восстановление устройства Почтой не прошло проверку");return result;});
  }
  @FunctionalInterface private interface Decoder<T>{T decode(byte[] bytes)throws IOException;}
  private <T> CompletableFuture<T> submit(MailPairing600.Request request,Decoder<T> decoder) {
    var result=new CompletableFuture<T>();if(closed.get()||!busy.compareAndSet(false,true)){result.completeExceptionally(new IOException("Подтверждение Почты уже выполняется или АЕГИС закрыт"));return result;}
    try{worker.execute(()->{try{result.complete(decoder.decode(exchange(request)));}catch(Exception e){result.completeExceptionally(e);}finally{stopActive();busy.set(false);}});}catch(RejectedExecutionException e){busy.set(false);result.completeExceptionally(new IOException("АЕГИС закрыт",e));}
    result.whenComplete((value,failure)->{if(result.isCancelled())stopActive();});return result;
  }
  private byte[] exchange(MailPairing600.Request request)throws IOException {
    installation.verify();if(closed.get())throw new IOException("АЕГИС закрыт");long end=System.nanoTime()+Duration.ofMinutes(3).toNanos();
    String purpose=request instanceof MailPairing600.RegistrationRequest?MailPairing600.PURPOSE_REGISTER:request instanceof MailPairing600.VoiceDelegationRequest?MailPairing600.PURPOSE_VOICE:request instanceof MailPairing600.OwnerTransferRequest?MailPairing600.PURPOSE_OWNER_TRANSFER:request instanceof MailPairing600.FirstDelegateRequest?MailPairing600.PURPOSE_FIRST_DELEGATE:request instanceof MailPairing600.OwnerBootstrapRequest?MailPairing600.PURPOSE_OWNER_BOOTSTRAP:request instanceof MailPairing600.DeviceRecoveryRequest?MailPairing600.PURPOSE_DEVICE_RECOVERY:MailPairing600.PURPOSE_STEP_UP;
    ComponentLease bootstrapLease=new ComponentLease(ComponentId.MAIL,purpose,1,MailPairing600.requestBytes(request));
    ScheduledExecutorService pulse=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-consent-heartbeat");t.setDaemon(true);return t;});
    ExecutorService pipe=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"aegis-consent-pipe");t.setDaemon(true);return t;});
    try(ServerSocket accept=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"));var boot=new LocalIpc.Bootstrap(bootstrapLease,accept.getLocalPort())) {
      listener=accept;accept.setSoTimeout(10000);ProcessBuilder command=new ProcessBuilder(installation.pairingCommand());command.redirectOutput(ProcessBuilder.Redirect.DISCARD);command.redirectError(ProcessBuilder.Redirect.DISCARD);command.environment().keySet().removeIf(key->!allowedEnvironment(key));
      active=command.start();if(closed.get())throw new IOException("АЕГИС закрыт");Process process=active;
      Future<?> sent=pipe.submit(()->{try(OutputStream out=process.getOutputStream()){boot.write(out);}catch(IOException e){throw new UncheckedIOException(e);}});
      try{sent.get(10,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("Подтверждение отменено",e);}catch(ExecutionException|TimeoutException e){throw new IOException("Не удалось передать запрос подтверждения",e);}
      Socket socket=accept.accept();try{channel=LocalIpc.acceptParent(socket,boot,process.pid());}catch(IOException e){socket.close();throw e;}
      channel.startupTimeout(45000);if(channel.receive().type()!=LocalIpc.Type.READY)throw new IOException("Почта не подтвердила назначение запроса");channel.startupTimeout(6500);
      pulse.scheduleWithFixedDelay(()->{LocalIpc.Channel current=channel;if(current!=null)try{current.send(LocalIpc.Packet.command(LocalIpc.Type.HEARTBEAT));}catch(IOException e){stopActive();}},2,2,TimeUnit.SECONDS);
      while(!closed.get()&&System.nanoTime()-end<0) {
        LocalIpc.Packet packet=channel.receive();switch(packet.type()) {
          case PONG -> { }
          case PAIRING_CANCELLED -> throw new IOException("Пользователь отменил подтверждение в Почте");
          case PAIRING_RESULT -> {return packet.payload();}
          default -> throw new IOException("Недопустимое сообщение подтверждения");
        }
      }
      throw new IOException("Время подтверждения истекло");
    } finally {bootstrapLease.close();listener=null;pulse.shutdownNow();pipe.shutdownNow();}
  }
  private static boolean allowedEnvironment(String key){return key.startsWith("LC_")||Set.of("HOME","USER","LOGNAME","PATH","LANG","DISPLAY","WAYLAND_DISPLAY","XDG_RUNTIME_DIR","XDG_SESSION_TYPE","XDG_CURRENT_DESKTOP","DBUS_SESSION_BUS_ADDRESS","XAUTHORITY","XDG_CONFIG_HOME","XDG_DATA_HOME","XDG_CACHE_HOME","SystemRoot","SYSTEMROOT","WINDIR","LOCALAPPDATA","APPDATA","TEMP","TMP","PROGRAMDATA","USERPROFILE").contains(key);}
  private synchronized void stopActive(){
    LocalIpc.Channel connection=channel;channel=null;if(connection!=null)try{connection.send(LocalIpc.Packet.command(LocalIpc.Type.SHUTDOWN));}catch(IOException ignored){}finally{try{connection.close();}catch(IOException ignored){}}
    ServerSocket socket=listener;listener=null;if(socket!=null)try{socket.close();}catch(IOException ignored){}
    Process process=active;active=null;if(process!=null){try{if(!process.waitFor(3,TimeUnit.SECONDS)){process.destroy();if(!process.waitFor(1,TimeUnit.SECONDS))process.destroyForcibly();}}catch(InterruptedException e){Thread.currentThread().interrupt();process.destroyForcibly();}}
  }
  @Override public void close(){if(closed.compareAndSet(false,true)){stopActive();worker.shutdownNow();}}
}
