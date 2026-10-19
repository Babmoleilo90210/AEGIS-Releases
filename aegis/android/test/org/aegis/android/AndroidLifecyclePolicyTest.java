package org.aegis.android;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
/** Actual shared lifecycle policy and real cross-thread loopback challenge; Android Binder itself NOT_RUN. */
public final class AndroidLifecyclePolicyTest {
  static int n;interface Test{void run()throws Exception;}static void t(String name,Test run)throws Exception{run.run();n++;System.out.println("PASS_LOCAL "+name);}static void yes(boolean v){if(!v)throw new AssertionError();}static void denied(Test t)throws Exception{try{t.run();}catch(SecurityException|IllegalStateException expected){return;}throw new AssertionError("Expected denial");}
  public static void main(String[] ignored)throws Exception {
    var gate=new MicrophonePermissionGate();int request=gate.begin(MicrophonePermissionGate.Purpose.CALL);gate.cancel();
    t("late-granted-after-lock-never-becomes-mic-test",()->yes(gate.consume(request,true)==MicrophonePermissionGate.Purpose.NONE));
    t("unsolicited-permission-callback-no-capture",()->yes(gate.consume(12,true)==MicrophonePermissionGate.Purpose.NONE));
    int next=gate.begin(MicrophonePermissionGate.Purpose.CODEC_TEST);
    t("old-callback-cannot-consume-new-purpose",()->{yes(gate.consume(request,true)==MicrophonePermissionGate.Purpose.NONE);yes(gate.pending()==MicrophonePermissionGate.Purpose.CODEC_TEST);});
    t("fresh-explicit-purpose-only-once",()->{yes(gate.consume(next,true)==MicrophonePermissionGate.Purpose.CODEC_TEST);yes(gate.consume(next,true)==MicrophonePermissionGate.Purpose.NONE);});
    t("denial-cancels-capture-purpose",()->{int r=gate.begin(MicrophonePermissionGate.Purpose.MIC_TEST);yes(gate.consume(r,false)==MicrophonePermissionGate.Purpose.NONE&&gate.pending()==MicrophonePermissionGate.Purpose.NONE);});
    t("concurrent-purpose-denied",()->{gate.begin(MicrophonePermissionGate.Purpose.CALL);denied(()->gate.begin(MicrophonePermissionGate.Purpose.MIC_TEST));gate.cancel();});
    var pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();String id=IdentityProtocol.id(pair.getPublic().getEncoded());long wall=System.currentTimeMillis();var cap=new IdentityProtocol.Capability(id,id,id,IdentityProtocol.App.GLAS,2,IdentityProtocol.nonce(),wall,wall+60000,wall+60000,pair.getPublic().getEncoded(),EnumSet.of(IdentityProtocol.Scope.VOICE_CALL),new byte[64]);var lease=new BrokerLease();long epoch=lease.epoch();lease.install(epoch,cap,50000,1);
    t("cross-thread-blocking-publish-can-sign-listener-proof",()->{Object ipcMonitor=new Object();ExecutorService worker=Executors.newSingleThreadExecutor();try(ServerSocket listener=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){Future<?> response=worker.submit(()->{try(Socket s=listener.accept()){s.setSoTimeout(1000);DataInputStream in=new DataInputStream(s.getInputStream());String nonce=in.readUTF();var current=lease.capability(2);byte[] signature=IdentityProtocol.sign(pair.getPrivate(),VoiceEndpointProof.canonical(current,listener.getLocalPort(),nonce));s.getOutputStream().write(signature);s.getOutputStream().flush();}catch(Exception e){throw new CompletionException(e);}});synchronized(ipcMonitor){try(Socket s=new Socket(InetAddress.getLoopbackAddress(),listener.getLocalPort())){s.setSoTimeout(1000);String nonce=IdentityProtocol.nonce();new DataOutputStream(s.getOutputStream()).writeUTF(nonce);s.getOutputStream().flush();byte[] sig=s.getInputStream().readNBytes(64);yes(sig.length==64&&IdentityProtocol.verify(cap.proofKey,VoiceEndpointProof.canonical(cap,listener.getLocalPort(),nonce),sig));}}response.get(1,TimeUnit.SECONDS);}finally{worker.shutdownNow();}});
    t("revoke-immediate-during-unrelated-ipc-monitor",()->{Object ipc=new Object();synchronized(ipc){FutureTask<Boolean> task=new FutureTask<>(lease::clear);new Thread(task).start();yes(task.get(1,TimeUnit.SECONDS)&&!lease.active(2));}});
    t("late-response-cannot-restore-revoked-lease",()->denied(()->lease.install(epoch,cap,50000,3)));
    t("fresh-refresh-after-revoke-can-install-current-lease",()->{lease.install(lease.epoch(),cap,50000,3);yes(lease.capability(4)==cap);});
    t("lease-expiry-denies-capability-and-clears-once",()->{yes(lease.expire(50000));yes(!lease.expire(50001));denied(()->lease.capability(50001));});
    t("queued-stale-data-skipped-but-mandatory-logout-clears-lease-and-owned-socket",()->{
      var currentEpoch=new java.util.concurrent.atomic.AtomicLong(7);var closed=new java.util.concurrent.atomic.AtomicBoolean();
      var dataRan=new java.util.concurrent.atomic.AtomicBoolean();var securityRan=new java.util.concurrent.atomic.AtomicBoolean();
      var activeLease=new BrokerLease();activeLease.install(activeLease.epoch(),cap,50000,1);
      var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var completed=new CountDownLatch(1);
      var worker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(4));
      try(ServerSocket owned=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){
        worker.execute(()->{entered.countDown();try{if(!release.await(2,TimeUnit.SECONDS))throw new AssertionError("worker gate timed out");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new AssertionError(e);}});
        yes(entered.await(1,TimeUnit.SECONDS));
        UiWorkScheduler.execute(worker,false,7,currentEpoch::get,closed::get,()->dataRan.set(true));
        UiWorkScheduler.execute(worker,true,7,currentEpoch::get,closed::get,()->{activeLease.clear();try{owned.close();}catch(IOException e){throw new UncheckedIOException(e);}securityRan.set(true);completed.countDown();});
        currentEpoch.incrementAndGet();closed.set(true);worker.shutdown();release.countDown();
        yes(completed.await(1,TimeUnit.SECONDS));yes(worker.awaitTermination(1,TimeUnit.SECONDS));
        yes(!dataRan.get()&&securityRan.get()&&!activeLease.active(2)&&owned.isClosed());
      }finally{release.countDown();worker.shutdownNow();}
    });
    t("stale-secret-worker-erases-captured-password-without-running-operation",()->{var worker=Executors.newSingleThreadExecutor();var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var epochNow=new java.util.concurrent.atomic.AtomicLong(1);char[] secret="test-only-password".toCharArray();var dataRan=new java.util.concurrent.atomic.AtomicBoolean();try{worker.execute(()->{entered.countDown();try{release.await(1,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}});yes(entered.await(1,TimeUnit.SECONDS));UiWorkScheduler.execute(worker,false,1,epochNow::get,()->false,()->dataRan.set(true),()->Arrays.fill(secret,'\0'));epochNow.incrementAndGet();worker.shutdown();release.countDown();yes(worker.awaitTermination(1,TimeUnit.SECONDS));yes(!dataRan.get());for(char ch:secret)yes(ch==0);}finally{release.countDown();worker.shutdownNow();}});
    t("shutdownNow-erases-secret-of-never-started-optional-task",()->{var worker=Executors.newSingleThreadExecutor();var entered=new CountDownLatch(1);var release=new CountDownLatch(1);char[] secret="discard-only-secret".toCharArray();try{worker.execute(()->{entered.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}});yes(entered.await(1,TimeUnit.SECONDS));UiWorkScheduler.execute(worker,false,1,()->1,()->false,()->{throw new AssertionError("Optional operation ran");},()->Arrays.fill(secret,'\0'));worker.shutdownNow().forEach(UiWorkScheduler::discard);for(char ch:secret)yes(ch==0);}finally{release.countDown();worker.shutdownNow().forEach(UiWorkScheduler::discard);}});
    t("current-data-work-runs-on-owned-worker",()->{var worker=Executors.newSingleThreadExecutor();var completed=new CountDownLatch(1);try{UiWorkScheduler.execute(worker,false,9,()->9,()->false,completed::countDown);yes(completed.await(1,TimeUnit.SECONDS));}finally{worker.shutdownNow();}});
    t("closed-current-data-denied-security-still-executed",()->{var dataRan=new java.util.concurrent.atomic.AtomicBoolean();var cleanRan=new java.util.concurrent.atomic.AtomicBoolean();UiWorkScheduler.execute(Runnable::run,false,9,()->9,()->true,()->dataRan.set(true));UiWorkScheduler.execute(Runnable::run,true,9,()->9,()->true,()->cleanRan.set(true));yes(!dataRan.get()&&cleanRan.get());});
    System.out.println("AndroidLifecyclePolicyTest: "+n+" PASS_LOCAL; real Android permission/Binder acceptance NOT_RUN");
  }
}
