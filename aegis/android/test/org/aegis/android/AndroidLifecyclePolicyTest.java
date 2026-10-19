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
    System.out.println("AndroidLifecyclePolicyTest: "+n+" PASS_LOCAL; real Android permission/Binder acceptance NOT_RUN");
  }
}
