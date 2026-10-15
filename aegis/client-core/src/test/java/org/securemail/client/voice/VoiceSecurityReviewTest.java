package org.securemail.client.voice;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.time.Clock;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.Identity;
import org.securemail.client.net.PeerServer;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

/** Independent hostile-client checks: real TLS/framing, explicit loopback, no audio hardware or Tor claims. */
class VoiceSecurityReviewTest {
  @TempDir Path directory;
  private static final char[] PASSWORD="independent-glas-security-test".toCharArray();

  private static void await(BooleanSupplier condition)throws Exception {
    long deadline=System.nanoTime()+5_000_000_000L;
    while(!condition.getAsBoolean()&&System.nanoTime()<deadline)Thread.sleep(10);
    assertTrue(condition.getAsBoolean(),"Security state did not reach its bounded expected result");
  }

  private final class Fixture implements AutoCloseable {
    final LocalStore receiver;
    final Identity caller=Identity.create();
    final AtomicInteger opened=new AtomicInteger(),received=new AtomicInteger();
    final AtomicBoolean mediaClosed=new AtomicBoolean();
    final VoiceCallService calls;
    final PeerServer peer;
    Fixture()throws Exception {
      receiver=new LocalStore(directory.resolve(UUID.randomUUID().toString()),PASSWORD,Clock.systemUTC(),200_000,2_000_000);
      receiver.bindNickname("receiver");receiver.trust(new UserInfo(caller.userId(),"caller",caller.publicKey(),null));
      calls=new VoiceCallService(receiver,new LocalFeatures(receiver),contact->{throw new IOException("No reverse test dial");},
          (config,sink,failure)->{
            opened.incrementAndGet();
            return new VoiceCallService.Media(){
              public void receive(long sequence,long timestamp,byte[] opus){received.incrementAndGet();}
              public void microphone(boolean enabled){assertFalse(enabled,"No microphone action was authorized by this test");}
              public void configure(GlasAudioSession.Config value){}
              public GlasAudioSession.Stats stats(){return null;}
              public void close(){mediaClosed.set(true);}
            };
          });
      peer=new PeerServer(0,receiver,200_000,receiver::accept,null,calls::handleIncoming);peer.start();calls.networkAvailable(true);
    }
    void preface(DataOutputStream output)throws IOException {
      Binary.header(output);output.writeByte(VoiceFrames.OPERATION);Binary.text(output,"");
    }
    ScriptedCaller connect(UUID callId)throws Exception{return new ScriptedCaller(this,callId);}
    public void close()throws Exception{calls.close();peer.close();receiver.close();}
  }

  private static final class ScriptedCaller implements AutoCloseable {
    final Socket raw;
    final SSLSocket tls;
    final DataInputStream in;
    final DataOutputStream out;
    ScriptedCaller(Fixture fixture,UUID callId)throws Exception {
      raw=new Socket(InetAddress.getLoopbackAddress(),fixture.peer.port());raw.setSoTimeout(5000);
      SSLSocket negotiated=null;
      try(var pending=VoiceTls.create(fixture.caller,callId,VoiceTls.Role.CALLER,fixture.receiver.identity().publicKey())){
        var initial=new DataOutputStream(raw.getOutputStream());fixture.preface(initial);pending.offer().write(initial);initial.flush();
        var remote=VoiceTls.read(new DataInputStream(raw.getInputStream()));
        negotiated=pending.handshake(raw,remote,fixture.receiver.identity().publicKey(),true);
      }catch(Exception failure){raw.close();throw failure;}
      tls=negotiated;tls.setSoTimeout(5000);in=new DataInputStream(tls.getInputStream());out=new DataOutputStream(tls.getOutputStream());
    }
    void ring()throws IOException {
      VoiceFrames.write(out,VoiceFrames.start(false));
      var frame=VoiceFrames.read(in);try{assertEquals(VoiceFrames.RINGING,frame.type());}finally{frame.wipe();}
    }
    public void close()throws IOException{raw.close();tls.close();}
  }

  @Test void validContactOfferBoundToAnotherRecipientIsRejectedBeforeTlsOrRinging()throws Exception {
    try(var fixture=new Fixture();var raw=new Socket(InetAddress.getLoopbackAddress(),fixture.peer.port());
        var pending=VoiceTls.create(fixture.caller,UUID.randomUUID(),VoiceTls.Role.CALLER,Identity.create().publicKey())){
      raw.setSoTimeout(5000);var output=new DataOutputStream(raw.getOutputStream());fixture.preface(output);pending.offer().write(output);output.flush();
      assertThrows(IOException.class,()->VoiceTls.read(new DataInputStream(raw.getInputStream())));
      assertEquals(VoiceCallService.State.IDLE,fixture.calls.snapshot().state());assertEquals(0,fixture.opened.get());
      assertNotNull(fixture.receiver.contact("caller"));
    }
  }

  @Test void completedCallIdCannotRingAgainEvenWithFreshValidTlsMaterial()throws Exception {
    try(var fixture=new Fixture()){
      UUID id=UUID.randomUUID();
      try(var caller=fixture.connect(id)){
        caller.ring();VoiceFrames.write(caller.out,VoiceFrames.control(VoiceFrames.END));await(()->fixture.calls.snapshot().state()==VoiceCallService.State.ENDED&&!fixture.calls.busy());
      }
      try(var raw=new Socket(InetAddress.getLoopbackAddress(),fixture.peer.port());
          var fresh=VoiceTls.create(fixture.caller,id,VoiceTls.Role.CALLER,fixture.receiver.identity().publicKey())){
        raw.setSoTimeout(5000);var output=new DataOutputStream(raw.getOutputStream());fixture.preface(output);fresh.offer().write(output);output.flush();
        assertThrows(IOException.class,()->VoiceTls.read(new DataInputStream(raw.getInputStream())));
        assertEquals(VoiceCallService.State.ENDED,fixture.calls.snapshot().state());assertEquals(0,fixture.opened.get());
      }
    }
  }

  @Test void authenticatedDuplicateAudioSequenceClosesLinkAndNeverReachesMediaTwice()throws Exception {
    try(var fixture=new Fixture();var caller=fixture.connect(UUID.randomUUID())){
      caller.ring();fixture.calls.accept(fixture.calls.snapshot().callId());
      var frame=VoiceFrames.read(caller.in);try{assertEquals(VoiceFrames.ACCEPT,frame.type());}finally{frame.wipe();}
      VoiceFrames.write(caller.out,VoiceFrames.control(VoiceFrames.READY));await(()->fixture.calls.snapshot().state()==VoiceCallService.State.SECURE);
      VoiceFrames.write(caller.out,VoiceFrames.audio(4,80,new byte[]{7}));await(()->fixture.received.get()==1);
      VoiceFrames.write(caller.out,VoiceFrames.audio(4,80,new byte[]{8}));
      await(()->fixture.calls.snapshot().state()==VoiceCallService.State.RECONNECTING&&fixture.mediaClosed.get());
      assertEquals(1,fixture.received.get());assertEquals(1,fixture.opened.get());assertFalse(fixture.calls.snapshot().microphoneEnabled());
    }
  }

  @Test void repeatedAuthenticatedRingingDoesNotProduceAnUnboundedUiEventStream()throws Exception {
    Identity callee=Identity.create();var repeat=new CountDownLatch(1);var done=new CountDownLatch(1);var release=new CountDownLatch(1);
    var executor=Executors.newSingleThreadExecutor(task->{var thread=new Thread(task,"hostile-ringing-test");thread.setDaemon(true);return thread;});
    try(var local=new LocalStore(directory.resolve("ringing-caller"),PASSWORD,Clock.systemUTC(),200_000,2_000_000);
        var server=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){
      local.bindNickname("caller");var contact=new UserInfo(callee.userId(),"callee",callee.publicKey(),null);local.trust(contact);
      Future<?> remote=executor.submit(()->{
        try(var raw=server.accept()){
          raw.setSoTimeout(5000);var input=new DataInputStream(raw.getInputStream());var output=new DataOutputStream(raw.getOutputStream());
          Binary.header(input);assertEquals(VoiceFrames.OPERATION,input.readUnsignedByte());assertEquals("",Binary.text(input,64));var offer=VoiceTls.read(input);
          try(var pending=VoiceTls.create(callee,offer.callId(),VoiceTls.Role.CALLEE,local.identity().publicKey())){
            pending.offer().write(output);output.flush();SSLSocket tls=pending.handshake(raw,offer,local.identity().publicKey(),false);
            try{
              var secureIn=new DataInputStream(tls.getInputStream());var secureOut=new DataOutputStream(tls.getOutputStream());var start=VoiceFrames.read(secureIn);try{assertFalse(VoiceFrames.start(start));}finally{start.wipe();}
              VoiceFrames.write(secureOut,VoiceFrames.control(VoiceFrames.RINGING));assertTrue(repeat.await(5,TimeUnit.SECONDS));
              for(int n=0;n<20;n++){VoiceFrames.write(secureOut,VoiceFrames.control(VoiceFrames.RINGING));Thread.sleep(10);}
              done.countDown();assertTrue(release.await(5,TimeUnit.SECONDS));
            }finally{raw.close();tls.close();}
          }
        }catch(Exception failure){throw new CompletionException(failure);}
      });
      try(var calls=new VoiceCallService(local,new LocalFeatures(local),target->new Socket(InetAddress.getLoopbackAddress(),server.getLocalPort()),
          (config,sink,failure)->{fail("Ringing must not open audio");throw new IOException("unreachable");})){
        var notifications=new AtomicInteger();try(var subscription=calls.listen(notifications::incrementAndGet)){
          calls.networkAvailable(true);calls.start(contact);await(()->calls.snapshot().state()==VoiceCallService.State.RINGING);
          Thread.sleep(50);notifications.set(0);repeat.countDown();assertTrue(done.await(5,TimeUnit.SECONDS));Thread.sleep(50);
          assertEquals(VoiceCallService.State.RINGING,calls.snapshot().state());assertTrue(notifications.get()<=2,"Duplicate RINGING generated "+notifications.get()+" UI notifications");
        }finally{release.countDown();}
      }
      remote.get(5,TimeUnit.SECONDS);
    }finally{repeat.countDown();release.countDown();executor.shutdownNow();}
  }
}
