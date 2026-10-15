package org.securemail.client.voice;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.net.PeerServer;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

/** Real mutual TLS and peer framing over explicit LOOPBACK TEST CONNECTORS.
 * Device seams are deterministic, harmless substitutes. This is neither Tor
 * connectivity evidence nor native microphone/playback acceptance.
 */
class VoiceCallServiceTest {
  @TempDir Path root;
  private static final char[] PASSWORD="voice-controller-test-password".toCharArray();
  private static final class MutableClock extends Clock {
    final AtomicLong offset=new AtomicLong();public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){return this;}public Instant instant(){return Instant.ofEpochMilli(millis());}public long millis(){return System.currentTimeMillis()+offset.get();}
  }
  private static final class Media implements VoiceCallService.Media {
    final VoiceCallService.EncodedSink sink;final AtomicBoolean microphone=new AtomicBoolean(),closed=new AtomicBoolean();final BlockingQueue<byte[]> received=new LinkedBlockingQueue<>();final Runnable closeHook;volatile boolean microphoneThrows,configureThrows;long sequence;
    Media(VoiceCallService.EncodedSink sink,Runnable closeHook){this.sink=sink;this.closeHook=closeHook;}
    public void receive(long sequence,long timestamp,byte[] opus){received.add(opus.clone());}
    public void microphone(boolean enabled){if(closed.get()||microphoneThrows)throw new IllegalStateException("synthetic device state failure");microphone.set(enabled);}
    public void configure(GlasAudioSession.Config value){if(configureThrows)throw new IllegalStateException("synthetic device configuration failure");}
    public GlasAudioSession.Stats stats(){return null;}
    public void close(){microphone.set(false);if(closed.compareAndSet(false,true))closeHook.run();}
    boolean emit(byte[] bytes){return microphone.get()&&!closed.get()&&sink.offer(sequence++,sequence*20,bytes.clone());}
  }
  private static final class Factory implements VoiceCallService.MediaFactory {
    final List<Media> sessions=new CopyOnWriteArrayList<>();volatile boolean unavailable;volatile Runnable closeHook=()->{};
    public VoiceCallService.Media open(GlasAudioSession.Config config,VoiceCallService.EncodedSink sink,java.util.function.Consumer<String> failure)throws IOException{if(unavailable)throw new IOException("unit device unavailable");Media media=new Media(sink,closeHook);sessions.add(media);return media;}
    Media last(){return sessions.getLast();}
  }
  private final class Pair implements AutoCloseable {
    final MutableClock clock=new MutableClock();final LocalStore a,b;final LocalFeatures af,bf;final Factory am=new Factory(),bm=new Factory();final VoiceCallService ac,bc;final PeerServer server;final AtomicReference<Socket> lastConnection=new AtomicReference<>();final AtomicInteger connections=new AtomicInteger();final UserInfo ai,bi;
    Pair()throws Exception{
      a=new LocalStore(root.resolve(UUID.randomUUID()+"-a"),PASSWORD,clock,200000,4_000_000);b=new LocalStore(root.resolve(UUID.randomUUID()+"-b"),PASSWORD,clock,200000,4_000_000);a.bindNickname("raven");b.bindNickname("blackfox");
      ai=new UserInfo(a.identity().userId(),a.nickname(),a.identity().publicKey(),null);bi=new UserInfo(b.identity().userId(),b.nickname(),b.identity().publicKey(),null);a.trust(bi);b.trust(ai);af=new LocalFeatures(a);bf=new LocalFeatures(b);
      bc=new VoiceCallService(b,bf,contact->{throw new IOException("unexpected reverse test dial");},bm);
      server=new PeerServer(0,b,200000,b::accept,null,bc::handleIncoming);server.start();
      ac=new VoiceCallService(a,af,contact->{Socket socket=new Socket(InetAddress.getLoopbackAddress(),server.port());lastConnection.set(socket);connections.incrementAndGet();return socket;},am);ac.networkAvailable(true);bc.networkAvailable(true);
    }
    void ring()throws Exception{ac.start(bi);await(()->bc.snapshot().state()==VoiceCallService.State.INCOMING);await(()->ac.snapshot().state()==VoiceCallService.State.RINGING);}
    void secure()throws Exception{ring();bc.accept(bc.snapshot().callId());await(()->ac.snapshot().state()==VoiceCallService.State.SECURE&&bc.snapshot().state()==VoiceCallService.State.SECURE);}
    public void close()throws Exception{ac.close();bc.close();server.close();a.close();b.close();}
  }
  private static void await(BooleanSupplier condition)throws Exception{await(condition,12_000);}
  private static void await(BooleanSupplier condition,long timeout)throws Exception{long until=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeout);while(!condition.getAsBoolean()&&System.nanoTime()<until)Thread.sleep(10);assertTrue(condition.getAsBoolean(),"Timed out waiting for the tested state");}

  @Test void mutualTlsConsentGatesDevicesAndMediaWhileMailStillDelivers()throws Exception{
    try(var pair=new Pair()){
      pair.ac.setHistoryEnabled(true);pair.bc.setHistoryEnabled(true);pair.ring();assertTrue(pair.am.sessions.isEmpty());assertTrue(pair.bm.sessions.isEmpty());assertFalse(pair.ac.snapshot().microphoneEnabled());
      pair.ac.setMicrophoneEnabled(true);assertTrue(pair.am.sessions.isEmpty());
      pair.bc.accept(pair.bc.snapshot().callId());await(()->pair.ac.snapshot().state()==VoiceCallService.State.SECURE&&pair.bc.snapshot().state()==VoiceCallService.State.SECURE);
      assertEquals(pair.ac.snapshot().safetyCode(),pair.bc.snapshot().safetyCode());assertFalse(pair.ac.snapshot().safetyCode().isBlank());assertEquals(Identity.fingerprint(pair.bi.publicKey()),pair.ac.snapshot().fingerprint());assertFalse(pair.am.last().microphone.get());assertFalse(pair.bm.last().microphone.get());
      // Real encrypted/signed mail packet on the SAME peer listener during a call.
      EncryptedPacket packet;try(var plain=PlainMessage.text("mail continues during audio")){packet=new AutomaticEncryption(Clock.systemUTC()).encrypt(plain,300,60_000,pair.a.identity(),pair.a.nickname(),pair.bi);}
      try(var socket=new Socket(InetAddress.getLoopbackAddress(),pair.server.port());var out=new DataOutputStream(socket.getOutputStream());var in=new DataInputStream(socket.getInputStream())){
        socket.setSoTimeout(5000);Binary.header(out);out.writeByte(Operation.DELIVER.code);Binary.text(out,"");PacketCodec.write(out,packet);out.flush();Binary.header(in);assertEquals(0,in.readInt());assertEquals(packet.messageId(),Receipt.read(in).messageId());
      }
      assertEquals(1,pair.b.inbox().size());
      pair.ac.setMicrophoneEnabled(true);await(()->pair.ac.snapshot().microphoneEnabled());assertTrue(pair.am.last().emit(new byte[]{1,2,3}));assertArrayEquals(new byte[]{1,2,3},pair.bm.last().received.poll(5,TimeUnit.SECONDS));
      pair.ac.setMicrophoneEnabled(false);assertFalse(pair.ac.snapshot().microphoneEnabled());await(()->!pair.am.last().microphone.get());assertFalse(pair.am.last().emit(new byte[]{9}));
      pair.ac.hangup();await(()->pair.ac.snapshot().state()==VoiceCallService.State.ENDED&&pair.bc.snapshot().state()==VoiceCallService.State.ENDED);await(()->!pair.ac.busy()&&!pair.bc.busy());
      assertTrue(pair.am.last().closed.get());assertTrue(pair.bm.last().closed.get());assertEquals(1,pair.ac.history().size());assertEquals(1,pair.bc.history().size());assertEquals(0,pair.ac.history().getFirst().startedMinute()%60_000);
    }
  }
  @Test void declineAndDisabledIncomingDoNotOpenDevicesAndNextCallStillWorks()throws Exception{
    try(var pair=new Pair()){
      pair.ring();pair.bc.decline(pair.bc.snapshot().callId());await(()->pair.ac.snapshot().state()==VoiceCallService.State.DECLINED);await(()->!pair.ac.busy()&&!pair.bc.busy());assertTrue(pair.am.sessions.isEmpty());assertTrue(pair.bm.sessions.isEmpty());
      pair.bc.setIncomingEnabled(false);pair.ac.start(pair.bi);await(()->pair.ac.snapshot().state()==VoiceCallService.State.DECLINED);await(()->!pair.ac.busy());assertTrue(pair.am.sessions.isEmpty());assertTrue(pair.bm.sessions.isEmpty());
      pair.bc.setIncomingEnabled(true);pair.secure();assertEquals(1,pair.am.sessions.size());assertEquals(1,pair.bm.sessions.size());
    }
  }
  @Test void unknownAndBlockedIdentitiesNeverRingOrBecomeTrusted()throws Exception{
    try(var pair=new Pair()){
      pair.b.removeContact(pair.ai.nickname());pair.ac.start(pair.bi);await(()->pair.ac.snapshot().state()==VoiceCallService.State.UNAVAILABLE);await(()->!pair.ac.busy());assertEquals(VoiceCallService.State.IDLE,pair.bc.snapshot().state());assertNull(pair.b.contact(pair.ai.nickname()));assertTrue(pair.bm.sessions.isEmpty());
      pair.b.trust(pair.ai);pair.bf.blockSender(pair.ai.userId(),true);pair.ac.start(pair.bi);await(()->pair.ac.snapshot().state()==VoiceCallService.State.UNAVAILABLE);assertEquals(VoiceCallService.State.IDLE,pair.bc.snapshot().state());assertTrue(pair.bm.sessions.isEmpty());
      pair.af.blockSender(pair.bi.userId(),true);assertThrows(IOException.class,()->pair.ac.start(pair.bi));
    }
  }
  @Test void contactKeyReplacementClosesAuthenticatedCallWithoutTrustingOldKey()throws Exception{
    try(var pair=new Pair()){
      pair.secure();pair.ac.setMicrophoneEnabled(true);await(()->pair.ac.snapshot().microphoneEnabled());Identity replacement=Identity.create();pair.a.removeContact(pair.bi.nickname());pair.a.trust(new UserInfo(replacement.userId(),pair.bi.nickname(),replacement.publicKey(),null));
      await(()->pair.ac.snapshot().state()==VoiceCallService.State.UNAVAILABLE);await(()->pair.am.last().closed.get());assertFalse(pair.ac.snapshot().microphoneEnabled());assertEquals(replacement.userId(),pair.a.contact(pair.bi.nickname()).userId());assertThrows(IOException.class,()->pair.ac.start(pair.bi));
    }
  }
  @Test void freshAuthenticatedReconnectKeepsIdentityAndMutesBothEndpoints()throws Exception{
    try(var pair=new Pair()){
      pair.secure();String initialCode=pair.ac.snapshot().safetyCode(),fingerprint=pair.ac.snapshot().fingerprint();pair.ac.setMicrophoneEnabled(true);await(()->pair.ac.snapshot().microphoneEnabled());pair.lastConnection.get().close();
      await(()->pair.ac.snapshot().state()==VoiceCallService.State.RECONNECTING&&pair.bc.snapshot().state()==VoiceCallService.State.RECONNECTING);
      await(()->pair.ac.snapshot().state()==VoiceCallService.State.SECURE&&pair.bc.snapshot().state()==VoiceCallService.State.SECURE,15_000);
      assertEquals(2,pair.connections.get());assertEquals(2,pair.am.sessions.size());assertEquals(2,pair.bm.sessions.size());assertTrue(pair.am.sessions.getFirst().closed.get());assertTrue(pair.bm.sessions.getFirst().closed.get());assertFalse(pair.ac.snapshot().microphoneEnabled());assertFalse(pair.bc.snapshot().microphoneEnabled());assertFalse(pair.am.last().microphone.get());assertEquals(fingerprint,pair.ac.snapshot().fingerprint());assertNotEquals(initialCode,pair.ac.snapshot().safetyCode());assertEquals(pair.ac.snapshot().safetyCode(),pair.bc.snapshot().safetyCode());
    }
  }
  @Test void unavailableDeviceEndsCallAndServiceCanAcceptAnotherCall()throws Exception{
    try(var pair=new Pair()){
      pair.bm.unavailable=true;pair.ring();pair.bc.accept(pair.bc.snapshot().callId());await(()->pair.bc.snapshot().state()==VoiceCallService.State.UNAVAILABLE);await(()->!pair.bc.busy());pair.ac.hangup();await(()->!pair.ac.busy());
      pair.bm.unavailable=false;pair.secure();assertEquals(VoiceCallService.State.SECURE,pair.bc.snapshot().state());assertFalse(pair.bc.snapshot().microphoneEnabled());
    }
  }
  @Test void singleCallOwnershipAndCachedSnapshotStayResponsiveDuringSlowDial()throws Exception{
    try(var local=new LocalStore(root,PASSWORD,Clock.systemUTC(),200000,4_000_000)){
      local.bindNickname("raven");Identity remote=Identity.create();UserInfo contact=new UserInfo(remote.userId(),"blackfox",remote.publicKey(),null);local.trust(contact);var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var attempts=new AtomicInteger();
      try(var service=new VoiceCallService(local,new LocalFeatures(local),person->{attempts.incrementAndGet();entered.countDown();try{release.await();}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}throw new IOException("unit slow dial ended");},new Factory())){
        service.networkAvailable(true);service.start(contact);assertTrue(entered.await(3,TimeUnit.SECONDS));long begin=System.nanoTime();assertEquals(VoiceCallService.State.PREPARING,service.snapshot().state());assertThrows(IOException.class,()->service.start(contact));assertTrue(System.nanoTime()-begin<500_000_000L);assertEquals(1,attempts.get());service.hangup();await(()->service.snapshot().state()==VoiceCallService.State.ENDED);assertTrue(service.history().isEmpty());
      }finally{release.countDown();}
    }
  }
  @Test void ringingAndReconnectDeadlinesEndWithoutTorOrDeviceFallback()throws Exception{
    try(var pair=new Pair()){
      pair.ring();pair.clock.offset.addAndGet(61_000);await(()->!pair.ac.busy()&&!pair.bc.busy(),4000);assertTrue(pair.am.sessions.isEmpty());assertTrue(pair.bm.sessions.isEmpty());
    }
    try(var pair=new Pair()){
      pair.secure();pair.ac.networkAvailable(false);pair.bc.networkAvailable(false);await(()->pair.ac.snapshot().state()==VoiceCallService.State.RECONNECTING&&pair.bc.snapshot().state()==VoiceCallService.State.RECONNECTING);pair.clock.offset.addAndGet(46_000);await(()->!pair.ac.busy()&&!pair.bc.busy(),4000);assertEquals(1,pair.connections.get());assertTrue(pair.am.last().closed.get());assertTrue(pair.bm.last().closed.get());
    }
  }
  @Test void anotherAuthenticatedContactGetsBusyWithoutReplacingTheActiveCall()throws Exception{
    try(var pair=new Pair();var third=new LocalStore(root.resolve("third"),PASSWORD,Clock.systemUTC(),200000,4_000_000)){
      pair.secure();String originalId=pair.bc.snapshot().callId();third.bindNickname("falcon");var thirdIdentity=new UserInfo(third.identity().userId(),third.nickname(),third.identity().publicKey(),null);third.trust(pair.bi);pair.b.trust(thirdIdentity);Factory devices=new Factory();
      try(var service=new VoiceCallService(third,new LocalFeatures(third),contact->new Socket(InetAddress.getLoopbackAddress(),pair.server.port()),devices)){
        service.networkAvailable(true);service.start(pair.bi);await(()->service.snapshot().state()==VoiceCallService.State.UNAVAILABLE);assertEquals(originalId,pair.bc.snapshot().callId());assertEquals(VoiceCallService.State.SECURE,pair.bc.snapshot().state());assertTrue(devices.sessions.isEmpty());assertThrows(IOException.class,()->pair.ac.start(pair.bi));
      }
    }
  }
  @Test void legacyPeerRejectsVoiceAndRemainsAvailableForMail()throws Exception{
    try(var pair=new Pair();var old=new PeerServer(0,pair.b,200000);var service=new VoiceCallService(pair.a,pair.af,contact->new Socket(InetAddress.getLoopbackAddress(),old.port()),new Factory())){
      old.start();service.networkAvailable(true);service.start(pair.bi);await(()->service.snapshot().state()==VoiceCallService.State.UNAVAILABLE);assertTrue(pair.am.sessions.isEmpty());
      EncryptedPacket packet;try(var plain=PlainMessage.text("legacy peer still receives")){packet=new AutomaticEncryption(Clock.systemUTC()).encrypt(plain,300,60_000,pair.a.identity(),pair.a.nickname(),pair.bi);}
      try(var socket=new Socket(InetAddress.getLoopbackAddress(),old.port());var out=new DataOutputStream(socket.getOutputStream());var in=new DataInputStream(socket.getInputStream())){socket.setSoTimeout(5000);Binary.header(out);out.writeByte(Operation.DELIVER.code);Binary.text(out,"");PacketCodec.write(out,packet);out.flush();Binary.header(in);assertEquals(0,in.readInt());assertEquals(packet.messageId(),Receipt.read(in).messageId());}
    }
  }
  @Test void authenticatedAudioBeforeAcceptanceClosesCallWithoutOpeningAnyDevice()throws Exception{
    try(var pair=new Pair();var socket=new Socket(InetAddress.getLoopbackAddress(),pair.server.port());var pending=VoiceTls.create(pair.a.identity(),UUID.randomUUID(),VoiceTls.Role.CALLER,pair.bi.publicKey())){
      socket.setSoTimeout(5000);var out=new DataOutputStream(socket.getOutputStream());var in=new DataInputStream(socket.getInputStream());Binary.header(out);out.writeByte(VoiceFrames.OPERATION);Binary.text(out,"");pending.offer().write(out);out.flush();var remote=VoiceTls.read(in);
      try(var tls=pending.handshake(socket,remote,pair.bi.publicKey(),true)){
        var secureOut=new DataOutputStream(tls.getOutputStream());var secureIn=new DataInputStream(tls.getInputStream());VoiceFrames.write(secureOut,VoiceFrames.start(false));VoiceFrames.Frame ring=VoiceFrames.read(secureIn);assertEquals(VoiceFrames.RINGING,ring.type());VoiceFrames.write(secureOut,VoiceFrames.audio(0,0,new byte[]{1}));await(()->pair.bc.snapshot().state()==VoiceCallService.State.UNAVAILABLE);assertTrue(pair.bm.sessions.isEmpty());assertFalse(pair.bc.snapshot().microphoneEnabled());
      }
    }
  }
  @Test void damagedOptionalVoiceMetadataPreservesMailIdentityAndRequiresExplicitVoiceReset()throws Exception{
    try(var pair=new Pair()){
      pair.ac.close();pair.a.writeVoiceState(new byte[]{9,8,7});byte[] before=Files.readAllBytes(pair.a.root().resolve("voice-v1.vault"));String originalIdentity=pair.a.identity().userId();
      try(var service=new VoiceCallService(pair.a,pair.af,contact->{throw new IOException("not connected in recovery test");},new Factory())){
        service.networkAvailable(true);assertEquals(VoiceCallService.State.UNAVAILABLE,service.snapshot().state());assertFalse(service.incomingEnabled());assertThrows(IOException.class,()->service.start(pair.bi));assertThrows(IOException.class,()->service.setHistoryEnabled(true));assertArrayEquals(before,Files.readAllBytes(pair.a.root().resolve("voice-v1.vault")));
        EncryptedPacket packet;try(var plain=PlainMessage.text("mail remains usable despite damaged optional voice state")){packet=new AutomaticEncryption(Clock.systemUTC()).encrypt(plain,300,60_000,pair.b.identity(),pair.b.nickname(),pair.ai);}pair.a.accept(packet);assertEquals(1,pair.a.inbox().size());assertEquals(originalIdentity,pair.a.identity().userId());
        service.clearHistory();assertTrue(service.incomingEnabled());assertTrue(service.history().isEmpty());assertFalse(service.snapshot().historyEnabled());assertEquals(0,new VoiceHistory(pair.a).entries().size());
      }
    }
  }
  @Test void hangupIsImmediateButOwnershipRemainsUntilSlowDeviceCleanupCompletes()throws Exception{
    try(var pair=new Pair()){
      var entered=new CountDownLatch(1);var release=new CountDownLatch(1);pair.am.closeHook=()->{entered.countDown();try{release.await();}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}};pair.secure();
      try{long begin=System.nanoTime();pair.ac.hangup();assertTrue(System.nanoTime()-begin<500_000_000L);assertTrue(entered.await(3,TimeUnit.SECONDS));assertEquals(VoiceCallService.State.ENDED,pair.ac.snapshot().state());assertTrue(pair.ac.busy());assertThrows(IOException.class,()->pair.ac.start(pair.bi));await(()->pair.bc.snapshot().state()==VoiceCallService.State.ENDED);}
      finally{release.countDown();}
      await(()->!pair.ac.busy());
    }
  }
  @Test void uncheckedDeviceFailuresCloseTheCallAndLeaveServiceUsable()throws Exception{
    try(var pair=new Pair()){
      pair.secure();pair.am.last().microphoneThrows=true;pair.ac.setMicrophoneEnabled(true);await(()->pair.ac.snapshot().state()==VoiceCallService.State.UNAVAILABLE);await(()->!pair.ac.busy()&&!pair.bc.busy());assertTrue(pair.am.last().closed.get());assertFalse(pair.ac.snapshot().microphoneEnabled());
      pair.secure();pair.am.last().configureThrows=true;pair.ac.configureAudio(GlasAudioSession.Config.defaults());await(()->pair.ac.snapshot().state()==VoiceCallService.State.UNAVAILABLE);await(()->!pair.ac.busy()&&!pair.bc.busy());assertTrue(pair.am.last().closed.get());
      pair.secure();assertEquals(VoiceCallService.State.SECURE,pair.ac.snapshot().state());assertFalse(pair.ac.snapshot().microphoneEnabled());
    }
  }
}
