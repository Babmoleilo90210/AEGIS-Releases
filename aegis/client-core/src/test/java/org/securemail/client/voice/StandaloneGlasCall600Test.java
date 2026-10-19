package org.securemail.client.voice;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.Identity;
import org.securemail.client.security.SystemSecrets;
import org.securemail.client.voice600.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;
import org.securemail.protocol.*;

/** Production delegated voice service + real TLS sockets; explicit loopback/media/OS-secret fixtures, not physical-device or Tor evidence. */
@Timeout(25)
class StandaloneGlasCall600Test {
  @TempDir Path directory;static final String AUDIENCE="ab".repeat(32);
  private static final class Secrets implements SystemSecrets{byte[] key;public void store(byte[] value){key=value.clone();}public byte[] load(){return key==null?null:key.clone();}public void clear(){key=null;}}
  private static final class Media implements VoiceCallService.Media{
    final VoiceCallService.EncodedSink sink;final AtomicBoolean microphone=new AtomicBoolean(),closed=new AtomicBoolean();final BlockingQueue<byte[]> received=new ArrayBlockingQueue<>(4);long sequence;
    Media(VoiceCallService.EncodedSink sink){this.sink=sink;}public void receive(long s,long t,byte[] bytes){received.offer(bytes.clone());}public void microphone(boolean on){microphone.set(on);}public void configure(GlasAudioSession.Config config){}public GlasAudioSession.Stats stats(){return null;}public void close(){microphone.set(false);closed.set(true);}boolean emit(byte[] bytes){return microphone.get()&&!closed.get()&&sink.offer(sequence++,sequence*20,bytes.clone());}
  }
  private static final class Factory implements VoiceCallService.MediaFactory{final List<Media> sessions=new CopyOnWriteArrayList<>();public VoiceCallService.Media open(GlasAudioSession.Config config,VoiceCallService.EncodedSink sink,java.util.function.Consumer<String> error){Media m=new Media(sink);sessions.add(m);return m;}Media last(){return sessions.getLast();}}
  private static GlasGrant600 grant(Identity root,KeyPair app,UserInfo contact)throws Exception{long now=System.currentTimeMillis();var d=new GlasProtocol600.Delegation(AUDIENCE,root.publicKey(),"cd".repeat(32),1,app.getPublic().getEncoded(),now-1000,now+600000,IdentityProtocol.nonce(),new byte[64]);d=d.signed(root.sign(d.signingBytes()));var g=new GlasGrant600(d,List.of(new GlasGrant600.Contact(contact,false)),new byte[64]);return g.signed(root.sign(g.signingBytes()));}
  private final class Pair implements AutoCloseable{
    final Identity alice=Identity.create(),bob=Identity.create();final KeyPair aa=KeyPairGenerator.getInstance("Ed25519").generateKeyPair(),ba=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    final UserInfo ai=new UserInfo(alice.userId(),"raven",alice.publicKey(),null),bi=new UserInfo(bob.userId(),"blackfox",bob.publicKey(),null);final Secrets ak=new Secrets(),bk=new Secrets();final GlasGrant600 ag=grant(alice,aa,bi),bg=grant(bob,ba,ai);final GlasState600 a=new GlasState600(directory.resolve("a"),ag,aa.getPrivate(),ak),b=new GlasState600(directory.resolve("b"),bg,ba.getPrivate(),bk);final AtomicBoolean active=new AtomicBoolean(true);final AtomicInteger verified=new AtomicInteger();final Factory af=new Factory(),bf=new Factory();final VoiceCallService ac,bc;final ServerSocket listener;final ExecutorService inbound=Executors.newSingleThreadExecutor();final Set<Socket> connections=ConcurrentHashMap.newKeySet();
    Pair()throws Exception{
      a.remoteVerifier(offer->{assertNotNull(offer.delegation());verified.incrementAndGet();},peer->active.get());b.remoteVerifier(offer->{assertNotNull(offer.delegation());verified.incrementAndGet();},peer->active.get());
      bc=new VoiceCallService(b,contact->{throw new IOException("No reverse test dial");},bf);listener=new ServerSocket(0,2,InetAddress.getLoopbackAddress());inbound.submit(()->{try{while(!listener.isClosed()){Socket socket=listener.accept();connections.add(socket);try(socket){var input=new DataInputStream(socket.getInputStream());Binary.header(input);if(input.readUnsignedByte()!=101||!Binary.text(input,64).isEmpty())throw new IOException("Fixture preface");bc.handleIncoming(socket);}catch(Exception ignored){}finally{connections.remove(socket);}}}catch(IOException closed){}});
      ac=new VoiceCallService(a,contact->new Socket(InetAddress.getLoopbackAddress(),listener.getLocalPort()),af);ac.networkAvailable(true);bc.networkAvailable(true);
    }
    void ring()throws Exception{ac.start(bi);await(()->bc.snapshot().state()==VoiceCallService.State.INCOMING);await(()->ac.snapshot().state()==VoiceCallService.State.RINGING);}
    void secure()throws Exception{ring();bc.accept(bc.snapshot().callId());await(()->ac.snapshot().state()==VoiceCallService.State.SECURE&&bc.snapshot().state()==VoiceCallService.State.SECURE);}
    public void close()throws Exception{ac.close();bc.close();listener.close();for(Socket s:connections)s.close();inbound.shutdownNow();a.close();b.close();}
  }
  private static void await(BooleanSupplier condition)throws Exception{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(12);while(!condition.getAsBoolean()&&System.nanoTime()<until)Thread.sleep(10);assertTrue(condition.getAsBoolean(),"Expected actual call state did not arrive");}
  @Test void lockedIncomingCanAcceptAuthenticatedAudioWithoutOpeningHistoryOrOutgoingAccess()throws Exception{
    try(var p=new Pair()){
      p.bc.setHistoryEnabled(true);p.bc.lockRestricted();p.b.lockHistory();assertTrue(p.bc.restricted());assertTrue(p.b.historyLocked());assertThrows(IOException.class,()->p.bc.start(p.ai));assertThrows(IOException.class,()->p.bc.setHistoryEnabled(true));assertThrows(IOException.class,p.b::readVoiceState);
      p.ring();assertTrue(p.af.sessions.isEmpty());assertTrue(p.bf.sessions.isEmpty());assertTrue(p.verified.get()>=2);p.bc.accept(p.bc.snapshot().callId());await(()->p.ac.snapshot().state()==VoiceCallService.State.SECURE&&p.bc.snapshot().state()==VoiceCallService.State.SECURE);assertFalse(p.af.last().microphone.get());assertFalse(p.bf.last().microphone.get());
      p.bc.setMicrophoneEnabled(true);await(()->p.bc.snapshot().microphoneEnabled());assertTrue(p.bf.last().emit(new byte[]{7,8,9}));assertArrayEquals(new byte[]{7,8,9},p.af.last().received.poll(5,TimeUnit.SECONDS));assertFalse(p.bc.snapshot().historyEnabled());assertTrue(p.bc.history().isEmpty());
      p.bc.hangup();await(()->!p.ac.busy()&&!p.bc.busy());assertTrue(p.bf.last().closed.get());assertFalse(p.bf.last().microphone.get());assertThrows(IOException.class,p.b::readVoiceState);assertFalse(Files.exists(directory.resolve("b/state.vault")));
    }
  }
  @Test void revokedLivePeerLeaseStopsActualDelegatedCallAndReleasesMedia()throws Exception{
    try(var p=new Pair()){p.secure();p.ac.setMicrophoneEnabled(true);await(()->p.ac.snapshot().microphoneEnabled());p.active.set(false);await(()->!p.ac.busy()&&!p.bc.busy());assertTrue(p.af.last().closed.get());assertTrue(p.bf.last().closed.get());assertFalse(p.ac.snapshot().microphoneEnabled());assertFalse(p.bc.snapshot().microphoneEnabled());}
  }
}
