package org.securemail.client.voice;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;

/** Production audio queue and frame serialization with fake monotonic time.
 * The deliberately blocked OutputStream is not a Tor/TLS/microphone test.
 */
class VoiceAudioQueueTest {
  private static VoiceFrames.Frame frame(long sequence)throws IOException{return VoiceFrames.audio(sequence,sequence*20,new byte[]{1,2,3});}
  private static VoiceCallService.AudioQueue queue(int size,AtomicLong time){return new VoiceCallService.AudioQueue(size,VoiceCallService.AUDIO_TTL_NANOS,time::get);}
  private static VoiceCallService.QueuedAudio poll(VoiceCallService.AudioQueue queue)throws InterruptedException{return queue.poll(0,TimeUnit.NANOSECONDS);}
  private static void wiped(VoiceFrames.Frame frame){assertArrayEquals(new byte[frame.payload().length],frame.payload());}

  @Test void fullQueueRetainsNewestButReportsPressureAndWipesEvicted()throws Exception{
    AtomicLong now=new AtomicLong();var queue=queue(2,now);var first=frame(0);var second=frame(1);var newest=frame(2);
    assertTrue(queue.offerOwned(first));assertTrue(queue.offerOwned(second));assertFalse(queue.offerOwned(newest));assertEquals(2,queue.size());wiped(first);
    assertSame(second,poll(queue).frame);assertSame(newest,poll(queue).frame);assertNull(poll(queue));second.wipe();newest.wipe();
  }
  @Test void ttlBoundaryUsesLocalEnqueueTimeAndPreservesWireTimestamp()throws Exception{
    AtomicLong now=new AtomicLong(1000);var queue=queue(2,now);var fresh=VoiceFrames.audio(42,Long.MAX_VALUE,new byte[]{7,8});assertTrue(queue.offerOwned(fresh));var held=poll(queue);
    now.addAndGet(VoiceCallService.AUDIO_TTL_NANOS-1);var bytes=new ByteArrayOutputStream();assertTrue(queue.writeIfFresh(new DataOutputStream(bytes),held));wiped(fresh);
    VoiceFrames.Frame wire=VoiceFrames.read(new DataInputStream(new ByteArrayInputStream(bytes.toByteArray())));var audio=VoiceFrames.audio(wire);assertEquals(42,audio.sequence());assertEquals(Long.MAX_VALUE,audio.timestampMillis());assertArrayEquals(new byte[]{7,8},audio.opus());Arrays.fill(audio.opus(),(byte)0);wire.wipe();
    var exact=frame(43);assertTrue(queue.offerOwned(exact));now.addAndGet(VoiceCallService.AUDIO_TTL_NANOS);assertNull(poll(queue));wiped(exact);
  }
  @Test void staleHeldFrameIsWipedBeforeWritingAndPressureReachesNextOffer()throws Exception{
    AtomicLong now=new AtomicLong();var queue=queue(2,now);var expired=frame(0);assertTrue(queue.offerOwned(expired));var held=poll(queue);
    now.set(VoiceCallService.AUDIO_TTL_NANOS);var bytes=new ByteArrayOutputStream();assertFalse(queue.writeIfFresh(new DataOutputStream(bytes),held));assertEquals(0,bytes.size());wiped(expired);
    assertFalse(queue.offerOwned(frame(1)));assertTrue(queue.offerOwned(frame(2)));queue.clear();
  }
  @Test void blockedOutputDoesNotBlockOffersOrReplayExpiredQueuedSpeech()throws Exception{
    AtomicLong now=new AtomicLong();var queue=queue(3,now);var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var once=new AtomicBoolean();
    var bytes=new ByteArrayOutputStream();OutputStream blocked=new OutputStream(){public void write(int value)throws IOException{if(once.compareAndSet(false,true)){entered.countDown();try{if(!release.await(3,TimeUnit.SECONDS))throw new IOException("Synthetic write deadline");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}}bytes.write(value);}};
    var wire=new DataOutputStream(blocked);var inFlight=frame(1);assertTrue(queue.offerOwned(inFlight));var held=poll(queue);ExecutorService worker=Executors.newSingleThreadExecutor();
    try{
      Future<Boolean> write=worker.submit(()->queue.writeIfFresh(wire,held));assertTrue(entered.await(3,TimeUnit.SECONDS));var old1=frame(2);var old2=frame(3);assertTrue(queue.offerOwned(old1));assertTrue(queue.offerOwned(old2));
      now.set(VoiceCallService.AUDIO_TTL_NANOS+1);assertNull(poll(queue));wiped(old1);wiped(old2);assertFalse(queue.offerOwned(frame(4)));assertEquals(1,queue.size());
      release.countDown();assertTrue(write.get(3,TimeUnit.SECONDS));assertTrue(queue.writeIfFresh(wire,poll(queue)));wiped(inFlight);
      var input=new DataInputStream(new ByteArrayInputStream(bytes.toByteArray()));List<Long> sequences=new ArrayList<>();while(input.available()>0){var frame=VoiceFrames.read(input);var audio=VoiceFrames.audio(frame);sequences.add(audio.sequence());Arrays.fill(audio.opus(),(byte)0);frame.wipe();}assertEquals(List.of(1L,4L),sequences);
    }finally{release.countDown();worker.shutdownNow();queue.clear();}
  }
  @Test void enqueuePurgesExpiredHeadAndReportsLossOnceWhileKeepingFreshTail()throws Exception{
    AtomicLong now=new AtomicLong();var queue=queue(3,now);var expired=frame(0);assertTrue(queue.offerOwned(expired));now.set(VoiceCallService.AUDIO_TTL_NANOS-1);var tail=frame(1);assertTrue(queue.offerOwned(tail));
    now.incrementAndGet();var newest=frame(2);assertFalse(queue.offerOwned(newest));wiped(expired);assertEquals(2,queue.size());assertTrue(queue.offerOwned(frame(3)));assertSame(tail,poll(queue).frame);tail.wipe();queue.clear();wiped(newest);
  }
  @Test void clearWipesAllRetainedFramesAndAllowsASeparateFreshBatch()throws Exception{
    AtomicLong now=new AtomicLong();var queue=queue(2,now);var a=frame(0);var b=frame(1);assertTrue(queue.offerOwned(a));assertTrue(queue.offerOwned(b));queue.clear();assertEquals(0,queue.size());assertNull(poll(queue));wiped(a);wiped(b);assertTrue(queue.offerOwned(frame(2)));queue.clear();
  }
  @Test void nanoTimeWraparoundStillExpiresAtExactElapsedLimit()throws Exception{
    AtomicLong now=new AtomicLong(Long.MAX_VALUE-10);var queue=new VoiceCallService.AudioQueue(2,20,now::get);var old=frame(0);assertTrue(queue.offerOwned(old));now.addAndGet(19);var held=poll(queue);assertNotNull(held);now.incrementAndGet();assertFalse(queue.writeIfFresh(new DataOutputStream(new ByteArrayOutputStream()),held));wiped(old);
  }
  @Test void inputBytesAreWipedForSuccessReplacementAndRejectedEncoding()throws Exception{
    AtomicLong now=new AtomicLong();var queue=queue(1,now);byte[] success={1,2},pressure={3,4},invalid={5,6},oversized=new byte[VoiceFrames.MAX_OPUS+1];Arrays.fill(oversized,(byte)7);
    assertTrue(queue.offer(0,0,success));assertArrayEquals(new byte[2],success);assertFalse(queue.offer(1,20,pressure));assertArrayEquals(new byte[2],pressure);assertFalse(queue.offer(-1,20,invalid));assertArrayEquals(new byte[2],invalid);assertFalse(queue.offer(2,40,oversized));assertArrayEquals(new byte[oversized.length],oversized);assertEquals(1,queue.size());queue.clear();
  }
  @Test void failedWriteWipesTheDequeuedOwnedPayload()throws Exception{
    AtomicLong now=new AtomicLong();var queue=queue(1,now);var frame=frame(0);assertTrue(queue.offerOwned(frame));var held=poll(queue);OutputStream failure=new OutputStream(){public void write(int value)throws IOException{throw new IOException("Synthetic output failure");}};
    assertThrows(IOException.class,()->queue.writeIfFresh(new DataOutputStream(failure),held));wiped(frame);assertEquals(0,queue.size());
  }
  @Test void controlFramesCannotEnterOrDisplaceTheAudioQueue()throws Exception{
    AtomicLong now=new AtomicLong();var queue=queue(1,now);var audio=frame(0);assertTrue(queue.offerOwned(audio));var control=new VoiceFrames.Frame(VoiceFrames.PONG,new byte[]{9});assertThrows(IllegalArgumentException.class,()->queue.offerOwned(control));wiped(control);assertSame(audio,poll(queue).frame);audio.wipe();
  }
}
