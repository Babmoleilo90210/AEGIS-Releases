package org.securemail.client.community;

import org.junit.jupiter.api.Test;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class VoiceGrantLeaseTest {
  @Test void monotonicLeaseExpiresEvenWhenWallClockWouldPermitOldGrant() {
    long start = 4_000_000_000L;
    assertTrue(VoiceGrantCache.leaseAlive(start,start+TimeUnit.SECONDS.toNanos(19)));
    // Wall-clock rollback cannot renew or stretch the independent duration cap.
    assertFalse(VoiceGrantCache.leaseAlive(start,start+TimeUnit.SECONDS.toNanos(20)));
    assertFalse(VoiceGrantCache.leaseAlive(start,start+TimeUnit.MINUTES.toNanos(1)));
    assertFalse(VoiceGrantCache.leaseAlive(start,start-1));
  }
  @Test void nanoTimeSignedWrapStillHonorsDuration() {
    long start=Long.MAX_VALUE-TimeUnit.SECONDS.toNanos(2);
    assertTrue(VoiceGrantCache.leaseAlive(start,start+TimeUnit.SECONDS.toNanos(3)));
    assertFalse(VoiceGrantCache.leaseAlive(start,start+TimeUnit.SECONDS.toNanos(20)));
  }
}
