package org.securemail.client.ecosystem;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class IdleLockGuardTest {
  @Test void tenMinuteMonotonicDeadlineDoesNotDependOnWallClockAndLocksOnce(){
    AtomicLong time=new AtomicLong(Long.MAX_VALUE-Duration.ofMinutes(5).toNanos());List<IdleLockGuard.Reason> reasons=new ArrayList<>();var guard=new IdleLockGuard(time::get,Duration.ofMinutes(10),reasons::add);
    time.addAndGet(Duration.ofMinutes(9).toNanos());guard.check();assertFalse(guard.locked());
    time.addAndGet(Duration.ofMinutes(1).toNanos());guard.check();guard.check();guard.userActivity();assertTrue(guard.locked());assertEquals(List.of(IdleLockGuard.Reason.INACTIVITY),reasons);
    guard.authenticatedUnlock();assertFalse(guard.locked());time.addAndGet(Duration.ofMinutes(10).toNanos());guard.check();assertEquals(2,reasons.size());
  }
  @Test void actualInputRenewsIdleButOsLockCannotBeClearedByInput(){
    AtomicLong time=new AtomicLong();List<IdleLockGuard.Reason> reasons=new ArrayList<>();var guard=new IdleLockGuard(time::get,Duration.ofMinutes(10),reasons::add);
    time.addAndGet(Duration.ofMinutes(9).toNanos());guard.userActivity();time.addAndGet(Duration.ofMinutes(2).toNanos());guard.check();assertFalse(guard.locked());
    guard.operatingSystemLocked();guard.userActivity();assertTrue(guard.locked());assertEquals(List.of(IdleLockGuard.Reason.OPERATING_SYSTEM),reasons);
    assertThrows(IllegalArgumentException.class,()->new IdleLockGuard(time::get,Duration.ofMinutes(11),reasons::add));
  }
  @Test void revocationAlwaysLocksBeforeAnotherAction(){var guard=new IdleLockGuard(reason->{});guard.sessionRevoked();assertTrue(guard.locked());}
}
