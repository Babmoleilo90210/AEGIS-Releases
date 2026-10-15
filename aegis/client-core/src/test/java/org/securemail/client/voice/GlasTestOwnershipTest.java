package org.securemail.client.voice;

import static org.junit.jupiter.api.Assertions.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** Exercises actual lifetime interleavings without pretending a test handle is an OS microphone. */
class GlasTestOwnershipTest {
    private static final class Handle implements AutoCloseable {
        final AtomicInteger closes = new AtomicInteger();
        public void close() { assertEquals(1, closes.incrementAndGet(), "Test handle closed twice"); }
    }
    private static void close(Handle handle) { if (handle != null) handle.close(); }

    @Test void stoppedBlockedOpenCannotReplaceNewerTest() throws Exception {
        var owner = new GlasTestOwnership<Handle>();
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        var executor = Executors.newSingleThreadExecutor();
        Handle old = new Handle(), fresh = new Handle();
        try {
            long oldToken = owner.begin();
            Future<?> opening = executor.submit(() -> {
                entered.countDown();
                try { assertTrue(release.await(3, TimeUnit.SECONDS)); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
                if (!owner.claim(oldToken, old)) old.close();
            });
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            assertNull(owner.stop());
            long freshToken = owner.begin(); assertTrue(owner.claim(freshToken, fresh));
            release.countDown(); opening.get(3, TimeUnit.SECONDS);
            assertEquals(1, old.closes.get()); assertSame(fresh, owner.resource());
            assertFalse(owner.owns(oldToken, old)); assertTrue(owner.owns(freshToken, fresh));
            close(owner.retire()); assertEquals(1, fresh.closes.get());
        } finally { release.countDown(); executor.shutdownNow(); }
    }

    @Test void shutdownDuringBlockedOpenRejectsEveryDelayedClaim() throws Exception {
        var owner = new GlasTestOwnership<Handle>(); long token = owner.begin();
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        var executor = Executors.newSingleThreadExecutor(); Handle handle = new Handle();
        try {
            Future<?> opening = executor.submit(() -> {
                entered.countDown();
                try { assertTrue(release.await(3, TimeUnit.SECONDS)); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
                if (!owner.claim(token, handle)) handle.close();
            });
            assertTrue(entered.await(3, TimeUnit.SECONDS)); assertNull(owner.retire());
            release.countDown(); opening.get(3, TimeUnit.SECONDS);
            assertNull(owner.resource()); assertEquals(1, handle.closes.get());
            assertThrows(IllegalStateException.class, owner::begin); assertFalse(owner.current(token));
        } finally { release.countDown(); executor.shutdownNow(); }
    }

    @Test void concurrentClaimAndStopAlwaysTransferExactlyOneCleanupResponsibility() throws Exception {
        var executor = Executors.newFixedThreadPool(2);
        try {
            for (int n = 0; n < 200; n++) {
                var owner = new GlasTestOwnership<Handle>(); long token = owner.begin();
                var barrier = new CyclicBarrier(2); Handle handle = new Handle();
                Future<?> claim = executor.submit(() -> {
                    try { barrier.await(3, TimeUnit.SECONDS); }
                    catch (Exception e) { throw new AssertionError(e); }
                    if (!owner.claim(token, handle)) handle.close();
                });
                Future<?> stop = executor.submit(() -> {
                    try { barrier.await(3, TimeUnit.SECONDS); }
                    catch (Exception e) { throw new AssertionError(e); }
                    close(owner.stop());
                });
                claim.get(3, TimeUnit.SECONDS); stop.get(3, TimeUnit.SECONDS);
                assertNull(owner.resource()); assertEquals(1, handle.closes.get());
            }
        } finally { executor.shutdownNow(); }
    }

    @Test void delayedUiCallbacksLoseOwnershipAfterStopAndAnotherOpen() {
        var owner = new GlasTestOwnership<Handle>(); long oldToken = owner.begin(); Handle old = new Handle();
        assertTrue(owner.claim(oldToken, old)); assertTrue(owner.owns(oldToken, old)); close(owner.stop());
        long nextToken = owner.begin(); Handle next = new Handle(); assertTrue(owner.claim(nextToken, next));
        assertFalse(owner.owns(oldToken, old)); assertFalse(owner.current(oldToken));
        assertNull(owner.stop(oldToken)); assertSame(next, owner.resource());
        assertTrue(owner.owns(nextToken, next)); close(owner.retire());
    }

    @Test void activeHandleCannotBeSilentlyOverwrittenAndRepeatedStopDoesNotDoubleClose() {
        var owner = new GlasTestOwnership<Handle>(); long token = owner.begin(); Handle first = new Handle(), second = new Handle();
        assertTrue(owner.claim(token, first)); assertFalse(owner.claim(token, second)); second.close();
        assertThrows(IllegalStateException.class, owner::begin); close(owner.stop());
        assertNull(owner.stop()); assertNull(owner.retire()); assertNull(owner.retire());
        assertEquals(1, first.closes.get()); assertEquals(1, second.closes.get());
    }
}
