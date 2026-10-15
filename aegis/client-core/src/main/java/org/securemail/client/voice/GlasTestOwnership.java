package org.securemail.client.voice;

import java.util.Objects;

/**
 * Device-independent lifetime state for an asynchronously opened local microphone test.
 * All state transitions are atomic. No device I/O or executor call happens under this lock.
 * The caller closes rejected claims and the resource returned by stop()/retire() on its
 * guaranteed device-cleanup path, never by silently dropping a rejected executor task.
 */
public final class GlasTestOwnership<T extends AutoCloseable> {
    private long generation;
    private T resource;
    private boolean retired;

    /** Start a new attempt after any previous held resource has been detached with stop(). */
    public synchronized long begin() {
        if (retired) throw new IllegalStateException("Microphone test controls are closed");
        if (resource != null) throw new IllegalStateException("Stop the previous microphone test first");
        return ++generation;
    }

    public synchronized boolean current(long token) {
        return !retired && token == generation;
    }

    public synchronized T resource() { return resource; }

    /** Ownership of candidate transfers only if true; false leaves cleanup to the opening worker. */
    public synchronized boolean claim(long token, T candidate) {
        Objects.requireNonNull(candidate);
        if (!current(token) || resource != null) return false;
        resource = candidate;
        return true;
    }

    /** Check before a delayed UI callback; object identity is intentional. */
    public synchronized boolean owns(long token, T candidate) {
        return current(token) && resource == candidate;
    }

    /** Invalidate every pending open and return the one detached resource, if present. */
    public synchronized T stop() {
        ++generation;
        T detached = resource;
        resource = null;
        return detached;
    }

    /** Invalidate this attempt only; a stale callback cannot stop its successor. */
    public synchronized T stop(long token) {
        return current(token) ? stop() : null;
    }

    /** Permanent disposal: a delayed opener can never claim this owner again. */
    public synchronized T retire() {
        retired = true;
        return stop();
    }
}
