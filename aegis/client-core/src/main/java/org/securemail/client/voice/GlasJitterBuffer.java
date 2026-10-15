package org.securemail.client.voice;

import java.util.Arrays;
import java.util.TreeMap;

/** Bounded playout queue. Times are local monotonic arrivals; remote clocks are never trusted. */
final class GlasJitterBuffer {
    static final int MAX_FRAMES = 15, MAX_AGE_MS = 300;
    record Frame(long sequence, byte[] packet, long arrivalNanos) {}
    private final TreeMap<Long, Frame> queue = new TreeMap<>();
    private long consumed = -1, lastSequence = -1, lastTimestamp, lastArrival, dropped;
    private double jitter;
    private int targetMs = 60;
    private boolean primed;

    synchronized boolean offer(long sequence, long timestampMs, byte[] bytes, long now) {
        if (sequence < 0 || timestampMs < 0 || sequence <= consumed || queue.containsKey(sequence)) return false;
        if (lastSequence >= 0 && sequence > lastSequence && timestampMs >= lastTimestamp) {
            long remoteDelta = timestampMs - lastTimestamp;
            if (remoteDelta <= 5000) {
                double variation = Math.abs((now - lastArrival) / 1_000_000.0 - remoteDelta);
                jitter += (Math.min(1000, variation) - jitter) / 16;
                targetMs = Math.max(40, Math.min(180, ((int) Math.ceil((40 + 4 * jitter) / 20)) * 20));
            }
        }
        if (sequence > lastSequence) { lastSequence = sequence; lastTimestamp = timestampMs; lastArrival = now; }
        expire(now);
        if (queue.size() == MAX_FRAMES) { discard(queue.pollFirstEntry().getValue()); dropped++; }
        queue.put(sequence, new Frame(sequence, bytes.clone(), now));
        return true;
    }
    synchronized byte[] poll(long now) {
        expire(now);
        if (queue.isEmpty()) { primed = false; return null; }
        if (!primed) {
            Frame oldest = queue.firstEntry().getValue();
            if (queue.size() * 20 < targetMs && now - oldest.arrivalNanos < targetMs * 1_000_000L) return null;
            primed = true;
        }
        Frame frame = queue.pollFirstEntry().getValue();
        consumed = frame.sequence;
        return frame.packet;
    }
    private void expire(long now) {
        while (!queue.isEmpty() && now - queue.firstEntry().getValue().arrivalNanos > MAX_AGE_MS * 1_000_000L) {
            Frame frame = queue.pollFirstEntry().getValue(); consumed = Math.max(consumed, frame.sequence);
            discard(frame); dropped++;
        }
    }
    synchronized void clear() { for (Frame frame : queue.values()) discard(frame); queue.clear(); primed = false; }
    synchronized int size() { return queue.size(); }
    synchronized int targetMs() { return targetMs; }
    synchronized long dropped() { return dropped; }
    private static void discard(Frame frame) { Arrays.fill(frame.packet, (byte) 0); }
}
