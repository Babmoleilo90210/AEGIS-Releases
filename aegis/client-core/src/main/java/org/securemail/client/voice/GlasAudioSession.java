package org.securemail.client.voice;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.function.DoubleConsumer;

/**
 * Authenticated-call media only. The call controller MUST create this after acceptance and
 * peer authentication. Starting leaves the capture device closed until explicit mic enable.
 * This class never opens a network connection or writes audio to a file.
 */
public final class GlasAudioSession implements AutoCloseable {
    public static final int SAMPLE_RATE = 48000, FRAME_SAMPLES = 960, FRAME_MS = 20, MAX_PACKET_BYTES = 1275;
    public record Device(String id, String name, boolean input) {}
    public record Config(String inputDeviceId, String outputDeviceId, double inputGain,
                         double speakerVolume, boolean echoCancellation, boolean noiseSuppression) {
        public Config {
            inputDeviceId = inputDeviceId == null ? "" : inputDeviceId;
            outputDeviceId = outputDeviceId == null ? "" : outputDeviceId;
            if (inputDeviceId.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 256 || outputDeviceId.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 256) throw new IllegalArgumentException("device id");
            range(inputGain, 0, 2); range(speakerVolume, 0, 1);
        }
        public static Config defaults() { return new Config("", "", 1, 1, true, true); }
    }
    /** Must return immediately. Ownership of the packet is transferred to the sink. */
    @FunctionalInterface public interface EncodedSink { boolean offer(long sequence, long timestampMs, byte[] opus); }
    public interface Listener {
        default void failed(String reason) {}
        default void level(double inputLevel, double outputLevel) {}
    }
    public record Stats(long capturedFrames, long sentFrames, long receivedFrames, long droppedFrames,
                        long concealedFrames, int queuedFrames, int targetBufferMs, int bitrate,
                        double inputLevel, double outputLevel, boolean microphoneEnabled, boolean processingAvailable) {}
    private final GlasNativeAudio codec;
    private final GlasAudioDevices.Provider devices;
    private final EncodedSink sink;
    private final Listener listener;
    private final GlasJitterBuffer jitter = new GlasJitterBuffer();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Object micLock = new Object(), outputLock = new Object();
    private volatile GlasAudioDevices.Input input;
    private volatile GlasAudioDevices.Output output;
    private volatile boolean microphoneEnabled;
    private volatile double gain, volume, inputLevel, outputLevel;
    private volatile String inputId, outputId;
    private final AtomicLong captured = new AtomicLong(), sent = new AtomicLong(), received = new AtomicLong(), dropped = new AtomicLong(), concealed = new AtomicLong();
    private final Thread captureThread, playbackThread;
    private final long startedNanos = System.nanoTime();
    private long micGeneration;

    public static GlasAudioSession start(Config config, EncodedSink sink, Listener listener) throws IOException {
        return new GlasAudioSession(config, sink, listener, GlasAudioDevices.SYSTEM);
    }
    GlasAudioSession(Config config, EncodedSink sink, Listener listener, GlasAudioDevices.Provider devices) throws IOException {
        Objects.requireNonNull(config); this.sink = Objects.requireNonNull(sink);
        this.listener = listener == null ? new Listener() {} : listener; this.devices = devices;
        gain = config.inputGain; volume = config.speakerVolume; inputId = config.inputDeviceId; outputId = config.outputDeviceId;
        codec = new GlasNativeAudio(config.echoCancellation, config.noiseSuppression);
        try { output = devices.output(outputId); }
        catch (IOException | RuntimeException e) { codec.close(); throw e; }
        captureThread = worker("aegis-glas-capture", this::captureLoop);
        playbackThread = worker("aegis-glas-playback", this::playbackLoop);
        captureThread.start(); playbackThread.start();
    }
    public static List<Device> inputDevices() { return GlasAudioDevices.devices(true); }
    public static List<Device> outputDevices() { return GlasAudioDevices.devices(false); }
    public static List<Device> devices() {
        var all = new java.util.ArrayList<Device>(inputDevices()); all.addAll(outputDevices()); return List.copyOf(all);
    }
    public void setMicrophoneEnabled(boolean enabled) throws IOException {
        synchronized (micLock) {
            check(); if (enabled == microphoneEnabled) return;
            micGeneration++;
            if (!enabled) {
                microphoneEnabled = false; inputLevel = 0;
                GlasAudioDevices.Input old = input; input = null; if (old != null) closeInput(old);
            } else {
                input = devices.input(inputId); microphoneEnabled = true; micLock.notifyAll();
            }
            codec.resetEcho();
        }
    }
    public void setSpeakerVolume(double value) { range(value, 0, 1); volume = value; }
    public void setInputGain(double value) { range(value, 0, 2); gain = value; }
    public void setProcessing(boolean echoCancellation, boolean noiseSuppression) throws IOException { check(); codec.processing(echoCancellation, noiseSuppression); }
    public void switchInput(String deviceId) throws IOException {
        synchronized (micLock) {
            check(); boolean enabled = microphoneEnabled; micGeneration++;
            microphoneEnabled = false;
            GlasAudioDevices.Input old = input; input = null; if (old != null) closeInput(old);
            inputLevel = 0; inputId = deviceId == null ? "" : deviceId;
            if (enabled) { input = devices.input(inputId); microphoneEnabled = true; micLock.notifyAll(); }
            codec.resetEcho();
        }
    }
    public void switchOutput(String deviceId) throws IOException {
        synchronized (outputLock) {
            check(); String nextId = deviceId == null ? "" : deviceId;
            GlasAudioDevices.Output next = devices.output(nextId);
            GlasAudioDevices.Output old = output; output = next; outputId = nextId;
            if (old != null) closeOutput(old); jitter.clear(); codec.resetEcho();
        }
    }
    /** Bounded packet ingress: copy at most 1275 bytes, reject invalid counters and duplicates. */
    public boolean receive(long sequence, long timestampMs, byte[] packet) {
        if (closed.get() || packet == null || packet.length == 0 || packet.length > MAX_PACKET_BYTES || sequence < 0 || timestampMs < 0) return false;
        boolean accepted = jitter.offer(sequence, timestampMs, packet, System.nanoTime());
        if (accepted) received.incrementAndGet(); else dropped.incrementAndGet();
        return accepted;
    }
    public Stats stats() {
        return new Stats(captured.get(), sent.get(), received.get(), dropped.get() + jitter.dropped(), concealed.get(),
                jitter.size(), jitter.targetMs(), codec.bitrate(), inputLevel, outputLevel, microphoneEnabled, true);
    }
    private void captureLoop() {
        byte[] bytes = new byte[FRAME_SAMPLES * 2]; short[] pcm = new short[FRAME_SAMPLES];
        long sequence = 0, lastAdapt = System.nanoTime(), rejected = 0, successful = 0;
        try {
            while (!closed.get()) {
                GlasAudioDevices.Input owned; long generation;
                synchronized (micLock) {
                    while (!closed.get() && !microphoneEnabled) micLock.wait();
                    if (closed.get()) break; owned = input; generation = micGeneration;
                }
                int offset = 0;
                while (offset < bytes.length && !closed.get()) {
                    int n;
                    try { n = owned.read(bytes, offset, bytes.length - offset); }
                    catch (IOException | RuntimeException e) {
                        if (owned != input || closed.get()) break;
                        throw e;
                    }
                    if (n <= 0) break; offset += n;
                }
                synchronized (micLock) {
                    if (closed.get()) break;
                    if (owned != input || generation != micGeneration || !microphoneEnabled) { Arrays.fill(bytes, (byte) 0); continue; }
                    if (offset != bytes.length) throw new IOException("Микрофон отключён");
                }
                fromBytes(bytes, pcm); Arrays.fill(bytes, (byte) 0); scale(pcm, gain);
                captured.incrementAndGet(); inputLevel = level(pcm); codec.process(pcm);
                byte[] encoded = codec.encode(pcm); Arrays.fill(pcm, (short) 0);
                synchronized (micLock) {
                    if (closed.get() || generation != micGeneration || !microphoneEnabled) { Arrays.fill(encoded, (byte) 0); continue; }
                    if (sink.offer(sequence++, (System.nanoTime() - startedNanos) / 1_000_000, encoded)) { sent.incrementAndGet(); successful++; }
                    else { Arrays.fill(encoded, (byte) 0); dropped.incrementAndGet(); rejected++; }
                }
                long now = System.nanoTime();
                if (now - lastAdapt >= 2_000_000_000L) {
                    // Sink pressure and arrival jitter give real bounded congestion signals; TCP hides packet loss.
                    int rate = rejected > 0 || jitter.targetMs() >= 140 ? 12000 : jitter.targetMs() >= 100 ? 16000 : 24000;
                    if (successful + rejected > 0) codec.bitrate(rate);
                    rejected = successful = 0; lastAdapt = now;
                }
            }
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        catch (IOException | RuntimeException e) { if (!closed.get()) fail("Микрофон или обработка звука недоступны"); }
        finally { Arrays.fill(bytes, (byte) 0); Arrays.fill(pcm, (short) 0); }
    }
    private void playbackLoop() {
        long deadline = System.nanoTime(), lastLevel = deadline;
        boolean playedRemote = false; int missing = 0;
        byte[] bytes = new byte[FRAME_SAMPLES * 2];
        try {
            while (!closed.get()) {
                long now = System.nanoTime();
                if (now < deadline) { LockSupport.parkNanos(deadline - now); continue; }
                if (now - deadline > 100_000_000L) deadline = now; // never catch up an unbounded delayed audio backlog
                deadline += FRAME_MS * 1_000_000L;
                byte[] packet = jitter.poll(now); short[] pcm;
                if (packet != null) {
                    try { pcm = codec.decode(packet); } finally { Arrays.fill(packet, (byte) 0); }
                    playedRemote = true; missing = 0;
                } else if (playedRemote && missing++ < 3) { pcm = codec.decode(null); concealed.incrementAndGet(); }
                else pcm = new short[FRAME_SAMPLES];
                try { scale(pcm, volume); outputLevel = level(pcm); toBytes(pcm, bytes);
                    if (microphoneEnabled) codec.played(pcm);
                } finally { Arrays.fill(pcm, (short) 0); }
                GlasAudioDevices.Output owned = output;
                int offset = 0;
                while (offset < bytes.length && !closed.get()) {
                    int n;
                    try { n = owned.write(bytes, offset, bytes.length - offset); }
                    catch (IOException | RuntimeException e) {
                        if (owned != output || closed.get()) break;
                        throw e;
                    }
                    if (n <= 0) break; offset += n;
                }
                Arrays.fill(bytes, (byte) 0);
                if (!closed.get() && owned == output && offset != bytes.length) throw new IOException("Устройство воспроизведения отключено");
                if (now - lastLevel >= 100_000_000L) { safeLevel(); lastLevel = now; }
            }
        } catch (IOException | RuntimeException e) { if (!closed.get()) fail("Воспроизведение или декодирование звука недоступны"); }
        finally { Arrays.fill(bytes, (byte) 0); }
    }
    private void safeLevel() { try { listener.level(inputLevel, outputLevel); } catch (RuntimeException ignored) {} }
    private void fail(String reason) {
        close(); try { listener.failed(reason); } catch (RuntimeException ignored) {}
    }
    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        synchronized (micLock) {
            microphoneEnabled = false; micGeneration++; micLock.notifyAll();
            GlasAudioDevices.Input old = input; input = null; if (old != null) closeInput(old);
        }
        synchronized (outputLock) { GlasAudioDevices.Output old = output; output = null; if (old != null) closeOutput(old); }
        captureThread.interrupt(); playbackThread.interrupt();
        join(captureThread); join(playbackThread); jitter.clear(); inputLevel = outputLevel = 0;
        codec.close();
    }
    private static void closeInput(GlasAudioDevices.Input input) { try { input.close(); } catch (RuntimeException ignored) {} }
    private static void closeOutput(GlasAudioDevices.Output output) { try { output.close(); } catch (RuntimeException ignored) {} }
    private static void join(Thread thread) {
        if (thread == Thread.currentThread()) return;
        try { thread.join(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
    private void check() throws IOException { if (closed.get()) throw new IOException("Аудиосессия закрыта"); }
    private static Thread worker(String name, Runnable job) { Thread thread = new Thread(job, name); thread.setDaemon(true); return thread; }
    static void fromBytes(byte[] bytes, short[] pcm) { for (int i = 0; i < pcm.length; i++) pcm[i] = (short) ((bytes[2 * i] & 255) | bytes[2 * i + 1] << 8); }
    static void toBytes(short[] pcm, byte[] bytes) { for (int i = 0; i < pcm.length; i++) { bytes[2 * i] = (byte) pcm[i]; bytes[2 * i + 1] = (byte) (pcm[i] >>> 8); } }
    static void scale(short[] pcm, double gain) { for (int i = 0; i < pcm.length; i++) pcm[i] = (short) Math.max(Short.MIN_VALUE, Math.min(Short.MAX_VALUE, Math.round(pcm[i] * gain))); }
    static double level(short[] pcm) { double energy = 0; for (short sample : pcm) energy += (double) sample * sample; return Math.min(1, Math.sqrt(energy / pcm.length) / 32768); }
    private static void range(double value, double min, double max) { if (!Double.isFinite(value) || value < min || value > max) throw new IllegalArgumentException("audio level"); }

    /** Explicit local level meter: caller must invoke from a user action. No network, no playback, auto stop 15s. */
    public static MicrophoneTest testMicrophone(String deviceId, DoubleConsumer level) throws IOException { return new MicrophoneTest(deviceId, level); }
    public static final class MicrophoneTest implements AutoCloseable {
        private final GlasAudioDevices.Input input;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final Thread thread, timeout;
        MicrophoneTest(String deviceId, DoubleConsumer listener) throws IOException {
            Objects.requireNonNull(listener); input = GlasAudioDevices.SYSTEM.input(deviceId);
            thread = worker("aegis-glas-mic-test", () -> {
                byte[] bytes = new byte[FRAME_SAMPLES * 2]; short[] samples = new short[FRAME_SAMPLES];
                long end = System.nanoTime() + 15_000_000_000L;
                try {
                    while (!closed.get() && System.nanoTime() < end) {
                        int n = input.read(bytes, 0, bytes.length);
                        if (n != bytes.length) break; fromBytes(bytes, samples); listener.accept(level(samples));
                        Arrays.fill(bytes, (byte) 0); Arrays.fill(samples, (short) 0);
                    }
                } catch (IOException | RuntimeException ignored) { /* Test ends on device removal. */ }
                finally { Arrays.fill(bytes, (byte) 0); Arrays.fill(samples, (short) 0); close(); }
            });
            timeout = worker("aegis-glas-mic-test-timeout", () -> {
                LockSupport.parkNanos(15_000_000_000L); if (!Thread.currentThread().isInterrupted()) close();
            });
            thread.start(); timeout.start();
        }
        @Override public void close() { if (closed.compareAndSet(false, true)) { closeInput(input); thread.interrupt(); timeout.interrupt(); } }
        public boolean running() { return !closed.get(); }
    }
}
