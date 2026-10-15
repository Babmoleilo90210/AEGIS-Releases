package org.securemail.client.voice;

import org.junit.jupiter.api.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

class GlasAudioTest {
    @Test void realOpusRoundTripAndPacketBounds() throws Exception {
        try (var codec = new GlasNativeAudio(false, false)) {
            double energy = 0; int packets = 0;
            for (int frame = 0; frame < 80; frame++) {
                short[] input = tone(frame, 0.25);
                byte[] packet = codec.encode(input);
                assertTrue(packet.length > 0 && packet.length <= 1275);
                short[] decoded = codec.decode(packet);
                assertEquals(960, decoded.length);
                if (frame > 5) energy += GlasAudioSession.level(decoded);
                packets++;
            }
            assertEquals(80, packets); assertTrue(energy / 74 > 0.08, "real audio energy survives codec");
            assertEquals(960, codec.decode(null).length);
            codec.bitrate(12000); assertEquals(12000, codec.bitrate());
            assertThrows(IOException.class, () -> codec.decode(new byte[1276]));
            assertThrows(IOException.class, () -> codec.decode(new byte[0]));
        }
    }
    @Test void realSpeexNoiseSuppressionProcessesBoundedPcm() throws Exception {
        try (var codec = new GlasNativeAudio(false, true)) {
            var random = new java.util.Random(4); double before = 0, after = 0;
            for (int frame = 0; frame < 180; frame++) {
                short[] pcm = new short[960];
                for (int i = 0; i < pcm.length; i++) pcm[i] = (short) (random.nextGaussian() * 900);
                double original = GlasAudioSession.level(pcm); codec.process(pcm);
                if (frame > 120) { before += original; after += GlasAudioSession.level(pcm); }
            }
            assertTrue(after < before * 0.8, "real Speex denoiser attenuates stationary noise");
        }
    }
    @Test void realSpeexEchoStateAcceptsPlaybackReferenceAndResets() throws Exception {
        try (var codec = new GlasNativeAudio(true, true)) {
            short[][] previous = new short[3][960];
            for (int frame = 0; frame < 160; frame++) {
                short[] played = tone(frame, 0.15); codec.played(played);
                short[] recorded = previous[frame % 3].clone();
                for (int i = 0; i < recorded.length; i++) recorded[i] /= 3;
                previous[frame % 3] = played; codec.process(recorded);
                assertTrue(Double.isFinite(GlasAudioSession.level(recorded)));
            }
            codec.resetEcho(); codec.processing(false, false); codec.processing(true, true);
            short[] pcm = tone(200, 0.1); codec.process(pcm);
        }
    }
    @Test void realSpeexCancelsSyntheticAcousticEcho() throws Exception {
        var library = GlasAudioLibraries.load(System.getProperty("aegis.native.root"), System.getProperty("os.name").startsWith("Windows") ? "speexdsp.dll" : "libspeexdsp.so", GlasNativeAudio.Speex.class);
        var echo = library.speex_echo_state_init(960, 9600);
        assertNotNull(echo);
        try {
            assertEquals(0, library.speex_echo_ctl(echo, 24, new com.sun.jna.ptr.IntByReference(48000)));
            var random = new java.util.Random(3); short[][] history = new short[3][960];
            double before = 0, after = 0;
            for (int frame = 0; frame < 500; frame++) {
                short[] played = new short[960], input = new short[960], output = new short[960];
                for (int i = 0; i < 960; i++) { played[i] = (short) (random.nextGaussian() * 3000); input[i] = (short) (history[frame % 3][i] * 0.4); }
                history[frame % 3] = played;
                library.speex_echo_cancellation(echo, input, played, output);
                if (frame >= 400) { before += GlasAudioSession.level(input); after += GlasAudioSession.level(output); }
            }
            assertTrue(after < before * 0.25, "real Speex AEC converges on delayed synthetic echo");
        } finally { library.speex_echo_state_destroy(echo); }
    }
    @Test void microphoneClosedUntilExplicitEnableMuteAndHotSwitchCloseOldDevice() throws Exception {
        var hardware = new FakeDevices(); var sent = new AtomicInteger(); var failure = new AtomicReference<String>();
        try (var audio = new GlasAudioSession(GlasAudioSession.Config.defaults(), (seq, time, packet) -> { sent.incrementAndGet(); return true; },
                new GlasAudioSession.Listener() { public void failed(String reason) { failure.set(reason); } }, hardware)) {
            Thread.sleep(90); assertEquals(0, hardware.inputs.get()); assertEquals(0, sent.get());
            audio.setMicrophoneEnabled(true); await(() -> sent.get() >= 3);
            FakeDevices.In old = hardware.latest;
            audio.switchInput("new-device"); assertTrue(old.closed); assertEquals(2, hardware.inputs.get());
            await(() -> sent.get() >= 5);
            audio.setMicrophoneEnabled(false); assertTrue(hardware.latest.closed);
            int afterMute = sent.get(); Thread.sleep(90); assertEquals(afterMute, sent.get());
            assertFalse(audio.stats().microphoneEnabled()); assertNull(failure.get());
            audio.switchOutput("new-output"); assertEquals(2, hardware.outputs.get());
        }
        assertTrue(hardware.outputClosed.get());
    }
    @Test void boundedReceiveQueueAndMalformedFramesFailClosed() throws Exception {
        var hardware = new FakeDevices(); var failure = new CountDownLatch(1);
        try (var audio = new GlasAudioSession(GlasAudioSession.Config.defaults(), (s,t,p) -> true,
                new GlasAudioSession.Listener() { public void failed(String reason) { failure.countDown(); } }, hardware)) {
            assertFalse(audio.receive(-1, 0, new byte[]{1}));
            assertFalse(audio.receive(0, -1, new byte[]{1}));
            assertFalse(audio.receive(0, 0, new byte[1276]));
            assertTrue(audio.receive(0, 0, new byte[]{(byte) 255}));
            assertTrue(failure.await(2, TimeUnit.SECONDS));
            assertFalse(audio.stats().microphoneEnabled());
        }
    }
    @Test void backpressureReducesRealOpusBitrateWithoutGrowingAQueue() throws Exception {
        var hardware = new FakeDevices();
        try (var audio = new GlasAudioSession(GlasAudioSession.Config.defaults(), (seq, time, packet) -> false, null, hardware)) {
            audio.setMicrophoneEnabled(true);
            long until = System.nanoTime() + 3_000_000_000L;
            while (audio.stats().bitrate() != 12000 && System.nanoTime() < until) Thread.sleep(20);
            assertEquals(12000, audio.stats().bitrate()); assertTrue(audio.stats().droppedFrames() > 10);
            assertEquals(0, audio.stats().queuedFrames());
        }
    }
    @Test void jitterTargetAdaptsToActualArrivalVariationWithinBounds() {
        var jitter = new GlasJitterBuffer(); long now = 1_000_000_000L;
        for (int i = 0; i < 40; i++) { now += (i % 2 == 0 ? 180 : 1) * 1_000_000L; jitter.offer(i, i * 20, new byte[]{1}, now); }
        assertTrue(jitter.targetMs() > 60); assertTrue(jitter.targetMs() <= 180); assertTrue(jitter.size() <= 15);
    }
    @Test void jitterBoundsStaleFramesAndCopiesIngress() {
        var jitter = new GlasJitterBuffer(); byte[] bytes = {1,2,3}; long now = 1_000_000_000;
        for (int i = 0; i < 50; i++) jitter.offer(i, i * 20, bytes, now);
        assertEquals(GlasJitterBuffer.MAX_FRAMES, jitter.size()); assertEquals(35, jitter.dropped());
        bytes[0] = 99; assertEquals(1, jitter.poll(now)[0]);
        assertNull(jitter.poll(now + 400_000_000)); assertEquals(0, jitter.size());
        assertFalse(jitter.offer(1, 20, new byte[]{1}, now + 400_000_000));
    }
    @Test void compiledDigestRejectsTamperedLibraryAndSymlinks(@org.junit.jupiter.api.io.TempDir java.nio.file.Path temporary) throws Exception {
        String filename = System.getProperty("os.name").startsWith("Windows") ? "opus.dll" : "libopus.so";
        String platform = System.getProperty("os.name").startsWith("Windows") ? "windows-x86_64" : "linux-x86_64";
        java.nio.file.Path original = java.nio.file.Path.of(System.getProperty("aegis.native.root"), "native", filename);
        java.nio.file.Path copy = temporary.resolve(filename); java.nio.file.Files.copy(original, copy);
        byte[] verified = GlasAudioLibraries.verified(copy, filename, platform); assertTrue(verified.length > 0); verified[verified.length / 2] ^= 1;
        java.nio.file.Files.write(copy, verified); assertThrows(IOException.class, () -> GlasAudioLibraries.verified(copy, filename, platform));
        if (!System.getProperty("os.name").startsWith("Windows")) {
            java.nio.file.Path link = temporary.resolve("linked.so"); java.nio.file.Files.createSymbolicLink(link, original);
            assertThrows(IOException.class, () -> GlasAudioLibraries.verified(link, filename, platform));
        }
    }
    @Test void gainClipsAndConfigurationRejectsNonFiniteValues() {
        assertThrows(IllegalArgumentException.class, () -> new GlasAudioSession.Config("", "", Double.NaN, 1, true, true));
        short[] pcm = {32767, -32768, 20}; GlasAudioSession.scale(pcm, 2);
        assertArrayEquals(new short[]{32767, -32768, 40}, pcm);
        byte[] bytes = new byte[6]; GlasAudioSession.toBytes(pcm, bytes); short[] out = new short[3]; GlasAudioSession.fromBytes(bytes, out);
        assertArrayEquals(pcm, out); assertNotNull(GlasAudioSession.inputDevices()); assertNotNull(GlasAudioSession.outputDevices());
    }
    static short[] tone(int frame, double amplitude) {
        short[] pcm = new short[960]; for (int i = 0; i < pcm.length; i++) pcm[i] = (short) (32767 * amplitude * Math.sin(2 * Math.PI * 440 * (frame * 960L + i) / 48000)); return pcm;
    }
    static void await(java.util.function.BooleanSupplier condition) throws Exception {
        long until = System.nanoTime() + 2_000_000_000L;
        while (!condition.getAsBoolean() && System.nanoTime() < until) Thread.sleep(10);
        assertTrue(condition.getAsBoolean());
    }
    static final class FakeDevices implements GlasAudioDevices.Provider {
        final AtomicInteger inputs = new AtomicInteger(), outputs = new AtomicInteger();
        final AtomicBoolean outputClosed = new AtomicBoolean(); volatile In latest;
        public GlasAudioDevices.Input input(String id) { inputs.incrementAndGet(); latest = new In(); return latest; }
        public GlasAudioDevices.Output output(String id) { outputs.incrementAndGet(); return new GlasAudioDevices.Output() {
            boolean closed; public int write(byte[] pcm, int offset, int length) throws IOException {
                try { Thread.sleep(20); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                if (closed) return 0; return length;
            }
            public void close() { closed = true; outputClosed.set(true); }
        }; }
        static final class In implements GlasAudioDevices.Input {
            volatile boolean closed; int frame;
            public int read(byte[] pcm, int offset, int length) {
                try { Thread.sleep(20); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                if (closed) return 0; byte[] bytes = new byte[1920]; GlasAudioSession.toBytes(tone(frame++, .2), bytes);
                System.arraycopy(bytes, 0, pcm, offset, length); return length;
            }
            public void close() { closed = true; }
        }
    }
}
