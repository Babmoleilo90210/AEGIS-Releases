package org.securemail.client.voice;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;

/** Thin bindings to pinned, bundled Xiph codecs. No executable or system library search. */
final class GlasNativeAudio implements AutoCloseable {
    interface Opus extends Library {
        String opus_get_version_string();
        Pointer opus_encoder_create(int rate, int channels, int application, IntByReference error);
        Pointer opus_decoder_create(int rate, int channels, IntByReference error);
        int opus_encoder_ctl(Pointer encoder, int request, int value);
        int opus_encode(Pointer encoder, short[] pcm, int samples, byte[] out, int maxBytes);
        int opus_decode(Pointer decoder, byte[] packet, int bytes, short[] out, int samples, int fec);
        int opus_packet_get_nb_samples(byte[] packet, int bytes, int rate);
        int opus_packet_get_nb_channels(byte[] packet);
        void opus_encoder_destroy(Pointer encoder);
        void opus_decoder_destroy(Pointer decoder);
    }
    interface Speex extends Library {
        Pointer speex_echo_state_init(int frameSamples, int filterSamples);
        int speex_echo_ctl(Pointer state, int request, IntByReference value);
        void speex_echo_playback(Pointer state, short[] pcm);
        void speex_echo_capture(Pointer state, short[] input, short[] output);
        void speex_echo_cancellation(Pointer state, short[] input, short[] played, short[] output);
        void speex_echo_state_reset(Pointer state);
        void speex_echo_state_destroy(Pointer state);
        Pointer speex_preprocess_state_init(int samples, int rate);
        int speex_preprocess_ctl(Pointer state, int request, Pointer value);
        int speex_preprocess_run(Pointer state, short[] pcm);
        void speex_preprocess_state_destroy(Pointer state);
    }
    static final int RATE = 48000, SAMPLES = 960, PACKET_MAX = 1275;
    private final Opus opus;
    private final Speex speex;
    private Pointer encoder, decoder, echo, preprocessor;
    private final Object encodeLock = new Object(), decodeLock = new Object(), dspLock = new Object();
    private volatile boolean closed;
    private boolean echoCaptureStarted;
    private volatile int bitrate = 24000;

    GlasNativeAudio(boolean echoCancellation, boolean noiseSuppression) throws IOException {
        try {
            boolean windows = System.getProperty("os.name", "").startsWith("Windows");
            String home = System.getProperty("aegis.home", System.getProperty("aegis.native.root"));
            if (home == null) throw new IOException("Каталог аудиобиблиотек не настроен");
            opus = GlasAudioLibraries.load(home, windows ? "opus.dll" : "libopus.so", Opus.class);
            speex = GlasAudioLibraries.load(home, windows ? "speexdsp.dll" : "libspeexdsp.so", Speex.class);
            if (!"libopus 1.6.1".equals(opus.opus_get_version_string()))
                throw new IOException("Версия аудиокодека не поддерживается");
            IntByReference error = new IntByReference();
            encoder = opus.opus_encoder_create(RATE, 1, 2048, error); // OPUS_APPLICATION_VOIP
            if (encoder == null || error.getValue() != 0) throw new IOException("Не удалось создать аудиокодек");
            decoder = opus.opus_decoder_create(RATE, 1, error);
            if (decoder == null || error.getValue() != 0) throw new IOException("Не удалось создать аудиодекодер");
            ctl(4002, bitrate); // OPUS_SET_BITRATE
            ctl(4006, 1); // OPUS_SET_VBR
            ctl(4010, 5); // OPUS_SET_COMPLEXITY
            ctl(4016, 1); // OPUS_SET_DTX
            ctl(4024, 3001); // OPUS_SET_SIGNAL / OPUS_SIGNAL_VOICE
            if (echoCancellation) {
                echo = speex.speex_echo_state_init(SAMPLES, RATE / 5); // 200 ms echo tail
                if (echo == null || speex.speex_echo_ctl(echo, 24, new IntByReference(RATE)) != 0)
                    throw new IOException("Не удалось включить эхоподавление");
            }
            preprocessor = speex.speex_preprocess_state_init(SAMPLES, RATE);
            if (preprocessor == null) throw new IOException("Не удалось включить обработку звука");
            preprocessCtl(0, noiseSuppression ? 1 : 0); // DENOISE
            preprocessCtl(2, 0); // AGC off; user controls input gain
            // Speex VAD remains disabled (the pinned library default); Opus controls DTX.
            preprocessCtl(18, -20); // noise suppression limit dB
            if (echo != null && speex.speex_preprocess_ctl(preprocessor, 24, echo) != 0)
                throw new IOException("Не удалось связать эхоподавление");
        } catch (IOException e) { close(); throw e; }
        catch (LinkageError | RuntimeException e) { close(); throw new IOException("Аудиобиблиотеки недоступны или несовместимы", e); }
    }
    private void ctl(int request, int value) throws IOException {
        if (opus.opus_encoder_ctl(encoder, request, value) != 0) throw new IOException("Не удалось настроить аудиокодек");
    }
    private void preprocessCtl(int request, int value) throws IOException {
        IntByReference data = new IntByReference(value);
        if (speex.speex_preprocess_ctl(preprocessor, request, data.getPointer()) != 0) throw new IOException("Не удалось настроить обработку звука");
    }
    int bitrate() { return bitrate; }
    void bitrate(int value) throws IOException {
        if (value < 12000 || value > 32000) throw new IllegalArgumentException("bitrate");
        synchronized (encodeLock) { check(); if (value != bitrate) { ctl(4002, value); bitrate = value; } }
    }
    byte[] encode(short[] pcm) throws IOException {
        if (pcm.length != SAMPLES) throw new IllegalArgumentException("frame");
        synchronized (encodeLock) {
            check(); byte[] packet = new byte[PACKET_MAX];
            try {
                int n = opus.opus_encode(encoder, pcm, SAMPLES, packet, packet.length);
                if (n <= 0 || n > packet.length) throw new IOException("Ошибка кодирования звука");
                return Arrays.copyOf(packet, n);
            } finally { Arrays.fill(packet, (byte) 0); }
        }
    }
    short[] decode(byte[] packet) throws IOException {
        synchronized (decodeLock) {
            check();
            if (packet != null && (packet.length == 0 || packet.length > PACKET_MAX ||
                    opus.opus_packet_get_nb_samples(packet, packet.length, RATE) != SAMPLES ||
                    opus.opus_packet_get_nb_channels(packet) != 1)) throw new IOException("Неверный аудиокадр");
            short[] pcm = new short[SAMPLES];
            boolean success=false;
            try {
                if (opus.opus_decode(decoder, packet, packet == null ? 0 : packet.length, pcm, SAMPLES, 0) != SAMPLES)
                    throw new IOException("Ошибка декодирования звука");
                success=true;return pcm;
            } finally { if(!success)Arrays.fill(pcm, (short) 0); }
        }
    }
    void process(short[] pcm) throws IOException {
        synchronized (dspLock) {
            check();
            if (echo != null) {
                short[] clean = new short[SAMPLES];
                try { speex.speex_echo_capture(echo, pcm, clean); echoCaptureStarted = true;
                    System.arraycopy(clean, 0, pcm, 0, SAMPLES);
                } finally { Arrays.fill(clean, (short) 0); }
            }
            speex.speex_preprocess_run(preprocessor, pcm);
        }
    }
    void played(short[] pcm) throws IOException {
        synchronized (dspLock) { check(); if (echo != null && echoCaptureStarted) speex.speex_echo_playback(echo, pcm); }
    }
    void processing(boolean echoCancellation, boolean noiseSuppression) throws IOException {
        synchronized (dspLock) {
            check(); preprocessCtl(0, noiseSuppression ? 1 : 0);
            if (echoCancellation && echo == null) {
                Pointer next = speex.speex_echo_state_init(SAMPLES, RATE / 5);
                if (next == null) throw new IOException("Не удалось включить эхоподавление");
                if (speex.speex_echo_ctl(next, 24, new IntByReference(RATE)) != 0 ||
                        speex.speex_preprocess_ctl(preprocessor, 24, next) != 0) {
                    speex.speex_echo_state_destroy(next);
                    throw new IOException("Не удалось настроить эхоподавление");
                }
                echo = next; echoCaptureStarted = false;
            } else if (!echoCancellation && echo != null) {
                if (speex.speex_preprocess_ctl(preprocessor, 24, null) != 0)
                    throw new IOException("Не удалось изменить эхоподавление");
                speex.speex_echo_state_destroy(echo); echo = null; echoCaptureStarted = false;
            }
        }
    }
    void resetEcho() {
        synchronized (dspLock) { if (!closed && echo != null) { speex.speex_echo_state_reset(echo); echoCaptureStarted = false; } }
    }
    private void check() throws IOException { if (closed) throw new IOException("Аудиосессия закрыта"); }
    @Override public void close() {
        synchronized (encodeLock) { synchronized (decodeLock) { synchronized (dspLock) {
            if (closed) return; closed = true;
            if (encoder != null) { opus.opus_encoder_destroy(encoder); encoder = null; }
            if (decoder != null) { opus.opus_decoder_destroy(decoder); decoder = null; }
            if (preprocessor != null) { speex.speex_preprocess_state_destroy(preprocessor); preprocessor = null; }
            if (echo != null) { speex.speex_echo_state_destroy(echo); echo = null; }
        } } }
    }
}
