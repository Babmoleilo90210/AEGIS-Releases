package org.securemail.client.voice;

import javax.sound.sampled.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

final class GlasAudioDevices {
    static final AudioFormat FORMAT = new AudioFormat(48000, 16, 1, true, false);
    interface Input extends AutoCloseable { int read(byte[] pcm, int offset, int length) throws IOException; void close(); }
    interface Output extends AutoCloseable { int write(byte[] pcm, int offset, int length) throws IOException; void close(); }
    interface Provider {
        Input input(String id) throws IOException;
        Output output(String id) throws IOException;
    }
    static final Provider SYSTEM = new Provider() {
        public Input input(String id) throws IOException {
            TargetDataLine line = null;
            try {
                line = AudioSystem.getTargetDataLine(FORMAT, mixer(id, true));
                line.open(FORMAT, 960 * 2 * 4); line.start();
                TargetDataLine owned = line;
                return new Input() {
                    public int read(byte[] pcm, int offset, int length) { return owned.read(pcm, offset, length); }
                    public void close() { try { owned.stop(); } finally { try { owned.flush(); } finally { owned.close(); } } }
                };
            } catch (LineUnavailableException | IllegalArgumentException | SecurityException e) {
                if (line != null) line.close(); throw new IOException("Микрофон недоступен", e);
            }
        }
        public Output output(String id) throws IOException {
            SourceDataLine line = null;
            try {
                line = AudioSystem.getSourceDataLine(FORMAT, mixer(id, false));
                line.open(FORMAT, 960 * 2 * 4); line.start();
                SourceDataLine owned = line;
                return new Output() {
                    public int write(byte[] pcm, int offset, int length) { return owned.write(pcm, offset, length); }
                    public void close() { try { owned.stop(); } finally { try { owned.flush(); } finally { owned.close(); } } }
                };
            } catch (LineUnavailableException | IllegalArgumentException | SecurityException e) {
                if (line != null) line.close(); throw new IOException("Устройство воспроизведения недоступно", e);
            }
        }
    };
    static List<GlasAudioSession.Device> devices(boolean input) {
        List<GlasAudioSession.Device> devices = new ArrayList<>();
        Mixer.Info[] infos = AudioSystem.getMixerInfo();
        for (int i = 0; i < infos.length; i++) {
            Mixer.Info info = infos[i];
            try {
                Mixer mixer = AudioSystem.getMixer(info);
                if (mixer.isLineSupported(new DataLine.Info(input ? TargetDataLine.class : SourceDataLine.class, FORMAT)))
                    devices.add(new GlasAudioSession.Device(id(info, i), info.getName(), input));
            } catch (IllegalArgumentException | SecurityException ignored) { /* Device removed while enumerating. */ }
        }
        return List.copyOf(devices);
    }
    private static Mixer.Info mixer(String id, boolean input) throws IOException {
        if (id == null || id.isEmpty()) return null;
        Mixer.Info[] infos = AudioSystem.getMixerInfo();
        for (int i = 0; i < infos.length; i++) if (id(infos[i], i).equals(id)) return infos[i];
        throw new IOException(input ? "Выбранный микрофон отключён" : "Выбранное устройство воспроизведения отключено");
    }
    private static String id(Mixer.Info info, int index) {
        String text = info.getName() + '\0' + info.getVendor() + '\0' + info.getVersion() + '\0' + info.getDescription() + '\0' + index;
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))).substring(0, 24); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }
}
