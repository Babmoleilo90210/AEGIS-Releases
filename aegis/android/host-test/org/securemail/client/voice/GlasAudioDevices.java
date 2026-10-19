package org.securemail.client.voice;
import java.io.IOException;
import java.util.List;
/** Host test has no real audio hardware. Tests explicitly inject bounded synthetic PCM devices. */
final class GlasAudioDevices {
    interface Input extends AutoCloseable {int read(byte[] p,int o,int n)throws IOException;void close();}
    interface Output extends AutoCloseable {int write(byte[] p,int o,int n)throws IOException;void close();}
    interface Provider {Input input(String id)throws IOException;Output output(String id)throws IOException;}
    static final Provider SYSTEM=new Provider(){public Input input(String id)throws IOException{throw new IOException("Physical Android device NOT_RUN");}public Output output(String id)throws IOException{throw new IOException("Physical Android device NOT_RUN");}};
    static List<GlasAudioSession.Device> devices(boolean input){return List.of();}
}
