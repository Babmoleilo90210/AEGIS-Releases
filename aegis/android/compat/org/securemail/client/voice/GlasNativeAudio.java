package org.securemail.client.voice;

import java.io.IOException;

/** Thin Android adapter to the same official Opus/Speex primitives as desktop. */
final class GlasNativeAudio implements AutoCloseable {
    static final int RATE=48000,SAMPLES=960,PACKET_MAX=1275;
    static { System.loadLibrary("aegis_audio"); }
    private long handle;
    private int bitrate=24000;
    GlasNativeAudio(boolean echo,boolean noise)throws IOException {handle=create(echo,noise);if(handle==0)throw new IOException("Аудиокодек недоступен");}
    synchronized int bitrate(){return bitrate;}
    synchronized void bitrate(int value)throws IOException {if(value<12000||value>32000)throw new IllegalArgumentException("bitrate");check();setBitrate(handle,value);bitrate=value;}
    synchronized byte[] encode(short[] pcm)throws IOException {if(pcm==null||pcm.length!=SAMPLES)throw new IllegalArgumentException("frame");check();return encodeFrame(handle,pcm);}
    synchronized short[] decode(byte[] packet)throws IOException {if(packet!=null&&(packet.length==0||packet.length>PACKET_MAX))throw new IOException("Неверный аудиокадр");check();return decodeFrame(handle,packet);}
    synchronized void process(short[] pcm)throws IOException {if(pcm==null||pcm.length!=SAMPLES)throw new IllegalArgumentException("frame");check();processFrame(handle,pcm);}
    synchronized void played(short[] pcm)throws IOException {if(pcm==null||pcm.length!=SAMPLES)throw new IllegalArgumentException("frame");check();playedFrame(handle,pcm);}
    synchronized void processing(boolean echo,boolean noise)throws IOException {check();setProcessing(handle,echo,noise);}
    synchronized void resetEcho(){if(handle!=0)reset(handle);}
    private void check()throws IOException {if(handle==0)throw new IOException("Аудиосессия закрыта");}
    @Override public synchronized void close(){long owned=handle;handle=0;if(owned!=0)destroy(owned);}
    private static native long create(boolean echo,boolean noise)throws IOException;
    private static native void destroy(long handle);
    private static native void setBitrate(long handle,int bitrate)throws IOException;
    private static native byte[] encodeFrame(long handle,short[] pcm)throws IOException;
    private static native short[] decodeFrame(long handle,byte[] packet)throws IOException;
    private static native void processFrame(long handle,short[] pcm)throws IOException;
    private static native void playedFrame(long handle,short[] pcm)throws IOException;
    private static native void setProcessing(long handle,boolean echo,boolean noise)throws IOException;
    private static native void reset(long handle);
}
