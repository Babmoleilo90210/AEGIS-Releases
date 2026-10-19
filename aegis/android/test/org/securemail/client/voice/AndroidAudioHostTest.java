package org.securemail.client.voice;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.LockSupport;

/** Actual JNI Opus/Speex + existing media pipeline. Synthetic PCM is explicitly a host fixture. */
public final class AndroidAudioHostTest {
    private static int passed;
    private interface Checked {void run()throws Exception;}
    private static void ok(boolean value,String name){if(!value)throw new AssertionError(name);passed++;System.out.println("PASS "+name);}
    private static void denied(Checked action,String name)throws Exception {try{action.run();throw new AssertionError("Accepted: "+name);}catch(IOException|IllegalArgumentException expected){passed++;System.out.println("PASS "+name);}}
    private static short[] tone(int frame){short[] p=new short[960];for(int i=0;i<p.length;i++)p[i]=(short)(Math.sin(2*Math.PI*440*(frame*960+i)/48000)*11000);return p;}
    private static void await(java.util.function.BooleanSupplier done)throws Exception {long end=System.nanoTime()+2_000_000_000L;while(!done.getAsBoolean()&&System.nanoTime()<end)Thread.sleep(5);if(!done.getAsBoolean())throw new AssertionError("Host pipeline timeout");}
    public static void main(String[] args)throws Exception {
        long started=System.nanoTime();long bytes=0;
        try(GlasNativeAudio a=new GlasNativeAudio(true,true)){
            byte[] last=null;double energy=0;
            for(int i=0;i<200;i++){short[] pcm=tone(i);a.process(pcm);byte[] packet=a.encode(pcm);bytes+=packet.length;okFrame(packet);short[] decoded=a.decode(packet);for(short sample:decoded)energy+=(double)sample*sample;a.played(decoded);Arrays.fill(pcm,(short)0);Arrays.fill(decoded,(short)0);if(last!=null)Arrays.fill(last,(byte)0);last=packet;}
            ok(energy>1e6&&last!=null,"actual Opus encode/decode nonzero 200-frame PCM signal");
            ok(bytes>0&&bytes<200L*1275,"real encoded packet sizes within 1275-byte bound");
            short[] concealed=a.decode(null);ok(concealed.length==960,"actual Opus packet loss concealment returns fixed frame");Arrays.fill(concealed,(short)0);
            a.bitrate(12000);ok(a.bitrate()==12000,"real codec bitrate change to 12000");a.bitrate(32000);ok(a.bitrate()==32000,"real codec bitrate change to 32000");
            denied(()->a.bitrate(11999),"reject bitrate below bound");denied(()->a.encode(new short[959]),"reject short PCM frame");denied(()->a.process(new short[961]),"reject oversized DSP frame");
            denied(()->a.decode(new byte[1276]),"reject oversized Opus packet");denied(()->a.decode(new byte[0]),"reject empty Opus packet");
            // TOC configuration 3 = 60ms SILK; configuration 19 stereo = wrong channel count.
            denied(()->a.decode(new byte[]{24,0}),"reject 60ms Opus frame");denied(()->a.decode(new byte[]{(byte)156,0}),"reject stereo Opus frame");
            a.processing(false,false);a.processing(true,true);a.resetEcho();ok(a.encode(tone(201)).length>0,"actual DSP toggle/reset and continued encoding");
            if(last!=null)Arrays.fill(last,(byte)0);
        }
        GlasNativeAudio closed=new GlasNativeAudio(false,false);closed.close();closed.close();denied(()->closed.encode(tone(0)),"idempotent close rejects further encoding");
        List<GlasNativeAudio> contexts=new ArrayList<>();try{for(int i=0;i<4;i++)contexts.add(new GlasNativeAudio(false,false));denied(()->new GlasNativeAudio(false,false),"native bounded context registry rejects fifth instance");}finally{for(GlasNativeAudio a:contexts)a.close();}
        try(GlasNativeAudio reused=new GlasNativeAudio(false,false)){ok(reused.encode(tone(0)).length>0,"released native slot safely reused with new generation");}
        fixtureSession();
        System.out.println("MEASURE hostFrames=200 encodedBytes="+bytes+" elapsedMs="+((System.nanoTime()-started)/1_000_000));
        System.out.println("RESULT "+passed+" PASS; AudioRecord/Track, native ARM64 and real network call NOT_RUN");
    }
    private static void okFrame(byte[] p){if(p.length==0||p.length>1275)throw new AssertionError("Opus packet bound");}
    private static void fixtureSession()throws Exception {
        AtomicInteger inputs=new AtomicInteger(),inputClosed=new AtomicInteger(),outputs=new AtomicInteger(),outputClosed=new AtomicInteger();AtomicLong played=new AtomicLong();AtomicReference<String> failure=new AtomicReference<>();
        GlasAudioDevices.Provider provider=new GlasAudioDevices.Provider(){
            public GlasAudioDevices.Input input(String id)throws IOException {if("removed".equals(id))throw new IOException("fixture removed");inputs.incrementAndGet();return new GlasAudioDevices.Input(){volatile boolean closed;int phase;public int read(byte[] p,int o,int n)throws IOException{if(closed)throw new IOException("fixture closed");LockSupport.parkNanos(20_000_000L);for(int i=0;i<n/2;i++){short s=(short)(Math.sin(2*Math.PI*440*(phase++)/48000)*10000);p[o+2*i]=(byte)s;p[o+2*i+1]=(byte)(s>>>8);}return closed?0:n;}public void close(){if(!closed){closed=true;inputClosed.incrementAndGet();}}};}
            public GlasAudioDevices.Output output(String id){outputs.incrementAndGet();return new GlasAudioDevices.Output(){volatile boolean closed;public int write(byte[] p,int o,int n)throws IOException{if(closed)throw new IOException("fixture closed");played.addAndGet(n);return n;}public void close(){if(!closed){closed=true;outputClosed.incrementAndGet();}}};}
        };
        AtomicReference<GlasAudioSession> reference=new AtomicReference<>();
        GlasAudioSession s=new GlasAudioSession(GlasAudioSession.Config.defaults(),(seq,time,packet)->{try{GlasAudioSession target=reference.get();return target!=null&&target.receive(seq,time,packet);}finally{Arrays.fill(packet,(byte)0);}},new GlasAudioSession.Listener(){public void failed(String value){failure.set(value);}},provider);reference.set(s);
        try{
            Thread.sleep(60);ok(inputs.get()==0&&!s.stats().microphoneEnabled(),"existing session never opens capture before explicit enable");
            s.setMicrophoneEnabled(true);await(()->s.stats().sentFrames()>=8&&s.stats().receivedFrames()>=8);ok(inputs.get()==1&&played.get()>0,"real codec frames traverse existing bounded capture/jitter/playback pipeline");
            ok(s.stats().queuedFrames()<=15&&s.stats().targetBufferMs()<=180,"existing adaptive jitter has bounded queue and target");
            s.setMicrophoneEnabled(false);ok(inputClosed.get()==1&&!s.stats().microphoneEnabled(),"mute immediately releases fixture capture device");
            long sent=s.stats().sentFrames();Thread.sleep(60);ok(s.stats().sentFrames()==sent,"no more audio frames sent after mute");
            s.switchInput("replacement");s.setMicrophoneEnabled(true);await(()->s.stats().sentFrames()>sent);ok(inputs.get()==2,"input switching reopens selected fixture device");
            s.switchOutput("replacement");ok(outputs.get()==2&&outputClosed.get()==1,"output switching releases previous fixture device");
            denied(()->s.switchInput("removed"),"device removal fails closed without alternative microphone");
            ok(!s.stats().microphoneEnabled(),"failed input switch leaves microphone disabled");
            ok(!s.receive(-1,0,new byte[]{0})&&!s.receive(1,0,new byte[1276]),"session rejects bad counters and oversized ingress");
            ok(failure.get()==null,"no unexpected media worker failure in host fixture");
        }finally{s.close();}
        ok(inputClosed.get()==inputs.get()&&outputClosed.get()==outputs.get(),"close releases every opened fixture audio device");
        ok(!s.receive(999,0,new byte[]{0}),"closed session rejects late ingress");
    }
}
