package org.aegis.android;

import android.content.Context;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import org.securemail.client.voice.GlasAudioSession;

/** Explicit ten-second local codec/device check. Never represents a network call. */
public final class AndroidGlasAudio {
    private AndroidGlasAudio(){}
    public static GlasAudioSession localCodecTest(Context context,String input,String output,double volume,GlasAudioSession.Listener listener)throws IOException {
        org.securemail.client.voice.AndroidAudioSetup.initialize(context);
        AtomicReference<GlasAudioSession> holder=new AtomicReference<>();
        GlasAudioSession session=GlasAudioSession.start(new GlasAudioSession.Config(input,output,1,volume,true,true),(sequence,time,packet)->{
            try{GlasAudioSession current=holder.get();return current!=null&&current.receive(sequence,time,packet);}
            finally{Arrays.fill(packet,(byte)0);}
        },listener);
        holder.set(session);
        // The explicit caller enables the microphone only after its own foreground/auth checks.
        return session;
    }
}
