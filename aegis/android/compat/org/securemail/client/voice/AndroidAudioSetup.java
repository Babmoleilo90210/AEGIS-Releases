package org.securemail.client.voice;
import android.content.Context;
/** Only the Glas UID may initialize the Android audio provider. */
public final class AndroidAudioSetup {
    private AndroidAudioSetup(){}
    public static void initialize(Context context){GlasAudioDevices.initialize(context);}
}
