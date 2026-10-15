package org.securemail.client.voice;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import org.junit.jupiter.api.Test;
import org.securemail.protocol.Binary;

class VoiceFramesTest {
  @Test void oversizedLengthAndUnknownTypeAreRejectedBeforeAllocation()throws Exception{
    for(int length:new int[]{-1,Integer.MAX_VALUE,VoiceFrames.MAX_PAYLOAD+1}){
      byte[] data=Binary.encode(out->{out.writeByte(VoiceFrames.AUDIO);out.writeInt(length);});assertThrows(IOException.class,()->VoiceFrames.read(new DataInputStream(new ByteArrayInputStream(data))));
    }
    assertThrows(IOException.class,()->VoiceFrames.read(new DataInputStream(new ByteArrayInputStream(new byte[]{127}))));
  }
  @Test void controlCannotCarryAudioAndUnsupportedCodecIsRejected()throws Exception{
    byte[] bytes=Binary.encode(out->{out.writeByte(VoiceFrames.ACCEPT);Binary.bytes(out,new byte[]{1});});assertThrows(IOException.class,()->VoiceFrames.read(new DataInputStream(new ByteArrayInputStream(bytes))));
    var wrong=new VoiceFrames.Frame(VoiceFrames.START,Binary.encode(out->{out.writeInt(1);out.writeBoolean(false);Binary.text(out,"pcm");out.writeInt(48000);out.writeInt(1);out.writeInt(20);}));assertThrows(IOException.class,()->VoiceFrames.start(wrong));
    assertThrows(IOException.class,()->VoiceFrames.audio(-1,0,new byte[]{1}));assertThrows(IOException.class,()->VoiceFrames.audio(0,-1,new byte[]{1}));assertThrows(IOException.class,()->VoiceFrames.audio(0,0,new byte[1276]));
  }
  @Test void validFrameStaysBoundedAndBufferCanBeWiped()throws Exception{
    var frame=VoiceFrames.audio(5,100,new byte[]{4,2});byte[] encoded=Binary.encode(out->VoiceFrames.write(out,frame));var decoded=VoiceFrames.read(new DataInputStream(new ByteArrayInputStream(encoded)));var audio=VoiceFrames.audio(decoded);assertEquals(5,audio.sequence());assertEquals(100,audio.timestampMillis());assertArrayEquals(new byte[]{4,2},audio.opus());decoded.wipe();for(byte value:decoded.payload())assertEquals(0,value);assertTrue(VoiceFrames.start(VoiceFrames.start(true)));
  }
}
