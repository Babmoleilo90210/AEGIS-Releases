package org.securemail.client.voice;

import java.io.*;
import java.util.Arrays;
import org.securemail.protocol.Binary;

/** Bounded application frames inside the mutually authenticated TLS channel. */
final class VoiceFrames {
  static final int OPERATION=101,START=1,RINGING=2,ACCEPT=3,READY=4,DECLINE=5,BUSY=6,END=7,AUDIO=8,PING=9,PONG=10,MUTED=11;
  static final int MAX_OPUS=1275,MAX_PAYLOAD=MAX_OPUS+20;
  record Frame(int type,byte[] payload) {
    Frame { if(type<START||type>MUTED||payload.length>MAX_PAYLOAD)throw new IllegalArgumentException("Voice frame"); }
    void wipe(){Arrays.fill(payload,(byte)0);}
  }
  record Audio(long sequence,long timestampMillis,byte[] opus){}
  static Frame control(int type){if(type< RINGING||type>MUTED||type==AUDIO)throw new IllegalArgumentException("Voice control");return new Frame(type,new byte[0]);}
  static Frame start(boolean resume)throws IOException{return new Frame(START,Binary.encode(out->{out.writeInt(1);out.writeBoolean(resume);Binary.text(out,"opus");out.writeInt(48000);out.writeInt(1);out.writeInt(20);}));}
  static boolean start(Frame frame)throws IOException{
    if(frame.type()!=START)throw new IOException("Voice START required");
    try(var in=new DataInputStream(new ByteArrayInputStream(frame.payload()))){if(in.readInt()!=1)throw new IOException("Voice version");boolean resume=in.readBoolean();if(!Binary.text(in,8).equals("opus")||in.readInt()!=48000||in.readInt()!=1||in.readInt()!=20)throw new IOException("Unsupported voice format");Binary.end(in);return resume;}
  }
  static Frame audio(long sequence,long timestamp,byte[] opus)throws IOException{
    if(sequence<0||timestamp<0||opus.length<1||opus.length>MAX_OPUS)throw new IOException("Voice audio bounds");
    return new Frame(AUDIO,Binary.encode(out->{out.writeLong(sequence);out.writeLong(timestamp);Binary.bytes(out,opus);}));
  }
  static Audio audio(Frame frame)throws IOException{
    byte[] bytes=null;boolean accepted=false;
    try(var in=new DataInputStream(new ByteArrayInputStream(frame.payload()))){long sequence=in.readLong(),timestamp=in.readLong();bytes=Binary.bytes(in,MAX_OPUS);Binary.end(in);if(sequence<0||timestamp<0||bytes.length<1)throw new IOException("Voice audio bounds");accepted=true;return new Audio(sequence,timestamp,bytes);}
    finally{if(!accepted&&bytes!=null)Arrays.fill(bytes,(byte)0);}
  }
  static void write(DataOutputStream out,Frame frame)throws IOException{out.writeByte(frame.type());Binary.bytes(out,frame.payload());out.flush();}
  static Frame read(DataInputStream in)throws IOException{
    int type=in.readUnsignedByte();if(type<START||type>MUTED)throw new IOException("Voice frame type");
    byte[] payload=Binary.bytes(in,MAX_PAYLOAD);if(type!=AUDIO&&type!=START&&payload.length!=0){Arrays.fill(payload,(byte)0);throw new IOException("Voice control payload");}
    return new Frame(type,payload);
  }
}
