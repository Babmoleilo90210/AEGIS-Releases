package org.securemail.client.security600;

import com.sun.jna.*;
import com.sun.jna.ptr.*;
import com.sun.jna.platform.win32.Wtsapi32;

/** Win64 WTSINFOEXW level 1. Reads only state/flags; usernames from the OS buffer are never copied or logged. */
final class WindowsLockProbe600 implements OperatingSystemLockMonitor600.Probe {
  @Structure.FieldOrder({"SessionId","SessionState","SessionFlags","WinStationName","UserName","DomainName","LogonTime","ConnectTime","DisconnectTime","LastInputTime","CurrentTime","IncomingBytes","OutgoingBytes","IncomingFrames","OutgoingFrames","IncomingCompressedBytes","OutgoingCompressedBytes"})
  public static final class Level1 extends Structure {
    public int SessionId,SessionState,SessionFlags;
    // WCHAR is explicitly two bytes, including during parser/layout tests on Linux.
    public short[] WinStationName=new short[33],UserName=new short[21],DomainName=new short[18];
    public long LogonTime,ConnectTime,DisconnectTime,LastInputTime,CurrentTime;
    public int IncomingBytes,OutgoingBytes,IncomingFrames,OutgoingFrames,IncomingCompressedBytes,OutgoingCompressedBytes;
    public Level1(){super(ALIGN_MSVC);} int offset(String field){return fieldOffset(field);}
  }
  @Structure.FieldOrder({"Level","Data"})
  public static final class Information extends Structure {
    public int Level;public Level1 Data=new Level1();
    public Information(){super(ALIGN_MSVC);} int offset(String field){return fieldOffset(field);}
  }
  @Override public OperatingSystemLockMonitor600.State read(){
    if(Native.POINTER_SIZE!=8||!supportedVersion(System.getProperty("os.version","")))return OperatingSystemLockMonitor600.State.UNKNOWN;
    PointerByReference buffer=new PointerByReference();IntByReference bytes=new IntByReference();Pointer memory=null;
    try{
      if(!Wtsapi32.INSTANCE.WTSQuerySessionInformation(Wtsapi32.WTS_CURRENT_SERVER_HANDLE,Wtsapi32.WTS_CURRENT_SESSION,Wtsapi32.WTS_INFO_CLASS.WTSSessionInfoEx,buffer,bytes))return OperatingSystemLockMonitor600.State.UNKNOWN;
      memory=buffer.getValue();Information shape=new Information();int count=bytes.getValue();
      if(memory==null||Pointer.nativeValue(memory)==0||count<shape.size()||count>4096)return OperatingSystemLockMonitor600.State.UNKNOWN;
      int data=shape.offset("Data");return parse(memory.getInt(shape.offset("Level")),memory.getInt(data+shape.Data.offset("SessionState")),memory.getInt(data+shape.Data.offset("SessionFlags")));
    }catch(RuntimeException|LinkageError unavailable){return OperatingSystemLockMonitor600.State.UNKNOWN;}
    finally{if(memory==null)memory=buffer.getValue();if(memory!=null&&Pointer.nativeValue(memory)!=0)try{Wtsapi32.INSTANCE.WTSFreeMemory(memory);}catch(RuntimeException|LinkageError ignored){/* Never expose an OS buffer in diagnostics. */}}
  }
  static boolean supportedVersion(String value){
    if(value==null||!value.matches("[0-9]{1,3}(?:\\.[0-9]{1,6}){1,3}"))return false;
    return Integer.parseInt(value.substring(0,value.indexOf('.')))>=10;
  }
  static OperatingSystemLockMonitor600.State parse(int level,int connection,int flags){
    if(level!=1||connection<0||connection>Wtsapi32.WTS_CONNECTSTATE_CLASS.WTSInit)return OperatingSystemLockMonitor600.State.UNKNOWN;
    if(connection!=Wtsapi32.WTS_CONNECTSTATE_CLASS.WTSActive)return OperatingSystemLockMonitor600.State.LOCKED;
    // Windows 11 uses LOCK=0/UNLOCK=1. The documented Windows 7 inversion is outside supported platforms.
    return flags==0?OperatingSystemLockMonitor600.State.LOCKED:flags==1?OperatingSystemLockMonitor600.State.UNLOCKED:OperatingSystemLockMonitor600.State.UNKNOWN;
  }
}
