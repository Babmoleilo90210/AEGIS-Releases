package org.securemail.client.safeweb600;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.securemail.client.safeweb.SafeWebUrl;

/** One bounded anonymous-pipe launch handshake. Contains a URL and a one-use nonce, never an account capability. */
public final class VzorBootstrap600 implements AutoCloseable {
  private static final int MAGIC=0x565A5236,VERSION=1,MAX_URL_BYTES=4096;
  private static final byte[] DOMAIN="AEGIS-VZOR-INDEPENDENT-START-v1\0".getBytes(StandardCharsets.US_ASCII);
  public enum Reply {READY,ALREADY_RUNNING,STATE_UNAVAILABLE,UI_UNAVAILABLE}
  public record Acknowledgement(Reply reply,long pid){}
  private final byte[] nonce;
  private final String address;
  private boolean replied,closed;
  private VzorBootstrap600(byte[] nonce,String address){this.nonce=nonce;this.address=address;}
  public String address(){return address;}
  public static byte[] freshNonce(){byte[] nonce=new byte[32];new SecureRandom().nextBytes(nonce);return nonce;}
  public static void write(OutputStream output,byte[] nonce,String address)throws IOException{
    Objects.requireNonNull(output);checkNonce(nonce);String checked=SafeWebUrl.parse(address).toString();byte[] text=checked.getBytes(StandardCharsets.UTF_8);
    if(text.length>MAX_URL_BYTES)throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);
    var out=new DataOutputStream(output);out.writeInt(MAGIC);out.writeByte(VERSION);out.write(nonce);out.writeShort(text.length);out.write(text);out.flush();
  }
  /** Caller closes its pipe after the frame. Extra bytes and stdin-less/direct entry are rejected. */
  public static VzorBootstrap600 read(InputStream input,Duration timeout)throws IOException{
    return bounded(()->readFrame(input),timeout);
  }
  private static VzorBootstrap600 readFrame(InputStream input)throws IOException{
    var in=new DataInputStream(input);byte[] nonce=new byte[32];boolean success=false;
    try{
      if(in.readInt()!=MAGIC||in.readUnsignedByte()!=VERSION)throw new IOException("Invalid bootstrap");
      in.readFully(nonce);checkNonce(nonce);int length=in.readUnsignedShort();if(length<1||length>MAX_URL_BYTES)throw new IOException("Invalid URL size");
      byte[] bytes=in.readNBytes(length);if(bytes.length!=length||in.read()!=-1)throw new IOException("Invalid frame boundary");
      String address=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
      SafeWebUrl.parse(address);success=true;return new VzorBootstrap600(nonce,address);
    }catch(IOException|IllegalArgumentException error){throw new VzorFailure600(VzorFailure600.Code.AUTHORIZATION_REQUIRED);}
    finally{if(!success)Arrays.fill(nonce,(byte)0);}
  }
  public synchronized void acknowledge(OutputStream output,Reply reply)throws IOException{
    if(closed||replied)throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);
    long pid=ProcessHandle.current().pid();byte[] proof=proof(nonce,reply,pid);
    try{var out=new DataOutputStream(output);out.writeInt(MAGIC);out.writeByte(VERSION);out.writeByte(reply.ordinal());out.writeLong(pid);out.write(proof);out.flush();replied=true;}
    finally{Arrays.fill(proof,(byte)0);close();}
  }
  public static Acknowledgement readAcknowledgement(InputStream input,byte[] nonce,long expectedPid,Duration timeout)throws IOException{
    checkNonce(nonce);
    return bounded(()->{
      var in=new DataInputStream(input);if(in.readInt()!=MAGIC||in.readUnsignedByte()!=VERSION)throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);
      int status=in.readUnsignedByte();long pid=in.readLong();if(status>=Reply.values().length||pid!=expectedPid)throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);
      Reply reply=Reply.values()[status];byte[] actual=in.readNBytes(32),expected=proof(nonce,reply,pid);
      try{if(actual.length!=32||!MessageDigest.isEqual(actual,expected))throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);return new Acknowledgement(reply,pid);}
      finally{Arrays.fill(actual,(byte)0);Arrays.fill(expected,(byte)0);}
    },timeout);
  }
  private static byte[] proof(byte[] nonce,Reply reply,long pid)throws IOException{
    try{Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(nonce,"HmacSHA256"));mac.update(DOMAIN);mac.update((byte)reply.ordinal());return mac.doFinal(ByteBuffer.allocate(8).putLong(pid).array());}
    catch(GeneralSecurityException error){throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);}
  }
  private static void checkNonce(byte[] nonce)throws IOException{if(nonce==null||nonce.length!=32)throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);int bits=0;for(byte b:nonce)bits|=b;if(bits==0)throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);}
  private static <T>T bounded(Callable<T> action,Duration timeout)throws IOException{
    if(timeout.isNegative()||timeout.isZero()||timeout.compareTo(Duration.ofSeconds(30))>0)throw new IllegalArgumentException("Bounded startup timeout required");
    var worker=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"aegis-vzor-startup-pipe");t.setDaemon(true);return t;});Future<T> task=worker.submit(action);
    try{return task.get(timeout.toMillis(),TimeUnit.MILLISECONDS);}
    catch(TimeoutException error){task.cancel(true);throw new VzorFailure600(VzorFailure600.Code.STARTUP_TIMEOUT);}
    catch(InterruptedException error){task.cancel(true);Thread.currentThread().interrupt();throw new InterruptedIOException("Запуск Взора отменён");}
    catch(ExecutionException error){if(error.getCause() instanceof IOException io)throw io;throw new VzorFailure600(VzorFailure600.Code.STARTUP_REJECTED);}
    finally{worker.shutdownNow();}
  }
  @Override public synchronized void close(){if(!closed){closed=true;Arrays.fill(nonce,(byte)0);}}
}
