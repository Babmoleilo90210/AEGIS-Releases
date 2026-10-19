package org.securemail.client.ecosystem;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Versioned, authenticated, bounded local control protocol. Bootstrap travels only over an anonymous stdin pipe. */
public final class LocalIpc {
  private static final int BOOT_MAGIC=0x41454736, HELLO_MAGIC=0x49504336;
  private static final SecureRandom RANDOM=new SecureRandom();
  public static final int MAX_PAYLOAD=65536;
  private LocalIpc() {}
  public enum Type { LOCK, UNLOCK, SHUTDOWN, HEARTBEAT, CALL_ACCEPT, CALL_REJECT, READY, LOCKED, FLUSHED, PONG, NOTIFICATION_COUNT, FAILURE, OPEN_URL, PAIRING_RESULT, PAIRING_CANCELLED, USER_ACTIVITY }
  public record Packet(Type type, byte[] payload) {
    public Packet {
      Objects.requireNonNull(type); Objects.requireNonNull(payload);
      if (payload.length > MAX_PAYLOAD) throw new IllegalArgumentException("Слишком большое сообщение IPC");
      if (type == Type.NOTIFICATION_COUNT) {
        if (payload.length != 4 || java.nio.ByteBuffer.wrap(payload).getInt() < 0) throw new IllegalArgumentException("Некорректный счётчик");
      } else if (type == Type.FAILURE) {
        if (payload.length != 4) throw new IllegalArgumentException("Некорректный код ошибки");
      } else if(type==Type.OPEN_URL) {
        if(payload.length<1||payload.length>4096)throw new IllegalArgumentException("Некорректная ссылка IPC");
        try{String url=StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(payload)).toString();org.securemail.client.safeweb.SafeWebUrl.parse(url);}catch(java.nio.charset.CharacterCodingException invalid){throw new IllegalArgumentException("Некорректная ссылка IPC",invalid);}
      } else if(type==Type.PAIRING_RESULT){if(payload.length<1||payload.length>65536)throw new IllegalArgumentException("Некорректный ответ сопряжения");
      } else if (payload.length != 0) throw new IllegalArgumentException("Недопустимые параметры IPC");
      payload=payload.clone();
    }
    @Override public byte[] payload() { return payload.clone(); }
    public static Packet command(Type type) { return new Packet(type,new byte[0]); }
    public static Packet openUrl(String url){return new Packet(Type.OPEN_URL,org.securemail.client.safeweb.SafeWebUrl.parse(url).toASCIIString().getBytes(StandardCharsets.UTF_8));}
    public static Packet count(int count) { return new Packet(Type.NOTIFICATION_COUNT,java.nio.ByteBuffer.allocate(4).putInt(count).array()); }
  }
  @FunctionalInterface public interface CapabilityVerifier {
    /** Independently verify the Identity signature, component, generation, expiry and local proof key; do not trust the parent assertion alone. */
    void verify(ComponentLease lease) throws IOException;
  }
  static final class Bootstrap implements AutoCloseable {
    final ComponentLease lease; final int port; final byte[] secret=random(32), nonce=random(32);
    final long createdNanos;final java.util.concurrent.atomic.AtomicBoolean claimed=new java.util.concurrent.atomic.AtomicBoolean();
    Bootstrap(ComponentLease lease,int port) { this.lease=lease; this.port=port;this.createdNanos=System.nanoTime(); }
    Bootstrap(ComponentLease lease,int port,byte[] secret,byte[] nonce) {
      this(lease,port,secret,nonce,System.nanoTime());
    }
    Bootstrap(ComponentLease lease,int port,byte[] secret,byte[] nonce,long createdNanos) {
      this.lease=lease;this.port=port;this.createdNanos=createdNanos;System.arraycopy(secret,0,this.secret,0,32);System.arraycopy(nonce,0,this.nonce,0,32);
    }
    void write(OutputStream stream) throws IOException {
      var out=new DataOutputStream(stream); out.writeInt(BOOT_MAGIC); out.writeInt(3);
      out.writeUTF(lease.component().name()); out.writeUTF(lease.accountId()); out.writeLong(lease.generation()); out.writeInt(port);
      out.write(secret); out.write(nonce); byte[] cap=lease.capability(); out.writeInt(cap.length); out.write(cap);byte[] privateKey=lease.proofPrivatePkcs8(),publicKey=lease.proofPublicX509();out.writeInt(privateKey.length);out.write(privateKey);out.writeInt(publicKey.length);out.write(publicKey);byte[] auxiliary=lease.auxiliaryPublic();out.writeInt(auxiliary.length);out.write(auxiliary);out.flush();Arrays.fill(privateKey,(byte)0);Arrays.fill(cap,(byte)0);
    }
    static Bootstrap read(InputStream stream,ComponentId expected) throws IOException {
      var in=new DataInputStream(stream);
      if (in.readInt()!=BOOT_MAGIC || in.readInt()!=3) throw rejected();
      ComponentId component; try { component=ComponentId.valueOf(in.readUTF()); } catch(IllegalArgumentException e) { throw rejected(); }
      String account=in.readUTF(); long generation=in.readLong(); int port=in.readInt();
      byte[] secret=in.readNBytes(32),nonce=in.readNBytes(32); int length=in.readInt();
      if(component!=expected || port<1 || port>65535 || secret.length!=32 || nonce.length!=32 || length<1 || length>32768) throw rejected();
      byte[] capability=in.readNBytes(length); if(capability.length!=length) throw rejected();
      byte[] privateKey=new byte[0],publicKey=new byte[0];
      try {
        int privateLength=in.readInt();if(privateLength!=0&&(privateLength<48||privateLength>256))throw rejected();privateKey=in.readNBytes(privateLength);if(privateKey.length!=privateLength)throw rejected();
        int publicLength=in.readInt();if(publicLength!=0&&publicLength!=44)throw rejected();publicKey=in.readNBytes(publicLength);if(publicKey.length!=publicLength)throw rejected();
        int auxiliaryLength=in.readInt();if(auxiliaryLength<0||auxiliaryLength>65536)throw rejected();byte[] auxiliary=in.readNBytes(auxiliaryLength);if(auxiliary.length!=auxiliaryLength)throw rejected();
        return new Bootstrap(new ComponentLease(component,account,generation,capability,privateKey,publicKey,auxiliary),port,secret,nonce);
      }
      catch(IllegalArgumentException e) { throw rejected(); }
      finally { Arrays.fill(secret,(byte)0);Arrays.fill(privateKey,(byte)0);Arrays.fill(capability,(byte)0); }
    }
    byte[] binding() throws IOException {
      var bytes=new ByteArrayOutputStream(); var out=new DataOutputStream(bytes);
      out.writeUTF("AEGIS-LOCAL-IPC-6/v1"); out.writeUTF(lease.component().name()); out.writeUTF(lease.accountId()); out.writeLong(lease.generation());
      out.writeInt(port); out.write(nonce); out.write(sha(lease.capability()));out.write(sha(lease.proofPublicX509()));out.write(sha(lease.auxiliaryPublic())); return bytes.toByteArray();
    }
    @Override public void close() { Arrays.fill(secret,(byte)0); Arrays.fill(nonce,(byte)0); }
  }
  /** Child must call before opening any account data, network service, microphone or JavaFX scene. */
  public static ChildConnection connectChild(InputStream anonymousStdin,ComponentId component,CapabilityVerifier verifier) throws IOException {
    Objects.requireNonNull(verifier);
    try (Bootstrap boot=Bootstrap.read(anonymousStdin,component)) {
      verifier.verify(boot.lease);
      Socket socket=new Socket();
      try {
        socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),boot.port),3000); socket.setSoTimeout(6500); socket.setTcpNoDelay(true);
        var in=new DataInputStream(socket.getInputStream()); var out=new DataOutputStream(socket.getOutputStream());
        byte[] random=random(32); long pid=ProcessHandle.current().pid();
        out.writeInt(HELLO_MAGIC); out.writeLong(pid); out.write(random);
        out.write(hmac(boot.secret,combine(boot.binding(),longBytes(pid),random))); out.flush();
        byte[] parent=in.readNBytes(32),proof=in.readNBytes(32);
        if (parent.length!=32 || proof.length!=32 || !MessageDigest.isEqual(proof,hmac(boot.secret,combine(boot.binding(),random,parent)))) throw rejected();
        byte[] master=hmac(boot.secret,combine("channel".getBytes(StandardCharsets.US_ASCII),boot.binding(),random,parent));
        var channel=new Channel(socket,master,false,component); Arrays.fill(master,(byte)0);
        return new ChildConnection(boot.lease,channel);
      } catch (IOException|RuntimeException e) { socket.close(); throw e; }
    }
  }
  static Channel acceptParent(Socket socket,Bootstrap boot,long expectedPid) throws IOException {
    if (!socket.getInetAddress().isLoopbackAddress() || System.nanoTime()-boot.createdNanos>java.util.concurrent.TimeUnit.SECONDS.toNanos(10) || !boot.claimed.compareAndSet(false,true)) throw rejected();
    socket.setSoTimeout(3000); socket.setTcpNoDelay(true);
    var in=new DataInputStream(socket.getInputStream()); var out=new DataOutputStream(socket.getOutputStream());
    if(in.readInt()!=HELLO_MAGIC) throw rejected(); long pid=in.readLong(); byte[] child=in.readNBytes(32),proof=in.readNBytes(32);
    if(pid!=expectedPid || child.length!=32 || proof.length!=32 || !MessageDigest.isEqual(proof,hmac(boot.secret,combine(boot.binding(),longBytes(pid),child)))) throw rejected();
    byte[] parent=random(32); out.write(parent); out.write(hmac(boot.secret,combine(boot.binding(),child,parent))); out.flush();
    byte[] master=hmac(boot.secret,combine("channel".getBytes(StandardCharsets.US_ASCII),boot.binding(),child,parent));
    Channel result=new Channel(socket,master,true,boot.lease.component()); Arrays.fill(master,(byte)0); socket.setSoTimeout(6500); return result;
  }
  public record ChildConnection(ComponentLease lease,Channel channel) implements AutoCloseable {
    @Override public void close() throws IOException {try{channel.close();}finally{lease.close();}}
  }
  public static final class Channel implements AutoCloseable {
    private final Socket socket; private final DataInputStream in; private final DataOutputStream out;
    private final byte[] sendKey,readKey; private final boolean parent; private final ComponentId component;
    private long sent,received; private volatile boolean closed;
    Channel(Socket socket,byte[] master,boolean parent,ComponentId component) throws IOException {
      this.socket=socket; this.parent=parent; this.component=component;
      this.in=new DataInputStream(socket.getInputStream()); this.out=new DataOutputStream(socket.getOutputStream());
      this.sendKey=hmac(master,(parent?"parent-to-child":"child-to-parent").getBytes(StandardCharsets.US_ASCII));
      this.readKey=hmac(master,(parent?"child-to-parent":"parent-to-child").getBytes(StandardCharsets.US_ASCII));
    }
    public synchronized void send(Packet packet) throws IOException {
      checkDirection(packet.type(),parent,component); if(closed || sent==Long.MAX_VALUE) throw rejected();
      long sequence=++sent; var buffer=new ByteArrayOutputStream(); var frame=new DataOutputStream(buffer);
      frame.writeLong(sequence); frame.writeByte(packet.type().ordinal()); byte[] payload=packet.payload(); frame.writeInt(payload.length); frame.write(payload);
      byte[] bytes=buffer.toByteArray(); out.writeInt(bytes.length+32); out.write(bytes); out.write(hmac(sendKey,bytes)); out.flush();
    }
    public void startupTimeout(int millis)throws IOException{if(millis<1000||millis>45000)throw new IllegalArgumentException("IPC deadline");socket.setSoTimeout(millis);}
    /** One reader only; authentication/sequence validation precedes dispatch. */
    public Packet receive() throws IOException {
      if(closed)throw rejected();
      int length=in.readInt(); if(length<45 || length>MAX_PAYLOAD+45) throw rejected();
      byte[] bytes=in.readNBytes(length-32),proof=in.readNBytes(32);
      if(bytes.length!=length-32 || proof.length!=32 || !MessageDigest.isEqual(proof,hmac(readKey,bytes))) throw rejected();
      var frame=new DataInputStream(new ByteArrayInputStream(bytes)); long sequence=frame.readLong(); int kind=frame.readUnsignedByte(),size=frame.readInt();
      if(received==Long.MAX_VALUE || sequence!=received+1 || kind>=Type.values().length || size<0 || size>MAX_PAYLOAD || size!=bytes.length-13) throw rejected();
      Type type=Type.values()[kind]; checkDirection(type,!parent,component);
      Packet result; try { result=new Packet(type,frame.readNBytes(size)); } catch(IllegalArgumentException e) { throw rejected(); }
      if(closed)throw rejected();received=sequence; return result;
    }
    @Override public void close() throws IOException { closed=true; socket.close(); Arrays.fill(sendKey,(byte)0); Arrays.fill(readKey,(byte)0); }
  }
  private static void checkDirection(Type type,boolean fromParent,ComponentId component) throws IOException {
    boolean command=type.ordinal()<=Type.CALL_REJECT.ordinal();
    if(command!=fromParent || ((type==Type.CALL_ACCEPT || type==Type.CALL_REJECT) && component!=ComponentId.GLAS)) throw rejected();
  }
  static IOException rejected() { return new IOException("Локальное соединение АЕГИС не авторизовано"); }
  static byte[] random(int size) { byte[] result=new byte[size]; RANDOM.nextBytes(result); return result; }
  static byte[] hmac(byte[] key,byte[] bytes) throws IOException {
    try { Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key,"HmacSHA256")); return mac.doFinal(bytes); }
    catch(GeneralSecurityException e) { throw new IOException("Недоступна защита IPC",e); }
  }
  static byte[] sha(byte[] bytes) throws IOException { try { return MessageDigest.getInstance("SHA-256").digest(bytes); } catch(GeneralSecurityException e) { throw new IOException(e); } }
  static byte[] longBytes(long value) { return java.nio.ByteBuffer.allocate(8).putLong(value).array(); }
  static byte[] combine(byte[]... values) { var out=new ByteArrayOutputStream(); for(byte[] value:values) out.writeBytes(value); return out.toByteArray(); }
}
