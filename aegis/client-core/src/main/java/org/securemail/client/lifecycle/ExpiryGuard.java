package org.securemail.client.lifecycle;

import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.securemail.client.AppPaths;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

/** Device-local encrypted high-water ledger outside rollback/profile snapshots.
 * It protects against an old profile backup and wall-clock rollback on the same boot.
 * A reboot cannot supply trustworthy offline elapsed time: opened letters fail closed.
 * It cannot protect against a hostile OS or deliberate manual extraction of keys. */
public final class ExpiryGuard implements AutoCloseable {
  private static final int MAX=2*1024*1024;
  private final Path file;private final byte[] key,aad;private final BootClock clock;
  private FileChannel channel;private FileLock lock;private boolean available,closed;
  private final Map<String,Entry> entries=new LinkedHashMap<>();
  private static final class Entry {String boot;long start,wall,duration,consumed,baseline;boolean confirmed,expired;}
  public ExpiryGuard(LocalStore local,String deviceId,boolean fresh)throws IOException,GeneralSecurityException {this(local,deviceId,fresh,defaultDirectory(),BootClock.system());}
  public ExpiryGuard(LocalStore local,String deviceId,boolean fresh,Path directory,BootClock clock)throws IOException,GeneralSecurityException {
    Limits.userId(deviceId);this.clock=clock;key=local.sessionUnlockKey();aad=("AEGIS-expiry-device-ledger-v1/"+deviceId).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    AtomicFiles.directory(directory);file=directory.resolve(deviceId+".enc");
    try {channel=FileChannel.open(directory.resolve(deviceId+".lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);lock=channel.tryLock();if(lock==null)throw new IOException("Device ledger already in use");
      if(Files.exists(file))load();else if(fresh)save();else return;clock.stamp();available=true;
    }catch(IOException|GeneralSecurityException|RuntimeException failure){available=false;/* Keep original ledger; basic mail remains usable. */}
  }
  public static Path defaultDirectory(){return AppPaths.root().getParent().resolve("aegis-lifecycle-guards");}
  public synchronized boolean available(){return available&&!closed;}
  /** Persist a prepared reveal before decrypting. An interrupted reveal never restarts a timer. */
  public synchronized void prepare(String id,long duration,long wall)throws IOException,GeneralSecurityException {
    require();Limits.messageId(id);if(duration<60_000||duration>30L*86400_000)throw new IOException("Expiry duration");
    if(entries.containsKey(id)){if(entries.get(id).expired)throw new IOException("Письмо исчезло");return;}
    if(entries.size()>=8192)throw new IOException("Expiry ledger quota");var stamp=clock.stamp();var e=new Entry();e.boot=stamp.boot();e.start=stamp.elapsed();e.wall=wall;e.duration=duration;entries.put(id,e);save();
  }
  /** Called only after actual body display. The event time is persisted before returning. */
  public synchronized void confirm(String id,long wall,long now)throws IOException,GeneralSecurityException {require();Entry e=entry(id);if(e.expired||!e.boot.equals(clock.stamp().boot()))throw new IOException("Письмо недоступно после перезагрузки");var stamp=clock.stamp();if(!e.confirmed){e.start=stamp.elapsed();e.wall=wall;e.baseline=Math.max(0,now-wall);e.consumed=e.baseline;e.confirmed=true;save();}}
  public synchronized boolean confirmed(String id){Entry e=entries.get(id);return e!=null&&e.confirmed&&!e.expired;}
  public synchronized long firstDisplay(String id){Entry e=entries.get(id);return e==null?0:e.wall;}
  /** Unread letters have no countdown. Ambiguous prepared reveals are inaccessible on a later process. */
  public synchronized long remaining(String id,long wall)throws IOException,GeneralSecurityException {
    require();Entry e=entries.get(id);if(e==null)return Long.MAX_VALUE;if(e.expired)return 0;if(!e.confirmed)return Long.MAX_VALUE;
    var stamp=clock.stamp();if(!e.boot.equals(stamp.boot())||stamp.elapsed()<e.start){e.expired=true;save();return 0;}
    long elapsed=Math.max(e.consumed,Math.max(e.baseline+stamp.elapsed()-e.start,Math.max(0,wall-e.wall)));e.consumed=elapsed;
    if(elapsed>=e.duration){e.expired=true;save();return 0;}return e.duration-elapsed;
  }
  /** On startup a reveal prepared but never durably confirmed is treated as uncertain. */
  public synchronized void recover()throws IOException,GeneralSecurityException {if(!available())return;boolean changed=false;for(Entry e:entries.values())if(!e.confirmed&&!e.expired){e.expired=true;changed=true;}if(changed)save();}
  public synchronized void expire(String id)throws IOException,GeneralSecurityException {require();Limits.messageId(id);Entry e=entries.get(id);if(e==null){if(entries.size()>=8192)throw new IOException("Expiry ledger quota");var stamp=clock.stamp();e=new Entry();e.boot=stamp.boot();e.start=stamp.elapsed();e.wall=Math.max(1,System.currentTimeMillis());e.duration=60_000;entries.put(id,e);}if(!e.expired){e.expired=true;save();}}
  private Entry entry(String id)throws IOException{Entry e=entries.get(id);if(e==null)throw new IOException("Reveal not prepared");return e;}
  private void require()throws IOException {if(!available())throw new IOException("Нельзя подтвердить время исчезающего письма на этом устройстве");}
  private void save()throws IOException,GeneralSecurityException {
    byte[] bytes=Binary.encode(o->{o.writeInt(1);o.writeInt(entries.size());for(var item:entries.entrySet()){Binary.text(o,item.getKey());var e=item.getValue();Binary.text(o,e.boot);o.writeLong(e.start);o.writeLong(e.wall);o.writeLong(e.duration);o.writeLong(e.consumed);o.writeLong(e.baseline);o.writeBoolean(e.confirmed);o.writeBoolean(e.expired);}});
    byte[] nonce=Secrets.random(12);try{var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(aad);byte[] ciphertext=cipher.doFinal(bytes);AtomicFiles.write(file,Binary.encode(o->{Binary.bytes(o,nonce);Binary.bytes(o,ciphertext);}));}finally{Arrays.fill(bytes,(byte)0);}
  }
  private void load()throws IOException,GeneralSecurityException {
    try(var i=new DataInputStream(new ByteArrayInputStream(AtomicFiles.read(file,MAX)))){byte[] nonce=Binary.bytes(i,12);if(nonce.length!=12)throw new IOException("Ledger nonce");byte[] ciphertext=Binary.bytes(i,MAX);Binary.end(i);var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(aad);byte[] plain=cipher.doFinal(ciphertext);
      try(var in=new DataInputStream(new ByteArrayInputStream(plain))){if(in.readInt()!=1)throw new IOException("Ledger schema");int n=in.readInt();if(n<0||n>8192)throw new IOException("Ledger quota");for(;n>0;n--){String id=Binary.text(in,36);Limits.messageId(id);Entry e=new Entry();e.boot=Binary.text(in,128);e.start=in.readLong();e.wall=in.readLong();e.duration=in.readLong();e.consumed=in.readLong();e.baseline=in.readLong();e.confirmed=in.readBoolean();e.expired=in.readBoolean();if(e.start<0||e.wall<1||e.duration<60_000||e.duration>30L*86400_000||e.consumed<0||e.baseline<0||entries.put(id,e)!=null)throw new IOException("Ledger fields");}Binary.end(in);}finally{Arrays.fill(plain,(byte)0);}
    }
  }
  @Override public synchronized void close()throws IOException {if(closed)return;closed=true;available=false;Arrays.fill(key,(byte)0);if(lock!=null&&lock.isValid())lock.release();if(channel!=null)channel.close();}
}
