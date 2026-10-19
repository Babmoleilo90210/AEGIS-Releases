package org.securemail.client.voice600;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.securemail.client.security.SystemSecrets;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.client.voice.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.protocol.UserInfo;

/** Separate encrypted voice settings/history. Contains public contact pins and an app key, never a Mail vault/root private key. */
public final class GlasState600 implements VoiceLocalStore600,AutoCloseable {
  @FunctionalInterface public interface RemoteVerifier{void verify(VoiceTls.Offer offer)throws IOException;}
  private final Path stateFile;private final GlasGrant600 grant;private final PrivateKey appKey;private final byte[] stateKey;private final Map<String,UserInfo> byName=new HashMap<>();private final Set<String> blocked=new HashSet<>();
  private volatile boolean closed,historyLocked;private volatile RemoteVerifier remoteVerifier=offer->{throw new IOException("Сигнализация Гласа не готова");};private volatile java.util.function.Predicate<UserInfo> livePeer=peer->false;
  public GlasState600(Path directory,GlasGrant600 grant,PrivateKey appKey,SystemSecrets secrets)throws IOException{
    this.grant=Objects.requireNonNull(grant);this.appKey=Objects.requireNonNull(appKey);directory=directory.toAbsolutePath().normalize();for(Path p=directory;p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылка в хранилище Гласа запрещена");AtomicFiles.directory(directory);stateFile=directory.resolve("voice-state.aeg6");
    for(var c:grant.contacts()){byName.put(c.user().nickname(),c.user());if(c.blocked())blocked.add(c.user().userId());}
    byte[] loaded=secrets.load();if(loaded==null){if(Files.exists(stateFile))throw new IOException("Ключ истории Гласа отсутствует в защищённом хранилище ОС");loaded=new byte[32];new SecureRandom().nextBytes(loaded);try{secrets.store(loaded);}catch(IOException failure){Arrays.fill(loaded,(byte)0);throw failure;}}
    if(loaded.length!=32){Arrays.fill(loaded,(byte)0);throw new IOException("Ключ истории Гласа повреждён");}stateKey=loaded;
  }
  public void remoteVerifier(RemoteVerifier verifier,java.util.function.Predicate<UserInfo> active){remoteVerifier=Objects.requireNonNull(verifier);livePeer=Objects.requireNonNull(active);}
  public byte[] accountPublic(){return grant.delegation().accountPublic();}public long now(){return System.currentTimeMillis();}public String identityAudience(){return grant.delegation().audience;}
  public UserInfo contact(String nickname){return closed?null:byName.get(nickname);}public List<UserInfo> contacts(){return closed?List.of():byName.values().stream().sorted(Comparator.comparing(UserInfo::nickname)).toList();}public boolean blocked(String id){return closed||blocked.contains(id);}
  public boolean sessionAuthorized(UserInfo peer){return !closed&&livePeer.test(peer);}
  public void verifyRemote(VoiceTls.Offer offer,byte[] peer,UUID callId,VoiceTls.Role role)throws IOException,GeneralSecurityException{if(closed||offer.delegation()==null)throw new IOException("Собеседник не поддерживает делегированную идентичность Гласа");offer.verify(peer,accountPublic(),callId,role,now(),identityAudience());remoteVerifier.verify(offer);}
  public VoiceTls.Pending createTls(UUID id,VoiceTls.Role role,byte[] peer)throws IOException,GeneralSecurityException{if(closed)throw new IOException("Глас заблокирован");return VoiceTls.createDelegated(grant.delegation(),appKey,id,role,peer,identityAudience());}
  private byte[] aad(){return ("AEGIS-GLAS-LOCAL-STATE/v1\n"+grant.delegation().accountId()).getBytes(java.nio.charset.StandardCharsets.US_ASCII);}
  public synchronized byte[] readVoiceState()throws IOException,GeneralSecurityException{
    if(closed||historyLocked)throw new IOException("История Гласа заблокирована");if(!Files.exists(stateFile))return null;byte[] bytes=AtomicFiles.read(stateFile,262144);try{if(bytes.length<4+12+16)throw new IOException("История Гласа повреждена");ByteBuffer b=ByteBuffer.wrap(bytes);if(b.getInt()!=0x474c5336)throw new IOException("Формат истории Гласа");byte[] nonce=new byte[12],sealed=new byte[b.remaining()-12];b.get(nonce).get(sealed);try{Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(stateKey,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad());return c.doFinal(sealed);}finally{Arrays.fill(sealed,(byte)0);Arrays.fill(nonce,(byte)0);}}finally{Arrays.fill(bytes,(byte)0);}
  }
  public synchronized void writeVoiceState(byte[] plain)throws IOException,GeneralSecurityException{
    if(closed||historyLocked||plain==null||plain.length>260000)throw new IOException("Глас заблокирован или история слишком велика");byte[] nonce=new byte[12];new SecureRandom().nextBytes(nonce);Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(stateKey,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad());byte[] sealed=c.doFinal(plain);try{ByteBuffer encoded=ByteBuffer.allocate(4+nonce.length+sealed.length);encoded.putInt(0x474c5336).put(nonce).put(sealed);AtomicFiles.write(stateFile,encoded.array());}finally{Arrays.fill(nonce,(byte)0);Arrays.fill(sealed,(byte)0);}
  }
  /** Restricted incoming calls keep only the narrow app key/contact pins; the history encryption key is discarded until a new authorized process. */
  public synchronized void lockHistory(){historyLocked=true;Arrays.fill(stateKey,(byte)0);}
  public boolean historyLocked(){return historyLocked;}
  @Override public synchronized void close(){if(closed)return;closed=true;Arrays.fill(stateKey,(byte)0);byName.clear();blocked.clear();try{appKey.destroy();}catch(javax.security.auth.DestroyFailedException ignored){/* JVM provider may retain internal key objects until collection. */}}
}
