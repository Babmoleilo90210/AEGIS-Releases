package org.securemail.client.voice600;
import java.io.*;
import java.security.*;
import java.util.*;
import java.util.function.*;
import org.securemail.client.voice.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;
import org.securemail.protocol.UserInfo;

/** Narrow Android voice state: public approved identity/contacts and encrypted voice metadata only. */
public final class AndroidGlasState implements AndroidVoiceLocalStore600,AutoCloseable {
    public interface Storage {byte[] read()throws IOException;void write(byte[] data)throws IOException;}
    @FunctionalInterface public interface TlsFactory {AndroidVoiceTls.Pending create(UUID id,AndroidVoiceTls.Role role,byte[] peer)throws IOException,GeneralSecurityException;}
    @FunctionalInterface public interface RemoteVerifier {void verify(AndroidVoiceTls.Offer offer)throws IOException;}
    private final GlasGrant600 grant;private final Storage storage;private final TlsFactory factory;private final BooleanSupplier authorized;private volatile boolean closed,historyLocked;
    private volatile RemoteVerifier remote=offer->{throw new IOException("Сигнализация не подтверждена");};private volatile Predicate<UserInfo> peerLive=peer->false;
    public AndroidGlasState(GlasGrant600 grant,IdentityProtocol.Capability cap,byte[] server,Storage storage,TlsFactory factory,BooleanSupplier authorized)throws IOException {
        this.grant=Objects.requireNonNull(grant);this.storage=Objects.requireNonNull(storage);this.factory=Objects.requireNonNull(factory);this.authorized=Objects.requireNonNull(authorized);long now=System.currentTimeMillis();
        if(!GlasProtocol600.verifyDelegation(grant.delegation(),cap,server,now)||!grant.verify(grant.delegation().accountPublic(),cap.audience,now)||grant.delegation().expiresAt>cap.offlineUntil)throw new IOException("Публичный допуск Гласа недействителен");check();
    }
    private void check()throws IOException{if(closed||!authorized.getAsBoolean()||!grant.verify(accountPublic(),identityAudience(),now()))throw new IOException("Глас заблокирован или допуск истёк");}
    public byte[] accountPublic(){return grant.delegation().accountPublic();}public long now(){return System.currentTimeMillis();}public String identityAudience(){return grant.delegation().audience;}
    public List<UserInfo> contacts(){return grant.contacts().stream().map(GlasGrant600.Contact::user).collect(java.util.stream.Collectors.toUnmodifiableList());}
    public UserInfo contact(String nickname){return grant.contacts().stream().filter(c->c.user().nickname().equals(nickname)).map(GlasGrant600.Contact::user).findFirst().orElse(null);}
    public boolean blocked(String id){return grant.contacts().stream().noneMatch(c->c.user().userId().equals(id)&&!c.blocked());}
    public byte[] readVoiceState()throws IOException {check();if(historyLocked)throw new IOException("История заблокирована");byte[] bytes=storage.read();if(bytes!=null&&bytes.length>65536){Arrays.fill(bytes,(byte)0);throw new IOException("Размер истории Гласа");}return bytes;}
    public void writeVoiceState(byte[] bytes)throws IOException {check();if(historyLocked||bytes==null||bytes.length>65536)throw new IOException("История заблокирована или превышен размер");storage.write(bytes);}
    public AndroidVoiceTls.Pending createTls(UUID id,AndroidVoiceTls.Role role,byte[] peer)throws IOException,GeneralSecurityException {check();if(blocked(IdentityProtocol.id(peer)))throw new IOException("Контакт недоступен");return factory.create(id,role,peer);}
    public void remoteVerifier(RemoteVerifier verifier,Predicate<UserInfo> peerLive){remote=Objects.requireNonNull(verifier);this.peerLive=Objects.requireNonNull(peerLive);}
    @Override public void verifyRemote(AndroidVoiceTls.Offer offer,byte[] peer,UUID call,AndroidVoiceTls.Role role)throws IOException,GeneralSecurityException {check();offer.verify(peer,accountPublic(),call,role,now(),identityAudience());remote.verify(offer);check();}
    @Override public boolean sessionAuthorized(UserInfo contact){try{check();return peerLive.test(contact);}catch(IOException|RuntimeException denied){return false;}}
    public void lockHistory(){historyLocked=true;}
    @Override public void close(){closed=true;historyLocked=true;remote=offer->{throw new IOException("Глас закрыт");};peerLive=peer->false;}
}
