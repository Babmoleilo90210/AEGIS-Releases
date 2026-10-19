package org.securemail.client.voice;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.Identity;
import org.securemail.client.security.SystemSecrets;
import org.securemail.client.voice600.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;
import org.securemail.protocol.UserInfo;

/** Real delegated Ed25519 verification and SunJSSE TLS sockets. Loopback/OS-secret fixture are not Tor or native audio acceptance. */
@Timeout(20)
class DelegatedVoiceTls600Test {
  @TempDir Path directory;
  static Identity alice,bob,untrusted;static KeyPair aliceApp,bobApp;static final String AUDIENCE="ab".repeat(32);
  @BeforeAll static void identities()throws Exception{alice=Identity.create();bob=Identity.create();untrusted=Identity.create();aliceApp=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();bobApp=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
  static GlasProtocol600.Delegation delegated(Identity root,KeyPair app,long now)throws Exception{var d=new GlasProtocol600.Delegation(AUDIENCE,root.publicKey(),"cd".repeat(32),1,app.getPublic().getEncoded(),now-1000,now+600000,IdentityProtocol.nonce(),new byte[64]);return d.signed(root.sign(d.signingBytes()));}
  static final class Sockets implements AutoCloseable{final Socket client,server;Sockets()throws IOException{try(ServerSocket listen=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){client=new Socket(InetAddress.getLoopbackAddress(),listen.getLocalPort());server=listen.accept();client.setSoTimeout(5000);server.setSoTimeout(5000);}}public void close()throws IOException{try{client.close();}finally{server.close();}}}
  @Test void appDelegationsAuthenticateRealDuplexTlsAndStandardKeyUpdates()throws Exception{
    long now=System.currentTimeMillis();UUID id=UUID.randomUUID();try(var a=VoiceTls.createDelegated(delegated(alice,aliceApp,now),aliceApp.getPrivate(),id,VoiceTls.Role.CALLER,bob.publicKey(),AUDIENCE);var b=VoiceTls.createDelegated(delegated(bob,bobApp,now),bobApp.getPrivate(),id,VoiceTls.Role.CALLEE,alice.publicKey(),AUDIENCE);var sockets=new Sockets();var jobs=Executors.newFixedThreadPool(1)){
      Future<SSLSocket> accepted=jobs.submit(()->b.handshake(sockets.server,a.offer(),alice.publicKey(),false));try(SSLSocket caller=a.handshake(sockets.client,b.offer(),bob.publicKey(),true);SSLSocket callee=accepted.get(5,TimeUnit.SECONDS)){
        assertEquals("TLSv1.3",caller.getSession().getProtocol());assertEquals(VoiceTls.DELEGATED_ALPN,caller.getApplicationProtocol());byte[] audio=new byte[32000];new SecureRandom().nextBytes(audio);caller.getOutputStream().write(audio);caller.getOutputStream().flush();assertArrayEquals(audio,callee.getInputStream().readNBytes(audio.length));
        VoiceTls.requestKeyUpdate(callee);callee.getOutputStream().write(73);callee.getOutputStream().flush();assertEquals(73,caller.getInputStream().read());assertEquals(VoiceTls.shortCode(a.offer(),b.offer()),VoiceTls.shortCode(b.offer(),a.offer()));
      }
    }
  }
  @Test void delegatedOfferRejectsWrongAudienceContactRecipientRoleAndAppPrivateKey()throws Exception{
    long now=System.currentTimeMillis();var d=delegated(alice,aliceApp,now);UUID id=UUID.randomUUID();assertThrows(GeneralSecurityException.class,()->VoiceTls.createDelegated(d,bobApp.getPrivate(),id,VoiceTls.Role.CALLER,bob.publicKey(),AUDIENCE));assertThrows(GeneralSecurityException.class,()->VoiceTls.createDelegated(d,aliceApp.getPrivate(),id,VoiceTls.Role.CALLER,bob.publicKey(),"ff".repeat(32)));
    try(var pending=VoiceTls.createDelegated(d,aliceApp.getPrivate(),id,VoiceTls.Role.CALLER,bob.publicKey(),AUDIENCE)){
      var offer=pending.offer();offer.verify(alice.publicKey(),bob.publicKey(),id,VoiceTls.Role.CALLER,now,AUDIENCE);
      assertThrows(GeneralSecurityException.class,()->offer.verify(alice.publicKey(),bob.publicKey(),id,VoiceTls.Role.CALLER,now));assertThrows(GeneralSecurityException.class,()->offer.verify(untrusted.publicKey(),bob.publicKey(),id,VoiceTls.Role.CALLER,now,AUDIENCE));assertThrows(GeneralSecurityException.class,()->offer.verify(alice.publicKey(),untrusted.publicKey(),id,VoiceTls.Role.CALLER,now,AUDIENCE));assertThrows(GeneralSecurityException.class,()->offer.verify(alice.publicKey(),bob.publicKey(),id,VoiceTls.Role.CALLEE,now,AUDIENCE));assertThrows(GeneralSecurityException.class,()->offer.verify(alice.publicKey(),bob.publicKey(),id,VoiceTls.Role.CALLER,now+700000,AUDIENCE));
      byte[] signature=offer.signature();signature[0]^=1;var changed=new VoiceTls.Offer(id,offer.role(),offer.callerId(),offer.calleeId(),offer.issuedAtMillis(),offer.expiresAtMillis(),offer.identityPublicKey(),offer.certificate(),signature,d);assertThrows(GeneralSecurityException.class,()->changed.verify(alice.publicKey(),bob.publicKey(),id,VoiceTls.Role.CALLER,now,AUDIENCE));
    }
  }
  @Test void delegatedWireIsBoundedCanonicalAndCannotDowngradeIntoLegacyTls()throws Exception{
    long now=System.currentTimeMillis();UUID id=UUID.randomUUID();try(var delegated=VoiceTls.createDelegated(delegated(alice,aliceApp,now),aliceApp.getPrivate(),id,VoiceTls.Role.CALLER,bob.publicKey(),AUDIENCE);var legacy=VoiceTls.create(bob,id,VoiceTls.Role.CALLEE,alice.publicKey());var sockets=new Sockets()){
      ByteArrayOutputStream encoded=new ByteArrayOutputStream();delegated.offer().write(new DataOutputStream(encoded));var decoded=VoiceTls.read(new DataInputStream(new ByteArrayInputStream(encoded.toByteArray())));assertNotNull(decoded.delegation());decoded.verify(alice.publicKey(),bob.publicKey(),id,VoiceTls.Role.CALLER,now,AUDIENCE);
      assertThrows(GeneralSecurityException.class,()->delegated.handshake(sockets.client,legacy.offer(),bob.publicKey(),true));assertTrue(sockets.client.isClosed());assertTrue(encoded.size()<=VoiceTls.MAX_OFFER_BYTES+4);
    }
  }
  @Test void pinnedContactGrantDetectsModifiedContactsAndUntrustedMailRoot()throws Exception{
    var d=delegated(alice,aliceApp,System.currentTimeMillis());var person=new UserInfo(bob.userId(),"blackfox",bob.publicKey(),null);var unsigned=new GlasGrant600(d,List.of(new GlasGrant600.Contact(person,false)),new byte[64]);var grant=unsigned.signed(alice.sign(unsigned.signingBytes()));assertTrue(grant.verify(alice.publicKey(),AUDIENCE,System.currentTimeMillis()));var decoded=GlasGrant600.decode(grant.encode());assertEquals(person.userId(),decoded.contacts().getFirst().user().userId());assertFalse(decoded.verify(untrusted.publicKey(),AUDIENCE,System.currentTimeMillis()));
    byte[] changed=grant.encode();changed[changed.length-1]^=1;assertFalse(GlasGrant600.decode(changed).verify(alice.publicKey(),AUDIENCE,System.currentTimeMillis()));assertThrows(IOException.class,()->GlasGrant600.decode(Arrays.copyOf(grant.encode(),grant.encode().length-1)));
  }
  static final class MemorySecrets implements SystemSecrets{byte[] value;public void store(byte[] key){value=key.clone();}public byte[] load(){return value==null?null:value.clone();}public void clear(){value=null;}}
  @Test void voiceOnlyEncryptedHistorySurvivesRestartAndLockDiscardsHistoryKey()throws Exception{
    var d=delegated(alice,aliceApp,System.currentTimeMillis());var unsigned=new GlasGrant600(d,List.of(new GlasGrant600.Contact(new UserInfo(bob.userId(),"blackfox",bob.publicKey(),null),false)),new byte[64]);var grant=unsigned.signed(alice.sign(unsigned.signingBytes()));var secrets=new MemorySecrets();byte[] privateHistory="PRIVATE-CALL-METADATA-ONLY".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    try(var state=new GlasState600(directory,grant,aliceApp.getPrivate(),secrets)){state.writeVoiceState(privateHistory);byte[] disk=Files.readAllBytes(directory.resolve("voice-state.aeg6"));assertFalse(new String(disk,java.nio.charset.StandardCharsets.ISO_8859_1).contains("PRIVATE-CALL-METADATA-ONLY"));assertArrayEquals(privateHistory,state.readVoiceState());state.lockHistory();assertTrue(state.historyLocked());assertThrows(IOException.class,state::readVoiceState);assertThrows(IOException.class,()->state.writeVoiceState(privateHistory));assertEquals(1,state.contacts().size());assertNotNull(state.createTls(UUID.randomUUID(),VoiceTls.Role.CALLER,bob.publicKey()));}
    try(var reopened=new GlasState600(directory,grant,aliceApp.getPrivate(),secrets)){assertArrayEquals(privateHistory,reopened.readVoiceState());}
    byte[] disk=Files.readAllBytes(directory.resolve("voice-state.aeg6"));disk[disk.length-1]^=1;Files.write(directory.resolve("voice-state.aeg6"),disk);try(var damaged=new GlasState600(directory,grant,aliceApp.getPrivate(),secrets)){assertThrows(GeneralSecurityException.class,damaged::readVoiceState);}
    assertFalse(Files.exists(directory.resolve("state.vault")));assertThrows(IOException.class,()->new GlasState600(directory,grant,aliceApp.getPrivate(),new MemorySecrets()));
  }
}
