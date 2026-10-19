package org.securemail.client.voice;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;
import org.securemail.client.crypto.Identity;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;

/** Actual explicit BCJSSE ↔ unchanged desktop SunJSSE. Loopback is not Tor or Android acceptance. */
public final class AndroidTlsInteropHostTest {
    private static int passed;private static final String AUDIENCE="ab".repeat(32);
    private static final Identity ALICE=identity(),BOB=identity(),MALLORY=identity();
    private static final KeyPair A=key(),B=key();
    private interface Checked{void run()throws Exception;}
    private static Identity identity(){try{return Identity.create();}catch(Exception e){throw new AssertionError(e);}}
    private static KeyPair key(){try{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}catch(Exception e){throw new AssertionError(e);}}
    private static void ok(boolean value,String name){if(!value)throw new AssertionError(name);passed++;System.out.println("PASS "+name);}
    private static void denied(Checked action,String name)throws Exception{try{action.run();throw new AssertionError("Accepted "+name);}catch(GeneralSecurityException|IOException expected){passed++;System.out.println("PASS "+name);}}
    private static GlasProtocol600.Delegation grant(Identity root,KeyPair app)throws GeneralSecurityException{long now=System.currentTimeMillis();var d=new GlasProtocol600.Delegation(AUDIENCE,root.publicKey(),"cd".repeat(32),1,app.getPublic().getEncoded(),now-1000,now+600000,IdentityProtocol.nonce(),new byte[64]);return d.signed(root.sign(d.signingBytes()));}
    private static VoiceTls.Offer desktop(AndroidVoiceTls.Offer offer)throws IOException{ByteArrayOutputStream b=new ByteArrayOutputStream();offer.write(new DataOutputStream(b));return VoiceTls.read(new DataInputStream(new ByteArrayInputStream(b.toByteArray())));}
    private static AndroidVoiceTls.Offer android(VoiceTls.Offer offer)throws IOException{ByteArrayOutputStream b=new ByteArrayOutputStream();offer.write(new DataOutputStream(b));return AndroidVoiceTls.read(new DataInputStream(new ByteArrayInputStream(b.toByteArray())));}
    private static final class Sockets implements AutoCloseable{final Socket caller,callee;Sockets()throws IOException{try(ServerSocket s=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){caller=new Socket(InetAddress.getLoopbackAddress(),s.getLocalPort());callee=s.accept();caller.setSoTimeout(5000);callee.setSoTimeout(5000);}}public void close()throws IOException{try{caller.close();}finally{callee.close();}}}
    public static void main(String[] args)throws Exception{
        String[] providers=Arrays.stream(Security.getProviders()).map(Provider::getName).toArray(String[]::new);
        interop(true);interop(false);negative();
        ok(Arrays.equals(providers,Arrays.stream(Security.getProviders()).map(Provider::getName).toArray(String[]::new)),"explicit BC providers never alter global Security provider registry");
        System.out.println("RESULT "+passed+" PASS; physical Android provider, Tor and actual voice devices NOT_RUN");
    }
    private static void interop(boolean androidCaller)throws Exception{
        UUID id=UUID.randomUUID();
        try(var android=AndroidVoiceTls.createDelegated(grant(ALICE,A),A.getPrivate(),id,androidCaller?AndroidVoiceTls.Role.CALLER:AndroidVoiceTls.Role.CALLEE,BOB.publicKey(),AUDIENCE);
            var desktop=VoiceTls.createDelegated(grant(BOB,B),B.getPrivate(),id,androidCaller?VoiceTls.Role.CALLEE:VoiceTls.Role.CALLER,ALICE.publicKey(),AUDIENCE);var sockets=new Sockets()){
            ExecutorService jobs=Executors.newFixedThreadPool(1);
            try{
                Future<SSLSocket> remote=jobs.submit(()->desktop.handshake(androidCaller?sockets.callee:sockets.caller,desktop(android.offer()),ALICE.publicKey(),!androidCaller));
                try(SSLSocket mobile=android.handshake(androidCaller?sockets.caller:sockets.callee,android(desktop.offer()),BOB.publicKey(),androidCaller);SSLSocket pc=remote.get(8,TimeUnit.SECONDS)){
                    ok("TLSv1.3".equals(mobile.getSession().getProtocol())&&"aegis-glas/2".equals(AndroidVoiceTls.applicationProtocol(mobile)),"actual BCJSSE TLS1.3 and exact v2 ALPN as "+(androidCaller?"caller":"callee"));
                    byte[] audio=new byte[32768];new SecureRandom().nextBytes(audio);mobile.getOutputStream().write(audio);mobile.getOutputStream().flush();ok(Arrays.equals(audio,pc.getInputStream().readNBytes(audio.length)),"actual Android adapter → desktop authenticated encrypted payload");
                    pc.getOutputStream().write(audio);pc.getOutputStream().flush();ok(Arrays.equals(audio,mobile.getInputStream().readNBytes(audio.length)),"actual desktop → Android adapter authenticated encrypted payload");
                    VoiceTls.requestKeyUpdate(pc);pc.getOutputStream().write(73);pc.getOutputStream().flush();ok(mobile.getInputStream().read()==73,"Android BCJSSE receives standard desktop TLS1.3 KeyUpdate");
                    mobile.getOutputStream().write(97);mobile.getOutputStream().flush();ok(pc.getInputStream().read()==97,"duplex data survives standard peer KeyUpdate response");
                    ok(AndroidVoiceTls.shortCode(android.offer(),android(desktop.offer())).equals(VoiceTls.shortCode(desktop(android.offer()),desktop.offer())),"security comparison code matches exact desktop offer context");
                    denied(()->AndroidVoiceTls.requestKeyUpdate(mobile),"unsupported manual BC KeyUpdate explicitly refused");
                    Socket replay=new Socket();denied(()->android.handshake(replay,android(desktop.offer()),BOB.publicKey(),androidCaller),"used Android TLS attempt cannot be replayed");ok(replay.isClosed(),"replayed attempt closes supplied transport");
                }
            }finally{jobs.shutdownNow();jobs.awaitTermination(3,TimeUnit.SECONDS);}
        }
    }
    private static void negative()throws Exception{
        UUID id=UUID.randomUUID();var grant=grant(ALICE,A);
        denied(()->AndroidVoiceTls.createDelegated(grant,B.getPrivate(),id,AndroidVoiceTls.Role.CALLER,BOB.publicKey(),AUDIENCE),"wrong app private key rejected before TLS");
        denied(()->AndroidVoiceTls.createDelegated(grant,A.getPrivate(),id,AndroidVoiceTls.Role.CALLER,BOB.publicKey(),"ff".repeat(32)),"wrong Identity audience rejected before TLS");
        try(var pending=AndroidVoiceTls.createDelegated(grant,A.getPrivate(),id,AndroidVoiceTls.Role.CALLER,BOB.publicKey(),AUDIENCE)){
            var o=pending.offer();long now=System.currentTimeMillis();
            denied(()->o.verify(MALLORY.publicKey(),BOB.publicKey(),id,AndroidVoiceTls.Role.CALLER,now,AUDIENCE),"wrong pinned account root rejected");
            denied(()->o.verify(ALICE.publicKey(),MALLORY.publicKey(),id,AndroidVoiceTls.Role.CALLER,now,AUDIENCE),"different recipient root rejected");
            denied(()->o.verify(ALICE.publicKey(),BOB.publicKey(),UUID.randomUUID(),AndroidVoiceTls.Role.CALLER,now,AUDIENCE),"call-context replay rejected");
            denied(()->o.verify(ALICE.publicKey(),BOB.publicKey(),id,AndroidVoiceTls.Role.CALLER,now+700000,AUDIENCE),"expired delegated offer rejected");
            byte[] signature=o.signature();signature[0]^=1;var changed=new AndroidVoiceTls.Offer(id,o.role(),o.callerId(),o.calleeId(),o.issuedAtMillis(),o.expiresAtMillis(),o.identityPublicKey(),o.certificate(),signature,o.delegation());
            denied(()->changed.verify(ALICE.publicKey(),BOB.publicKey(),id,AndroidVoiceTls.Role.CALLER,now,AUDIENCE),"actual modified offer app signature rejected");
            byte[] certificate=o.certificate();certificate[certificate.length-1]^=1;var badCert=new AndroidVoiceTls.Offer(id,o.role(),o.callerId(),o.calleeId(),o.issuedAtMillis(),o.expiresAtMillis(),o.identityPublicKey(),certificate,o.signature(),o.delegation());
            denied(()->badCert.verify(ALICE.publicKey(),BOB.publicKey(),id,AndroidVoiceTls.Role.CALLER,now,AUDIENCE),"modified ephemeral certificate rejected");
        }
        try(var mobile=AndroidVoiceTls.createDelegated(grant,A.getPrivate(),id,AndroidVoiceTls.Role.CALLER,BOB.publicKey(),AUDIENCE);var old=VoiceTls.create(BOB,id,VoiceTls.Role.CALLEE,ALICE.publicKey());var sockets=new Sockets()){
            denied(()->mobile.handshake(sockets.caller,android(old.offer()),BOB.publicKey(),true),"legacy TLS offer never downgrades Android v2 delegation");ok(sockets.caller.isClosed(),"downgrade rejection closes transport");
        }
        certificateSubstitution();
    }
    private static void certificateSubstitution()throws Exception{
        UUID id=UUID.randomUUID();
        try(var caller=AndroidVoiceTls.createDelegated(grant(ALICE,A),A.getPrivate(),id,AndroidVoiceTls.Role.CALLER,BOB.publicKey(),AUDIENCE);var actual=VoiceTls.createDelegated(grant(BOB,B),B.getPrivate(),id,VoiceTls.Role.CALLEE,ALICE.publicKey(),AUDIENCE);var advertised=VoiceTls.createDelegated(grant(BOB,B),B.getPrivate(),id,VoiceTls.Role.CALLEE,ALICE.publicKey(),AUDIENCE);var sockets=new Sockets()){
            ExecutorService jobs=Executors.newSingleThreadExecutor();try{Future<SSLSocket> server=jobs.submit(()->actual.handshake(sockets.callee,desktop(caller.offer()),ALICE.publicKey(),false));denied(()->caller.handshake(sockets.caller,android(advertised.offer()),BOB.publicKey(),true),"actual TLS certificate substitution fails exact advertised pin");try{server.get(5,TimeUnit.SECONDS);throw new AssertionError("substituted server accepted");}catch(ExecutionException expected){ok(true,"substituted desktop TLS endpoint receives fatal failure");}}finally{jobs.shutdownNow();jobs.awaitTermination(3,TimeUnit.SECONDS);}
        }
    }
}
