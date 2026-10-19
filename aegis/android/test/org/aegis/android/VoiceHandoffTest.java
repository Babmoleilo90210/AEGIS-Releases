package org.aegis.android;
import java.io.*;
import java.security.*;
import java.util.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.voice600.GlasGrant600;
import org.securemail.glas.protocol600.GlasProtocol600;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Production public-carrier policy with real signed caps/delegations. Native Binder tests remain NOT_RUN. */
public final class VoiceHandoffTest {
    private static int passed;private static long now;private static KeyPair server,app;private static Identity root;
    private interface Checked{void run()throws Exception;}
    private static void ok(boolean value,String name){if(!value)throw new AssertionError(name);passed++;System.out.println("PASS "+name);}
    private static void denied(Checked action,String name)throws Exception{try{action.run();throw new AssertionError("Accepted "+name);}catch(SecurityException|IllegalArgumentException|IOException expected){passed++;System.out.println("PASS "+name);}}
    private static IdentityProtocol.Capability cap(IdentityProtocol.App kind,long gen){Set<IdentityProtocol.Scope> scopes=kind==IdentityProtocol.App.GLAS?EnumSet.of(IdentityProtocol.Scope.VOICE_CALL,IdentityProtocol.Scope.CONTACTS_READ):kind==IdentityProtocol.App.MAIL?EnumSet.of(IdentityProtocol.Scope.MAIL_READ,IdentityProtocol.Scope.MAIL_SEND,IdentityProtocol.Scope.CONTACTS_READ):EnumSet.of(IdentityProtocol.Scope.ACCOUNT_READ);var c=new IdentityProtocol.Capability(IdentityProtocol.id(server.getPublic().getEncoded()),root.userId(),"cd".repeat(32),kind,gen,IdentityProtocol.nonce(),now-1000,now+600000,now+600000,app.getPublic().getEncoded(),scopes,new byte[0]);return c.signed(IdentityProtocol.sign(server.getPrivate(),IdentityProtocol.capabilityBytes(c)));}
    private static byte[] grant(IdentityProtocol.Capability cap,String id)throws Exception {var d=new GlasProtocol600.Delegation(cap.audience,root.publicKey(),cap.deviceId,cap.generation,cap.proofKey,now,cap.expiresAt,id,new byte[64]);d=d.signed(root.sign(d.signingBytes()));var g=new GlasGrant600(d,List.of(),new byte[64]);return g.signed(root.sign(g.signingBytes())).encode();}
    public static void main(String[] args)throws Exception {
        now=System.currentTimeMillis();server=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();app=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();root=Identity.create();byte[] pin=server.getPublic().getEncoded();var glas=cap(IdentityProtocol.App.GLAS,1);var mail=cap(IdentityProtocol.App.MAIL,1);var core=cap(IdentityProtocol.App.AEGIS,1);String wire=IdentityProtocol.encodeCapability(glas);VoiceHandoff h=new VoiceHandoff();String request=h.stage(wire,core,pin,now,1000);
        ok(request.length()==43&&h.pending(mail,pin,now,1001).equals(request+"\n"+wire),"typed pending cap exposed only under matching Mail session");
        denied(()->h.pending(glas,pin,now,1002),"Glas cannot approve its own account delegation");
        denied(()->h.stage(wire,core,pin,now,1002),"bounded carrier rejects overlapping pending request");
        denied(()->h.pending(cap(IdentityProtocol.App.MAIL,2),pin,now,1002),"new generation cannot consume old pending grant");
        denied(()->h.deliver(IdentityProtocol.nonce(),grant(glas,request),mail,pin,now,1003),"different request nonce denied");
        byte[] approved=grant(glas,request);h.deliver(request,approved,mail,pin,now,1004);
        denied(()->h.deliver(request,approved,mail,pin,now,1005),"duplicate Mail grant delivery rejected");
        denied(()->h.receive(mail,pin,now,1005),"Mail cannot retrieve delegated Glas response");
        denied(()->h.receive(cap(IdentityProtocol.App.GLAS,1),pin,now,1005),"replacement Glas token cannot consume earlier token request");
        byte[] delivered=h.receive(glas,pin,now,1006);ok(MessageDigest.isEqual(approved,delivered),"exact bounded public grant delivered to original Glas token once");
        denied(()->h.receive(glas,pin,now,1007),"retrieval clears carrier and cannot be replayed");
        String fresh=h.stage(wire,core,pin,now,2000);byte[] altered=grant(glas,fresh);altered[altered.length-1]^=1;
        denied(()->h.deliver(fresh,altered,mail,pin,now,2001),"modified public contact/root signature rejected");
        denied(()->h.deliver(fresh,new byte[65537],mail,pin,now,2001),"public carrier enforces 64KiB limit");
        denied(()->h.deliver(fresh,approved,mail,pin,now,2001),"old delegation cannot be replayed into new request nonce");
        h.clear();denied(()->h.pending(mail,pin,now,2002),"explicit lock/revoke clears pending public data");
        h.stage(wire,core,pin,now,3000);h.expire(63000);denied(()->h.pending(mail,pin,now,63000),"monotonic timeout clears carrier");
        h.stage(wire,core,pin,now,4000);denied(()->h.pending(mail,pin,now,3999),"elapsed-time rollback clears carrier");
        denied(()->VoiceHandoff.voiceCapability(IdentityProtocol.encodeCapability(mail),core,pin,now),"Mail cap cannot be substituted for voice cap");
        denied(()->VoiceHandoff.validateGrant(approved,cap(IdentityProtocol.App.GLAS,2),pin,request,now),"root grant is generation bound");
        denied(()->VoiceHandoff.validateGrant(approved,glas,KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded(),request,now),"wrong Identity authority fails capability verification");
        denied(()->VoiceHandoff.validateGrant(approved,glas,pin,request,now+700000),"expired voice grant denied");
        ok(!Arrays.equals(AndroidPolicy.proof(AndroidPolicy.MAIL,request,app.getPublic().getEncoded(),12),AndroidPolicy.proof(AndroidPolicy.GLAS,request,app.getPublic().getEncoded(),13)),"new Binder operations remain package and operation bound");
        System.out.println("RESULT "+passed+" PASS; actual Binder UID/certificate/platform races NOT_RUN");
    }
}
