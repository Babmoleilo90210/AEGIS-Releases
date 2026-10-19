package org.aegis.android;
import java.io.*;
import java.security.*;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
/** Pure configuration/listener/typed-proof checks; they are not native Tor or Android Binder tests. */
public final class TorRuntimePolicyTest {
  private static int n;interface Test {void run()throws Exception;}static void t(String name,Test x)throws Exception{x.run();System.out.println("PASS_LOCAL "+name);n++;}static void yes(boolean b){if(!b)throw new AssertionError();}static void deny(Test x)throws Exception{try{x.run();}catch(IOException|IllegalArgumentException expected){return;}throw new AssertionError("Expected denial");}
  public static void main(String[] args)throws Exception {
    String complete="NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=Done",ports="\"127.0.0.1:41001\" \"127.0.0.1:41002\" \"127.0.0.1:41003\"";
    t("Tor-three-loopback-contexts",()->yes(Arrays.equals(TorRuntimePolicy.ports(complete,ports),new int[]{41001,41002,41003})));
    t("Tor-incomplete-bootstrap-never-ready",()->yes(TorRuntimePolicy.ports("PROGRESS=99",ports).length==0));
    t("Tor-prefix-progress-not-ready",()->yes(TorRuntimePolicy.ports("PROGRESS=1000",ports).length==0));
    t("Tor-nonloopback-denied",()->deny(()->TorRuntimePolicy.ports(complete,ports.replace("127.0.0.1","0.0.0.0"))));
    t("Tor-duplicate-port-denied",()->deny(()->TorRuntimePolicy.ports(complete,ports.replace("41003","41001"))));
    t("Tor-extra-listener-denied",()->deny(()->TorRuntimePolicy.ports(complete,ports+" \"127.0.0.1:41004\"")));
    t("Tor-control-injection-denied",()->deny(()->TorRuntimePolicy.ports(complete,ports+"\nControlPort 9051")));
    t("Tor-listener-quota",()->deny(()->TorRuntimePolicy.ports(complete,"x".repeat(513))));
    t("Tor-fixed-no-DNS-HTTP-control-listener",()->{String c=TorRuntimePolicy.CONFIG;yes(c.contains("DNSPort 0\n")&&c.contains("HTTPTunnelPort 0\n")&&!c.contains("ControlPort")&&!c.contains("DisableNetwork 0"));yes(c.lines().filter(v->v.startsWith("SocksPort auto IPv4Only SessionGroup=")).count()==3);});
    KeyPairGenerator g=KeyPairGenerator.getInstance("Ed25519");KeyPair key=g.generateKeyPair();String id=IdentityProtocol.id(key.getPublic().getEncoded());long now=System.currentTimeMillis();IdentityProtocol.Capability cap=new IdentityProtocol.Capability(id,id,id,IdentityProtocol.App.GLAS,1,IdentityProtocol.nonce(),now,now+60000,now+60000,key.getPublic().getEncoded(),EnumSet.of(IdentityProtocol.Scope.VOICE_CALL),new byte[64]);String nonce=IdentityProtocol.nonce();byte[] b=VoiceEndpointProof.canonical(cap,41001,nonce),sig=IdentityProtocol.sign(key.getPrivate(),b);
    t("endpoint-proof-real-Ed25519",()->yes(IdentityProtocol.verify(key.getPublic().getEncoded(),b,sig)));
    t("endpoint-proof-port-bound",()->yes(!IdentityProtocol.verify(key.getPublic().getEncoded(),VoiceEndpointProof.canonical(cap,41002,nonce),sig)));
    t("endpoint-proof-nonce-bound",()->yes(!IdentityProtocol.verify(key.getPublic().getEncoded(),VoiceEndpointProof.canonical(cap,41001,IdentityProtocol.nonce()),sig)));
    t("endpoint-proof-invalid-port",()->deny(()->VoiceEndpointProof.canonical(cap,0,nonce)));
    t("endpoint-proof-other-app-denied",()->{IdentityProtocol.Capability mail=new IdentityProtocol.Capability(id,id,id,IdentityProtocol.App.MAIL,1,IdentityProtocol.nonce(),now,now+60000,now+60000,key.getPublic().getEncoded(),EnumSet.of(IdentityProtocol.Scope.MAIL_READ),new byte[64]);deny(()->VoiceEndpointProof.canonical(mail,41001,nonce));});
    System.out.println("TorRuntimePolicyTest: "+n+" PASS_LOCAL; native Tor/Binder/ARM64 NOT_RUN");
  }
}
