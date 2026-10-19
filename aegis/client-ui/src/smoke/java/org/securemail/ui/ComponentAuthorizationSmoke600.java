package org.securemail.ui;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.securemail.client.ecosystem.*;
import org.securemail.client.voice600.GlasGrant600;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;
import org.securemail.ui.ecosystem.ComponentHost;

/** Actual production component host signature/pin validation; local signed fixtures, no server/Tor/native acceptance claim. */
public final class ComponentAuthorizationSmoke600 {
  private ComponentAuthorizationSmoke600(){}
  @FunctionalInterface private interface Check{void run()throws Exception;}
  private static int checks;
  private static void pass(Check action)throws Exception{action.run();checks++;}
  private static void denied(Check action)throws Exception{try{action.run();throw new AssertionError("Untrusted component authorization was accepted");}catch(IOException expected){checks++;}}
  private static IdentityProtocol.Capability capability(KeyPair service,KeyPair account,KeyPair app,IdentityProtocol.App id,long generation)throws Exception{long now=System.currentTimeMillis();var cap=new IdentityProtocol.Capability(IdentityProtocol.id(service.getPublic().getEncoded()),IdentityProtocol.id(account.getPublic().getEncoded()),"cd".repeat(32),id,generation,IdentityProtocol.nonce(),now-1000,now+120000,now+120000,app.getPublic().getEncoded(),IdentityProtocol.allowed(id),new byte[0]);return cap.signed(IdentityProtocol.sign(service.getPrivate(),IdentityProtocol.capabilityBytes(cap)));}
  private static ComponentLease lease(ComponentId id,IdentityProtocol.Capability cap,KeyPair app,byte[] auxiliary){return new ComponentLease(id,cap.accountId,cap.generation,IdentityProtocol.encodeCapability(cap).getBytes(StandardCharsets.US_ASCII),app.getPrivate().getEncoded(),app.getPublic().getEncoded(),auxiliary);}
  public static void main(String[] args)throws Exception{
    Path profile=Files.createTempDirectory("aegis-host-auth600-");System.setProperty("aegis.profile",profile.toString());KeyPairGenerator generator=KeyPairGenerator.getInstance("Ed25519");KeyPair service=generator.generateKeyPair(),otherService=generator.generateKeyPair(),account=generator.generateKeyPair(),app=generator.generateKeyPair(),wrongApp=generator.generateKeyPair();
    Properties config=new Properties();config.setProperty("identityOnion","a".repeat(56)+".onion");config.setProperty("identityPort","80");config.setProperty("identityPublicKey",IdentityProtocol.b64(service.getPublic().getEncoded()));config.setProperty("socksPort","19350");Files.createDirectories(profile.resolve("core600"));try(OutputStream out=Files.newOutputStream(profile.resolve("core600/identity.properties"))){config.store(out,"PUBLIC TEST FIXTURE");}
    var mail=capability(service,account,app,IdentityProtocol.App.MAIL,1);var mailHost=new LegacyMailComponentHost600();pass(()->mailHost.verifyAuthorization(lease(ComponentId.MAIL,mail,app,new byte[0])));denied(()->mailHost.verifyAuthorization(lease(ComponentId.MAIL,mail,wrongApp,new byte[0])));denied(()->mailHost.verifyAuthorization(lease(ComponentId.MAIL,mail,app,new byte[]{1})));denied(()->mailHost.verifyAuthorization(lease(ComponentId.GLAS,mail,app,new byte[0])));denied(()->mailHost.verifyAuthorization(new ComponentLease(ComponentId.MAIL,mail.accountId,mail.generation,IdentityProtocol.encodeCapability(mail).getBytes(StandardCharsets.US_ASCII))));denied(()->mailHost.verifyAuthorization(new ComponentLease(ComponentId.MAIL,mail.accountId,mail.generation+1,IdentityProtocol.encodeCapability(mail).getBytes(StandardCharsets.US_ASCII),app.getPrivate().getEncoded(),app.getPublic().getEncoded())));denied(()->mailHost.verifyAuthorization(lease(ComponentId.MAIL,capability(otherService,account,app,IdentityProtocol.App.MAIL,1),app,new byte[0])));denied(()->mailHost.verifyAuthorization(lease(ComponentId.MAIL,mail,account,new byte[0])));
    var voice=capability(service,account,app,IdentityProtocol.App.GLAS,1);long now=System.currentTimeMillis();var d=new GlasProtocol600.Delegation(voice.audience,account.getPublic().getEncoded(),voice.deviceId,voice.generation,app.getPublic().getEncoded(),now,voice.expiresAt,IdentityProtocol.nonce(),new byte[64]);d=d.signed(IdentityProtocol.sign(account.getPrivate(),d.signingBytes()));var unsigned=new GlasGrant600(d,List.of(),new byte[64]);var grant=unsigned.signed(IdentityProtocol.sign(account.getPrivate(),unsigned.signingBytes()));var glasHost=new StandaloneGlasComponentHost600();pass(()->glasHost.verifyAuthorization(lease(ComponentId.GLAS,voice,app,grant.encode())));denied(()->glasHost.verifyAuthorization(lease(ComponentId.GLAS,voice,wrongApp,grant.encode())));denied(()->glasHost.verifyAuthorization(lease(ComponentId.MAIL,voice,app,grant.encode())));denied(()->glasHost.verifyAuthorization(lease(ComponentId.GLAS,voice,app,new byte[0])));denied(()->glasHost.verifyAuthorization(lease(ComponentId.GLAS,voice,account,grant.encode())));byte[] changed=grant.encode();changed[changed.length-1]^=1;denied(()->glasHost.verifyAuthorization(lease(ComponentId.GLAS,voice,app,changed)));denied(()->glasHost.verifyAuthorization(new ComponentLease(ComponentId.GLAS,"ff".repeat(32),1,IdentityProtocol.encodeCapability(voice).getBytes(StandardCharsets.US_ASCII),app.getPrivate().getEncoded(),app.getPublic().getEncoded(),grant.encode())));
    var hosts=ServiceLoader.load(ComponentHost.class).stream().map(ServiceLoader.Provider::get).toList();for(ComponentId id:ComponentId.values()){long count=hosts.stream().filter(host->host.supports(id)).count();if(count!=(id==ComponentId.USER_DAEMON?0:1))throw new AssertionError("Installed provider selection is ambiguous");checks++;}
    System.out.println("PASS: "+checks+" actual Mail/Glas provider authorization and installed-service checks. Scope=local signed fixtures; live Identity/Tor/native NOT_RUN.");
  }
}
