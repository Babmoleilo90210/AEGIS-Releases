package org.securemail.client.ecosystemauth;

import com.google.gson.*;
import java.net.*;import java.nio.file.*;import java.security.*;import java.time.*;import java.util.*;
import org.junit.jupiter.api.*;import org.junit.jupiter.api.io.TempDir;
import org.securemail.identity.*;import org.securemail.ecosystem.protocol.IdentityProtocol;import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import static org.junit.jupiter.api.Assertions.*;

/** Actual public client exchange over signed HTTP, with generated root proofs standing in for independent Mail consent. */
class AuthoritySetupFlow600Test {
 @TempDir Path dir;
 static KeyPair key()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
 @Test void operatorBootstrapAndTypedFirstDelegationCompleteWithoutExportingRootKeys()throws Exception{
  try(Fixture f=new Fixture()){
   var challenge=f.store.ownerChallenge(f.owner.id());OwnerBootstrap b=new OwnerBootstrap(f.client.audience(),f.owner.id(),challenge.challenge(),challenge.expiresAt());String document=new Gson().toJson(Map.of("type","AEGIS-OWNER-BOOTSTRAP/v1","audience",b.audience,"accountId",b.accountId,"challenge",b.challenge,"expiresAt",b.expiresAt,"proofBytes",IdentityProtocol.b64(IdentityProtocol.ownerBootstrapBytes(b)),"bootstrap",IdentityProtocol.b64(IdentityProtocol.ownerBootstrapBytes(b))));
   var bootstrap=new OwnerBootstrapFlow600(f.client,f.owner.session);assertArrayEquals(IdentityProtocol.ownerBootstrapBytes(b),IdentityProtocol.ownerBootstrapBytes(bootstrap.inspect(OwnerBootstrapFlow600.parse(document))));
   assertThrows(java.io.IOException.class,()->new OwnerBootstrapFlow600(f.client,f.delegate.session).inspect(b));assertThrows(java.io.IOException.class,()->bootstrap.publicCliProof(b,new byte[64]));String proof=bootstrap.publicCliProof(b,IdentityProtocol.sign(f.owner.root.getPrivate(),IdentityProtocol.ownerBootstrapBytes(b)));JsonObject publicProof=JsonParser.parseString(proof).getAsJsonObject();assertEquals(Set.of("audience","accountId","challenge","signature"),publicProof.keySet());
   f.store.bootstrapOwner(b.accountId,b.challenge,IdentityProtocol.unb64(publicProof.get("signature").getAsString(),64));assertThrows(java.io.IOException.class,()->bootstrap.inspect(b));f.owner.relogin();f.owner.step();
   var first=new FirstDelegationFlow600(f.client,f.owner.session);var target=new FirstDelegationFlow600(f.client,f.delegate.session);var request=first.prepare(f.delegate.id(),"Оператор безопасности");assertEquals(request.encode(),FirstDelegationFlow600.Request.parse(request.encode()).encode());assertArrayEquals(IdentityProtocol.firstDelegationBytes(request.delegation()),IdentityProtocol.firstDelegationBytes(target.inspect(request)));
   var d=request.delegation();byte[] payload=IdentityProtocol.firstDelegationBytes(d);var owner=first.consent(request,FirstDelegateRole.OWNER_APPROVE,IdentityProtocol.sign(f.owner.root.getPrivate(),payload));var delegate=target.consent(request,FirstDelegateRole.DELEGATE_ACCEPT,IdentityProtocol.sign(f.delegate.root.getPrivate(),payload));assertEquals(delegate.encode(),FirstDelegationFlow600.Consent.parse(delegate.encode()).encode());
   assertThrows(java.io.IOException.class,()->f.delegate.session.signFirstDelegationConsent(d,FirstDelegateRole.OWNER_APPROVE));assertThrows(java.io.IOException.class,()->first.complete(owner,owner));first.complete(owner,delegate);assertEquals(false,f.store.profile(f.delegate.id()).get("ownerBadge"));assertEquals(true,f.store.profile(f.delegate.id()).get("delegatedAdministrator"));assertThrows(java.io.IOException.class,()->first.prepare(f.delegate.id(),"Повтор"));
   f.delegate.relogin();f.delegate.step();assertTrue(f.delegate.session.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ,Scope.ADMIN)).capability().capabilities.contains(Scope.ADMIN));assertTrue(f.store.verifyAudit());
  }
 }
 @Test void bootstrapParserAndTypedConsentRejectAmbiguousOrDifferentRequests()throws Exception{
  try(Fixture f=new Fixture()){
   var c=f.store.ownerChallenge(f.owner.id());var b=new OwnerBootstrap(f.client.audience(),f.owner.id(),c.challenge(),c.expiresAt());String doc=new Gson().toJson(Map.of("type","AEGIS-OWNER-BOOTSTRAP/v1","audience",b.audience,"accountId",b.accountId,"challenge",b.challenge,"expiresAt",b.expiresAt,"proofBytes",IdentityProtocol.b64(IdentityProtocol.ownerBootstrapBytes(b)),"bootstrap",IdentityProtocol.b64(IdentityProtocol.ownerBootstrapBytes(b))));
   assertThrows(java.io.IOException.class,()->OwnerBootstrapFlow600.parse(doc.replace("\"type\":","\"type\":\"wrong\",\"type\":")));assertThrows(java.io.IOException.class,()->OwnerBootstrapFlow600.parse(doc.replace(b.accountId,f.delegate.id())));assertThrows(java.io.IOException.class,()->OwnerBootstrapFlow600.parse(doc+" {}"));f.owner.session.lock();assertThrows(java.io.IOException.class,()->new OwnerBootstrapFlow600(f.client,f.owner.session).inspect(b));
  }
 }
 final class Fixture implements AutoCloseable{
  final KeyPair service=key();final IdentityStore store;final IdentityHttpServer http;final IdentityClient600 client;final Person owner,delegate;
  Fixture()throws Exception{store=new IdentityStore(dir.resolve(UUID.randomUUID()+".db"),service,new byte[32],Clock.systemUTC());http=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),store,service);http.start();client=new IdentityClient600("a".repeat(56)+".onion",80,service.getPublic().getEncoded(),(host,port,observer)->{Socket s=new Socket();observer.opened(s);s.connect(new InetSocketAddress("127.0.0.1",http.port()));return s;},Clock.systemUTC());owner=new Person(this);delegate=new Person(this);}
  public void close()throws Exception{owner.session.close();delegate.session.close();client.close();http.close();store.close();}
 }
 static final class Person{
  final Fixture f;final KeyPair root=key(),device=key(),recovery=key();CoreAccountSession600 session;
  Person(Fixture f)throws Exception{this.f=f;session=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),credentials());long t=System.currentTimeMillis();String n=IdentityProtocol.nonce();session.register("Участник",t,n,IdentityProtocol.sign(root.getPrivate(),IdentityProtocol.registration(f.client.audience(),root.getPublic().getEncoded(),device.getPublic().getEncoded(),recovery.getPublic().getEncoded(),"Участник",t,n)));}
  String id(){return IdentityProtocol.id(root.getPublic().getEncoded());}DeviceCredentials600 credentials(){return new DeviceCredentials600(root.getPublic().getEncoded(),device,recovery.getPublic().getEncoded());}
  void relogin()throws Exception{session.close();session=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),credentials());session.login();}
  void step()throws Exception{var c=f.store.stepUpChallenge(session.accountId(),session.deviceId(),session.generation());session.completeStepUp(c.challenge(),c.expiresAt(),IdentityProtocol.sign(root.getPrivate(),IdentityProtocol.stepUp(f.client.audience(),session.accountId(),session.deviceId(),c.challenge(),c.expiresAt())));}
 }
}
