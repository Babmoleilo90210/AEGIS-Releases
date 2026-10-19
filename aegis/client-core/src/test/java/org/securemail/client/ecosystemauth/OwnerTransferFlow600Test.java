package org.securemail.client.ecosystemauth;

import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.identity.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real signed Identity HTTP/SQLite. Root keys below are independent generated test identities, not Mail exports. */
class OwnerTransferFlow600Test {
  @TempDir Path dir;
  @Test void actualThreeParticipantHttpTransferRevokesBothSessionsWithoutReplacingRootKeys()throws Exception{
    try(Fixture f=new Fixture()){
      byte[] old=f.owner.root.getPublic().getEncoded(),next=f.successor.root.getPublic().getEncoded();var request=f.owner.flow().prepare(f.successor.id());
      assertEquals(request.encode(),OwnerTransferFlow600.Request.parse(request.encode()).encode());assertArrayEquals(IdentityProtocol.ownerTransferBytes(request.transfer()),IdentityProtocol.ownerTransferBytes(f.successor.flow().inspect(request)));
      var first=f.owner.consent(request,OwnerTransferRole.OWNER_APPROVE);var second=f.successor.consent(request,OwnerTransferRole.SUCCESSOR_ACCEPT);
      assertEquals(second.encode(),OwnerTransferFlow600.Consent.parse(second.encode()).encode());
      assertThrows(java.io.IOException.class,()->f.owner.flow().complete(first,second));f.administrator.flow().approve(request);f.owner.flow().complete(first,second);
      assertEquals(false,f.store.profile(f.owner.id()).get("ownerBadge"));assertEquals("Обычный пользователь",f.store.profile(f.owner.id()).get("systemRole"));assertEquals(true,f.store.profile(f.successor.id()).get("ownerBadge"));
      assertFalse(f.client.isActive(firstCap(f.owner)));assertFalse(f.client.isActive(firstCap(f.successor)));assertTrue(f.client.isActive(firstCap(f.administrator)));
      assertArrayEquals(old,f.owner.session.accountPublic());assertArrayEquals(next,f.successor.session.accountPublic());assertTrue(f.store.verifyAudit());assertThrows(java.io.IOException.class,()->f.owner.flow().complete(first,second));
    }
  }
  @Test void exchangedCanonicalPayloadCannotApproveDifferentPermitOrConfuseConsentRole()throws Exception{
    try(Fixture f=new Fixture()){
      var request=f.owner.flow().prepare(f.successor.id());var t=request.transfer();var changed=new OwnerTransfer(t.audience,t.challenge,t.ownerAccountId,t.ownerDeviceId,t.ownerGeneration,t.targetAccountId,t.targetDeviceId,t.targetGeneration,t.authorityEpoch+1,t.expiresAt);
      var other=new OwnerTransferFlow600.Request(changed,request.requestId(),request.criticalExpiresAt());assertThrows(java.io.IOException.class,()->f.administrator.flow().approve(other));assertThrows(java.io.IOException.class,()->f.successor.flow().inspect(other));
      assertThrows(java.io.IOException.class,()->f.successor.session.signOwnerTransferConsent(t,OwnerTransferRole.OWNER_APPROVE));
      assertThrows(java.io.IOException.class,()->f.successor.flow().consent(request,OwnerTransferRole.SUCCESSOR_ACCEPT,IdentityProtocol.sign(f.successor.root.getPrivate(),IdentityProtocol.ownerTransferConsent(t,OwnerTransferRole.OWNER_APPROVE))));
      f.administrator.flow().approve(request);f.owner.flow().complete(f.owner.consent(request,OwnerTransferRole.OWNER_APPROVE),f.successor.consent(request,OwnerTransferRole.SUCCESSOR_ACCEPT));assertEquals(true,f.store.profile(f.successor.id()).get("ownerBadge"));
    }
  }
  @Test void publicExchangeRejectsDuplicateUnknownTypesAndOversizedFields()throws Exception{
    try(Fixture f=new Fixture()){
      String code=f.owner.flow().prepare(f.successor.id()).encode();assertThrows(java.io.IOException.class,()->OwnerTransferFlow600.Request.parse(code.replace("\"schema\":1","\"schema\":1,\"schema\":1")));assertThrows(java.io.IOException.class,()->OwnerTransferFlow600.Request.parse(code.replace("\"schema\":1","\"schema\":\"1\"")));assertThrows(java.io.IOException.class,()->OwnerTransferFlow600.Request.parse(code.replace("\"schema\":1","\"schema\":1,\"extra\":1")));assertThrows(java.io.IOException.class,()->OwnerTransferFlow600.Request.parse(" ".repeat(8193)));assertThrows(java.io.IOException.class,()->OwnerTransferFlow600.Request.parse(code+" {}"));
    }
  }
  @Test void localTypedDeviceSignerRejectsChangedAudienceGenerationAndLock()throws Exception{
    try(Fixture f=new Fixture()){
      var t=f.owner.flow().prepare(f.successor.id()).transfer();var changed=new OwnerTransfer(t.audience,t.challenge,t.ownerAccountId,t.ownerDeviceId,t.ownerGeneration+1,t.targetAccountId,t.targetDeviceId,t.targetGeneration,t.authorityEpoch,t.expiresAt);assertThrows(java.io.IOException.class,()->f.owner.session.signOwnerTransferConsent(changed,OwnerTransferRole.OWNER_APPROVE));
      byte[] signed=f.owner.session.signOwnerTransferConsent(t,OwnerTransferRole.OWNER_APPROVE);assertTrue(IdentityProtocol.verify(f.owner.device.getPublic().getEncoded(),IdentityProtocol.ownerTransferConsent(t,OwnerTransferRole.OWNER_APPROVE),signed));f.owner.session.lock();assertThrows(java.io.IOException.class,()->f.owner.session.signOwnerTransferConsent(t,OwnerTransferRole.OWNER_APPROVE));
    }
  }
  @Test void targetGenerationRevocationBlocksLateMailConsent()throws Exception{
    try(Fixture f=new Fixture()){
      var r=f.owner.flow().prepare(f.successor.id());byte[] root=IdentityProtocol.sign(f.successor.root.getPrivate(),IdentityProtocol.ownerTransferConsent(r.transfer(),OwnerTransferRole.SUCCESSOR_ACCEPT));
      try(var newer=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),f.successor.credentials())){newer.login();assertThrows(java.io.IOException.class,()->f.successor.flow().consent(r,OwnerTransferRole.SUCCESSOR_ACCEPT,root));}assertEquals(true,f.store.profile(f.owner.id()).get("ownerBadge"));
    }
  }
  static String firstCap(Person p)throws Exception{return p.session.coreGrant().wire();}
  static KeyPair key()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
  final class Fixture implements AutoCloseable{
    final KeyPair service=key();final IdentityStore store;final IdentityHttpServer http;final IdentityClient600 client;final Person owner,administrator,successor;
    Fixture()throws Exception{
      store=new IdentityStore(dir.resolve(UUID.randomUUID()+".db"),service,new byte[32],Clock.systemUTC());http=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),store,service);http.start();client=new IdentityClient600("a".repeat(56)+".onion",80,service.getPublic().getEncoded(),(host,port,observer)->{Socket s=new Socket();observer.opened(s);s.connect(new InetSocketAddress("127.0.0.1",http.port()));return s;},Clock.systemUTC());
      owner=new Person(this);administrator=new Person(this);successor=new Person(this);var c=store.ownerChallenge(owner.id());store.bootstrapOwner(owner.id(),c.challenge(),IdentityProtocol.sign(owner.root.getPrivate(),IdentityProtocol.ownerBootstrap(client.audience(),owner.id(),c.challenge(),c.expiresAt())));owner.relogin();owner.step();
      var grant=owner.session.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ,Scope.ADMIN));long now=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] proposal=IdentityProtocol.firstDelegateProposal(client.audience(),owner.id(),administrator.id(),"Первый оператор",now,nonce);var d=store.firstDelegateChallenge(grant.capability(),administrator.id(),"Первый оператор",now,nonce,IdentityProtocol.sign(grant.proofPrivate(),IdentityProtocol.requestDigest(grant.capability(),"admin.execute",IdentityProtocol.digest(proposal),now,nonce)));byte[] bytes=IdentityProtocol.unb64((String)d.get("proofBytes"),2048);store.completeFirstDelegation((String)d.get("challenge"),IdentityProtocol.sign(owner.root.getPrivate(),bytes),IdentityProtocol.sign(owner.device.getPrivate(),bytes),IdentityProtocol.sign(administrator.root.getPrivate(),bytes),IdentityProtocol.sign(administrator.device.getPrivate(),bytes));administrator.relogin();owner.step();administrator.step();successor.step();
    }
    public void close()throws Exception{owner.close();administrator.close();successor.close();client.close();http.close();store.close();}
  }
  static final class Person implements AutoCloseable{
    final Fixture f;final KeyPair root=key(),device=key(),recovery=key();CoreAccountSession600 session;
    Person(Fixture f)throws Exception{this.f=f;session=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),credentials());long now=System.currentTimeMillis();String n=IdentityProtocol.nonce();session.register("Участник",now,n,IdentityProtocol.sign(root.getPrivate(),IdentityProtocol.registration(f.client.audience(),root.getPublic().getEncoded(),device.getPublic().getEncoded(),recovery.getPublic().getEncoded(),"Участник",now,n)));}
    String id(){return IdentityProtocol.id(root.getPublic().getEncoded());}DeviceCredentials600 credentials(){return new DeviceCredentials600(root.getPublic().getEncoded(),device,recovery.getPublic().getEncoded());}
    void relogin()throws Exception{session.close();session=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),credentials());session.login();}
    void step()throws Exception{var c=f.store.stepUpChallenge(session.accountId(),session.deviceId(),session.generation());session.completeStepUp(c.challenge(),c.expiresAt(),IdentityProtocol.sign(root.getPrivate(),IdentityProtocol.stepUp(f.client.audience(),session.accountId(),session.deviceId(),c.challenge(),c.expiresAt())));}
    OwnerTransferFlow600 flow(){return new OwnerTransferFlow600(f.client,session);}OwnerTransferFlow600.Consent consent(OwnerTransferFlow600.Request r,OwnerTransferRole role)throws Exception{return flow().consent(r,role,IdentityProtocol.sign(root.getPrivate(),IdentityProtocol.ownerTransferConsent(r.transfer(),role)));}public void close(){session.close();}
  }
}
