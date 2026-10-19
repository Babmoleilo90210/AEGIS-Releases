package org.securemail.client.ecosystemauth;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.identity.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import org.securemail.ecosystem.protocol.IdentityAdministrationProtocol600.Operation;
import static org.junit.jupiter.api.Assertions.*;

/** Actual signed HTTP/SQLite Identity exchange. Generated test root signatures stand in for separate Mail consent. */
class IdentityAdministrationFlow600Test {
 @TempDir Path dir;
 static KeyPair pair()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
 @Test void assignmentAndRevocationUseTheSamePersistedTwoAdminPermit()throws Exception{try(Fixture f=new Fixture()){
  f.owner.step();f.reviewer.step();var first=f.owner.flow();var second=f.reviewer.flow();var permit=first.prepare(Operation.ASSIGN,f.target.id(),"Смотритель");assertEquals(permit,IdentityAdministrationFlow600.Permit.parse(permit.encode()));assertThrows(IOException.class,()->first.execute(permit));assertThrows(IOException.class,()->first.approve(permit));second.approve(permit);first.execute(permit);assertEquals(true,f.store.profile(f.target.id()).get("delegatedAdministrator"));assertEquals("Смотритель",f.store.profile(f.target.id()).get("delegatedRoleName"));assertThrows(IOException.class,()->first.execute(permit));
  f.target.relogin();f.target.step();var targetAdmin=f.target.session.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ,Scope.ADMIN));var revoke=first.prepare(Operation.REVOKE,f.target.id(),"");second.approve(revoke);first.execute(revoke);assertFalse(f.store.isActive(targetAdmin.capability()));assertEquals(false,f.store.profile(f.target.id()).get("delegatedAdministrator"));assertThrows(IOException.class,()->f.target.flow().prepare(Operation.ASSIGN,f.reviewer.id(),"Подмена"));assertTrue(f.store.verifyAudit());
 }}
 @Test void changedTargetInitiatorOperationAndExpiryAreRejectedBeforeApproval()throws Exception{try(Fixture f=new Fixture()){
  f.owner.step();f.reviewer.step();var permit=f.owner.flow().prepare(Operation.ASSIGN,f.target.id(),"Редактор");JsonObject o=com.google.gson.JsonParser.parseString(permit.encode()).getAsJsonObject();o.addProperty("targetAccountId",f.reviewer.id());o.addProperty("payloadSha256",IdentityProtocol.b64(IdentityProtocol.digest(IdentityProtocol.administratorAssignment(f.reviewer.id(),"Редактор"))));var changed=IdentityAdministrationFlow600.Permit.parse(o.toString());assertThrows(IOException.class,()->f.reviewer.flow().approve(changed));
  o=com.google.gson.JsonParser.parseString(permit.encode()).getAsJsonObject();o.addProperty("initiatorAccountId",f.target.id());var wrongInitiator=IdentityAdministrationFlow600.Permit.parse(o.toString());assertThrows(IOException.class,()->f.reviewer.flow().inspect(wrongInitiator));
  o=com.google.gson.JsonParser.parseString(permit.encode()).getAsJsonObject();o.addProperty("expiresAt",permit.expiresAt()-1);var wrongExpiry=IdentityAdministrationFlow600.Permit.parse(o.toString());assertThrows(IOException.class,()->f.reviewer.flow().approve(wrongExpiry));f.reviewer.flow().approve(permit);f.owner.flow().execute(permit);
 }}
 @Test void actualRecoveryApprovalLiftsOnlyThePendingSensitiveRestriction()throws Exception{try(Fixture f=new Fixture()){
  var prior=f.target.session.grant(App.LIBRARY,Set.of(Scope.LIBRARY_READ));KeyPair next=pair();long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();var challenge=f.store.challengeDevice(f.target.id(),next.getPublic().getEncoded(),time,nonce,IdentityProtocol.sign(next.getPrivate(),IdentityProtocol.login(f.client.audience(),f.target.id(),IdentityProtocol.id(next.getPublic().getEncoded()),time,nonce)));byte[] payload=IdentityProtocol.recovery(f.client.audience(),f.target.id(),challenge.challenge(),next.getPublic().getEncoded(),challenge.expiresAt());f.store.recoverDevice(f.target.id(),challenge.challenge(),IdentityProtocol.sign(f.target.root.getPrivate(),payload),IdentityProtocol.sign(f.target.recovery.getPrivate(),payload));assertFalse(f.store.isActive(prior.capability()));
  try(var recovered=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),new DeviceCredentials600(f.target.root.getPublic().getEncoded(),next,f.target.recovery.getPublic().getEncoded()))){recovered.login();assertThrows(IOException.class,()->recovered.grant(App.LIBRARY,Set.of(Scope.LIBRARY_READ)));f.owner.step();f.reviewer.step();var request=f.owner.flow().prepare(Operation.APPROVE_RECOVERY,f.target.id(),"");f.reviewer.flow().approve(request);f.owner.flow().execute(request);assertEquals(false,f.store.profile(f.target.id()).get("sensitiveRecoveryPending"));assertEquals(false,f.store.profile(f.target.id()).get("delegatedAdministrator"));assertThrows(IOException.class,()->recovered.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ,Scope.ADMIN)));}
 }}
 @Test void boundedParserRejectsAmbiguousFieldsAndWrongPayloadDomain()throws Exception{try(Fixture f=new Fixture()){
  f.owner.step();var permit=f.owner.flow().prepare(Operation.ASSIGN,f.target.id(),"Редактор");String code=permit.encode();assertThrows(IOException.class,()->IdentityAdministrationFlow600.Permit.parse(code.replace("\"schema\":1","\"schema\":1,\"schema\":1")));assertThrows(IOException.class,()->IdentityAdministrationFlow600.Permit.parse(code.replace("\"schema\":1","\"schema\":\"1\"")));assertThrows(IOException.class,()->IdentityAdministrationFlow600.Permit.parse(code.substring(0,code.length()-1)+",\"extra\":\"x\"}"));assertThrows(IOException.class,()->IdentityAdministrationFlow600.Permit.parse(code+" {}"));assertThrows(IOException.class,()->IdentityAdministrationFlow600.Permit.parse("x".repeat(4097)));JsonObject o=com.google.gson.JsonParser.parseString(code).getAsJsonObject();o.addProperty("operation","REVOKE");assertThrows(IOException.class,()->IdentityAdministrationFlow600.Permit.parse(o.toString()));
 }}
 @Test void missingStepUpAndLocalLockPreventAdministrativeOperation()throws Exception{try(Fixture f=new Fixture()){
  assertThrows(IOException.class,()->f.owner.flow().prepare(Operation.ASSIGN,f.target.id(),"Редактор"));f.owner.step();var permit=f.owner.flow().prepare(Operation.ASSIGN,f.target.id(),"Редактор");f.reviewer.session.lock();assertThrows(IOException.class,()->f.reviewer.flow().approve(permit));assertEquals(false,f.store.profile(f.target.id()).get("delegatedAdministrator"));
 }}
 final class Fixture implements AutoCloseable{
  final KeyPair service=pair();final Set<String> external=new HashSet<>();final IdentityStore store;final IdentityHttpServer http;final IdentityClient600 client;final Person owner,reviewer,target;
  Fixture()throws Exception{store=new IdentityStore(dir.resolve(UUID.randomUUID()+".db"),service,new byte[32],Clock.systemUTC(),external::contains);http=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),store,service);http.start();client=new IdentityClient600("a".repeat(56)+".onion",80,service.getPublic().getEncoded(),(host,port,observer)->{Socket s=new Socket();observer.opened(s);s.connect(new InetSocketAddress("127.0.0.1",http.port()));return s;},Clock.systemUTC());owner=new Person(this);reviewer=new Person(this);target=new Person(this);var b=store.ownerChallenge(owner.id());store.bootstrapOwner(owner.id(),b.challenge(),IdentityProtocol.sign(owner.root.getPrivate(),IdentityProtocol.ownerBootstrap(client.audience(),owner.id(),b.challenge(),b.expiresAt())));owner.relogin();external.add(reviewer.id());reviewer.relogin();}
  public void close()throws Exception{owner.session.close();reviewer.session.close();target.session.close();client.close();http.close();store.close();}
 }
 static final class Person{
  final Fixture f;final KeyPair root=pair(),device=pair(),recovery=pair();CoreAccountSession600 session;
  Person(Fixture f)throws Exception{this.f=f;session=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),credentials());long t=System.currentTimeMillis();String n=IdentityProtocol.nonce();session.register("Участник",t,n,IdentityProtocol.sign(root.getPrivate(),IdentityProtocol.registration(f.client.audience(),root.getPublic().getEncoded(),device.getPublic().getEncoded(),recovery.getPublic().getEncoded(),"Участник",t,n)));}
  String id(){return IdentityProtocol.id(root.getPublic().getEncoded());}DeviceCredentials600 credentials(){return new DeviceCredentials600(root.getPublic().getEncoded(),device,recovery.getPublic().getEncoded());}
  IdentityAdministrationFlow600 flow(){return new IdentityAdministrationFlow600(f.client,session);}
  void relogin()throws Exception{session.close();session=new CoreAccountSession600(f.client,f.service.getPublic().getEncoded(),credentials());session.login();}
  void step()throws Exception{var c=f.store.stepUpChallenge(session.accountId(),session.deviceId(),session.generation());session.completeStepUp(c.challenge(),c.expiresAt(),IdentityProtocol.sign(root.getPrivate(),IdentityProtocol.stepUp(f.client.audience(),session.accountId(),session.deviceId(),c.challenge(),c.expiresAt())));}
 }
}
