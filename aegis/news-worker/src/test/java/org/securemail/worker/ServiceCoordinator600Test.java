package org.securemail.worker;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.community.agent.*;
import org.securemail.community.access.AccessControl;
import org.securemail.community.core.CommunityStore;
import org.securemail.community.gateway600.CommunityMain600;
import org.securemail.community.protocol.CommunityAuth;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Actual fresh Community6 operator CLI / HTTP / SQLite, with loopback injected for Tor transport only. */
final class ServiceCoordinator600Test {
  @TempDir Path temp;Path home,pub;KeyPair worker,identity;byte[]communityPublic;String workerId,fingerprint;CommunityMain600.Running server;
  static final URI SERVICE=URI.create("http://"+"a".repeat(56)+".onion"+WorkerWire600.PATH);
  @BeforeEach void setup()throws Exception {
    worker=key();identity=key();fingerprint=CommunityAuth.id(worker.getPublic().getEncoded());workerId=WorkerWire600.serviceActor(worker.getPublic().getEncoded());home=temp.resolve("community");pub=temp.resolve("worker.pub");Files.write(pub,worker.getPublic().getEncoded());Path idPub=temp.resolve("identity.pub");Files.write(idPub,identity.getPublic().getEncoded());
    CommunityMain600.initialize(home,Map.of("--identity-public",idPub.toString(),"--identity-fingerprint",CommunityAuth.id(identity.getPublic().getEncoded()),"--identity-port",Integer.toString(unused()),"--port",Integer.toString(unused())),new PrintStream(OutputStream.nullOutputStream()));
    assertEquals(0,cli("--worker-allow",home.toString(),"--public",pub.toString(),"--fingerprint",fingerprint));communityPublic=Files.readAllBytes(home.resolve("service-public.x509"));
  }
  @AfterEach void close(){if(server!=null)server.close();}
  int cli(String...args){return CommunityMain600.run(args,new PrintStream(OutputStream.nullOutputStream()),new PrintStream(OutputStream.nullOutputStream()));}
  void start()throws Exception{server=CommunityMain600.start(home);}
  WorkerCoordinatorClient client()throws Exception{return client(worker,communityPublic);}
  WorkerCoordinatorClient client(KeyPair who,byte[]pin)throws Exception{return new WorkerCoordinatorClient(SERVICE,pin,who,(host,port)->new Socket("127.0.0.1",server.port()),WorkerCoordinatorClient.Mode.SERVICE6);}
  @Test void explicitOperatorAllowlistNeverElevatesExistingUserAndLiveRevokeSurvivesRestart()throws Exception {
    try(CommunityStore store=new CommunityStore(home.resolve("community.sqlite"));AccessControl access=new AccessControl(store,Files.readAllBytes(home.resolve("factor-kek.bin")))) {
      assertEquals(Set.of("AGENT_WORK"),access.permissions(workerId,"GLOBAL"));assertFalse(access.isGlobalAdmin(workerId));
      KeyPair user=key();String userId=store.ensureIdentity(user.getPublic().getEncoded(),"Existing user");Path userPub=temp.resolve("user.pub");Files.write(userPub,user.getPublic().getEncoded());
      assertEquals(1,cli("--worker-allow",home.toString(),"--public",userPub.toString(),"--fingerprint",userId));
      assertEquals(1,cli("--worker-allow",home.toString(),"--public",pub.toString(),"--fingerprint","0".repeat(64)));
    }
    start();assertEquals(Map.of(),client().call("agent.worker.claim",Map.of()).get("job"));assertThrows(IOException.class,()->client(key(),communityPublic).call("agent.worker.claim",Map.of()));
    assertEquals(0,cli("--worker-revoke",home.toString(),"--fingerprint",fingerprint));assertThrows(IOException.class,()->client().call("agent.worker.claim",Map.of()));
    server.close();server=null;start();assertThrows(IOException.class,()->client().call("agent.worker.claim",Map.of()));
    assertEquals(0,cli("--worker-allow",home.toString(),"--public",pub.toString(),"--fingerprint",fingerprint));assertEquals(Map.of(),client().call("agent.worker.claim",Map.of()).get("job"));
  }
  @Test void identityMirrorOfSamePublicKeyNeverInheritsServiceRights()throws Exception {
    assertNotEquals(fingerprint,workerId);
    try(CommunityStore store=new CommunityStore(home.resolve("community.sqlite"));AccessControl access=new AccessControl(store,Files.readAllBytes(home.resolve("factor-kek.bin")))) {
      String ordinaryAccount=store.ensureIdentity(worker.getPublic().getEncoded(),"Account created after service allowlist");
      assertEquals(fingerprint,ordinaryAccount);assertEquals(Set.of(),access.permissions(ordinaryAccount,"GLOBAL"));
      assertFalse(access.isServiceIdentity(ordinaryAccount));assertEquals(Set.of("AGENT_WORK"),access.permissions(workerId,"GLOBAL"));
      assertFalse(access.isGlobalAdmin(workerId));assertFalse(access.isGlobalAdmin(ordinaryAccount));
    }
    start();assertEquals(Map.of(),client().call("agent.worker.claim",Map.of()).get("job"));
  }
  @Test void authenticatedInvalidActionsConsumePersistentBudgetBeforeDispatch()throws Exception {
    start();byte[]body=AgentJson.bytes(Map.of("action","admin.roles.list","data",Map.of()));long time=System.currentTimeMillis();
    for(int n=0;n<30;n++)assertEquals(403,request(body,body,nonce(),time,CommunityAuth.id(communityPublic),false));
    byte[]valid=AgentJson.bytes(Map.of("action","agent.worker.claim","data",Map.of()));
    assertEquals(429,request(valid,valid,nonce(),time,CommunityAuth.id(communityPublic),false));
    server.close();server=null;start();assertEquals(429,request(valid,valid,nonce(),time,CommunityAuth.id(communityPublic),false));
  }
  @Test void rawBudgetIncludesUnauthenticatedWorkerTraffic()throws Exception {
    start();for(int n=0;n<600;n++)try(Socket socket=new Socket("127.0.0.1",server.port())){
      socket.setSoTimeout(5000);socket.getOutputStream().write(("GET "+WorkerWire600.PATH+" HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().flush();
      assertEquals(403,PublicSourceHttp.readResponse(socket.getInputStream(),SERVICE,WorkerWire600.MAX_BODY).status());
    }
    byte[]body=AgentJson.bytes(Map.of("action","agent.worker.claim","data",Map.of()));
    assertEquals(403,request(body,body,nonce(),System.currentTimeMillis(),CommunityAuth.id(communityPublic),false));
    try(CommunityStore store=new CommunityStore(home.resolve("community.sqlite"))){assertEquals(0L,count(store,"SELECT count(*) FROM request_nonces"));}
  }
  @Test void signedClaimFailAndRetryUseActualDurableCoordinator()throws Exception {
    seedJob();start();Map<String,Object>job=map(client().call("agent.worker.claim",Map.of()).get("job"));assertFalse(job.isEmpty());
    assertEquals(true,client().call("agent.worker.fail",Map.of("jobId",job.get("id"),"leaseToken",job.get("leaseToken"),"reason","MODEL_UNAVAILABLE")).get("accepted"));
    assertEquals(Map.of(),client().call("agent.worker.claim",Map.of()).get("job"));
    server.close();server=null;try(CommunityStore store=new CommunityStore(home.resolve("community.sqlite"))){assertEquals("MODEL_UNAVAILABLE",store.tx(db->{try(var q=db.createStatement();var r=q.executeQuery("SELECT last_error FROM agent_job")){r.next();return r.getString(1);}}));}
  }
  @Test void completeValidatesLeasedSourceAndLivePermissionsWithoutPretendModelPublication()throws Exception {
    seedJob();start();var job=map(client().call("agent.worker.claim",Map.of()).get("job"));var source=map(((List<?>)job.get("sources")).getFirst());
    Map<String,Object>observation=new LinkedHashMap<>(Map.of("sourceId",source.get("id"),"sourceGroup",source.get("independenceGroup"),"official",true,"cityId",source.get("cityId"),"title","Synthetic transport fixture","text","Synthetic transport fixture; no public-source/model acceptance","url",source.get("url"),"publishedAt",Instant.now().toString(),"publicSource",true));
    Map<String,Object>complete=new LinkedHashMap<>(Map.of("jobId",job.get("id"),"leaseToken",job.get("leaseToken"),"observations",List.of(observation),"analysis",Map.of("candidates",List.of()),"inputTokens",10,"outputTokens",0,"fetchedSourceIds",List.of(source.get("id"))));
    observation.put("sourceGroup","forged");assertThrows(IOException.class,()->client().call("agent.worker.complete",complete));observation.put("sourceGroup",source.get("independenceGroup"));
    assertEquals(true,client().call("agent.worker.complete",complete).get("accepted"));assertEquals(true,client().call("agent.worker.complete",complete).get("duplicate"));
    try(CommunityStore store=new CommunityStore(home.resolve("community.sqlite"))){assertEquals(0L,count(store,"SELECT count(*) FROM content_material"));assertEquals(1L,count(store,"SELECT count(*) FROM agent_job WHERE state='COMPLETE'"));}
  }
  @Test void exactProofReplayAudienceTimeActionAndSizeAreEnforcedAcrossRestart()throws Exception {
    start();byte[]body=AgentJson.bytes(Map.of("action","agent.worker.claim","data",Map.of()));String nonce=nonce();long time=System.currentTimeMillis();
    assertEquals(200,request(body,body,nonce,time,CommunityAuth.id(communityPublic),false));assertEquals(403,request(body,body,nonce,time,CommunityAuth.id(communityPublic),false));
    server.close();server=null;start();assertEquals(403,request(body,body,nonce,time,CommunityAuth.id(communityPublic),false));
    assertEquals(403,request(body,AgentJson.bytes(Map.of("action","agent.worker.claim","data",Map.of("modified",true))),nonce(),time,CommunityAuth.id(communityPublic),false));
    assertEquals(403,request(body,body,nonce(),time,"f".repeat(64),false));assertEquals(403,request(body,body,nonce(),time-120000,CommunityAuth.id(communityPublic),false));
    assertEquals(403,request(body,body,nonce(),time,CommunityAuth.id(communityPublic),true));
    for(String action:List.of("admin.roles.list","content.library.get","agent.sources.list","agent.config.set")){byte[]invalid=AgentJson.bytes(Map.of("action",action,"data",Map.of()));assertEquals(403,request(invalid,invalid,nonce(),time,CommunityAuth.id(communityPublic),false));}
    byte[]oversized=new byte[WorkerWire600.MAX_BODY+1];Arrays.fill(oversized,(byte)' ');assertEquals(403,request(oversized,oversized,nonce(),time,CommunityAuth.id(communityPublic),false));
    assertThrows(IOException.class,()->new WorkerCoordinatorClient(SERVICE,communityPublic,worker,9050,WorkerCoordinatorClient.Mode.LEGACY5));
    assertThrows(IOException.class,()->new WorkerCoordinatorClient(URI.create("http://"+"a".repeat(56)+".onion/api/v1"),communityPublic,worker,9050,WorkerCoordinatorClient.Mode.SERVICE6));
  }
  @Test void persistentAuthenticatedBudgetAndRoleRevocationApplyBeforeEveryOperation()throws Exception {
    start();int denied=0;for(int n=0;n<61;n++)try{client().call("agent.worker.claim",Map.of());}catch(IOException expected){denied++;}assertTrue(denied>0);
    server.close();server=null;
    try(CommunityStore store=new CommunityStore(home.resolve("community.sqlite"))){assertTrue(count(store,"SELECT max(requests) FROM agent600_worker_rate WHERE identity<>'*'")>=30);store.tx(db->{try(var q=db.prepareStatement("DELETE FROM assignments WHERE identity=?")){q.setString(1,workerId);q.executeUpdate();}return null;});}
    start();assertThrows(IOException.class,()->client().call("agent.worker.claim",Map.of()));
  }
  @Test void serviceClientRejectsForgedResponseAndWrongPinnedService()throws Exception {
    start();assertThrows(IOException.class,()->client(worker,key().getPublic().getEncoded()).call("agent.worker.claim",Map.of()));
    try(var fixture=new Tampered()) {var client=new WorkerCoordinatorClient(SERVICE,fixture.key.getPublic().getEncoded(),worker,(h,p)->new Socket("127.0.0.1",fixture.http.getAddress().getPort()),WorkerCoordinatorClient.Mode.SERVICE6);assertThrows(IOException.class,()->client.call("agent.worker.claim",Map.of()));}
  }
  void seedJob()throws Exception {
    try(CommunityStore store=new CommunityStore(home.resolve("community.sqlite"))) {store.tx(db->{String publisher=store.ensureIdentity(key().getPublic().getEncoded(),"Synthetic publisher");Map<String,Object>c=AgentJson.object(queryBytes(db,"SELECT data FROM agent_config"),32768);c.put("enabled",true);c.put("model","not-run-transport-fixture");c.put("provider","ollama");c.put("endpoint","http://127.0.0.1:11434/api/chat");c.put("publisherIdentity",publisher);c.put("autoPublish",false);try(var q=db.prepareStatement("UPDATE agent_config SET data=?")){q.setBytes(1,AgentJson.bytes(c));q.executeUpdate();}try(var s=db.createStatement()){s.execute("INSERT INTO agent_city(id,name) VALUES('zz/test/transport','Synthetic transport bucket')");}try(var q=db.prepareStatement("INSERT INTO agent_source(id,url,city,source_group,official,enabled,min_interval,lawful_basis) VALUES(?,'https://fixture.example/rss','zz/test/transport','synthetic-fixture',1,1,15,'Transport fixture; never fetched')")){q.setString(1,UUID.randomUUID().toString());q.executeUpdate();}return null;});}
  }
  int request(byte[]signedBody,byte[]sentBody,String nonce,long time,String audience,boolean legacy)throws Exception {
    byte[]proof=legacy?CommunityAuth.requestBytes(audience,time,nonce,signedBody):WorkerWire600.requestBytes(audience,time,nonce,signedBody);String headers="POST "+WorkerWire600.PATH+" HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+sentBody.length+"\r\nAEGIS-Key: "+Base64.getEncoder().encodeToString(worker.getPublic().getEncoded())+"\r\nAEGIS-Time: "+time+"\r\nAEGIS-Nonce: "+nonce+"\r\nAEGIS-Signature: "+Base64.getEncoder().encodeToString(CommunityAuth.sign(worker.getPrivate(),proof))+"\r\n\r\n";
    try(Socket socket=new Socket("127.0.0.1",server.port())){socket.setSoTimeout(5000);socket.getOutputStream().write(headers.getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().write(sentBody);socket.getOutputStream().flush();return PublicSourceHttp.readResponse(socket.getInputStream(),SERVICE,WorkerWire600.MAX_BODY).status();}
  }
  static final class Tampered implements AutoCloseable {final KeyPair key=ServiceCoordinator600Test.key();final HttpServer http;Tampered()throws Exception{http=HttpServer.create(new InetSocketAddress("127.0.0.1",0),2);http.createContext("/",x->{try{byte[]request=x.getRequestBody().readAllBytes();byte[]original=AgentJson.bytes(Map.of("ok",true,"data",Map.of("job",Map.of()))),changed=AgentJson.bytes(Map.of("ok",true,"data",Map.of("job",Map.of("forged",true))));String nonce=x.getRequestHeaders().getFirst("AEGIS-Nonce");x.getResponseHeaders().set("AEGIS-Signature",Base64.getEncoder().encodeToString(CommunityAuth.sign(key.getPrivate(),WorkerWire600.responseBytes(CommunityAuth.id(key.getPublic().getEncoded()),nonce,request,original))));x.sendResponseHeaders(200,changed.length);x.getResponseBody().write(changed);x.close();}catch(Exception e){throw new IOException(e);}});http.start();}public void close(){http.stop(0);}}
  static KeyPair key(){try{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}catch(Exception e){throw new AssertionError(e);}}
  static int unused()throws Exception{try(ServerSocket s=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){return s.getLocalPort();}}
  static String nonce(){byte[]bytes=new byte[32];new SecureRandom().nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
  @SuppressWarnings("unchecked")static Map<String,Object>map(Object value){return (Map<String,Object>)value;}
  static long count(CommunityStore store,String sql)throws Exception{return store.tx(db->{try(var q=db.createStatement();var r=q.executeQuery(sql)){r.next();return r.getLong(1);}});}
  static byte[]queryBytes(java.sql.Connection db,String sql)throws Exception{try(var q=db.createStatement();var r=q.executeQuery(sql)){r.next();return r.getBytes(1);}}
}
