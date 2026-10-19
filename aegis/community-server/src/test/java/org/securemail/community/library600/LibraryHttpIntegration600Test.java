package org.securemail.community.library600;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.library600.*;
import org.securemail.client.net.TorTransport;
import org.securemail.community.access.*;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.*;
import org.securemail.community.http.StrictJson;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.library.protocol600.LibraryWire600;
import org.securemail.identity.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** Actual Identity+Library HTTP services, SQLite and production TorTransport via SOCKS fixture.
 * The fixture forwards loopback; this is NOT a real Tor/onion/native Obsidian acceptance result. */
class LibraryHttpIntegration600Test {
    @TempDir Path dir;
    static final String ONION="a".repeat(56)+".onion";
    KeyPair identityService,libraryService;
    IdentityStore identity;IdentityHttpServer identityHttp;
    CommunityStore community;AccessControl access;ContentService content;LibraryIdentityBridge600 bridge;LibraryHttpServer600 server;Socks socks;
    User editor,reader,other;List<HttpLibraryTransport600>clients=new ArrayList<>();
    record User(KeyPair root,KeyPair device,KeyPair app,IdentityStore.Session session,IdentityProtocol.Capability cap){}
    @BeforeEach void setup()throws Exception {
        identityService=pair();libraryService=pair();byte[]audit=new byte[32];new SecureRandom().nextBytes(audit);
        identity=new IdentityStore(dir.resolve("identity.db"),identityService,audit,Clock.systemUTC());Arrays.fill(audit,(byte)0);
        identityHttp=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),identity,identityService);identityHttp.start();
        community=new CommunityStore(dir.resolve("community.db"));access=new AccessControl(community);content=new ContentService(community,access);
        editor=user("Редактор");reader=user("Читатель");other=user("Другой");community.ensureIdentity(key(editor.root()),"Редактор");
        grant(editor.session().accountId(),Set.of("LIBRARY_CREATE","LIBRARY_EDIT","LIBRARY_PUBLISH","LIBRARY_EXPORT","LIBRARY_PROPOSE","LIBRARY_ACCESS_MANAGE"));
        bridge=new LibraryIdentityBridge600(identityHttp.port(),key(identityService),key(libraryService),access,community);
        server=new LibraryHttpServer600(new InetSocketAddress("127.0.0.1",0),community,access,content,libraryService,bridge);server.start();socks=new Socks(server.port());
    }
    @AfterEach void close()throws Exception {for(var c:clients)c.close();if(socks!=null)socks.close();if(server!=null)server.close();if(bridge!=null)bridge.close();if(identityHttp!=null)identityHttp.close();if(identity!=null)identity.close();if(community!=null)community.close();TorTransport.requireAvailability(()->true);}
    static KeyPair pair()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
    static byte[]key(KeyPair p){return p.getPublic().getEncoded();}
    User user(String nickname)throws Exception {
        KeyPair root=pair(),device=pair(),recovery=pair(),app=pair();String nonce=IdentityProtocol.nonce();long time=System.currentTimeMillis();
        byte[]payload=IdentityProtocol.registration(identity.audience(),key(root),key(device),key(recovery),nickname,time,nonce);
        var session=identity.register(key(root),key(device),key(recovery),nickname,time,nonce,IdentityProtocol.sign(root.getPrivate(),payload),IdentityProtocol.sign(device.getPrivate(),payload));
        Set<IdentityProtocol.Scope>scopes=Set.of(IdentityProtocol.Scope.LIBRARY_READ,IdentityProtocol.Scope.LIBRARY_WRITE);nonce=IdentityProtocol.nonce();time=System.currentTimeMillis();
        payload=IdentityProtocol.capabilityRequest(identity.audience(),session.accountId(),session.deviceId(),session.generation(),IdentityProtocol.App.LIBRARY,key(app),scopes,600000,time,nonce);
        var cap=identity.issueCapability(session.accountId(),session.deviceId(),session.generation(),IdentityProtocol.App.LIBRARY,key(app),scopes,600000,time,nonce,IdentityProtocol.sign(device.getPrivate(),payload),IdentityProtocol.sign(app.getPrivate(),payload));
        return new User(root,device,app,session,cap);
    }
    HttpLibraryTransport600 client(User user){return client(user,key(libraryService),user.app().getPrivate());}
    HttpLibraryTransport600 client(User user,byte[]pin,PrivateKey proof){var c=new HttpLibraryTransport600(ONION,80,pin,key(identityService),IdentityProtocol.encodeCapability(user.cap()),proof,new TorTransport("127.0.0.1",socks.port()));clients.add(c);return c;}
    Map<String,Object>call(HttpLibraryTransport600 client,String operation,Map<String,Object>args)throws Exception {
        @SuppressWarnings("unchecked")var data=(Map<String,Object>)client.verifiedRequest("library600."+operation,args).get("data");return data;
    }
    static void sql(java.sql.Connection db,String sql,Object...args)throws Exception{try(var q=db.prepareStatement(sql)){for(int i=0;i<args.length;i++)q.setObject(i+1,args[i]);q.executeUpdate();}}
    void grant(String actor,Set<String>rights)throws Exception {
        if(reader!=null&&actor.equals(reader.session().accountId()))community.ensureIdentity(key(reader.root()),"Читатель");
        community.tx(db->{String role=UUID.randomUUID().toString();sql(db,"INSERT INTO roles(id,scope,name) VALUES(?,'GLOBAL',?)",role,role);for(String permission:rights)sql(db,"INSERT INTO role_permissions VALUES(?,?)",role,permission);sql(db,"INSERT INTO assignments VALUES(?,?)",actor,role);community.bumpEpoch(db,actor);return null;});}
    Map<String,Object>document(boolean hidden,boolean offline)throws Exception {
        String editorId=editor.session().accountId();Map<String,Object>policy=new HashMap<>();policy.put("offlineAllowed",offline);if(hidden)policy.put("users",List.of(editorId));
        var d=content.handle(editorId,"content.library.create",Map.of("title","Настоящий документ","body","Русский текст","policy",policy));return content.handle(editorId,"content.library.publish",Map.of("id",d.get("id"),"revision",d.get("revision")));
    }
    @Test void actualSignedIdentityBridgeAllowsPublicReadButDeniesClosedContent()throws Exception {
        var allowed=document(false,false);var closed=document(true,false);var c=client(reader);
        assertEquals(1L,community.<Long>tx(db->CommunityStore.count(db,"identities")).longValue());
        assertEquals("Русский текст",call(c,"read",Map.of("id",allowed.get("id"))).get("body"));
        assertEquals(2L,community.<Long>tx(db->CommunityStore.count(db,"identities")).longValue());assertTrue(access.permissions(reader.session().accountId(),"GLOBAL").isEmpty());
        assertEquals("NOT_FOUND",assertThrows(HttpLibraryTransport600.Rejected.class,()->call(c,"read",Map.of("id",closed.get("id")))).code());
        assertTrue(((List<?>)call(c,"catalog",Map.of()).get("locked")).isEmpty());assertTrue(socks.connections>0);
    }
    @Test void actualHttpDiscoveryRequestsAndProposalApprovalPersistAndDoNotGrantReadImplicitly()throws Exception {
        var closed=document(true,false);var ec=client(editor);var rc=client(reader);var oc=client(other);call(rc,"catalog",Map.of());
        var grant=call(ec,"discovery.grant",Map.of("materialId",closed.get("id"),"subject",reader.session().accountId(),"displayTitle","Разрешённое название"));
        var request=call(rc,"access.request",Map.of("opaqueId",grant.get("opaqueId"),"reason","Прошу доступ"));
        assertEquals("APPROVED_PENDING_GRANT",call(ec,"access.decide",Map.of("requestId",request.get("id"),"decision","APPROVE")).get("state"));
        assertThrows(HttpLibraryTransport600.Rejected.class,()->call(rc,"read",Map.of("id",closed.get("id"))));assertTrue(((List<?>)call(oc,"catalog",Map.of()).get("locked")).isEmpty());
        var pub=document(false,false);grant(reader.session().accountId(),Set.of("LIBRARY_PROPOSE"));var proposal=call(rc,"proposal.create",Map.of("materialId",pub.get("id"),"baseRevision",pub.get("revision"),"changeId",UUID.randomUUID().toString(),"title","Редактура","body","Одобрено"));
        call(ec,"proposal.decide",Map.of("proposalId",proposal.get("id"),"decision","APPROVE"));assertEquals("Одобрено",call(rc,"read",Map.of("id",pub.get("id"))).get("body"));assertTrue(community.verifyAudit());
    }
    @Test void actualHttpProjectionAndPermissionRevocationClearManagedPlaintext()throws Exception {
        var d=document(false,true);grant(reader.session().accountId(),Set.of("LIBRARY_EXPORT"));var transport=client(reader);
        try(var projection=new VaultProjection600(dir.resolve("projected"));var connector=new LibraryConnector600(transport,projection,reader.session().accountId(),reader.session().deviceId(),reader.session().generation(),Clock.systemUTC(),System::nanoTime)){
            Path file=connector.project((String)d.get("id"));assertTrue(Files.readString(file).contains("Русский текст"));
            community.tx(db->{sql(db,"DELETE FROM assignments WHERE identity=?",reader.session().accountId());community.bumpEpoch(db,reader.session().accountId());return null;});
            assertThrows(HttpLibraryTransport600.Rejected.class,()->connector.project((String)d.get("id")));assertFalse(Files.exists(file));
        }
    }
    @Test void freshReadAuthorizationDoesNotRequireExportAndDetectsPerMaterialRevocation()throws Exception {
        var material=document(false,true);var closed=document(true,true);var transport=client(reader);
        var metadata=call(transport,"read.authorize",Map.of("id",material.get("id")));assertEquals(Set.of("id","revision","sha256","offlineAllowed"),metadata.keySet());assertEquals(false,metadata.get("offlineAllowed"));
        assertEquals("NOT_FOUND",assertThrows(HttpLibraryTransport600.Rejected.class,()->call(transport,"read.authorize",Map.of("id",closed.get("id")))).code());
        grant(reader.session().accountId(),Set.of("LIBRARY_EXPORT"));assertEquals(true,call(transport,"read.authorize",Map.of("id",material.get("id"))).get("offlineAllowed"));
        var fresh=transport.verifiedRequest("library600.read.authorize",Map.of("id",material.get("id")));var permit=LibraryReadPermit600.acceptVerified((String)material.get("id"),((Number)material.get("revision")).longValue(),"Русский текст",fresh,Clock.systemUTC(),System::nanoTime);permit.requireOffline();
        var updated=content.handle(editor.session().accountId(),"content.library.update",Map.of("id",material.get("id"),"revision",material.get("revision"),"title","Закрыт","body","Русский текст","policy",Map.of("users",List.of(editor.session().accountId()))));content.handle(editor.session().accountId(),"content.library.publish",Map.of("id",updated.get("id"),"revision",updated.get("revision")));
        assertEquals("NOT_FOUND",assertThrows(HttpLibraryTransport600.Rejected.class,()->call(transport,"read.authorize",Map.of("id",material.get("id")))).code());
    }
    @Test void actualPerMaterialCacheAuthorizationHasNoBodyAndRevocationDeniesStoredCiphertext()throws Exception {
        var material=document(false,true);var closed=document(true,true);grant(reader.session().accountId(),Set.of("LIBRARY_EXPORT"));var transport=client(reader);
        var metadata=call(transport,"cache.authorize",Map.of("id",material.get("id")));assertEquals(Set.of("id","revision","sha256","offlineAllowed"),metadata.keySet());assertFalse(metadata.containsKey("body"));assertThrows(HttpLibraryTransport600.Rejected.class,()->call(transport,"cache.authorize",Map.of("id",closed.get("id"))));
        org.securemail.client.security.SystemSecrets secrets=new org.securemail.client.security.SystemSecrets(){byte[]value;public byte[]load(){return value==null?null:value.clone();}public void store(byte[]v){value=v.clone();}public void clear(){value=null;}};
        var constructor=LibraryEncryptedCache600.class.getDeclaredConstructor(Path.class,String.class,String.class,org.securemail.client.security.SystemSecrets.class,Clock.class,java.util.function.LongSupplier.class);constructor.setAccessible(true);Path cacheRoot=dir.resolve("cache");
        var cache=constructor.newInstance(cacheRoot,reader.session().accountId(),reader.session().deviceId(),secrets,Clock.systemUTC(),(java.util.function.LongSupplier)System::nanoTime);
        try(var p=new VaultProjection600(dir.resolve("first-projection"));var c=new LibraryConnector600(transport,p,reader.session().accountId(),reader.session().deviceId(),reader.session().generation(),Clock.systemUTC(),System::nanoTime,cache)){assertTrue(Files.readString(c.project((String)material.get("id"))).contains("Русский текст"));assertTrue(c.offlineAvailable((String)material.get("id")));}
        cache=constructor.newInstance(cacheRoot,reader.session().accountId(),reader.session().deviceId(),secrets,Clock.systemUTC(),(java.util.function.LongSupplier)System::nanoTime);
        try(var p=new VaultProjection600(dir.resolve("second-projection"));var c=new LibraryConnector600(transport,p,reader.session().accountId(),reader.session().deviceId(),reader.session().generation(),Clock.systemUTC(),System::nanoTime,cache)){
            assertFalse(c.offlineAvailable((String)material.get("id")));assertThrows(IOException.class,()->c.projectOffline((String)material.get("id")));c.clearPlaintextProjections();try(var files=Files.list(cacheRoot)){assertTrue(files.anyMatch(path->path.getFileName().toString().endsWith(".lc6")));}Path file=c.project((String)material.get("id"));assertTrue(Files.readString(file).contains("Русский текст"));
            community.tx(db->{sql(db,"DELETE FROM assignments WHERE identity=?",reader.session().accountId());community.bumpEpoch(db,reader.session().accountId());return null;});assertThrows(HttpLibraryTransport600.Rejected.class,()->c.project((String)material.get("id")));assertFalse(Files.exists(file));assertFalse(c.offlineAvailable((String)material.get("id")));
        }
    }
    @Test void newLoginAtomicallyRevokesGenerationForFreshLibraryRequests()throws Exception {
        var d=document(false,false);var c=client(reader);call(c,"read",Map.of("id",d.get("id")));long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();
        identity.login(reader.session().accountId(),reader.session().deviceId(),time,nonce,IdentityProtocol.sign(reader.device().getPrivate(),IdentityProtocol.login(identity.audience(),reader.session().accountId(),reader.session().deviceId(),time,nonce)));
        assertThrows(HttpLibraryTransport600.Rejected.class,()->call(c,"read",Map.of("id",d.get("id"))));
    }
    @Test void identityOwnerAuthorityIsRequestScopedWithoutLocalAdminRowAndDoesNotBypassClosedRead()throws Exception {
        var pub=document(false,false);var closed=document(true,false);var old=client(reader);call(client(other),"catalog",Map.of());
        var challenge=identity.ownerChallenge(reader.session().accountId());identity.bootstrapOwner(reader.session().accountId(),challenge.challenge(),IdentityProtocol.sign(reader.root().getPrivate(),IdentityProtocol.ownerBootstrap(identity.audience(),reader.session().accountId(),challenge.challenge(),challenge.expiresAt())));
        assertThrows(HttpLibraryTransport600.Rejected.class,()->call(old,"read",Map.of("id",pub.get("id")))); // role snapshot changed
        long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();var scopes=Set.of(IdentityProtocol.Scope.LIBRARY_READ,IdentityProtocol.Scope.LIBRARY_WRITE);
        byte[]body=IdentityProtocol.capabilityRequest(identity.audience(),reader.session().accountId(),reader.session().deviceId(),reader.session().generation(),IdentityProtocol.App.LIBRARY,key(reader.app()),scopes,600000,time,nonce);
        var cap=identity.issueCapability(reader.session().accountId(),reader.session().deviceId(),reader.session().generation(),IdentityProtocol.App.LIBRARY,key(reader.app()),scopes,600000,time,nonce,IdentityProtocol.sign(reader.device().getPrivate(),body),IdentityProtocol.sign(reader.app().getPrivate(),body));
        var owner=client(new User(reader.root(),reader.device(),reader.app(),reader.session(),cap));
        assertEquals(true,call(owner,"capabilities",Map.of()).get("canCreateGlobal"));assertEquals(false,call(client(other),"capabilities",Map.of()).get("canCreateGlobal"));
        assertThrows(HttpLibraryTransport600.Rejected.class,()->call(client(other),"create",Map.of("title","Запрещено","body","x","type","TOPIC")));
        var topic=call(owner,"create",Map.of("title","Общий раздел","body","Описание раздела","type","TOPIC","policy",Map.of("offlineAllowed",true)));
        var note=call(owner,"create",Map.of("title","Материал раздела","body","Первая версия","type","ARTICLE"));
        var updated=call(owner,"update",Map.of("id",note.get("id"),"revision",note.get("revision"),"title","Материал раздела","body","Вторая версия"));
        assertEquals("CONFLICT",assertThrows(HttpLibraryTransport600.Rejected.class,()->call(owner,"update",Map.of("id",note.get("id"),"revision",note.get("revision"),"title","Старая","body","Потеря данных"))).code());
        var submitted=call(owner,"submit",Map.of("id",updated.get("id"),"revision",updated.get("revision")));var approved=call(owner,"moderate",Map.of("id",submitted.get("id"),"revision",submitted.get("revision"),"decision","APPROVE"));
        call(owner,"publish",Map.of("id",topic.get("id"),"revision",topic.get("revision")));call(owner,"publish",Map.of("id",approved.get("id"),"revision",approved.get("revision")));
        var link=call(owner,"link.propose",Map.of("from",topic.get("id"),"to",note.get("id"),"explanation","Раздел объединяет этот материал"));call(owner,"link.decide",Map.of("id",link.get("id"),"decision","APPROVE"));assertEquals(1,((List<?>)call(owner,"link.list",Map.of("id",topic.get("id"),"state","APPROVED")).get("items")).size());
        assertEquals("Вторая версия",call(client(other),"read",Map.of("id",note.get("id"))).get("body"));assertTrue(((Map<?,?>)call(owner,"permissions",Map.of("id",note.get("id"))).get("rights")).values().stream().allMatch(Boolean.TRUE::equals));
        assertNotNull(call(owner,"discovery.grant",Map.of("materialId",pub.get("id"),"subject",other.session().accountId(),"displayTitle","Общедоступное название")).get("opaqueId"));
        assertEquals(0L,community.<Long>tx(db->{try(var q=db.createStatement();var r=q.executeQuery("SELECT count(*) FROM global_admins")){r.next();return r.getLong(1);}}).longValue());assertFalse(access.isGlobalAdmin(reader.session().accountId()));
        assertEquals("NOT_FOUND",assertThrows(HttpLibraryTransport600.Rejected.class,()->call(owner,"read",Map.of("id",closed.get("id")))).code());
        assertThrows(HttpLibraryTransport600.Rejected.class,()->call(client(other),"discovery.grant",Map.of("materialId",pub.get("id"),"subject",reader.session().accountId(),"displayTitle","Попытка")));
        assertNull(org.securemail.community.gateway600.TrustedContext600.current());
    }
    @Test void forgedAppProofAndWrongServicePinsRejected()throws Exception {
        var d=document(false,false);var forged=client(reader,key(libraryService),pair().getPrivate());assertThrows(HttpLibraryTransport600.Rejected.class,()->call(forged,"read",Map.of("id",d.get("id"))));
        var wrongPin=client(reader,key(pair()),reader.app().getPrivate());assertThrows(IOException.class,()->call(wrongPin,"read",Map.of("id",d.get("id"))));
        try(var badBridge=new LibraryIdentityBridge600(identityHttp.port(),key(pair()),key(libraryService),access,community)){
            Map<String,Object>args=Map.of("id",d.get("id"));String raw=new String(StrictJson.bytes(args),StandardCharsets.UTF_8);long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[]operation=LibraryWire600.operation(IdentityProtocol.id(key(libraryService)),"library600.read",raw.getBytes(StandardCharsets.UTF_8));
            var ev=badBridge.evidence("library600.read",raw,args,Map.of("capability",IdentityProtocol.encodeCapability(reader.cap()),"time",time,"nonce",nonce,"proof",IdentityProtocol.b64(IdentityProtocol.sign(reader.app().getPrivate(),IdentityProtocol.requestDigest(reader.cap(),"library.read",IdentityProtocol.digest(operation),time,nonce)))));
            assertThrows(IOException.class,()->badBridge.authenticate(ev));
        }
    }
    @Test void exactOperationBindingRejectsMutationReplayAndDuplicateJson()throws Exception {
        var d=document(false,false);String raw=new String(StrictJson.bytes(Map.of("id",d.get("id"))),StandardCharsets.UTF_8),nonce=IdentityProtocol.nonce();long time=System.currentTimeMillis();byte[]operation=LibraryWire600.operation(IdentityProtocol.id(key(libraryService)),"library600.read",raw.getBytes(StandardCharsets.UTF_8));
        Map<String,Object>auth=Map.of("capability",IdentityProtocol.encodeCapability(reader.cap()),"time",time,"nonce",nonce,"proof",IdentityProtocol.b64(IdentityProtocol.sign(reader.app().getPrivate(),IdentityProtocol.requestDigest(reader.cap(),"library.read",IdentityProtocol.digest(operation),time,nonce))));
        assertEquals(200,rawHttp("library600.read",raw,auth));assertEquals(403,rawHttp("library600.read",raw,auth));
        assertEquals(403,rawHttp("library600.read","{\"id\":\""+UUID.randomUUID()+"\"}",auth));
        assertEquals(403,rawHttp("library600.read","{\"id\":\"a\",\"id\":\"b\"}",auth));
    }
    @Test void noClearnetConstructorOrTorUnavailableFallback()throws Exception {
        assertThrows(IllegalArgumentException.class,()->new HttpLibraryTransport600("example.com",80,key(libraryService),key(identityService),IdentityProtocol.encodeCapability(reader.cap()),reader.app().getPrivate(),new TorTransport("127.0.0.1",socks.port())));
        TorTransport.requireAvailability(()->false);var c=client(reader);assertThrows(IOException.class,()->call(c,"catalog",Map.of()));assertEquals(0,socks.connections);
    }
    @Test void largeActualDocumentExceedsIdentity64kFramingWithoutWeakeningSignatures()throws Exception {
        String body="я".repeat(240000);String actor=editor.session().accountId();var draft=content.handle(actor,"content.library.create",Map.of("title","Большой","body",body));
        var material=content.handle(actor,"content.library.publish",Map.of("id",draft.get("id"),"revision",draft.get("revision")));
        assertEquals(body,call(client(reader),"read",Map.of("id",material.get("id"))).get("body"));
    }
    @Test void dedicatedCliActuallyInitializesInspectsStartsAndSharesAuthenticatedCommunityAudit()throws Exception {
        Path communityHome=Files.createDirectory(dir.resolve("operator-community"));Files.setPosixFilePermissions(communityHome,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        byte[]kek=new byte[32];new SecureRandom().nextBytes(kek);Files.write(communityHome.resolve("factor-kek.bin"),kek);Files.writeString(communityHome.resolve("INITIALIZED"),"AEGIS-COMMUNITY-v1\n");
        for(String file:List.of("factor-kek.bin","INITIALIZED"))Files.setPosixFilePermissions(communityHome.resolve(file),java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        try(var s=new CommunityStore(communityHome.resolve("community.sqlite"));var a=new AccessControl(s,kek)){new ContentService(s,a);}
        Path identityPin=Files.write(dir.resolve("identity-public.x509"),key(identityService)),home=dir.resolve("library-runtime");int port;try(var ephemeral=new ServerSocket(0)){port=ephemeral.getLocalPort();}
        var output=new ByteArrayOutputStream();var errors=new ByteArrayOutputStream();
        String[]args={"--init",home.toString(),"--community-home",communityHome.toString(),"--identity-public",identityPin.toString(),"--identity-fingerprint",IdentityProtocol.id(key(identityService)),"--identity-port",Integer.toString(identityHttp.port()),"--port",Integer.toString(port)};
        assertEquals(0,LibraryServerMain600.run(args,new PrintStream(output),new PrintStream(errors)));assertEquals(0,errors.size());assertEquals(0,LibraryServerMain600.run(new String[]{"--inspect",home.toString()},new PrintStream(output),new PrintStream(errors)));
        assertFalse(Files.exists(home.resolve("factor-kek.bin")));assertEquals(1,LibraryServerMain600.run(args,new PrintStream(output),new PrintStream(errors)));
        try(var running=LibraryServerMain600.start(home);var proxy=new Socks(running.port());var c=new HttpLibraryTransport600(ONION,80,Files.readAllBytes(home.resolve("service-public.x509")),key(identityService),IdentityProtocol.encodeCapability(reader.cap()),reader.app().getPrivate(),new TorTransport("127.0.0.1",proxy.port()))){assertTrue(((List<?>)call(c,"catalog",Map.of()).get("items")).isEmpty());}
        try(var s=new CommunityStore(communityHome.resolve("community.sqlite"));var a=new AccessControl(s,kek)){assertTrue(s.verifyAudit());assertEquals(1L,s.<Long>tx(db->CommunityStore.count(db,"identities")).longValue());assertTrue(a.permissions(reader.session().accountId(),"GLOBAL").isEmpty());}
        assertFalse(output.toString(StandardCharsets.UTF_8).contains("PRIVATE KEY"));Arrays.fill(kek,(byte)0);
    }
    int rawHttp(String action,String raw,Map<String,Object>auth)throws Exception {
        byte[]body=StrictJson.bytes(Map.of("action",action,"argsJson",raw,"authorization",auth,"nonce",IdentityProtocol.nonce()));return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+server.port()+"/library/v1")).POST(HttpRequest.BodyPublishers.ofByteArray(body)).header("Content-Type","application/json").timeout(Duration.ofSeconds(10)).build(),HttpResponse.BodyHandlers.discarding()).statusCode();
    }
    static final class Socks implements AutoCloseable {
        final ServerSocket listener;final ExecutorService workers=Executors.newFixedThreadPool(4);final Thread accept;final int target;volatile int connections;
        Socks(int target)throws Exception{this.target=target;listener=new ServerSocket(0,8,InetAddress.getByAddress(new byte[]{127,0,0,1}));accept=new Thread(()->{while(!listener.isClosed())try{Socket socket=listener.accept();workers.submit(()->forward(socket));}catch(IOException ignored){}},"library-test-socks");accept.setDaemon(true);accept.start();}
        int port(){return listener.getLocalPort();}
        void forward(Socket client){try(client){client.setSoTimeout(15000);DataInputStream in=new DataInputStream(client.getInputStream());OutputStream out=client.getOutputStream();assertEquals(5,in.readUnsignedByte());int methods=in.readUnsignedByte();in.readNBytes(methods);out.write(new byte[]{5,0});out.flush();assertEquals(5,in.readUnsignedByte());assertEquals(1,in.readUnsignedByte());assertEquals(0,in.readUnsignedByte());assertEquals(3,in.readUnsignedByte());String host=new String(in.readNBytes(in.readUnsignedByte()),StandardCharsets.US_ASCII);assertEquals(ONION,host);assertEquals(80,in.readUnsignedShort());connections++;
            try(Socket upstream=new Socket(Proxy.NO_PROXY)){upstream.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),target),1000);upstream.setSoTimeout(15000);out.write(new byte[]{5,0,0,1,127,0,0,1,0,0});out.flush();
                // Each library request fits one content-length frame, forwarded without interpretation.
                ByteArrayOutputStream header=new ByteArrayOutputStream();int matched=0;byte[]ending={13,10,13,10};while(matched<4){int c=in.read();if(c<0)throw new EOFException();header.write(c);matched=c==ending[matched]?matched+1:(c==13?1:0);if(header.size()>16384)throw new IOException("Header limit");}
                String text=header.toString(StandardCharsets.US_ASCII);int length=-1;for(String line:text.split("\r\n"))if(line.toLowerCase(Locale.ROOT).startsWith("content-length:"))length=Integer.parseInt(line.substring(line.indexOf(':')+1).strip());if(length<0||length>LibraryWire600.MAX_BODY)throw new IOException("Size");upstream.getOutputStream().write(header.toByteArray());upstream.getOutputStream().write(in.readNBytes(length));upstream.getOutputStream().flush();upstream.getInputStream().transferTo(out);out.flush();
            }
        }catch(Exception failure){throw new RuntimeException(failure);}}
        @Override public void close()throws Exception{listener.close();workers.shutdownNow();accept.join(1000);}
    }
}
