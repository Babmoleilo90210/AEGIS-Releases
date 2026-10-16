package org.securemail.integration;

import com.google.gson.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.ClientConfig;
import org.securemail.client.community.CommunityClient;
import org.securemail.client.net.TorTransport;
import org.securemail.client.storage.LocalStore;
import org.securemail.community.access.AccessControl;
import org.securemail.community.agent.AgentService;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.*;
import org.securemail.community.http.CommunityHttpServer;
import org.securemail.community.org.OrgAdminService;
import org.securemail.community.protocol.CommunityAuth;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

/** Production CommunityClient/TorTransport + Ed25519-signed HTTP + actual SQLite/vaults.
 * The SOCKS5 endpoint is an explicitly bounded LOOPBACK FIXTURE forwarding only one
 * fixed onion name to this test's HTTP server. It is NOT Tor or a DNS/IP leak test.
 */
class CommunityIntegration500Test {
 @TempDir Path dir;
 private static final String ONION="a".repeat(56)+".onion";
 private static final char[] PASSWORD="integration-500-disposable-vault-secret".toCharArray();
 LocalStore alice,bob;CommunityClient a,b;CommunityStore store;AccessControl access;ContentService content;AgentService agent;CommunityHttpServer server;SocksFixture socks;byte[] aliceSeed,secondarySeed;KeyPair service,secondary;
 @BeforeEach void setup()throws Exception {
   TorTransport.requireAvailability(()->true);alice=new LocalStore(dir.resolve("alice-vault"),PASSWORD,Clock.systemUTC(),1000000,12_000_000);bob=new LocalStore(dir.resolve("bob-vault"),PASSWORD,Clock.systemUTC(),1000000,12_000_000);alice.bindNickname("alice");bob.bindNickname("bob");
   service=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();secondary=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();aliceSeed=new byte[32];secondarySeed=new byte[32];byte[] kek=new byte[32];new SecureRandom().nextBytes(aliceSeed);new SecureRandom().nextBytes(secondarySeed);new SecureRandom().nextBytes(kek);
   store=new CommunityStore(dir.resolve("server/community.sqlite"));access=new AccessControl(store,kek);Arrays.fill(kek,(byte)0);access.bootstrap(alice.identity().publicKey(),alice.identity().userId(),aliceSeed,secondary.getPublic().getEncoded(),CommunityAuth.id(secondary.getPublic().getEncoded()),secondarySeed);content=new ContentService(store,access);store.setNotificationSink(content::notifyAccount);agent=new AgentService(store,access,content::ingestAi);server=new CommunityHttpServer(new InetSocketAddress("127.0.0.1",0),store,access,new OrgAdminService(store,access,store.clock()),content,agent,service);server.start();socks=new SocksFixture(server.port());a=client(alice);b=client(bob);a.configure(ONION,80,Base64.getEncoder().encodeToString(service.getPublic().getEncoded()));b.configure(ONION,80,Base64.getEncoder().encodeToString(service.getPublic().getEncoded()));
 }
 private CommunityClient client(LocalStore local){int port=socks.port(),control=port==19051?19053:19051,update=port==19052||control==19052?19054:19052;return new CommunityClient(new ClientConfig("127.0.0.1",port,control,update,dir.resolve("unused-cookie"),19120,1800,"",80,local.root(),1000000,12_000_000,60000),local);}
 @AfterEach void close()throws Exception {if(a!=null)a.close();if(b!=null)b.close();if(socks!=null)socks.close();if(server!=null)server.close();if(agent!=null)agent.close();if(store!=null)store.close();if(alice!=null)alice.close();if(bob!=null)bob.close();if(aliceSeed!=null)Arrays.fill(aliceSeed,(byte)0);if(secondarySeed!=null)Arrays.fill(secondarySeed,(byte)0);TorTransport.requireAvailability(()->true);}
 private static JsonObject object(Map<String,Object> values){return new Gson().toJsonTree(values).getAsJsonObject();}
 private JsonObject call(CommunityClient client,String action,Map<String,Object> data)throws IOException{return client.rpc(action,object(data));}
 private String stepAlice()throws Exception {JsonObject begin=call(a,"admin.stepup.begin",Map.of());byte[] proof=alice.identity().sign(Base64.getDecoder().decode(begin.get("signingBytesBase64").getAsString()));return call(a,"admin.stepup.finish",Map.of("challenge",begin.get("challenge").getAsString(),"signatureBase64",Base64.getEncoder().encodeToString(proof),"code",Totp.code(aliceSeed,store.clock().millis()))).get("token").getAsString();}
 private JsonObject published(String title,Map<String,Object> policy)throws Exception {JsonObject draft=call(a,"content.library.create",Map.of("title",title,"body","## Разрешённый материал\n\nТекст документа","policy",policy));return call(a,"content.library.publish",Map.of("id",draft.get("id").getAsString(),"revision",draft.get("revision").getAsLong()));}
 @Test void exactSignedRpcPublicReadEncryptedCacheAndRevocationAcrossActualVaults()throws Exception {
   byte[] alicePublic=alice.identity().publicKey(),bobPublic=bob.identity().publicKey(),bobPrivate=bob.identity().privateKey();assertTrue(call(a,"session.capabilities",Map.of()).get("isAdmin").getAsBoolean());assertFalse(call(b,"session.capabilities",Map.of()).get("isAdmin").getAsBoolean());
   JsonObject material=published("Общий документ",Map.of("offlineAllowed",true));String id=material.get("id").getAsString();JsonObject args=object(Map.of("id",id));assertEquals("Общий документ",b.rpc("content.library.get",args).get("title").getAsString());assertTrue(b.offline("content.library.get",args).get("offlineCopy").getAsBoolean());
   byte[] sealed=Files.readAllBytes(bob.root().resolve("lifecycle/community-v1.enc"));assertFalse(new String(sealed,StandardCharsets.UTF_8).contains("Общий документ"));assertFalse(new String(sealed,StandardCharsets.UTF_8).contains("offlineAllowed"));
   long before=b.authorizationEpoch();call(a,"content.library.update",Map.of("id",id,"revision",material.get("revision").getAsLong(),"title","Теперь закрытый","body","Закрытое содержимое","policy",Map.of("users",List.of(alice.identity().userId()),"offlineAllowed",false)));call(b,"community.me",Map.of());assertTrue(b.authorizationEpoch()>before,"Changed ACL must invalidate cached authorization");assertThrows(IOException.class,()->b.offline("content.library.get",args));CommunityClient.Rejected denied=assertThrows(CommunityClient.Rejected.class,()->b.rpc("content.library.get",args));assertEquals("NOT_FOUND",denied.code());
   assertArrayEquals(alicePublic,alice.identity().publicKey());assertArrayEquals(bobPublic,bob.identity().publicKey());assertArrayEquals(bobPrivate,bob.identity().privateKey());assertTrue(store.verifyAudit());assertTrue(socks.domains.size()>=7);assertTrue(socks.domains.stream().allMatch(ONION::equals));assertEquals(Set.of(3),socks.addressTypes);
 }
 @Test void profileDisplayNamePublishUpdatesOnlyAuthenticatedIdentityWithoutGrantingAuthority()throws Exception {
   byte[] aliceKey=alice.identity().publicKey(),bobKey=bob.identity().publicKey();assertEquals("Пользователь",call(b,"community.me",Map.of()).get("nickname").getAsString());
   assertEquals("bob_updated",call(b,"community.profile.update",Map.of("nickname","bob_updated")).get("nickname").getAsString());JsonObject me=call(b,"community.me",Map.of());assertEquals("bob_updated",me.get("nickname").getAsString());assertEquals(bob.identity().userId(),me.get("identity").getAsString());assertFalse(me.get("isAdmin").getAsBoolean());assertEquals(0,me.get("clearance").getAsInt());
   assertEquals("INVALID",assertThrows(CommunityClient.Rejected.class,()->call(b,"community.profile.update",Map.of("nickname","stolen","identity",alice.identity().userId()))).code());assertEquals("INVALID",assertThrows(CommunityClient.Rejected.class,()->call(b,"community.profile.update",Map.of("nickname","fake_admin","isAdmin",true))).code());assertEquals("bob_updated",call(b,"community.me",Map.of()).get("nickname").getAsString());assertNotEquals("stolen",call(a,"community.me",Map.of()).get("nickname").getAsString());
   assertArrayEquals(aliceKey,alice.identity().publicKey());assertArrayEquals(bobKey,bob.identity().publicKey());assertEquals("bob",bob.nickname(),"Community display-name publication never rewrites vault identity");assertTrue(store.verifyAudit());
 }
 @Test void graphReturnsOnlyAuthorizedDocumentsAndCacheNeverComesFromPrivateArchive()throws Exception {
   call(b,"community.me",Map.of());JsonObject visible=published("Открытый узел",Map.of()),closed=published("Закрытый узел",Map.of("users",List.of(alice.identity().userId())));JsonObject graph=call(b,"content.library.graph",Map.of());JsonArray nodes=graph.getAsJsonArray("nodes");assertEquals(1,nodes.size());assertEquals(visible.get("id"),nodes.get(0).getAsJsonObject().get("id"));String json=graph.toString();assertFalse(json.contains("Закрытый узел"));assertFalse(json.contains(closed.get("id").getAsString()));assertThrows(IOException.class,()->b.offline("content.library.get",object(Map.of("id",visible.get("id").getAsString()))));assertFalse(Files.exists(bob.root().resolveSibling("bob-vault.personal-archive")));
 }
 @Test void organizationApplicationApprovalMembershipAndVoiceBatchUseServerAuthority()throws Exception {
   call(b,"community.me",Map.of());JsonObject application=call(b,"org.applications.create",Map.of("name","Тестовая организация","description","Реальная тестовая заявка","purpose","Проверка интеграции","joinPolicy","OPEN"));String org=application.get("id").getAsString();assertTrue(call(b,"org.list",Map.of()).getAsJsonArray("items").isEmpty());
   assertEquals("REAUTH_REQUIRED",assertThrows(CommunityClient.Rejected.class,()->call(b,"org.applications.decide",Map.of("id",org,"revision",1,"approve",true,"stepUp","x".repeat(43)))).code());
   String token=stepAlice();call(a,"org.applications.decide",Map.of("id",org,"revision",1,"approve",true,"delegatedPermissions",List.of("VOICE_CALL","VOICE_RECEIVE"),"stepUp",token));call(a,"org.join",Map.of("id",org));JsonObject owned=call(b,"org.get",Map.of("id",org));assertEquals("",owned.get("city").getAsString());assertTrue(owned.get("member").getAsBoolean());
   JsonObject grants=call(b,"org.calls.authorize_batch",Map.of("targets",List.of(alice.identity().userId()),"direction","OUTGOING"));assertTrue(grants.getAsJsonArray("decisions").get(0).getAsJsonObject().get("allowed").getAsBoolean());call(a,"org.leave",Map.of("id",org));JsonObject revoked=call(b,"org.calls.authorize_batch",Map.of("targets",List.of(alice.identity().userId()),"direction","OUTGOING"));assertFalse(revoked.getAsJsonArray("decisions").get(0).getAsJsonObject().get("allowed").getAsBoolean());assertTrue(store.verifyAudit());
 }
 @Test void cacheLargerThanMailQuotaSurvivesRekeyAndVerifiedProfileRestoreWithoutChangingIdentityOrArchive()throws Exception {
   call(b,"community.me",Map.of());String lastId="";String text="Я".repeat(240000);
   for(int n=0;n<3;n++){JsonObject draft=call(a,"content.library.create",Map.of("title","Большой разрешённый материал "+n,"body",text,"policy",Map.of("offlineAllowed",true)));String id=draft.get("id").getAsString();call(a,"content.library.publish",Map.of("id",id,"revision",1));call(b,"content.library.get",Map.of("id",id));lastId=id;}
   byte[] state=bob.readExtension("community-v1",4*1024*1024),publicKey=bob.identity().publicKey(),privateKey=bob.identity().privateKey();assertTrue(state.length>1_100_000,"Fixture must exceed maxCipher + mail overhead while remaining within the separate cache quota");Path original=bob.root(),archive=original.resolveSibling("bob-vault.personal-archive"),guards=dir.resolve("archive-guards");char[] archivePassword="independent-integration-archive-secret".toCharArray(),nextPassword="rekey-preserves-community-and-identity".toCharArray();String entry;
   try(var opened=org.securemail.client.archive.EncryptedArchive.create(archive,guards,archivePassword,false,Clock.systemUTC()).archive()){entry=opened.importBytes("keep.txt","text","Архив остаётся отдельным".getBytes(StandardCharsets.UTF_8),"",false,org.securemail.client.archive.EncryptedArchive.QUIET,()->false).id();}
   byte[] archiveBefore=Files.readAllBytes(archive.resolve("catalog.enc"));Path rekey=dir.resolve("rekey-copy");bob.rekeyCopy(rekey,nextPassword);
   try(var reopened=new LocalStore(rekey,nextPassword,Clock.systemUTC(),1000000,12_000_000)){assertArrayEquals(publicKey,reopened.identity().publicKey());assertArrayEquals(privateKey,reopened.identity().privateKey());assertArrayEquals(state,reopened.readExtension("community-v1",4*1024*1024));try(var client=client(reopened)){assertEquals(text,client.offline("content.library.get",object(Map.of("id",lastId))).get("body").getAsString());}}
   assertArrayEquals(archiveBefore,Files.readAllBytes(archive.resolve("catalog.enc")));bob.checkpoint();bob.close();bob=null;String previous=System.getProperty("aegis.profile");System.setProperty("aegis.profile",dir.resolve("profile-preferences").toString());
   try {ClientConfig config=new ClientConfig("127.0.0.1",socks.port(),19051,19052,dir.resolve("cookie"),19120,1800,"",80,original,1000000,12_000_000,60000);config.save(org.securemail.client.AppPaths.config());Path backup=org.securemail.client.storage.ClientUpgrade.beforeVersionOpen("5.0.0",config,dir.resolve("backups"));org.securemail.client.storage.ProfileSnapshot.verify(backup,config);assertArrayEquals(Files.readAllBytes(original.resolve("lifecycle/community-v1.enc")),Files.readAllBytes(backup.resolve("vault/lifecycle/community-v1.enc")));assertArrayEquals(archiveBefore,Files.readAllBytes(backup.resolve("personal-archives/main/catalog.enc")));assertEquals(backup,org.securemail.client.storage.ClientUpgrade.beforeVersionOpen("5.0.0",config,dir.resolve("backups")));
     Files.write(original.resolve("lifecycle/community-v1.enc"),new byte[]{1,2,3});org.securemail.client.storage.ProfileSnapshot.restore(backup,config);try(var restored=new LocalStore(original,PASSWORD,Clock.systemUTC(),1000000,12_000_000)){assertArrayEquals(publicKey,restored.identity().publicKey());assertArrayEquals(privateKey,restored.identity().privateKey());assertArrayEquals(state,restored.readExtension("community-v1",4*1024*1024));}try(var restored=org.securemail.client.archive.EncryptedArchive.open(archive,guards,archivePassword,false,Clock.systemUTC())){assertEquals("Архив остаётся отдельным",new String(restored.previewBytes(entry,1024),StandardCharsets.UTF_8));}
   }finally{if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);Arrays.fill(state,(byte)0);Arrays.fill(privateKey,(byte)0);Arrays.fill(archivePassword,'\0');Arrays.fill(nextPassword,'\0');}
 }
 @Test void routeUnavailableOrWrongServicePinNeverFallsBackToDirectHttp()throws Exception {
   int before=socks.domains.size();TorTransport.requireAvailability(()->false);assertThrows(IOException.class,()->call(b,"community.me",Map.of()));assertEquals(before,socks.domains.size());TorTransport.requireAvailability(()->true);
   KeyPair wrong=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();b.configure(ONION,80,Base64.getEncoder().encodeToString(wrong.getPublic().getEncoded()));assertThrows(IOException.class,()->call(b,"community.me",Map.of()));assertEquals(before+1,socks.domains.size());assertEquals(0L,store.tx(db->{try(var q=db.prepareStatement("SELECT count(*) FROM identities WHERE identity=?")){q.setString(1,bob.identity().userId());try(var r=q.executeQuery()){r.next();return r.getLong(1);}}}).longValue());
 }
 private static final class SocksFixture implements AutoCloseable {
   final ServerSocket listener;final int targetPort;final Set<Socket> sockets=ConcurrentHashMap.newKeySet();final List<String> domains=new CopyOnWriteArrayList<>();final Set<Integer>addressTypes=ConcurrentHashMap.newKeySet();final ThreadPoolExecutor workers=new ThreadPoolExecutor(8,8,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(16),r->{Thread t=new Thread(r,"LOOPBACK-SOCKS-FIXTURE");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());final Thread acceptor;volatile boolean closed;
   SocksFixture(int targetPort)throws IOException {this.targetPort=targetPort;listener=new ServerSocket(0,8,InetAddress.getByName("127.0.0.1"));acceptor=new Thread(()->{while(!closed)try{Socket client=listener.accept();client.setSoTimeout(10000);if(sockets.size()>=16){client.close();continue;}sockets.add(client);try{workers.execute(()->handle(client));}catch(RejectedExecutionException full){sockets.remove(client);client.close();}}catch(IOException stopped){if(!closed)throw new java.io.UncheckedIOException(stopped);}},"LOOPBACK-SOCKS-ACCEPTOR");acceptor.setDaemon(true);acceptor.start();}
   int port(){return listener.getLocalPort();}
   void handle(Socket client){Socket target=null;try(client){DataInputStream in=new DataInputStream(client.getInputStream());OutputStream out=client.getOutputStream();if(in.readUnsignedByte()!=5||in.readUnsignedByte()!=1||in.readUnsignedByte()!=0)throw new IOException("Only fixed SOCKS5 no-auth fixture");out.write(new byte[]{5,0});out.flush();if(in.readUnsignedByte()!=5||in.readUnsignedByte()!=1||in.readUnsignedByte()!=0)throw new IOException("SOCKS connect");int type=in.readUnsignedByte();addressTypes.add(type);if(type!=3)throw new IOException("Domain form required; no fixture DNS resolution");int size=in.readUnsignedByte();String host=new String(in.readNBytes(size),StandardCharsets.US_ASCII);int port=in.readUnsignedShort();if(!host.equals(ONION)||port!=80)throw new IOException("Fixture forwards only its fixed test onion service");domains.add(host);target=new Socket("127.0.0.1",targetPort);target.setSoTimeout(10000);sockets.add(target);out.write(new byte[]{5,0,0,1,127,0,0,1,0,80});out.flush();Socket owned=target;Future<?> upload=workers.submit(()->{try{copy(client.getInputStream(),owned.getOutputStream());}catch(IOException ignored){}finally{try{owned.shutdownOutput();}catch(IOException ignored){}}});try{copy(target.getInputStream(),client.getOutputStream());}finally{upload.cancel(true);}
   }catch(IOException|RejectedExecutionException ignored){}finally{sockets.remove(client);if(target!=null){sockets.remove(target);try{target.close();}catch(IOException ignored){}}}}
   static void copy(InputStream in,OutputStream out)throws IOException {byte[] buffer=new byte[4096];try{int n;while((n=in.read(buffer))!=-1){out.write(buffer,0,n);out.flush();}}finally{Arrays.fill(buffer,(byte)0);}}
   public void close()throws IOException {closed=true;listener.close();for(Socket socket:sockets)try{socket.close();}catch(IOException ignored){}workers.shutdownNow();try{acceptor.join(1000);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}}
 }
}
