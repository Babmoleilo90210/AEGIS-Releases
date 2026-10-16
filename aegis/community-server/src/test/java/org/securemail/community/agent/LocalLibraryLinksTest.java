package org.securemail.community.agent;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.community.access.*;
import org.securemail.community.core.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

final class LocalLibraryLinksTest {
 @TempDir Path temp;CommunityStore store;AccessControl acl;String actor,a,b;Map<String,Map<String,Object>>materials;AtomicInteger proposed;LocalLibraryLinks links;
 @BeforeEach void setup()throws Exception{store=new CommunityStore(temp.resolve("library.sqlite"),Clock.systemUTC());acl=new AccessControl(store);actor=store.ensureIdentity(KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded(),"Читатель");a=UUID.randomUUID().toString();b=UUID.randomUUID().toString();materials=new HashMap<>();materials.put(a,Map.of("id",a,"title","Материал А","body","Закрытый разрешённый текст А","revision",1));materials.put(b,Map.of("id",b,"title","Материал Б","body","Закрытый разрешённый текст Б","revision",1));proposed=new AtomicInteger();links=new LocalLibraryLinks(store,acl,(who,id)->{if(!actor.equals(who)||!materials.containsKey(id))throw CommunityException.missing();return materials.get(id);},(who,from,to,reason)->{proposed.incrementAndGet();return Map.of("from",from,"to",to,"state","PROPOSED","ai",true);});}
 @AfterEach void close()throws Exception{links.close();store.close();}
 Map<String,Object>data(){return Map.of("ids",List.of(a,b));}
 Map<String,Object>answer(String from,String to){return Map.of("links",List.of(Map.of("from",from,"to",to,"reason","Оба документа описывают одну организацию")));}
 @Test void proposalsUseOnlyCallerAuthorizedMaterialAndNeverAutoApprove()throws Exception{var result=links.suggest(actor,data(),input->{assertEquals(2,input.size());assertTrue(input.stream().allMatch(m->m.keySet().equals(Set.of("id","title","body"))));return answer(a,b);});assertEquals(true,result.get("localOnly"));assertEquals(true,result.get("requiresEditorConfirmation"));assertEquals(1,proposed.get());assertEquals("PROPOSED",((Map<?,?>)((List<?>)result.get("items")).get(0)).get("state"));}
 @Test void undisclosedMaterialIdCannotBeLoadedOrOfferedToModel(){AtomicBoolean modelCalled=new AtomicBoolean();assertThrows(CommunityException.class,()->links.suggest(actor,Map.of("ids",List.of(a,UUID.randomUUID().toString())),input->{modelCalled.set(true);return answer(a,b);}));assertFalse(modelCalled.get());assertEquals(0,proposed.get());}
 @Test void modelCannotInventClosedNodeOrPermanentLinks(){assertThrows(CommunityException.class,()->links.suggest(actor,data(),input->answer(a,UUID.randomUUID().toString())));assertThrows(CommunityException.class,()->links.suggest(actor,data(),input->Map.of("links",List.of(),"publish",true)));assertEquals(0,proposed.get());}
 @Test void revocationDuringInferenceBlocksPersistingSuggestions(){assertThrows(CommunityException.class,()->links.suggest(actor,data(),input->{store.tx(db->{store.bumpEpoch(db);return null;});return answer(a,b);}));assertEquals(0,proposed.get());}
 @Test void concurrentEditDuringInferenceRequiresFreshPreview(){assertThrows(CommunityException.class,()->links.suggest(actor,data(),input->{materials.put(a,Map.of("id",a,"title","Изменённый","body","Новая версия","revision",2));return answer(a,b);}));assertEquals(0,proposed.get());}
 @Test void externalPrivateInferenceAndInjectedUrlsAreRejected(){assertThrows(CommunityException.class,()->links.suggest(actor,data(),URI.create("https://provider.example/api/chat"),"model"));assertThrows(CommunityException.class,()->links.suggest(actor,data(),input->Map.of("links",List.of(Map.of("from",a,"to",b,"reason","https://steal.example/")))));assertEquals(0,proposed.get());}
 @Test void realLoopbackOllamaPrivateRequestRemainsOnLoopback()throws Exception{HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),2);AtomicReference<Map<String,Object>>payload=new AtomicReference<>();server.createContext("/api/chat",x->{payload.set(AgentJson.object(x.getRequestBody().readAllBytes(),180000));byte[] response=AgentJson.bytes(Map.of("message",Map.of("content",new String(AgentJson.bytes(answer(a,b)),java.nio.charset.StandardCharsets.UTF_8))));x.sendResponseHeaders(200,response.length);x.getResponseBody().write(response);x.close();});server.start();try{var result=links.suggest(actor,data(),URI.create("http://127.0.0.1:"+server.getAddress().getPort()+"/api/chat"),"fixture");assertEquals(1,proposed.get());assertFalse(payload.get().containsKey("tools"));assertEquals(true,result.get("localOnly"));}finally{server.stop(0);}}
 @Test void asynchronousRequestReturnsImmediatelyAndPollIsBoundToCaller()throws Exception{HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),2);server.createContext("/api/chat",x->{byte[] response=AgentJson.bytes(Map.of("message",Map.of("content",new String(AgentJson.bytes(answer(a,b)),java.nio.charset.StandardCharsets.UTF_8))));x.sendResponseHeaders(200,response.length);x.getResponseBody().write(response);x.close();});server.start();try{long start=System.nanoTime();Map<String,Object>job=links.request(actor,data(),URI.create("http://127.0.0.1:"+server.getAddress().getPort()+"/api/chat"),"fixture");assertTrue(System.nanoTime()-start<1000000000L);String id=job.get("jobId").toString();assertThrows(CommunityException.class,()->links.poll("f".repeat(64),Map.of("jobId",id)));Map<String,Object>result=Map.of();for(int n=0;n<100;n++){result=links.poll(actor,Map.of("jobId",id));if(result.get("state").equals("DONE"))break;Thread.sleep(10);}assertEquals("DONE",result.get("state"));assertEquals(1,proposed.get());}finally{server.stop(0);}}

}
