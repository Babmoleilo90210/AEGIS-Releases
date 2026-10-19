package org.securemail.worker;

import org.securemail.community.agent.*;
import org.securemail.community.access.AccessControl;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.CommunityStore;
import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/** Opt-in live public HTTPS evidence utility, never a normal CI test or a production agent. */
public final class NewsPublicSourceSmoke600 {
  public static void main(String[] args)throws Exception {
    if(args.length!=2)throw new IllegalArgumentException("Output directory and one explicit official HTTPS feed URL required");
    Path output=Path.of(args[0]).toAbsolutePath().normalize();Files.createDirectory(output);
    URI feed=URI.create(args[1]);PublicSourceHttp.validate(feed,Set.of(feed.getHost()));
    Map<String,Object> report=new LinkedHashMap<>();report.put("startedAt",Instant.now().toString());
    report.put("scope","Actual inherited NewsWorker -> public HTTPS/TLS/robots/SourceParser -> actual local SQLite coordinator; no Tor/native or semantic-model acceptance");
    report.put("source",feed.toString());report.put("productionReady",false);report.put("paidApiRequests",0);
    List<Map<String,Object>> exchanges=Collections.synchronizedList(new ArrayList<>());report.put("networkExchanges",exchanges);
    List<Map<String,Object>> dns=Collections.synchronizedList(new ArrayList<>());report.put("dnsAttempts",dns);
    PublicSourceHttp actual=new PublicSourceHttp();
    // Instrument only: every actual exchange is delegated to the unmodified production public
    // transport, which independently validates DNS/public addresses and pins its TLS socket.
    PublicSourceHttp observed=new PublicSourceHttp(host->{
      try{InetAddress[] addresses=InetAddress.getAllByName(host);dns.add(Map.of("host",host,"addresses",Arrays.stream(addresses).map(InetAddress::getHostAddress).toList()));return addresses;}
      catch(IOException error){dns.add(Map.of("host",host,"errorType",error.getClass().getSimpleName(),"error",Objects.toString(error.getMessage(),"")));throw error;}
    },(uri,ignored,max)->{
      long began=System.nanoTime();Map<String,Object> receipt=new LinkedHashMap<>();receipt.put("requested",uri.toString());
      try{var response=actual.get(uri,Set.of(uri.getHost()),max);receipt.put("status",response.status());receipt.put("finalUri",response.uri().toString());receipt.put("bytes",response.body().length);receipt.put("sha256",sha(response.body()));receipt.put("headers",safeHeaders(response.headers()));return response;}
      catch(IOException error){receipt.put("errorType",error.getClass().getSimpleName());receipt.put("error",Objects.toString(error.getMessage(),""));throw error;}
      finally{receipt.put("elapsedMillis",(System.nanoTime()-began)/1_000_000);exchanges.add(receipt);}
    });
    AtomicReference<List<Map<String,Object>>> publicInput=new AtomicReference<>(List.of());
    int modelPort;try(ServerSocket unused=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){modelPort=unused.getLocalPort();}
    report.put("modelEndpoint","http://127.0.0.1:"+modelPort+"/api/chat");report.put("modelPolicy","Deliberately unavailable local model; real HttpNewsModel adapter, no synthetic model output");
    try(CommunityStore store=new CommunityStore(output.resolve("smoke.db"));AccessControl access=new AccessControl(store)) {
      ContentService content=new ContentService(store,access);
      try(AgentService coordinator=new AgentService(store,access,content::ingestAi)) {
        String worker=store.ensureIdentity(key().getPublic().getEncoded(),"Служебный тест новостей");
        String publisher=store.ensureIdentity(key().getPublic().getEncoded(),"Локальный тестовый редактор");
        grant(store,worker,Set.of("AGENT_WORK"));grant(store,publisher,Set.of("NEWS_CREATE"));
        String sourceId=UUID.randomUUID().toString(),city="zz/test/public-source";
        // Explicit local-only SQL fixture setup, not an assertion that administration or its
        // two-administrator configuration ceremony was exercised. No live account/key is used.
        store.tx(db->{exec(db,"INSERT INTO agent_worker(identity,enabled) VALUES(?,1)",worker);return null;});
        try(NewsWorker disabled=new NewsWorker((action,data)->coordinator.handle(worker,action,data),observed,p->{throw new IOException("Disabled agent must not create a model");})) {
          if(disabled.runOnce())throw new AssertionError("Disabled agent produced work");
        }
        report.put("initialDisabledAgent","PASS; no job or external request");
        Map<String,Object> config=new LinkedHashMap<>(Map.of("enabled",true,"intervalMinutes",20,"provider","ollama","model","not-installed-for-live-source-smoke","endpoint",report.get("modelEndpoint"),"credentialRef","","publisherIdentity",publisher,"maxOutputTokens",128,"dailyBudgetMicros",0,"dailyRequestLimit",2));
        config.put("dailyTokenLimit",1000000);config.put("inputMicrosPerMillion",0);config.put("outputMicrosPerMillion",0);config.put("autoPublish",false);config.put("allowGlobal",false);
        store.tx(db->{exec(db,"UPDATE agent_config SET data=? WHERE id=1",AgentJson.bytes(config));exec(db,"INSERT INTO agent_city(id,name) VALUES(?,?)",city,"Explicit nongeographic local test bucket");exec(db,"INSERT INTO agent_source(id,url,city,source_group,official,enabled,min_interval,lawful_basis) VALUES(?,?,?,?,1,1,30,?)",sourceId,feed.toString(),city,"debian-project-official","Official public RSS link from https://www.debian.org/News/; single research fetch, no article copies/republication");return null;});
        coordinator.cycle();coordinator.cycle();
        if(count(store,"SELECT count(*) FROM agent_job")!=1)throw new AssertionError("Duplicate scheduled job");
        report.put("schedulerJobDeduplication","PASS; two cycles queued one job");
        try(NewsWorker workerProcess=new NewsWorker((action,data)->coordinator.handle(worker,action,data),observed,policy->{
          HttpNewsModel model=new HttpNewsModel("ollama",policy.get("model").toString(),URI.create(policy.get("endpoint").toString()),"",128);
          return new NewsModel(){public Result analyze(List<Map<String,Object>> observations)throws IOException {publicInput.set(List.copyOf(observations));return model.analyze(observations);}public void close(){model.close();}};
        })) {
          boolean completed=workerProcess.runOnce();if(completed)throw new AssertionError("An unavailable model completed a job");
          int requests=exchanges.size();if(workerProcess.runOnce())throw new AssertionError("Backoff was bypassed");
          if(exchanges.size()!=requests)throw new AssertionError("Immediate retry fetched a rate-limited source");
        }
        String error=store.tx(db->{try(var s=db.createStatement();var r=s.executeQuery("SELECT last_error FROM agent_job")){r.next();return r.getString(1);}});
        report.put("persistedJobFailure",error);report.put("workerOnlyPermissions",access.permissions(worker,"GLOBAL"));
        if(!access.permissions(worker,"GLOBAL").equals(Set.of("AGENT_WORK")))throw new AssertionError("Privileged worker");
        try{coordinator.enforceWorkerBoundary(worker,"content.library.get");throw new AssertionError("Private worker access");}catch(org.securemail.community.core.CommunityException expected){report.put("workerPrivateDataBoundary","PASS");}
        List<Map<String,Object>> observations=publicInput.get();List<Map<String,Object>> metadata=new ArrayList<>();Set<String> urls=new HashSet<>();int dates=0;
        for(var item:observations){if(!Boolean.TRUE.equals(item.get("publicSource"))||!sourceId.equals(item.get("sourceId"))||!Boolean.TRUE.equals(item.get("official"))||!"debian-project-official".equals(item.get("sourceGroup")))throw new AssertionError("Origin facts changed");String date=item.get("publishedAt").toString();if(!date.isEmpty()){Instant.parse(date);dates++;}String url=item.get("url").toString();urls.add(url);metadata.add(Map.of("url",url,"publishedAt",date,"titleSha256",sha(item.get("title").toString().getBytes(StandardCharsets.UTF_8)),"textSha256",sha(item.get("text").toString().getBytes(StandardCharsets.UTF_8)),"textChars",item.get("text").toString().length()));}
        report.put("observationCount",observations.size());report.put("uniqueObservationUrls",urls.size());report.put("normalizedPublicationDates",dates);report.put("observationsMetadataOnly",metadata);
        if(!observations.isEmpty()&&!error.equals("MODEL_UNAVAILABLE"))throw new AssertionError("Missing model was not reported");
        if(count(store,"SELECT count(*) FROM agent_candidate")!=0||count(store,"SELECT count(*) FROM content_material")!=0||count(store,"SELECT count(*) FROM content_notification")!=0)throw new AssertionError("Unexpected publication/notification");
        report.put("publishedMaterials",0);report.put("notifications",0);report.put("immediateRetryBackoff","PASS; no second public request");
        report.put("semanticModelAndAutopublish","BLOCKED; no installed permitted model and no external API used");report.put("publicationDedupe","BLOCKED with semantic-model publication; only actual scheduler job dedup was tested");
        report.put("collectionResult",observations.isEmpty()?"BLOCKED":"PASS");
      }
    }catch(Exception|Error error){report.put("collectionResult","FAIL");report.put("errorType",error.getClass().getName());report.put("error",Objects.toString(error.getMessage(),""));throw error;}
    finally{report.put("completedAt",Instant.now().toString());Files.write(output.resolve("RESULT.json"),AgentJson.bytes(report),StandardOpenOption.CREATE_NEW);System.out.println(new String(AgentJson.bytes(report),StandardCharsets.UTF_8));}
  }
  private static KeyPair key()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
  private static String sha(byte[] bytes)throws IOException{try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}catch(GeneralSecurityException error){throw new IOException(error);}}
  private static Map<String,String> safeHeaders(Map<String,String> h){Map<String,String> out=new LinkedHashMap<>();for(String k:List.of("content-type","content-length","last-modified","etag","date","location"))if(h.containsKey(k))out.put(k,h.get(k));return out;}
  private static long count(CommunityStore store,String sql)throws Exception{return store.tx(db->{try(var s=db.createStatement();var r=s.executeQuery(sql)){r.next();return r.getLong(1);}});}
  private static void grant(CommunityStore store,String who,Set<String> rights)throws Exception {String role=UUID.randomUUID().toString();store.tx(db->{exec(db,"INSERT INTO roles(id,scope,name,clearance) VALUES(?,'GLOBAL',?,0)",role,role);for(String right:rights)exec(db,"INSERT INTO role_permissions VALUES(?,?)",role,right);exec(db,"INSERT INTO assignments VALUES(?,?)",who,role);return null;});}
  private static void exec(Connection db,String sql,Object...args)throws Exception{try(var q=db.prepareStatement(sql)){for(int n=0;n<args.length;n++)q.setObject(n+1,args[n]);q.executeUpdate();}}
}
