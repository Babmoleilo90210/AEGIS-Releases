import org.securemail.community.core.*;
import org.securemail.community.access.*;
import org.securemail.community.agent.*;
import org.securemail.community.http.*;
import org.securemail.client.community.*;
import org.securemail.client.crypto.Identity;
import java.nio.file.*;
import java.time.*;
import java.util.*;
public class AgentSourcesPagingProbe {
 public static void main(String[] args)throws Exception{
  var root=Files.createTempDirectory("aegis-source-budget-probe-");try(var store=new CommunityStore(root.resolve("server.db"),Clock.systemUTC())){
   Identity first=Identity.create(),second=Identity.create(),service=Identity.create();store.bindServiceIdentity(service.userId());byte[] kek=new byte[32],a=new byte[32],b=new byte[32];new java.security.SecureRandom().nextBytes(kek);new java.security.SecureRandom().nextBytes(a);new java.security.SecureRandom().nextBytes(b);var access=new AccessControl(store,kek);access.bootstrap(first.publicKey(),first.userId(),a,second.publicKey(),second.userId(),b);Arrays.fill(kek,(byte)0);Arrays.fill(a,(byte)0);Arrays.fill(b,(byte)0);
   try(var agent=new AgentService(store,access,(actor,draft)->{throw new AssertionError("No publication in metadata-only probe");})){
    store.tx(db->{try(var s=db.createStatement()){s.execute("INSERT INTO agent_city(id,name) VALUES('ru/test/city','Тестовый город')");}try(var q=db.prepareStatement("INSERT INTO agent_source(id,url,city,source_group,official,enabled,min_interval,lawful_basis) VALUES(?,?,'ru/test/city','independent',1,1,30,'Synthetic isolated server fixture')")){for(int i=0;i<1000;i++){q.setString(1,UUID.randomUUID().toString());q.setString(2,"https://example.org/feed/"+i);q.addBatch();}q.executeBatch();}return null;});
    String cursor="";Set<String> seen=new HashSet<>();int pages=0,maxBytes=0;do{Map<String,Object> result=agent.handle(first.userId(),"agent.sources.list",Map.of("limit",100,"cursor",cursor));byte[] wire=StrictJson.bytes(result);StrictJson.object(wire,8*1024*1024);var decoded=CommunityJson.parse(wire);for(var row:decoded.getAsJsonArray("sources"))if(!seen.add(row.getAsJsonObject().get("id").getAsString()))throw new AssertionError("Duplicate source row");cursor=decoded.get("nextCursor").getAsString();maxBytes=Math.max(maxBytes,wire.length);if(++pages>1000)throw new AssertionError("Unbounded cursor chain");}while(!cursor.isEmpty());if(seen.size()!=1000)throw new AssertionError("Lost rows: "+seen.size());System.out.println("PASS_LOCAL_INTEROP actualServerSourceRows="+seen.size()+" pages="+pages+" maxPageBytes="+maxBytes);System.out.println("agentCodeSource="+AgentService.class.getProtectionDomain().getCodeSource().getLocation());System.out.println("clientDecoderCodeSource="+CommunityJson.class.getProtectionDomain().getCodeSource().getLocation());System.out.println("scope=production AgentService/AccessControl/SQLite/StrictJson/CommunityJson; direct fixture population; no network or native acceptance");
   }
  }
 }
}
