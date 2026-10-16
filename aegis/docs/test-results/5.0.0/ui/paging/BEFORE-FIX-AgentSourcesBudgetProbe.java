import org.securemail.community.core.*;
import org.securemail.community.access.*;
import org.securemail.community.agent.*;
import org.securemail.community.http.*;
import org.securemail.client.community.*;
import org.securemail.client.crypto.Identity;
import java.nio.file.*;
import java.time.*;
import java.util.*;
public class AgentSourcesBudgetProbe {
 public static void main(String[] args)throws Exception{
  var root=Files.createTempDirectory("aegis-source-budget-probe-");try(var store=new CommunityStore(root.resolve("server.db"),Clock.systemUTC())){
   Identity first=Identity.create(),second=Identity.create(),service=Identity.create();store.bindServiceIdentity(service.userId());byte[] kek=new byte[32],a=new byte[32],b=new byte[32];new java.security.SecureRandom().nextBytes(kek);new java.security.SecureRandom().nextBytes(a);new java.security.SecureRandom().nextBytes(b);var access=new AccessControl(store,kek);access.bootstrap(first.publicKey(),first.userId(),a,second.publicKey(),second.userId(),b);Arrays.fill(kek,(byte)0);Arrays.fill(a,(byte)0);Arrays.fill(b,(byte)0);
   try(var agent=new AgentService(store,access,(actor,draft)->{throw new AssertionError("No publication in metadata-only probe");})){
    store.tx(db->{try(var s=db.createStatement()){s.execute("INSERT INTO agent_city(id,name) VALUES('ru/test/city','Тестовый город')");}try(var q=db.prepareStatement("INSERT INTO agent_source(id,url,city,source_group,official,enabled,min_interval,lawful_basis) VALUES(?,?,'ru/test/city','independent',1,1,30,'Synthetic isolated server fixture')")){for(int i=0;i<1000;i++){q.setString(1,UUID.randomUUID().toString());q.setString(2,"https://example.org/feed/"+i);q.addBatch();}q.executeBatch();}return null;});
    Map<String,Object> result=agent.handle(first.userId(),"agent.sources.list",Map.of());byte[] wire=StrictJson.bytes(result);System.out.println("actualServerSourceRows="+((List<?>)result.get("sources")).size()+" wireBytes="+wire.length);try{CommunityJson.parse(wire);System.out.println("CLIENT_DECODE_PASS");}catch(java.io.IOException rejected){System.out.println("CONFIRMED_CLIENT_DECODE_FAIL="+rejected.getMessage());}
   }
  }
 }
}
