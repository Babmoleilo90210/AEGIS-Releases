package org.securemail.worker;
import java.nio.file.*;
import java.net.*;
import java.security.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import org.securemail.community.core.*;
import org.securemail.community.access.*;
import org.securemail.community.org.*;
import org.securemail.community.content.*;
import org.securemail.community.agent.*;
import org.securemail.community.http.*;
import org.securemail.community.protocol.*;

/** External operator proof only: final production classes, temporary SQLite, loopback connector seam (not Tor). */
public class WorkerBootstrapProof {
  static KeyPair key() throws Exception {return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
  static String id(KeyPair k)throws Exception{return CommunityAuth.id(k.getPublic().getEncoded());}
  static byte[] seed(){byte[] b=new byte[32];new SecureRandom().nextBytes(b);return b;}
  static String step(OrgAdminService rpc, KeyPair k, byte[] seed)throws Exception {
    String actor=id(k);var begin=rpc.handle(actor,"admin.stepup.begin",Map.of());String signature=Base64.getEncoder().encodeToString(CommunityAuth.sign(k.getPrivate(),Base64.getDecoder().decode((String)begin.get("signingBytesBase64"))));
    return (String)rpc.handle(actor,"admin.stepup.finish",Map.of("challenge",begin.get("challenge"),"signatureBase64",signature,"code",Totp.code(seed,System.currentTimeMillis()))).get("token");
  }
  static Map<String,Object> with(Map<String,Object> base,String key,Object value){var m=new LinkedHashMap<String,Object>(base);m.put(key,value);return m;}
  static String approval(OrgAdminService rpc,KeyPair a,KeyPair b,String aToken,String bToken,String kind,Map<String,Object> payload)throws Exception {
    var request=rpc.handle(id(a),"admin.critical.request",Map.of("kind",kind,"payload",payload,"stepUp",aToken));
    rpc.handle(id(b),"admin.critical.approve",Map.of("id",request.get("id"),"revision",request.get("revision"),"stepUp",bToken));return (String)request.get("id");
  }
  static boolean registeredElsewhere(Path db,String actor)throws Exception {
    try(var connection=DriverManager.getConnection("jdbc:sqlite:"+db);var q=connection.prepareStatement("SELECT 1 FROM identities WHERE identity=?")){q.setString(1,actor);try(var r=q.executeQuery()){return r.next();}}
  }
  public static void main(String[]args)throws Exception {
    Path dir=Files.createTempDirectory(Path.of(args[0]),"proof-");Path db=dir.resolve("community.sqlite");KeyPair a=key(),b=key(),service=key(),worker=key();byte[] firstSeed=seed(),secondSeed=seed(),kek=seed();String workerId=id(worker);
    try(var store=new CommunityStore(db,Clock.systemUTC());var access=new AccessControl(store,kek)){
      access.bootstrap(a.getPublic().getEncoded(),id(a),firstSeed,b.getPublic().getEncoded(),id(b),secondSeed);
      var content=new ContentService(store,access);store.setNotificationSink(content::notifyAccount);var rpc=new OrgAdminService(store,access,Clock.systemUTC());
      try(var agent=new AgentService(store,access,content::ingestAi);var http=new CommunityHttpServer(new InetSocketAddress("127.0.0.1",0),store,access,rpc,content,agent,service)){
        http.start();if(registeredElsewhere(db,workerId))throw new AssertionError("Unexpected pre-existing worker");
        // This seam replaces only Tor's TCP connector; request/response signing,
        // actual HTTP dispatch and actual SQLite transactions are production code.
        var remote=new WorkerCoordinatorClient(URI.create("http://"+"a".repeat(56)+".onion"),service.getPublic().getEncoded(),worker,(host,port)->new Socket("127.0.0.1",http.port()));
        boolean denied=false;try{remote.call("agent.worker.claim",Map.of());}catch(java.io.IOException expected){denied=true;}
        if(!denied||!registeredElsewhere(db,workerId))throw new AssertionError("Denied request did not commit identity registration");
        if(!access.permissions(workerId,"GLOBAL").isEmpty())throw new AssertionError("Registration unexpectedly grants permissions");
        System.out.println("PASS: first production signed worker.claim rejected; identity committed and visible from independent SQLite connection; permissions empty");
        String ta=step(rpc,a,firstSeed),tb=step(rpc,b,secondSeed);var rolePayload=Map.<String,Object>of("scope","GLOBAL","name","Служебный worker","permissions",List.of("AGENT_WORK"),"parents",List.of(),"clearance",0);
        String request=approval(rpc,a,b,ta,tb,"ROLE_CREATE",rolePayload);String role=(String)rpc.handle(id(a),"admin.roles.create",with(with(rolePayload,"requestId",request),"stepUp",ta)).get("id");
        var assignment=Map.<String,Object>of("role",role,"user",workerId);request=approval(rpc,a,b,ta,tb,"ROLE_ASSIGN",assignment);rpc.handle(id(a),"admin.roles.assign",with(with(assignment,"requestId",request),"stepUp",ta));
        var registration=Map.<String,Object>of("identity",workerId,"enabled",true);request=approval(rpc,a,b,ta,tb,"AGENT_CONFIG",registration);agent.handle(id(a),"agent.workers.put",with(with(registration,"requestId",request),"stepUp",ta));
        Map<String,Object> reply=remote.call("agent.worker.claim",Map.of());
        if(!access.permissions(workerId,"GLOBAL").equals(Set.of("AGENT_WORK")))throw new AssertionError("Unexpected worker permissions");
        System.out.println("PASS: actual independent-admin critical ROLE_CREATE, ROLE_ASSIGN and AGENT_CONFIG grant minimal worker; second production signed worker.claim accepted");
        System.out.println("Claim response keys: "+new TreeSet<>(reply.keySet()));
      }
    }finally{Arrays.fill(firstSeed,(byte)0);Arrays.fill(secondSeed,(byte)0);Arrays.fill(kek,(byte)0);}
    try(var db2=new CommunityStore(db,Clock.systemUTC())) {if(!registeredElsewhere(db,workerId))throw new AssertionError("Identity lost after reopen");System.out.println("PASS: committed worker identity persists after store reopen");}
    System.out.println("Scope: temporary SQLite + production HTTP/JCA/worker client; connector seam is loopback, NOT native Tor or deployed service");
  }
}
