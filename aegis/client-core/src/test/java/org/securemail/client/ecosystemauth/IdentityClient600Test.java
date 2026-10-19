package org.securemail.client.ecosystemauth;

import static org.junit.jupiter.api.Assertions.*;
import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.securemail.client.community.CommunityJson;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Actual loopback HTTP/JCA transport tests. This fixture is not a Tor or IdentityStore acceptance test. */
class IdentityClient600Test {
  enum Fault { NONE, WRONG_KEY, WRONG_NONCE, WRONG_REQUEST, DUPLICATE_LENGTH, TRANSFER_ENCODING, DUPLICATE_JSON, TOO_LARGE, REJECT, WRONG_CONTEXT }
  static KeyPair keys()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}
  static final String ONION="a".repeat(56)+".onion";

  @Test void verifiesExactSignedResponseAndNeverNeedsAccountPrivateKey()throws Exception {
    try(Fixture f=new Fixture(Fault.NONE);IdentityClient600 c=f.client()){
      JsonObject result=c.rpc("isActive",new JsonObject());assertTrue(result.get("active").getAsBoolean());assertEquals(1,f.requests.get());
    }
  }
  @Test void rejectsSignatureNonceAndExactRequestSubstitution()throws Exception {
    for(Fault fault:List.of(Fault.WRONG_KEY,Fault.WRONG_NONCE,Fault.WRONG_REQUEST))try(Fixture f=new Fixture(fault);IdentityClient600 c=f.client()){
      assertThrows(IOException.class,()->c.rpc("isActive",new JsonObject()),fault.name());
    }
  }
  @Test void rejectsAmbiguousHttpAndJsonBeforeTrustingData()throws Exception {
    for(Fault fault:List.of(Fault.DUPLICATE_LENGTH,Fault.TRANSFER_ENCODING,Fault.DUPLICATE_JSON,Fault.TOO_LARGE))try(Fixture f=new Fixture(fault);IdentityClient600 c=f.client()){
      assertThrows(IOException.class,()->c.rpc("isActive",new JsonObject()),fault.name());
    }
  }
  @Test void signedRejectionHasOnlySafeCodeAndNoUntrustedRemoteMessage()throws Exception {
    try(Fixture f=new Fixture(Fault.REJECT);IdentityClient600 c=f.client()){
      IdentityClient600.Rejected rejected=assertThrows(IdentityClient600.Rejected.class,()->c.rpc("isActive",new JsonObject()));
      assertEquals("DENIED",rejected.code());assertFalse(rejected.getMessage().contains("private"));
    }
  }
  @Test void forwardsDigestProofAndChecksReturnedAccountDeviceGeneration()throws Exception {
    for(Fault fault:List.of(Fault.NONE,Fault.WRONG_CONTEXT))try(Fixture f=new Fixture(fault);IdentityClient600 c=f.client()){
      KeyPair app=keys();String token=f.capability(app);byte[] actual="actual operation metadata".getBytes(StandardCharsets.UTF_8);
      if(fault==Fault.NONE){JsonObject context=c.authorizeDigest(token,app.getPrivate(),"mail.send",actual);assertEquals(7,context.get("generation").getAsLong());}
      else assertThrows(IOException.class,()->c.authorizeDigest(token,app.getPrivate(),"mail.send",actual));
    }
  }
  @Test void modifiedActualOperationIsRejectedBeforeAnyConnection()throws Exception {
    try(Fixture f=new Fixture(Fault.NONE);IdentityClient600 c=f.client()){
      KeyPair app=keys();String token=f.capability(app);IdentityProtocol.Capability cap=IdentityProtocol.decodeCapability(token);
      String nonce=IdentityProtocol.nonce();long time=System.currentTimeMillis();byte[] exact={1,2,3};
      byte[] signature=IdentityProtocol.sign(app.getPrivate(),IdentityProtocol.requestDigest(cap,"mail.send",MessageDigest.getInstance("SHA-256").digest(exact),time,nonce));
      assertThrows(IOException.class,()->c.authorizeDigestProof(token,"mail.send",new byte[]{1,2,4},time,nonce,signature));assertEquals(0,f.requests.get());
    }
  }
  @Test void rejectsClearnetAndClosingDisablesFurtherRequests()throws Exception {
    KeyPair pin=keys();assertThrows(IllegalArgumentException.class,()->new IdentityClient600("example.com",80,pin.getPublic().getEncoded(),(h,p,o)->{throw new AssertionError();},Clock.systemUTC()));
    try(Fixture f=new Fixture(Fault.NONE)){IdentityClient600 c=f.client();c.close();assertThrows(IOException.class,()->c.rpc("isActive",new JsonObject()));assertEquals(0,f.requests.get());}
  }
  @Test void outgoingRequestIsBoundedBeforeOpeningSocket()throws Exception {
    try(Fixture f=new Fixture(Fault.NONE);IdentityClient600 c=f.client()){
      JsonObject data=new JsonObject();data.addProperty("large","x".repeat(IdentityProtocol.MAX_BODY));assertThrows(IOException.class,()->c.rpc("register",data));assertEquals(0,f.requests.get());
    }
  }

  static final class Fixture implements AutoCloseable {
    final KeyPair service=keys();final Fault fault;final ServerSocket listener=new ServerSocket(0,8,InetAddress.getByAddress(new byte[]{127,0,0,1}));
    final ExecutorService worker=Executors.newSingleThreadExecutor();final AtomicInteger requests=new AtomicInteger();final Future<?> serving;
    Fixture(Fault fault)throws Exception {this.fault=fault;serving=worker.submit(()->{try(Socket socket=listener.accept()){serve(socket);}catch(IOException ignored){}return null;});}
    IdentityClient600 client(){return new IdentityClient600(ONION,80,service.getPublic().getEncoded(),(h,p,observer)->{assertEquals(ONION,h);assertEquals(80,p);Socket s=new Socket();observer.opened(s);s.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),listener.getLocalPort()),1000);return s;},Clock.systemUTC());}
    String capability(KeyPair app)throws Exception {
      long now=System.currentTimeMillis();IdentityProtocol.Capability c=new IdentityProtocol.Capability(IdentityProtocol.id(service.getPublic().getEncoded()),"b".repeat(64),"c".repeat(64),IdentityProtocol.App.MAIL,7,IdentityProtocol.nonce(),now-1000,now+60000,now+60000,app.getPublic().getEncoded(),Set.of(IdentityProtocol.Scope.MAIL_SEND),new byte[0]);
      return IdentityProtocol.encodeCapability(c.signed(IdentityProtocol.sign(service.getPrivate(),IdentityProtocol.capabilityBytes(c))));
    }
    void serve(Socket socket)throws Exception {
      socket.setSoTimeout(3000);DataInputStream in=new DataInputStream(socket.getInputStream());assertEquals("POST /identity/v1 HTTP/1.1",line(in));int length=0;
      for(;;){String h=line(in);if(h.isEmpty())break;if(h.startsWith("Content-Length:"))length=Integer.parseInt(h.substring(h.indexOf(':')+1).strip());}
      byte[] request=in.readNBytes(length);assertEquals(length,request.length);requests.incrementAndGet();JsonObject received=CommunityJson.parse(request);String nonce=received.get("nonce").getAsString();
      JsonObject result=new JsonObject();result.addProperty("active",true);
      if(received.get("operation").getAsString().equals("authorizeDigest")){
        JsonObject args=received.getAsJsonObject("data");IdentityProtocol.Capability cap=IdentityProtocol.decodeCapability(args.get("capability").getAsString());
        assertTrue(IdentityProtocol.verify(cap.proofKey,IdentityProtocol.requestDigest(cap,args.get("action").getAsString(),IdentityProtocol.unb64(args.get("bodySha256").getAsString(),32),args.get("time").getAsLong(),args.get("nonce").getAsString()),IdentityProtocol.unb64(args.get("proof").getAsString(),64)));
        result=new JsonObject();result.addProperty("accountId",cap.accountId);result.addProperty("deviceId",cap.deviceId);result.addProperty("appId",cap.appId.name());result.addProperty("generation",fault==Fault.WRONG_CONTEXT?cap.generation+1:cap.generation);result.addProperty("leaseUntil",cap.expiresAt);JsonArray scopes=new JsonArray();cap.capabilities.forEach(s->scopes.add(s.name()));result.add("capabilities",scopes);
      }
      JsonObject response=new JsonObject();response.addProperty("ok",fault!=Fault.REJECT);response.add("data",result);
      if(fault==Fault.REJECT){JsonObject error=new JsonObject();error.addProperty("code","DENIED");error.addProperty("message","private arbitrary remote text");response.add("error",error);}
      byte[] body=(fault==Fault.DUPLICATE_JSON?"{\"ok\":true,\"ok\":false,\"data\":{}}":response.toString()).getBytes(StandardCharsets.UTF_8);
      KeyPair signer=fault==Fault.WRONG_KEY?keys():service;String signedNonce=fault==Fault.WRONG_NONCE?IdentityProtocol.nonce():nonce;byte[] signedRequest=fault==Fault.WRONG_REQUEST?new byte[]{1}:request;
      byte[] sig=IdentityProtocol.sign(signer.getPrivate(),IdentityProtocol.response(IdentityProtocol.id(service.getPublic().getEncoded()),signedNonce,signedRequest,body));
      String headers="HTTP/1.1 "+(fault==Fault.REJECT?"403 Forbidden":"200 OK")+"\r\nContent-Length: "+(fault==Fault.TOO_LARGE?IdentityProtocol.MAX_BODY+1:body.length)+"\r\nAEGIS-Signature: "+IdentityProtocol.b64(sig)+"\r\n";
      if(fault==Fault.DUPLICATE_LENGTH)headers+="Content-Length: "+body.length+"\r\n";if(fault==Fault.TRANSFER_ENCODING)headers+="Transfer-Encoding: chunked\r\n";
      socket.getOutputStream().write((headers+"\r\n").getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().write(body);socket.getOutputStream().flush();
    }
    static String line(DataInputStream in)throws IOException {ByteArrayOutputStream b=new ByteArrayOutputStream();for(int n=0;n<8192;n++){int c=in.read();if(c<0)throw new EOFException();if(c=='\r'){if(in.read()!='\n')throw new IOException();return b.toString(StandardCharsets.US_ASCII);}b.write(c);}throw new IOException();}
    @Override public void close()throws IOException {listener.close();worker.shutdownNow();try{assertTrue(worker.awaitTermination(4,TimeUnit.SECONDS));serving.get(1,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}catch(ExecutionException|TimeoutException e){throw new IOException("Transport fixture did not complete",e);}}
  }
}
