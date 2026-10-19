package org.securemail.community.agent;

import org.securemail.community.protocol.CommunityAuth;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/** Separate service protocol; neither user app capabilities nor legacy Community requests. */
public final class WorkerWire600 {
  public static final String PATH="/agent-worker/v6";
  public static final int MAX_BODY=262144;
  public static final Set<String> ACTIONS=Set.of("agent.worker.claim","agent.worker.complete","agent.worker.fail");
  private WorkerWire600(){}
  /** A public worker key must never alias an account identity using the same key. */
  public static String serviceActor(byte[] publicKey)throws IOException {
    if(publicKey==null||publicKey.length!=44)throw new IOException("Worker public key");
    byte[] domain="AEGIS-NEWS-WORKER-SERVICE/v6".getBytes(StandardCharsets.US_ASCII);
    byte[] input=new byte[domain.length+publicKey.length];System.arraycopy(domain,0,input,0,domain.length);System.arraycopy(publicKey,0,input,domain.length,publicKey.length);
    return CommunityAuth.id(input);
  }
  public static byte[] requestBytes(String audience,long time,String nonce,byte[]body)throws IOException {
    return canonical("AEGIS-NEWS-WORKER-REQUEST/v6",audience,time,nonce,CommunityAuth.id(body),"");
  }
  public static byte[] responseBytes(String audience,String nonce,byte[]request,byte[]body)throws IOException {
    return canonical("AEGIS-NEWS-WORKER-RESPONSE/v6",audience,0,nonce,CommunityAuth.id(request),CommunityAuth.id(body));
  }
  private static byte[] canonical(String domain,String audience,long time,String nonce,String digest,String response)throws IOException {
    if(!audience.matches("[a-f0-9]{64}")||!nonce.matches("[A-Za-z0-9_-]{43}")||time<0)throw new IOException("Worker context");
    ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(bytes)){for(String s:new String[]{domain,audience,nonce,digest,response}){byte[]utf=s.getBytes(StandardCharsets.US_ASCII);out.writeInt(utf.length);out.write(utf);}out.writeLong(time);}return bytes.toByteArray();
  }
}
