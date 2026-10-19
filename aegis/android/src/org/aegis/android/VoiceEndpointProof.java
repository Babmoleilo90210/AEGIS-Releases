package org.aegis.android;
import java.io.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
/** Typed public proof of control of one loopback listener; never a generic signing oracle. */
public final class VoiceEndpointProof {
  public static final int OPERATION=102;
  private VoiceEndpointProof(){}
  public static byte[] canonical(IdentityProtocol.Capability cap,int port,String nonce)throws IOException {
    if(cap.appId!=IdentityProtocol.App.GLAS||!cap.capabilities.contains(IdentityProtocol.Scope.VOICE_CALL)||port<1||port>65535)throw new IOException("Недействительный голосовой адрес");
    IdentityProtocol.nonceValue(nonce);ByteArrayOutputStream b=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(b);
    out.writeUTF("AEGIS-ANDROID-GLAS-LISTENER/v1");out.writeUTF(cap.audience);out.writeUTF(cap.accountId);out.writeUTF(cap.deviceId);out.writeLong(cap.generation);out.writeUTF(cap.tokenId);out.write(cap.proofKey);out.writeInt(port);out.writeUTF(nonce);out.flush();return b.toByteArray();
  }
}
