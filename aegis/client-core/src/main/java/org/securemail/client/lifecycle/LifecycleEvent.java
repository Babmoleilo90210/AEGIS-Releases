package org.securemail.client.lifecycle;

import java.io.*;
import java.security.*;
import java.util.*;
import org.securemail.client.crypto.Identity;
import org.securemail.protocol.*;

/** Inner signed events, transported as ordinary E2EE. No plaintext reaches the relay. */
public record LifecycleEvent(String id,int kind,String owner,String target,long createdAt,byte[] payload,DeviceCapabilities capabilities,byte[] signature) {
  public static final int CONSENT=1,DELIVERED=2,DISPLAYED=3,ACK=4;
  public static final String PREFIX="AEGIS-LIFECYCLE-E2EE-v1:";
  public LifecycleEvent {Limits.messageId(id);Limits.userId(owner);Limits.userId(target);if(owner.equals(target)||kind<1||kind>4||createdAt<1||payload.length>4096||signature.length!=0&&signature.length!=64)throw new IllegalArgumentException("Lifecycle event fields");payload=payload.clone();signature=signature.clone();}
  public byte[] payload(){return payload.clone();}public byte[] signature(){return signature.clone();}
  private void unsigned(DataOutput o)throws IOException {Binary.text(o,id);o.writeInt(kind);Binary.text(o,owner);Binary.text(o,target);o.writeLong(createdAt);Binary.bytes(o,payload);capabilities.write(o);}
  public byte[] signingBytes()throws IOException{return Binary.encode(o->{Binary.text(o,"AEGIS-LIFECYCLE-EVENT-v1");unsigned(o);});}
  public byte[] semanticDigest()throws IOException,GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(Binary.encode(o->{Binary.text(o,id);o.writeInt(kind);Binary.text(o,owner);Binary.text(o,target);o.writeLong(createdAt);Binary.bytes(o,payload);}));}
  public static LifecycleEvent create(Identity owner,String target,long now,int kind,byte[] payload,DeviceCapabilities caps)throws IOException,GeneralSecurityException {var e=new LifecycleEvent(UUID.randomUUID().toString(),kind,owner.userId(),target,now,payload,caps,new byte[0]);return new LifecycleEvent(e.id,kind,e.owner,target,now,payload,caps,owner.sign(e.signingBytes()));}
  public void verify(EncryptedPacket outer,long now)throws IOException,GeneralSecurityException {
    UserInfo ownerInfo=new UserInfo(outer.senderId(),outer.senderNickname(),outer.senderPublicKey(),null);
    capabilities.verify(ownerInfo,null,Math.min(now,outer.createdAt()));
    if(!owner.equals(outer.senderId())||!target.equals(outer.recipientId())||createdAt>now+300_000||!Identity.verify(outer.senderPublicKey(),signingBytes(),signature))throw new GeneralSecurityException("Lifecycle event origin rejected");
  }
  public byte[] encode()throws IOException{return Binary.encode(o->{o.writeInt(1);unsigned(o);Binary.bytes(o,signature);});}
  public byte[] text()throws IOException{return (PREFIX+Base64.getEncoder().encodeToString(encode())).getBytes(java.nio.charset.StandardCharsets.US_ASCII);}
  public static LifecycleEvent decode(byte[] data)throws IOException {if(data.length>8192)throw new IOException("Event quota");try(var i=new DataInputStream(new ByteArrayInputStream(data))){if(i.readInt()!=1)throw new IOException("Event schema");var event=new LifecycleEvent(Binary.text(i,36),i.readInt(),Binary.text(i,64),Binary.text(i,64),i.readLong(),Binary.bytes(i,4096),DeviceCapabilities.read(i),Binary.bytes(i,64));Binary.end(i);return event;}catch(IllegalArgumentException bad){throw new IOException("Invalid lifecycle event",bad);}}
  public static LifecycleEvent fromText(byte[] text)throws IOException {if(text.length>PREFIX.length()+12000)return null;String s=new String(text,java.nio.charset.StandardCharsets.US_ASCII);if(!s.startsWith(PREFIX))return null;try{return decode(Base64.getDecoder().decode(s.substring(PREFIX.length())));}catch(IllegalArgumentException bad){throw new IOException("Invalid event encoding",bad);}}
}
