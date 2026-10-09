package org.securemail.protocol;

import java.io.*;

/** Signed directional contact consent. Mutual active assertions establish friendship. */
public record ContactAssertion(String ownerId,String targetId,long revision,boolean active,
    byte[] publicKey,byte[] signature) {
  public ContactAssertion{
    Limits.userId(ownerId);Limits.userId(targetId);
    if(ownerId.equals(targetId)||revision<1||publicKey.length!=44||signature.length!=0&&signature.length!=64)throw new IllegalArgumentException("Invalid contact assertion");
    publicKey=publicKey.clone();signature=signature.clone();
  }
  public byte[] publicKey(){return publicKey.clone();}public byte[] signature(){return signature.clone();}
  private void unsigned(DataOutput out)throws IOException{Binary.text(out,ownerId);Binary.text(out,targetId);out.writeLong(revision);out.writeBoolean(active);Binary.bytes(out,publicKey);}
  public byte[] signingBytes()throws IOException{return Binary.encode(o->{Binary.text(o,"AEGIS-CONTACT-ASSERTION-v1");unsigned(o);});}
  public void write(DataOutput out)throws IOException{out.writeInt(1);unsigned(out);Binary.bytes(out,signature);}
  public static ContactAssertion read(DataInput in)throws IOException{
    if(in.readInt()!=1)throw new IOException("Unsupported contact assertion");
    try{return new ContactAssertion(Binary.text(in,64),Binary.text(in,64),in.readLong(),in.readBoolean(),Binary.bytes(in,44),Binary.bytes(in,64));}
    catch(IllegalArgumentException failure){throw new IOException("Invalid contact assertion",failure);}
  }
}
