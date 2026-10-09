package org.securemail.protocol;

import java.io.*;
import java.util.*;

/** Optional protocol-1 public data. The owner's signature covers all fields. */
public record PublicProfile(String userId,String nickname,long revision,boolean visible,
    String about,byte[] avatar,byte[] publicKey,byte[] signature) {
  public static final int MAX_AVATAR=1024*1024,MAX_ENCODED=MAX_AVATAR+4096;
  public PublicProfile {
    Limits.userId(userId);nickname=Limits.nickname(nickname);
    if(revision<1||about.length()>500||publicKey.length!=44||avatar.length>MAX_AVATAR
        ||signature.length!=0&&signature.length!=64||!visible&&(!about.isEmpty()||avatar.length!=0)
        ||about.codePoints().anyMatch(c->Character.isISOControl(c)&&c!='\n'))throw new IllegalArgumentException("Invalid public profile");
    avatar=avatar.clone();publicKey=publicKey.clone();signature=signature.clone();
  }
  public byte[] avatar(){return avatar.clone();}public byte[] publicKey(){return publicKey.clone();}public byte[] signature(){return signature.clone();}
  public byte[] signingBytes()throws IOException{return Binary.encode(o->{Binary.text(o,"AEGIS-PUBLIC-PROFILE-v1");unsigned(o);});}
  private void unsigned(DataOutput out)throws IOException{
    Binary.text(out,userId);Binary.text(out,nickname);out.writeLong(revision);out.writeBoolean(visible);
    Binary.text(out,about);Binary.bytes(out,avatar);Binary.bytes(out,publicKey);
  }
  public void write(DataOutput out)throws IOException{out.writeInt(1);unsigned(out);Binary.bytes(out,signature);}
  public static PublicProfile read(DataInput in)throws IOException{
    if(in.readInt()!=1)throw new IOException("Unsupported profile version");
    try{return new PublicProfile(Binary.text(in,64),Binary.text(in,32),in.readLong(),in.readBoolean(),Binary.text(in,2000),Binary.bytes(in,MAX_AVATAR),Binary.bytes(in,44),Binary.bytes(in,64));}
    catch(IllegalArgumentException invalid){throw new IOException("Invalid public profile",invalid);}
  }
}
