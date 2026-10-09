package org.securemail.client.crypto;

import java.io.*;
import org.securemail.protocol.*;

/** Encrypted reply/forward references. Quotes are assertions by the replying author. */
public record MailContext(String threadId,String parentId,String author,String subject,long time,
    long expiresAt,byte[] digest,boolean forwarded) {
  public MailContext{
    if(!threadId.isEmpty())Limits.messageId(threadId);Limits.messageId(parentId);author=Limits.nickname(author);
    if(subject.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>1024||time<0||expiresAt<time||digest.length!=32)throw new IllegalArgumentException("Invalid reply reference");digest=digest.clone();
  }
  public byte[] digest(){return digest.clone();}
  void write(DataOutput out)throws IOException{Binary.text(out,threadId);Binary.text(out,parentId);Binary.text(out,author);Binary.text(out,subject);out.writeLong(time);out.writeLong(expiresAt);Binary.bytes(out,digest);out.writeBoolean(forwarded);}
  static MailContext read(DataInput in)throws IOException{try{return new MailContext(Binary.text(in,36),Binary.text(in,36),Binary.text(in,32),Binary.text(in,1024),in.readLong(),in.readLong(),Binary.bytes(in,32),in.readBoolean());}catch(IllegalArgumentException invalid){throw new IOException("Invalid mail reference",invalid);}}
}
