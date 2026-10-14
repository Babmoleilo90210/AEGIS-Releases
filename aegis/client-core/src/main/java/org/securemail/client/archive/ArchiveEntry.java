package org.securemail.client.archive;

import java.io.*;
import java.util.*;
import org.securemail.protocol.Binary;

/** Decrypted metadata is available only to an unlocked archive session. */
public record ArchiveEntry(String id,String folder,String name,String type,long size,long addedAt,String digest,List<String> tags,boolean favorite,boolean trash){
  public ArchiveEntry {UUID.fromString(id);if(!folder.isEmpty())UUID.fromString(folder);name=label(name,240);if(!Set.of("folder","letter","text","image","pdf","file").contains(type)||size<0||size>EncryptedArchive.MAX_FILE||addedAt<0)throw new IllegalArgumentException("Некорректный объект архива");if(!digest.matches("(?:[a-f0-9]{64})?"))throw new IllegalArgumentException("Некорректный hash");if(tags.size()>32)throw new IllegalArgumentException("Не более 32 тегов");tags=tags.stream().map(s->label(s,48)).distinct().toList();}
  public boolean directory(){return type.equals("folder");}
  public ArchiveEntry metadata(String parent,String title,List<String> labels,boolean pin,boolean deleted){return new ArchiveEntry(id,parent,title,type,size,addedAt,digest,labels,pin,deleted);}
  static String label(String s,int max){if(s==null||s.isBlank()||s.length()>max||s.codePoints().anyMatch(c->Character.isISOControl(c)||c=='/'||c=='\\'))throw new IllegalArgumentException("Недопустимое название");return s.strip();}
  void write(DataOutputStream o)throws IOException {Binary.text(o,id);Binary.text(o,folder);Binary.text(o,name);Binary.text(o,type);o.writeLong(size);o.writeLong(addedAt);Binary.text(o,digest);o.writeInt(tags.size());for(String s:tags)Binary.text(o,s);o.writeBoolean(favorite);o.writeBoolean(trash);}
  static ArchiveEntry read(DataInputStream i)throws IOException {String id=Binary.text(i,36),folder=Binary.text(i,36),name=Binary.text(i,960),type=Binary.text(i,16);long size=i.readLong(),time=i.readLong();String hash=Binary.text(i,64);int n=i.readInt();if(n<0||n>32)throw new IOException("Повреждены теги");List<String>tags=new ArrayList<>();for(int k=0;k<n;k++)tags.add(Binary.text(i,192));try{return new ArchiveEntry(id,folder,name,type,size,time,hash,tags,i.readBoolean(),i.readBoolean());}catch(IllegalArgumentException invalid){throw new IOException("Повреждены метаданные архива",invalid);}}
  @Override public String toString(){return "ArchiveEntry[redacted]";}
}
