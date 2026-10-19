package org.securemail.client.ecosystem;

import java.io.*;
import java.security.GeneralSecurityException;
import java.util.*;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.Limits;

/** Local encrypted unread-ID set. Only its integer count crosses Core IPC, never names, IDs or message bodies. */
public final class MailNotificationCounter600 {
  private static final String NAME="ecosystem6-unread-v1";private final LocalStore store;private final Set<String> unread=new TreeSet<>();
  public MailNotificationCounter600(LocalStore store)throws IOException,GeneralSecurityException {
    this.store=Objects.requireNonNull(store);byte[] data=store.readExtension(NAME,400000);if(data==null)return;
    try(var input=new DataInputStream(new ByteArrayInputStream(data))){if(input.readInt()!=1)throw new IOException("Некорректная очередь уведомлений");int count=input.readInt();if(count<0||count>8192)throw new IOException("Очередь уведомлений слишком велика");for(int index=0;index<count;index++){String id=input.readUTF();Limits.messageId(id);if(!unread.add(id))throw new IOException("Повторное уведомление");}if(input.read()!=-1)throw new IOException("Лишние данные уведомлений");}
    catch(IllegalArgumentException e){throw new IOException("Некорректная очередь уведомлений",e);}finally{Arrays.fill(data,(byte)0);}
  }
  public synchronized int add(Collection<String> messageIds)throws IOException,GeneralSecurityException {Set<String> next=new TreeSet<>(unread);for(String id:messageIds){Limits.messageId(id);next.add(id);}if(next.size()>8192)throw new IOException("Очередь уведомлений заполнена");if(!next.equals(unread)){save(next);unread.clear();unread.addAll(next);}return unread.size();}
  public synchronized int read(String id)throws IOException,GeneralSecurityException {Limits.messageId(id);if(unread.contains(id)){Set<String> next=new TreeSet<>(unread);next.remove(id);save(next);unread.remove(id);}return unread.size();}
  public synchronized int count(){return unread.size();}
  private void save(Set<String> values)throws IOException,GeneralSecurityException {var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.writeInt(1);out.writeInt(values.size());for(String id:values)out.writeUTF(id);byte[] encoded=bytes.toByteArray();try{store.writeExtension(NAME,encoded,400000);}finally{Arrays.fill(encoded,(byte)0);}}
}
