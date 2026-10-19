package org.securemail.client.voice600;

import java.io.*;
import java.util.*;
import org.securemail.glas.protocol600.GlasProtocol600;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.protocol.*;

/** Public Mail-approved voice delegation and exact pinned contact export. Never contains account private keys or audio. */
public final class GlasGrant600 {
  public static final byte[] CONSENT_BODY="AEGIS-MAIL-VOICE-CONSENT/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
  public record Contact(UserInfo user,boolean blocked){public Contact{Objects.requireNonNull(user);if(!IdentityProtocol.id(user.publicKey()).equals(user.userId()))throw new IllegalArgumentException("Контакт не соответствует ключу");user=new UserInfo(user.userId(),user.nickname(),user.publicKey(),null);}}
  private final GlasProtocol600.Delegation delegation;private final List<Contact> contacts;private final byte[] signature;
  public GlasGrant600(GlasProtocol600.Delegation delegation,List<Contact> contacts,byte[] mailSignature){
    this.delegation=Objects.requireNonNull(delegation);if(contacts==null||contacts.size()>256||mailSignature==null||mailSignature.length!=64)throw new IllegalArgumentException("Размер списка контактов Гласа");
    Set<String> ids=new HashSet<>(),names=new HashSet<>();List<Contact> sorted=new ArrayList<>(contacts);sorted.sort(Comparator.comparing(c->c.user().userId()));
    for(Contact c:sorted)if(!ids.add(c.user().userId())||!names.add(c.user().nickname())||c.user().userId().equals(delegation.accountId()))throw new IllegalArgumentException("Некорректный контакт Гласа");this.contacts=List.copyOf(sorted);signature=mailSignature.clone();
  }
  public GlasProtocol600.Delegation delegation(){return delegation;}public List<Contact> contacts(){return contacts;}
  public byte[] signingBytes()throws IOException{return Binary.encode(out->{Binary.text(out,"AEGIS-GLAS-CONTACTS/v1");Binary.bytes(out,GlasProtocol600.sha256Delegation(delegation));out.writeInt(contacts.size());for(Contact c:contacts){c.user().write(out);out.writeBoolean(c.blocked());}});}
  public GlasGrant600 signed(byte[] mailSignature){return new GlasGrant600(delegation,contacts,mailSignature);}
  public boolean verify(byte[] pinnedRoot,String identityAudience,long now)throws IOException{return GlasProtocol600.verifyDelegation(delegation,pinnedRoot,identityAudience,now)&&IdentityProtocol.verify(pinnedRoot,signingBytes(),signature);}
  public byte[] encode()throws IOException{byte[] result=Binary.encode(out->{Binary.text(out,"AEGIS-GLAS-GRANT/v1");Binary.bytes(out,delegation.encode());out.writeInt(contacts.size());for(Contact c:contacts){c.user().write(out);out.writeBoolean(c.blocked());}Binary.bytes(out,signature);});if(result.length>65536)throw new IOException("Список контактов Гласа слишком велик");return result;}
  public static GlasGrant600 decode(byte[] wire)throws IOException{if(wire.length<1||wire.length>65536)throw new IOException("Размер допуска Гласа");try(var in=new DataInputStream(new ByteArrayInputStream(wire))){if(!Binary.text(in,64).equals("AEGIS-GLAS-GRANT/v1"))throw new IOException("Тип допуска Гласа");var d=GlasProtocol600.decodeDelegation(Binary.bytes(in,1024));int n=in.readInt();if(n<0||n>256)throw new IOException("Размер контактов Гласа");List<Contact> contacts=new ArrayList<>();for(int i=0;i<n;i++)contacts.add(new Contact(UserInfo.read(in),in.readBoolean()));var result=new GlasGrant600(d,contacts,Binary.bytes(in,64));Binary.end(in);if(!java.security.MessageDigest.isEqual(wire,result.encode()))throw new IOException("Порядок допуска Гласа");return result;}catch(IllegalArgumentException invalid){throw new IOException("Недействительный допуск Гласа",invalid);}}
}
