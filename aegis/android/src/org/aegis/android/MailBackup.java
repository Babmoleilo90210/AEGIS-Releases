package org.aegis.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.crypto.Secrets;
import org.securemail.protocol.*;

/** Read-only exact desktop AEB1/AEB2 account backup importer; never changes the source. */
final class MailBackup implements AutoCloseable {
    final Identity identity;final String nickname;final List<UserInfo> contacts;
    private MailBackup(Identity i,String n,List<UserInfo> c){identity=i;nickname=n;contacts=List.copyOf(c);}
    static MailBackup read(InputStream source,char[] password,String expectedAccount)throws Exception {
        Limits.userId(expectedAccount);byte[] encoded=readBounded(source,2*1024*1024+128),key=null,plain=null,secret=null;
        try(DataInputStream input=new DataInputStream(new ByteArrayInputStream(encoded))){
            int magic=input.readInt();if(magic!=0x41454231&&magic!=0x41454232)throw new IOException("Нужна защищённая резервная копия AEB1/AEB2");byte[] salt=Binary.bytes(input,16),sealed=Binary.bytes(input,2*1024*1024);Binary.end(input);if(salt.length!=16||sealed.length<28)throw new IOException("Повреждённая резервная копия");
            key=magic==0x41454232?Secrets.deriveVault(password,salt):Secrets.derive(password,salt);Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,sealed,0,12));c.updateAAD("state/v1".getBytes(StandardCharsets.US_ASCII));plain=c.doFinal(sealed,12,sealed.length-12);
            try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(plain))){
                if(in.readInt()!=1)throw new IOException("Неподдерживаемый формат identity");byte[] pub=Binary.bytes(in,44);secret=Binary.bytes(in,128);Identity identity=Identity.restore(pub,secret);if(!identity.userId().equals(expectedAccount))throw new SecurityException("Резервная копия относится к другому аккаунту");String nick=Binary.text(in,32);if(!nick.isEmpty())Limits.nickname(nick);if(in.readLong()<0)throw new IOException("Время резервной копии");
                int count=in.readInt();if(count<0||count>32)throw new IOException("Слишком много контактов");List<UserInfo> contacts=new ArrayList<>();Set<String> names=new HashSet<>();for(int i=0;i<count;i++){UserInfo u=UserInfo.read(in);if(!u.userId().equals(Identity.id(u.publicKey()))||!names.add(u.nickname()))throw new IOException("Повреждённый контакт");contacts.add(u);}
                int seen=in.readInt();if(seen<0||seen>8192)throw new IOException("Повреждённая история доставки");for(int i=0;i<seen;i++){Limits.messageId(Binary.text(in,36));if(Binary.bytes(in,32).length!=32)throw new IOException("Повреждённый digest");if(in.readLong()<0||in.readLong()<0)throw new IOException("Повреждённый срок");}Binary.end(in);return new MailBackup(identity,nick,contacts);
            }
        }finally{Arrays.fill(encoded,(byte)0);if(key!=null)Arrays.fill(key,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);if(secret!=null)Arrays.fill(secret,(byte)0);Arrays.fill(password,'\0');}
    }
    static byte[] readBounded(InputStream in,int max)throws IOException{ByteArrayOutputStream b=new ByteArrayOutputStream();byte[] buf=new byte[16384];int total=0;for(int n;(n=in.read(buf))!=-1;){total+=n;if(total>max)throw new IOException("Файл превышает допустимый размер");b.write(buf,0,n);}Arrays.fill(buf,(byte)0);return b.toByteArray();}
    public void close(){/* Provider-held private key objects remain subject to JVM garbage collection. */}
}
