package org.aegis.android;

import android.content.Context;
import android.security.keystore.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;

/** Per-UID Android Keystore wrapping key; no shared/external files or key-export RPC. */
final class PrivateVault {
    private final Context context;private final String alias;
    PrivateVault(Context c){context=c.getApplicationContext();alias=c.getPackageName()+".vault.v1";}
    private javax.crypto.SecretKey key()throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
        if(!store.containsAlias(alias)){KeyGenerator gen=KeyGenerator.getInstance("AES","AndroidKeyStore");gen.init(new KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build());gen.generateKey();}
        return (javax.crypto.SecretKey)store.getKey(alias,null);
    }
    private File file(String name){if(!name.matches("[a-z0-9_-]{1,48}"))throw new IllegalArgumentException("Имя записи");return new File(context.getNoBackupFilesDir(),name+".gcm");}
    synchronized void put(String name,byte[] plain)throws Exception {
        if(plain.length>262144)throw new IOException("Локальная запись больше 256 КиБ");Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key());if(cipher.getIV().length!=12)throw new GeneralSecurityException("Неподдерживаемый IV GCM");cipher.updateAAD((context.getPackageName()+"/"+name+"/v1").getBytes(StandardCharsets.UTF_8));byte[] encrypted=cipher.doFinal(plain);File target=file(name),temp=new File(target+".new");
        try(FileOutputStream out=new FileOutputStream(temp)){out.write(1);out.write(cipher.getIV());out.write(encrypted);out.getFD().sync();}finally{Arrays.fill(encrypted,(byte)0);}
        if(!temp.renameTo(target)){temp.delete();throw new IOException("Не удалось атомарно сохранить запись");}
    }
    synchronized byte[] get(String name)throws Exception {
        File f=file(name);if(!f.exists())return null;if(f.length()<30||f.length()>262174)throw new IOException("Повреждённая локальная запись");byte[] all;
        try(InputStream in=new FileInputStream(f)){all=in.readAllBytes();}
        try{if(all[0]!=1)throw new IOException("Версия локального формата");Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,Arrays.copyOfRange(all,1,13)));cipher.updateAAD((context.getPackageName()+"/"+name+"/v1").getBytes(StandardCharsets.UTF_8));return cipher.doFinal(all,13,all.length-13);}
        finally{Arrays.fill(all,(byte)0);}
    }
    synchronized void remove(String name)throws IOException{File f=file(name);if(f.exists()&&!f.delete())throw new IOException("Не удалось удалить локальную запись");}
    synchronized byte[] appPublicKey()throws Exception {return pair("app-proof-key").getPublic().getEncoded();}
    synchronized byte[] prove(byte[] bytes)throws Exception {return sign("app-proof-key",bytes);}
    synchronized byte[] devicePublicKey()throws Exception {coreOnly();return pair("device-auth-key").getPublic().getEncoded();}
    synchronized byte[] deviceProof(byte[] bytes)throws Exception {coreOnly();return sign("device-auth-key",bytes);}
    synchronized byte[] networkPublicKey()throws Exception{coreOnly();return pair("network-proof-key").getPublic().getEncoded();}
    synchronized byte[] networkProof(byte[] canonical)throws Exception{coreOnly();return sign("network-proof-key",canonical);}
    synchronized org.securemail.client.voice.AndroidVoiceTls.Pending voiceTls(org.securemail.glas.protocol600.GlasProtocol600.Delegation delegation,java.util.UUID call,org.securemail.client.voice.AndroidVoiceTls.Role role,byte[] peer,String audience)throws Exception {if(!AndroidPolicy.GLAS.equals(context.getPackageName()))throw new SecurityException("Ключ звонка доступен только Гласу");return org.securemail.client.voice.AndroidVoiceTls.createDelegated(delegation,pair("app-proof-key").getPrivate(),call,role,peer,audience);}
    private void coreOnly(){if(!AndroidPolicy.CORE.equals(context.getPackageName()))throw new SecurityException("Ключ устройства доступен только главному приложению");}
    private byte[] sign(String keyName,byte[] bytes)throws Exception{if(bytes==null||bytes.length>65536)throw new SecurityException("Размер доказательства");java.security.Signature signature=java.security.Signature.getInstance("Ed25519");signature.initSign(pair(keyName).getPrivate());signature.update(bytes);return signature.sign();}
    private KeyPair pair(String keyName)throws Exception {
        byte[] saved=get(keyName);
        try{if(saved!=null){try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(saved))){int n=in.readUnsignedShort();if(n!=44)throw new IOException("Ключ приложения");byte[] pub=new byte[n];in.readFully(pub);n=in.readUnsignedShort();if(n<32||n>256)throw new IOException("Ключ приложения");byte[] secret=new byte[n];in.readFully(secret);if(in.read()!=-1)throw new IOException("Ключ приложения");try{KeyFactory k=KeyFactory.getInstance("Ed25519");return new KeyPair(k.generatePublic(new java.security.spec.X509EncodedKeySpec(pub)),k.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(secret)));}finally{Arrays.fill(secret,(byte)0);}}}
            KeyPair pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();byte[] secret=pair.getPrivate().getEncoded();try{ByteArrayOutputStream b=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(b)){out.writeShort(pair.getPublic().getEncoded().length);out.write(pair.getPublic().getEncoded());out.writeShort(secret.length);out.write(secret);}byte[] record=b.toByteArray();try{put(keyName,record);}finally{Arrays.fill(record,(byte)0);}return pair;}finally{Arrays.fill(secret,(byte)0);}
        }finally{if(saved!=null)Arrays.fill(saved,(byte)0);}
    }
}
