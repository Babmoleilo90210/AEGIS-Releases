package org.securemail.client.attachments600;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.securemail.client.crypto.*;
import org.securemail.protocol.Binary;

/** Bounded metadata carried ONLY inside the existing signed E2EE mail payload. */
public final class AttachmentManifest600 implements AutoCloseable {
  public static final int MAX_BYTES=62000;
  public record File(String name,StreamingAttachmentCipher.Context context,long ciphertextBytes,String plaintextSha256,String ciphertextSha256,long expiresAt,long ttlMillis) {
    public File { PlainMessage.validateFilename(name);Objects.requireNonNull(context);if(ciphertextBytes<56||ciphertextBytes>StreamingAttachmentCipher.MAX_PLAINTEXT+1048576||!digest(plaintextSha256)||!digest(ciphertextSha256)||expiresAt<1||ttlMillis<60000||ttlMillis>30L*86400000)throw new IllegalArgumentException("Некорректное потоковое вложение");try{if(ciphertextBytes!=StreamingAttachmentCipher.ciphertextSize(context.plaintextBytes()))throw new IllegalArgumentException("Размер шифротекста");}catch(GeneralSecurityException e){throw new IllegalArgumentException(e);} }
    public AttachmentClient600.RemoteFile remote(long now){return new AttachmentClient600.RemoteFile(context.transferId(),context.recipientId(),ciphertextBytes,ciphertextSha256,ttlMillis);}
  }
  private final String audience;private final boolean protectedKeys;private final List<File> files;private final byte[] keyPayload;
  public AttachmentManifest600(String audience,boolean protectedKeys,List<File> files,byte[] keyPayload){
    if(!digest(audience)||files.isEmpty()||files.size()>64||keyPayload.length>(protectedKeys?LetterEnvelope.MAX_BYTES:32)||(!protectedKeys&&keyPayload.length!=32)||protectedKeys&&keyPayload.length<64)throw new IllegalArgumentException("Манифест вложений");
    long total=0;Set<String> names=new HashSet<>(),ids=new HashSet<>();String sender=files.getFirst().context.senderId(),recipient=files.getFirst().context.recipientId();for(var f:files){total=Math.addExact(total,f.context.plaintextBytes());if(total>StreamingAttachmentCipher.MAX_PLAINTEXT||!names.add(f.name.toLowerCase(Locale.ROOT))||!ids.add(f.context.transferId())||!sender.equals(f.context.senderId())||!recipient.equals(f.context.recipientId()))throw new IllegalArgumentException("Лимит вложений");}
    this.audience=audience;this.protectedKeys=protectedKeys;this.files=List.copyOf(files);this.keyPayload=keyPayload.clone();
  }
  public String audience(){return audience;}public boolean protectedKeys(){return protectedKeys;}public List<File> files(){return files;}public byte[] keyPayload(){return keyPayload.clone();}
  public byte[] encode()throws IOException {byte[] result=Binary.encode(o->{o.writeInt(1);Binary.text(o,audience);o.writeBoolean(protectedKeys);Binary.bytes(o,keyPayload);o.writeInt(files.size());for(var f:files){Binary.text(o,f.name);Binary.text(o,f.context.transferId());Binary.text(o,f.context.senderId());Binary.text(o,f.context.recipientId());o.writeLong(f.context.plaintextBytes());o.writeLong(f.ciphertextBytes);Binary.text(o,f.plaintextSha256);Binary.text(o,f.ciphertextSha256);o.writeLong(f.expiresAt);o.writeLong(f.ttlMillis);}});if(result.length>MAX_BYTES){Arrays.fill(result,(byte)0);throw new IOException("Слишком много метаданных вложений");}return result;}
  public static AttachmentManifest600 decode(byte[] bytes)throws IOException {if(bytes.length>MAX_BYTES)throw new IOException("Размер манифеста");byte[] key=null;try(var i=new DataInputStream(new ByteArrayInputStream(bytes))){if(i.readInt()!=1)throw new IOException("Версия вложения");String audience=Binary.text(i,64);boolean protectedKeys=i.readBoolean();key=Binary.bytes(i,LetterEnvelope.MAX_BYTES);int n=i.readInt();if(n<1||n>64)throw new IOException("Число вложений");List<File> files=new ArrayList<>();for(int x=0;x<n;x++){String name=Binary.text(i,800),id=Binary.text(i,36),sender=Binary.text(i,64),recipient=Binary.text(i,64);long plain=i.readLong(),cipher=i.readLong();files.add(new File(name,new StreamingAttachmentCipher.Context(id,sender,recipient,plain),cipher,Binary.text(i,64),Binary.text(i,64),i.readLong(),i.readLong()));}Binary.end(i);return new AttachmentManifest600(audience,protectedKeys,files,key);}catch(IllegalArgumentException|ArithmeticException e){throw new IOException("Некорректное вложение",e);}finally{if(key!=null)Arrays.fill(key,(byte)0);}}
  /** Every FF1 candidate yields a key. No correctness or syntax oracle is added to FF1. */
  public static byte[] fileKey(String candidate,String transferId)throws GeneralSecurityException {
    byte[] ikm=candidate.getBytes(StandardCharsets.UTF_8),salt="AEGIS-STREAMED-FILE-MASTER/v1".getBytes(StandardCharsets.US_ASCII),prk=null;
    try{Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(salt,"HmacSHA256"));prk=mac.doFinal(ikm);mac.init(new SecretKeySpec(prk,"HmacSHA256"));mac.update(("AEGIS-STREAMED-FILE/v1/"+UUID.fromString(transferId)).getBytes(StandardCharsets.US_ASCII));mac.update((byte)1);return mac.doFinal();}finally{Arrays.fill(ikm,(byte)0);if(prk!=null)Arrays.fill(prk,(byte)0);}
  }
  public String ordinaryCandidate()throws IOException{if(protectedKeys)throw new IOException("Сначала откройте защищённое письмо");return HexFormat.of().formatHex(keyPayload);}
  private static boolean digest(String x){return x!=null&&x.matches("[a-f0-9]{64}");}
  @Override public void close(){Arrays.fill(keyPayload,(byte)0);}
  @Override public String toString(){return "AttachmentManifest600[redacted]";}
}
