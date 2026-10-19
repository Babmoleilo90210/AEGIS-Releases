package org.securemail.client.attachments600;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.lifecycle.DeviceCapabilities;
import org.securemail.client.net.PeerServer;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.*;

/** Real file/vault/AEAD/packet tests. DiskRemote is explicitly a fixture, not Tor or HTTP acceptance. */
class MailAttachmentManager600Test {
  @TempDir Path directory;static final char[] PASS="Mail streaming fixture password".toCharArray();static final String AUDIENCE="a".repeat(64);
  final Identity recipient=Identity.create();final UserInfo peer=new UserInfo(recipient.userId(),"recipient",recipient.publicKey(),null);
  MailAttachmentManager600Test()throws Exception{}
  LocalStore store(String name)throws Exception{return new LocalStore(directory.resolve(name),PASS,Clock.systemUTC(),2_000_000,100_000_000);}
  final class DiskRemote implements MailAttachmentManager600.Remote {
    final Map<String,Path> files=new HashMap<>();final Map<String,AttachmentClient600.RemoteFile> metadata=new HashMap<>();boolean failOnce;int uploads;DiskRemote()throws IOException{Files.createDirectories(directory.resolve("remote"));}
    public void upload(Path cipher,AttachmentClient600.RemoteFile file,BooleanSupplier active,AttachmentClient600.Progress progress)throws IOException{uploads++;if(!active.getAsBoolean())throw new IOException("cancelled");metadata.putIfAbsent(file.transferId(),file);assertEquals(metadata.get(file.transferId()),file,"resume metadata must be immutable including TTL");Path copy=directory.resolve("remote").resolve(file.transferId());if(!Files.exists(copy))Files.copy(cipher,copy);files.put(file.transferId(),copy);progress.measured(Files.size(copy),file.ciphertextBytes());if(failOnce){failOnce=false;throw new IOException("fixture interrupted after durable encrypted upload");}}
    public void download(AttachmentClient600.RemoteFile file,Path partial,BooleanSupplier active,AttachmentClient600.Progress progress)throws IOException{if(!active.getAsBoolean())throw new IOException("cancelled");Files.copy(files.get(file.transferId()),partial,StandardCopyOption.REPLACE_EXISTING);progress.measured(Files.size(partial),file.ciphertextBytes());}
    public void abort(String id){files.remove(id);}public void close(){}
  }
  Path source()throws IOException{Path file=directory.resolve("источник.bin");byte[] bytes=new byte[3*1048576+51];new Random(60).nextBytes(bytes);Files.write(file,bytes);Arrays.fill(bytes,(byte)0);return file;}
  AttachmentFeatures600 features()throws Exception{return AttachmentFeatures600.sign(recipient,AUDIENCE,Secrets.random(32),System.currentTimeMillis());}
  @Test void boundedMetadataCrossesExistingE2eeAndRealStreamingDecrypt()throws Exception {
    Path source=source();var remote=new DiskRemote();try(var sender=store("sender");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true);var manifest=manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(d,t)->{})){
      byte[] encoded=manifest.encode();try(var plain=PlainMessage.streaming("Проверка","Содержимое",new byte[0],null,encoded)){
        assertTrue(plain.encode().length<4000);assertEquals(1,plain.attachmentCount());var automatic=new AutomaticEncryption(Clock.systemUTC());var packet=automatic.encrypt(plain,3600,120000,sender.identity(),"sender",peer);
        assertFalse(new String(packet.ciphertext(),java.nio.charset.StandardCharsets.ISO_8859_1).contains(manifest.files().getFirst().context().transferId()));
        try(var decoded=automatic.decrypt(packet,recipient,100);var received=AttachmentManifest600.decode(decoded.streamingManifest());var target=store("target");var receiver=new MailAttachmentManager600(target,AUDIENCE,remote,()->true)){
          // LocalStore's unrelated root is rejected before requesting the file.
          assertThrows(IOException.class,()->receiver.download(received,received.files().getFirst(),received.ordinaryCandidate(),sender.identity().userId(),directory.resolve("denied"),()->true,(d,t)->{}));
          assertFalse(Files.exists(directory.resolve("denied")));assertEquals("Содержимое",decoded.text());assertEquals(1,decoded.attachmentCount());
        }
        var descriptor=manifest.files().getFirst();byte[] key=AttachmentManifest600.fileKey(manifest.ordinaryCandidate(),descriptor.context().transferId());try(var in=Files.newInputStream(remote.files.get(descriptor.context().transferId()))){StreamingAttachmentCipher.decryptToNewFile(in,directory.resolve("получено.bin"),descriptor.context(),key,descriptor.plaintextSha256(),descriptor.ciphertextSha256(),()->true);}finally{Arrays.fill(key,(byte)0);}assertEquals(-1,Files.mismatch(source,directory.resolve("получено.bin")));
      }finally{Arrays.fill(encoded,(byte)0);}manager.packetPersisted();assertNull(sender.readExtension("mail6-attachment-queue-v1",63000));
    }
  }
  @Test void protectedMasterUsesSamePasswordAndFf1WithoutCandidateSyntaxOracle()throws Exception {
    var remote=new DiskRemote();char[] password="new letter password".toCharArray(),code="234567".toCharArray();try(var sender=store("protected");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true);var manifest=manager.prepareVerified(peer,List.of(source()),120000,password,code,features(),(d,t)->{})){
      assertTrue(manifest.protectedKeys());assertThrows(IOException.class,manifest::ordinaryCandidate);assertThrows(GeneralSecurityException.class,()->LetterEnvelope.open(manifest.keyPayload(),"wrong password".toCharArray()));
      try(var secret=LetterEnvelope.open(manifest.keyPayload(),password)){String candidate=secret.candidate(code),wrong=secret.candidate("765432".toCharArray());assertNotEquals(candidate,wrong);var file=manifest.files().getFirst();byte[] key=AttachmentManifest600.fileKey(candidate,file.context().transferId()),bad=AttachmentManifest600.fileKey(wrong,file.context().transferId());assertEquals(32,bad.length);try(var input=Files.newInputStream(remote.files.get(file.context().transferId()))){assertThrows(IOException.class,()->StreamingAttachmentCipher.decryptToNewFile(input,directory.resolve("wrong-code.bin"),file.context(),bad,file.plaintextSha256(),file.ciphertextSha256(),()->true));}assertFalse(Files.exists(directory.resolve("wrong-code.bin")));try(var input=Files.newInputStream(remote.files.get(file.context().transferId()))){StreamingAttachmentCipher.decryptToNewFile(input,directory.resolve("right-code.bin"),file.context(),key,file.plaintextSha256(),file.ciphertextSha256(),()->true);}finally{Arrays.fill(key,(byte)0);Arrays.fill(bad,(byte)0);}}
    }
  }
  @Test void interruptedUploadQueueSurvivesRealVaultCloseAndKeepsTransferIdAndTtl()throws Exception {
    var remote=new DiskRemote();remote.failOnce=true;Path source=source();String id;byte[] disk;
    try(var sender=store("resume");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true)){assertThrows(IOException.class,()->manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(d,t)->{}));id=remote.files.keySet().iterator().next();disk=Files.readAllBytes(sender.root().resolve("lifecycle/mail6-attachment-queue-v1.enc"));assertFalse(new String(disk,java.nio.charset.StandardCharsets.ISO_8859_1).contains(id));}
    try(var sender=store("resume");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true);var result=manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(d,t)->{})){assertEquals(id,result.files().getFirst().context().transferId());assertEquals(2,remote.uploads);manager.packetPersisted();try(var files=Files.list(sender.root().resolve("attachment-spool6"))){assertEquals(0,files.count());}}
  }
  @Test void changedQueueAndMissingAuthorityDenyBeforeUploadingNewData()throws Exception {
    var remote=new DiskRemote();AtomicBoolean active=new AtomicBoolean(true);Path source=source();try(var sender=store("bounds");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,active::get);var result=manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(d,t)->{})){Path other=directory.resolve("other");Files.write(other,new byte[3]);assertThrows(IOException.class,()->manager.prepareVerified(peer,List.of(other),120000,new char[0],new char[0],features(),(d,t)->{}));assertEquals(1,remote.uploads);active.set(false);assertThrows(IOException.class,()->manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(d,t)->{}));assertThrows(IOException.class,()->manager.features(Secrets.random(32)));}
  }
  @Test void rootSignedFeatureBindsServiceIdentityChallengeAndStrictNewOperation()throws Exception {
    Identity root=Identity.create(),device=Identity.create();UserInfo pinned=new UserInfo(root.userId(),"featurepeer",root.publicKey(),null);byte[] challenge=Secrets.random(32);try(var local=store("features");var server=new PeerServer(0,local,100000,local::accept,c->{try{return DeviceCapabilities.create(root,device,System.currentTimeMillis()+60000,7,c);}catch(Exception e){throw new IllegalStateException(e);}})){
      server.attachmentFeatures(c->{try{return AttachmentFeatures600.sign(root,AUDIENCE,c,System.currentTimeMillis());}catch(Exception e){throw new IllegalStateException(e);}});server.start();
      try(var socket=new Socket(InetAddress.getLoopbackAddress(),server.port());var out=new DataOutputStream(socket.getOutputStream());var in=new DataInputStream(socket.getInputStream())){Binary.header(out);out.writeByte(102);Binary.text(out,"");Binary.bytes(out,challenge);out.flush();Binary.header(in);assertEquals(0,in.readInt());var feature=AttachmentFeatures600.read(in);feature.verify(pinned,AUDIENCE,challenge,System.currentTimeMillis());assertThrows(GeneralSecurityException.class,()->feature.verify(pinned,"b".repeat(64),challenge,System.currentTimeMillis()));assertThrows(GeneralSecurityException.class,()->feature.verify(pinned,AUDIENCE,Secrets.random(32),System.currentTimeMillis()));}
      try(var socket=new Socket(InetAddress.getLoopbackAddress(),server.port());var out=new DataOutputStream(socket.getOutputStream());var in=new DataInputStream(socket.getInputStream())){Binary.header(out);out.writeByte(100);Binary.text(out,"");Binary.bytes(out,challenge);out.flush();Binary.header(in);assertEquals(0,in.readInt());var old=DeviceCapabilities.read(in);old.verify(pinned,challenge,System.currentTimeMillis());assertEquals(7,old.flags());}
    }
    var good=AttachmentFeatures600.sign(root,AUDIENCE,challenge,System.currentTimeMillis());byte[] signature=good.signature();signature[0]^=1;var changed=new AttachmentFeatures600(good.accountId(),good.rootPublic(),good.serviceAudience(),good.maximumBytes(),good.expiresAt(),good.challenge(),signature);assertThrows(GeneralSecurityException.class,()->changed.verify(pinned,AUDIENCE,challenge,System.currentTimeMillis()));
  }
  @Test void manifestBoundsProtectKeysAndPlainMessageRejectsProtectionMismatch()throws Exception {
    var remote=new DiskRemote();try(var sender=store("manifest");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true);var m=manager.prepareVerified(peer,List.of(source()),120000,new char[0],new char[0],features(),(d,t)->{})){
      byte[] encoded=m.encode();assertThrows(IOException.class,()->AttachmentManifest600.decode(Arrays.copyOf(encoded,encoded.length-1)));assertThrows(IOException.class,()->AttachmentManifest600.decode(new byte[AttachmentManifest600.MAX_BYTES+1]));assertThrows(IOException.class,()->PlainMessage.streaming("","",new byte[]{1},null,encoded));assertThrows(IllegalArgumentException.class,()->new AttachmentManifest600(AUDIENCE,false,List.of(m.files().getFirst(),m.files().getFirst()),m.keyPayload()));
      try(var legacy=PlainMessage.text("Старая почта");var decoded=PlainMessage.decode(legacy.encode(),100)){assertFalse(decoded.streamingAttachments());assertEquals(legacy.text(),decoded.text());}
    }
  }
  @Test void actualManagerReceiveChecksAccountThenPublishesVerifiedNewFileAndNeverOverwrites()throws Exception {
    Path source=source();var remote=new DiskRemote();AtomicBoolean permitted=new AtomicBoolean(true);
    try(var sender=store("receive-sender");var recipientStore=store("receive-recipient");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true);var receiver=new MailAttachmentManager600(recipientStore,AUDIENCE,remote,()->true)){
      var user=new UserInfo(recipientStore.identity().userId(),"target",recipientStore.identity().publicKey(),null);var feature=AttachmentFeatures600.sign(recipientStore.identity(),AUDIENCE,Secrets.random(32),System.currentTimeMillis());
      try(var manifest=manager.prepareVerified(user,List.of(source),120000,new char[0],new char[0],feature,(d,t)->{})){
        var file=manifest.files().getFirst();Path destination=directory.resolve("real-received.bin");
        assertThrows(IOException.class,()->receiver.download(manifest,file,manifest.ordinaryCandidate(),"b".repeat(64),destination,()->true,(d,t)->{}));assertFalse(Files.exists(destination));
        assertThrows(IOException.class,()->receiver.download(manifest,file,manifest.ordinaryCandidate(),sender.identity().userId(),destination,permitted::get,(d,t)->permitted.set(false)));assertFalse(Files.exists(destination));permitted.set(true);
        receiver.download(manifest,file,manifest.ordinaryCandidate(),sender.identity().userId(),destination,permitted::get,(d,t)->{});assertEquals(-1,Files.mismatch(source,destination));
        assertThrows(IOException.class,()->receiver.download(manifest,file,manifest.ordinaryCandidate(),sender.identity().userId(),destination,()->true,(d,t)->{}));assertEquals(-1,Files.mismatch(source,destination));
      }
    }
  }
  @Test void realRekeyPreservesEncryptedQueueAndCiphertextSpoolsWithoutCopyingPlaintext()throws Exception {
    Path source=source(),target=directory.resolve("rekeyed");var remote=new DiskRemote();String transfer;char[] next="new vault streaming rekey password".toCharArray();
    try(var sender=store("rekey-source");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true);var manifest=manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(d,t)->{})){transfer=manifest.files().getFirst().context().transferId();sender.rekeyCopy(target,next);assertEquals(Files.size(sender.root().resolve("attachment-spool6/out-"+transfer+".cipher")),Files.size(target.resolve("attachment-spool6/out-"+transfer+".cipher")));}
    try(var rekeyed=new LocalStore(target,next,Clock.systemUTC(),2_000_000,100_000_000);var resumed=new MailAttachmentManager600(rekeyed,AUDIENCE,remote,()->true);var manifest=resumed.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(d,t)->{})){assertEquals(transfer,manifest.files().getFirst().context().transferId());}
  }
  @Test void oversizedSparseSourceAndSymbolicLinksFailBeforeAnyCipherOrNetworkUpload()throws Exception {
    Path huge=directory.resolve("too-big.bin");try(var channel=java.nio.channels.FileChannel.open(huge,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){channel.position(StreamingAttachmentCipher.MAX_PLAINTEXT);channel.write(java.nio.ByteBuffer.wrap(new byte[]{1}));}
    var remote=new DiskRemote();try(var sender=store("max");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true)){assertThrows(IOException.class,()->manager.prepareVerified(peer,List.of(huge),120000,new char[0],new char[0],features(),(d,t)->{}));Path link=directory.resolve("link.bin");Files.createSymbolicLink(link,huge);assertThrows(IOException.class,()->manager.prepareVerified(peer,List.of(link),120000,new char[0],new char[0],features(),(d,t)->{}));assertEquals(0,remote.uploads);}
  }

  @Test void explicitCancellationKeepsEncryptedQueueAndNewAttemptCanResume()throws Exception {
    Path source=source();var remote=new DiskRemote();try(var sender=store("cancel");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true)){
      assertThrows(IOException.class,()->manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(done,total)->manager.cancelCurrent()));assertNotNull(sender.readExtension("mail6-attachment-queue-v1",63000));assertNotNull(manager.features(Secrets.random(32)));String transfer=remote.files.keySet().iterator().next();
      try(var resumed=manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(done,total)->{})){assertEquals(transfer,resumed.files().getFirst().context().transferId());}
    }
  }

  @Test void sourceMutationWithPreservedSizeAndTimestampNeverSendsTheOldSpoolAsNewContent()throws Exception {
    Path source=source();var remote=new DiskRemote();try(var sender=store("source-mutation");var manager=new MailAttachmentManager600(sender,AUDIENCE,remote,()->true);var manifest=manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(d,t)->{})){var timestamp=Files.getLastModifiedTime(source);try(var channel=java.nio.channels.FileChannel.open(source,StandardOpenOption.WRITE)){channel.position(1024);channel.write(java.nio.ByteBuffer.wrap(new byte[]{31,41,59}));}Files.setLastModifiedTime(source,timestamp);assertThrows(IOException.class,()->manager.prepareVerified(peer,List.of(source),120000,new char[0],new char[0],features(),(d,t)->{}));assertEquals(1,remote.uploads);assertNotNull(sender.readExtension("mail6-attachment-queue-v1",63000));}
  }

}
