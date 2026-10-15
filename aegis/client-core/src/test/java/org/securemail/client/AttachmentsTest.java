package org.securemail.client;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.protocol.*;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.enums.*;
class AttachmentsTest {
 @TempDir Path root;
 static final char[] PASSWORD="letter-password-1000".toCharArray(),CODE="ff1-code-1000".toCharArray();
 @Test void arbitraryTypesMultipleFilesEndToEndAndAesZip()throws Exception{
  List<Path> paths=new ArrayList<>();Map<String,byte[]> originals=new LinkedHashMap<>();
  for(String name:List.of("test.txt","document.pdf","photo.jpg","spreadsheet.xlsx","video.mp4","random.bin")){byte[] b=Secrets.random(3000);Path p=root.resolve(name);Files.write(p,b);paths.add(p);originals.put(name,b);}
  Identity a=Identity.create(),b=Identity.create();byte[] envelope=LetterEnvelope.seal("Protected attachments",PASSWORD,CODE);var crypto=new AutomaticEncryption(Clock.systemUTC());EncryptedPacket packet;
  try(var plain=PlainMessage.letterWithAttachments("Files",envelope,paths,20000)){packet=crypto.encrypt(plain,300,60000,a,"raven",new UserInfo(b.userId(),"blackfox",b.publicKey(),null));}
  String wire=new String(PacketCodec.encode(packet),java.nio.charset.StandardCharsets.ISO_8859_1);assertFalse(wire.contains("document.pdf"));assertFalse(wire.contains(new String(PASSWORD)));assertFalse(wire.contains(new String(CODE)));
  Path zip=root.resolve("attachments.zip");
  try(var plain=crypto.decrypt(packet,b,20000);var opened=LetterEnvelope.open(plain.letterEnvelope(),PASSWORD)){assertEquals("Protected attachments",opened.candidate(CODE));assertEquals(6,plain.files().size());plain.exportEncryptedZip(zip,PASSWORD,()->true);}
  try(var archive=new ZipFile(zip.toFile(),PASSWORD)){
   assertEquals(6,archive.getFileHeaders().size());for(var header:archive.getFileHeaders()){assertTrue(header.isEncrypted());assertEquals(EncryptionMethod.AES,header.getEncryptionMethod());assertEquals(AesKeyStrength.KEY_STRENGTH_256,header.getAesExtraDataRecord().getAesKeyStrength());try(var in=archive.getInputStream(header)){assertArrayEquals(originals.get(header.getFileName()),in.readAllBytes());}}
  }
  for(char[] wrong:List.of(CODE,"account-password-1000".toCharArray()))try(var archive=new ZipFile(zip.toFile(),wrong)){assertThrows(java.io.IOException.class,()->{try(var in=archive.getInputStream(archive.getFileHeaders().getFirst())){in.readAllBytes();}});}
 }
 @Test void aggregateLimitAndDuplicates()throws Exception{
  Path a=root.resolve("a"),b=root.resolve("b");Files.createDirectories(a);Files.createDirectories(b);Path x=a.resolve("duplicate.txt"),y=b.resolve("duplicate.txt");Files.write(x,new byte[60]);Files.write(y,new byte[50]);byte[] envelope=LetterEnvelope.seal("text",PASSWORD,CODE);
  assertThrows(PlainMessage.FileLimitException.class,()->PlainMessage.letterWithAttachments("",envelope,List.of(x,y),100));
  try(var plain=PlainMessage.letterWithAttachments("",envelope,List.of(x,y),110);var decoded=PlainMessage.decode(plain.encode(),110)){assertEquals(List.of("duplicate.txt","duplicate_2.txt"),decoded.files().stream().map(PlainMessage.FileInfo::name).toList());}
 }
 @Test void noTraversalNoOverwriteAndCancelledZipRemoved()throws Exception{
  for(String bad:List.of("../file.txt","..\\file.txt","C:\\file.txt","/var/tmp/file","NUL.txt","x:stream",".",".."))assertThrows(IllegalArgumentException.class,()->PlainMessage.validateFilename(bad));
  Path file=root.resolve("source.exe");Files.write(file,new byte[]{1,2,3});Path target=root.resolve("saved.zip");byte[] old=new byte[]{7,8};Files.write(target,old);
  try(var plain=PlainMessage.letterWithAttachments("",LetterEnvelope.seal("text",PASSWORD,CODE),List.of(file),100)){
   assertThrows(FileAlreadyExistsException.class,()->plain.exportEncryptedZip(target,PASSWORD,()->true));assertArrayEquals(old,Files.readAllBytes(target));
   Path cancelled=root.resolve("cancelled.zip");assertThrows(java.io.IOException.class,()->plain.exportEncryptedZip(cancelled,PASSWORD,()->false));assertFalse(Files.exists(cancelled));
  }
 }
}
