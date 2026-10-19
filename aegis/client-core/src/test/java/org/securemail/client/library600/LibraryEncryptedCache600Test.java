package org.securemail.client.library600;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.security.SystemSecrets;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;
/** Actual JCA AES-GCM/filesystem. OS secret-service is an explicit in-memory fixture, not native acceptance. */
class LibraryEncryptedCache600Test {
 @TempDir Path root;static final String ACCOUNT="a".repeat(64),DEVICE="d".repeat(64);final MemorySecrets secrets=new MemorySecrets();final MutableClock clock=new MutableClock();final AtomicLong nano=new AtomicLong();
 static final class MemorySecrets implements SystemSecrets {byte[]secret;public void store(byte[]v){secret=v.clone();}public byte[]load(){return secret==null?null:secret.clone();}public void clear(){if(secret!=null)Arrays.fill(secret,(byte)0);secret=null;}}
 static final class MutableClock extends Clock {long now=10000;public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(now);}public long millis(){return now;}}
 LibraryEncryptedCache600 open()throws Exception{return new LibraryEncryptedCache600(root.resolve("cache"),ACCOUNT,DEVICE,secrets,clock,nano::get);}
 static String sha(String s)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));}
 Map<String,Object>env(String id,String text,boolean full,boolean offline,long epoch,long gen)throws Exception {Map<String,Object>d=new HashMap<>(Map.of("id",id,"revision",1L,"offlineAllowed",offline));d.put(full?"markdown":"sha256",full?text:sha(text));return Map.of("accountId",ACCOUNT,"deviceId",DEVICE,"generation",gen,"aclEpoch",epoch,"serverNow",10000L,"leaseUntil",20000L,"data",d);}
 @Test void encryptsBodyAndMetadataAndRejectsTampering()throws Exception {
  String id=UUID.randomUUID().toString(),body="СЕКРЕТ_ТЕЛО_600";try(var cache=open()){cache.storeVerified(env(id,body,true,true,1,1));Path file=root.resolve("cache/"+id+".lc6");byte[]encrypted=Files.readAllBytes(file);assertFalse(new String(encrypted,StandardCharsets.UTF_8).contains(body));assertEquals(body,cache.readOffline(id).markdown());encrypted[encrypted.length-1]^=1;Files.write(file,encrypted);assertThrows(GeneralSecurityException.class,()->cache.readOffline(id));}
 }
 @Test void restartNeverRestoresPermitsAndRequiresFreshMaterialAuthorization()throws Exception {
  String a=UUID.randomUUID().toString(),b=UUID.randomUUID().toString();try(var cache=open()){cache.storeVerified(env(a,"one",true,true,1,1));cache.storeVerified(env(b,"two",true,true,1,1));}
  clock.now=500;try(var cache=open()){assertThrows(IOException.class,()->cache.readOffline(a));assertEquals("one",cache.authorizeAndReadVerified(env(a,"one",false,true,2,2)).markdown());assertThrows(IOException.class,()->cache.readOffline(b));assertEquals(2,cache.readOffline(a).context().generation());}
 }
 @Test void originalMonotonicLeaseExpiresAndCannotBeRecreatedFromDisk()throws Exception {
  String id=UUID.randomUUID().toString();try(var cache=open()){cache.storeVerified(env(id,"body",true,true,1,1));nano.set(9999_000_000L);assertEquals("body",cache.readOffline(id).markdown());nano.set(10000_000_000L);assertThrows(IOException.class,()->cache.readOffline(id));assertFalse(cache.offlineAvailable(id));}try(var cache=open()){assertThrows(IOException.class,()->cache.readOffline(id));}
 }
 @Test void policyDenialEpochChangeAndDifferentAccountFailClosed()throws Exception {
  String a=UUID.randomUUID().toString(),b=UUID.randomUUID().toString();try(var cache=open()){cache.storeVerified(env(a,"one",true,true,1,1));cache.storeVerified(env(b,"two",true,true,1,1));assertThrows(IOException.class,()->cache.authorizeAndReadVerified(env(a,"one",false,false,1,1)));assertThrows(IOException.class,()->cache.readOffline(b));cache.authorizeAndReadVerified(env(a,"one",false,true,2,1));assertThrows(IOException.class,()->cache.readOffline(b));}
  assertThrows(IOException.class,()->new LibraryEncryptedCache600(root.resolve("cache"),"b".repeat(64),DEVICE,secrets,clock,nano::get));
 }
 @Test void fileSwapAndWrongCurrentRevisionOrHashCannotRevealCachedContent()throws Exception {
  String a=UUID.randomUUID().toString(),b=UUID.randomUUID().toString();try(var cache=open()){cache.storeVerified(env(a,"one",true,true,1,1));cache.storeVerified(env(b,"two",true,true,1,1));Files.copy(root.resolve("cache/"+b+".lc6"),root.resolve("cache/"+a+".lc6"),StandardCopyOption.REPLACE_EXISTING);assertThrows(GeneralSecurityException.class,()->cache.authorizeAndReadVerified(env(a,"one",false,true,1,1)));assertThrows(IOException.class,()->cache.readOffline(a));assertThrows(IOException.class,()->cache.authorizeAndReadVerified(env(b,"changed",false,true,1,1)));}
 }
 @Test void cacheCapacityAndInputBoundsAreEnforced()throws Exception {
  try(var cache=open()){String id=UUID.randomUUID().toString();assertThrows(IOException.class,()->cache.storeVerified(env(id,"x".repeat(LibraryEncryptedCache600.MAX_TEXT+1),true,true,1,1)));for(int n=0;n<LibraryEncryptedCache600.MAX_ENTRIES;n++)Files.createFile(root.resolve("cache/"+UUID.randomUUID()+".lc6"));assertThrows(IOException.class,()->cache.storeVerified(env(id,"body",true,true,1,1)));assertThrows(IOException.class,()->cache.contains("../../private"));}
 }
 @Test void unavailableOsStoreNeverCreatesAPlaintextKeyFallback()throws Exception {
  SystemSecrets unavailable=new SystemSecrets(){public byte[]load(){return null;}public void store(byte[]secret)throws IOException{throw new IOException("OS locked fixture");}public void clear(){}};
  assertThrows(IOException.class,()->new LibraryEncryptedCache600(root.resolve("blocked"),ACCOUNT,DEVICE,unavailable,clock,nano::get));try(var files=Files.walk(root.resolve("blocked"))){assertEquals(List.of(".library-cache600"),files.filter(Files::isRegularFile).map(p->p.getFileName().toString()).toList());}
 }
}
