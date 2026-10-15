package org.securemail.client.security;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.Secrets;
import org.securemail.client.storage.*;

class RememberedLoginTest {
 @TempDir Path root;final String relay="a".repeat(56)+".onion",token="b".repeat(64);
 static class SystemVault implements SystemSecrets{byte[] value;boolean available=true;public void store(byte[] b)throws IOException{if(!available)throw new IOException("unavailable");value=b.clone();}public byte[] load(){return value==null?null:value.clone();}public void clear(){if(value!=null)Arrays.fill(value,(byte)0);value=null;}}
 static class TestClock extends Clock{long now=1_790_000_000_000L;public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(now);}}
 @Test void localUnlockSevenDaysButRelayTokenOnlyTwelveHoursAndNoPassword()throws Exception{SystemVault os=new SystemVault();TestClock clock=new TestClock();RememberedLogin saved=new RememberedLogin(root,os,clock);byte[] key=Secrets.random(32);saved.save("raven",relay,token,key);byte[] file=Files.readAllBytes(root.resolve("session/resume.enc"));assertFalse(new String(file,java.nio.charset.StandardCharsets.ISO_8859_1).contains(token));assertFalse(Arrays.equals(key,os.value));clock.now+=13*3600_000L;try(var resume=saved.load(relay).orElseThrow()){assertArrayEquals(key,resume.vaultKey());assertFalse(resume.relayValid(clock.millis()));assertEquals(RememberedLogin.LOCAL_AGE,resume.expiresAt()-resume.createdAt());}clock.now+=7*86400_000L;assertTrue(saved.load(relay).isEmpty());assertNull(os.value);assertFalse(Files.exists(root.resolve("session/resume.enc")));}
 @Test void rollbackClockAndWrongRelayInvalidateSavedSession()throws Exception{SystemVault os=new SystemVault();TestClock clock=new TestClock();RememberedLogin saved=new RememberedLogin(root,os,clock);saved.save("raven",relay,token,Secrets.random(32));clock.now-=1;assertTrue(saved.load(relay).isEmpty());clock.now+=2;saved.save("raven",relay,token,Secrets.random(32));assertTrue(saved.load("c".repeat(56)+".onion").isEmpty());}
 @Test void unavailableSystemVaultNeverCreatesPlaintextFallback()throws Exception{SystemVault os=new SystemVault();os.available=false;RememberedLogin saved=new RememberedLogin(root,os,Clock.systemUTC());assertThrows(IOException.class,()->saved.save("raven",relay,token,Secrets.random(32)));try(var files=Files.list(root.resolve("session"))){assertEquals(0,files.count());}}
 @Test void tamperingClearsSessionAndExplicitEndDeletesSecret()throws Exception{SystemVault os=new SystemVault();RememberedLogin saved=new RememberedLogin(root,os,Clock.systemUTC());saved.save("raven",relay,token,Secrets.random(32));Path path=root.resolve("session/resume.enc");byte[] bytes=Files.readAllBytes(path);bytes[30]^=1;Files.write(path,bytes);assertThrows(javax.crypto.AEADBadTagException.class,()->saved.load(relay));assertNull(os.value);saved.save("raven",relay,token,Secrets.random(32));saved.clear();assertFalse(Files.exists(path));assertNull(os.value);}
 @Test void resumeKeyOpensExistingModernVaultWithoutChangingIdentity()throws Exception{Path data=root.resolve("data");byte[] key;String id;try(LocalStore local=new LocalStore(data,"account-password-1234".toCharArray(),Clock.systemUTC(),100000,1000000)){local.bindNickname("raven");key=local.sessionUnlockKey();id=local.identity().userId();}try(LocalStore local=LocalStore.resume(data,key,Clock.systemUTC(),100000,1000000)){assertEquals(id,local.identity().userId());assertEquals("raven",local.nickname());}key[0]^=1;assertThrows(javax.crypto.AEADBadTagException.class,()->LocalStore.resume(data,key,Clock.systemUTC(),100000,1000000));assertThrows(IOException.class,()->LocalStore.resume(root.resolve("absent"),Secrets.random(32),Clock.systemUTC(),100000,1000000));}
 @Test @EnabledOnOs(OS.WINDOWS) void nativeDpapiCurrentUserRoundTrip()throws Exception{SystemSecrets.Dpapi dpapi=new SystemSecrets.Dpapi(root);byte[] key=Secrets.random(32);dpapi.store(key);assertArrayEquals(key,dpapi.load());assertFalse(Arrays.equals(key,Files.readAllBytes(root.resolve("session/device.dpapi"))));dpapi.clear();assertNull(dpapi.load());}
}
