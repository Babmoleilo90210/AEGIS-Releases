package org.securemail.client.ecosystemauth;
import java.nio.file.*;
import java.security.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
class CoreServiceEndpoints600Test {
  @TempDir Path dir;
  @Test void persistsOnlyExplicitPublicPinsForFixedServiceNames()throws Exception {var store=new CoreServiceEndpoints600(dir.resolve("core"));byte[] pub=KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();for(var s:CoreServiceEndpoints600.Service.values()){assertTrue(store.load(s).isEmpty());var endpoint=new CoreServiceEndpoints600.Endpoint(s.hasEndpoint()?"a".repeat(56)+".onion":"",s.hasEndpoint()?80:0,pub);store.save(s,endpoint);var restored=store.load(s).orElseThrow();assertArrayEquals(pub,restored.publicKey());assertEquals(endpoint.onion(),restored.onion());assertEquals(endpoint.port(),restored.port());assertEquals(endpoint.fingerprint(),restored.fingerprint());assertThrows(java.io.IOException.class,()->store.save(s,new CoreServiceEndpoints600.Endpoint(s.hasEndpoint()?"":"a".repeat(56)+".onion",s.hasEndpoint()?0:80,pub)));}}
  @Test void rejectsClearnetUnknownFieldsAndLinksWithoutOverwriting()throws Exception {byte[] pub=KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();assertThrows(IllegalArgumentException.class,()->new CoreServiceEndpoints600.Endpoint("example.org",443,pub));var store=new CoreServiceEndpoints600(dir);Path file=dir.resolve("community.properties");Files.writeString(file,"unknown=value\n");assertThrows(java.io.IOException.class,()->store.load(CoreServiceEndpoints600.Service.COMMUNITY));Files.delete(file);Path other=dir.resolve("other");Files.writeString(other,"unchanged");Files.createSymbolicLink(file,other);assertThrows(java.io.IOException.class,()->store.save(CoreServiceEndpoints600.Service.COMMUNITY,new CoreServiceEndpoints600.Endpoint("a".repeat(56)+".onion",80,pub)));assertEquals("unchanged",Files.readString(other));}
}
