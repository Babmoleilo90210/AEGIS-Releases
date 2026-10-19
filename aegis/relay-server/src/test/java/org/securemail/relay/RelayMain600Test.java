package org.securemail.relay;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class RelayMain600Test {
 @TempDir Path temp;
 @Test void operatorInitializationPinsIdentityCreatesOwnServiceKeyAndStartsOnlyExplicit6Mode()throws Exception{KeyPair identity=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();Path pin=temp.resolve("identity.pub"),config=temp.resolve("relay.properties"),home=temp.resolve("private-relay6");Files.write(pin,identity.getPublic().getEncoded());Files.writeString(config,"databasePath="+temp.resolve("database/relay.db")+"\nlistenPort=0\nregistrationMode=open\n");ByteArrayOutputStream output=new ByteArrayOutputStream();RelayMain600.initialize(home,config,pin,IdentityProtocol.id(identity.getPublic().getEncoded()),19120,new PrintStream(output));assertTrue(Files.size(home.resolve("service.key"))>44);assertEquals(44,Files.size(home.resolve("service-public.x509")));assertEquals(Files.readString(home.resolve("service-public.txt")).trim(),IdentityProtocol.b64(Files.readAllBytes(home.resolve("service-public.x509"))));try(RelayMain600.Running running=RelayMain600.start(home)){assertTrue(running.port()>0);}assertThrows(IOException.class,()->RelayMain600.initialize(home,config,pin,IdentityProtocol.id(identity.getPublic().getEncoded()),19120,System.out));RelayMain600.main(new String[]{"inspect","--home",home.toString()});}
 @Test void wrongIdentityFingerprintSymlinkAndChangedServicePublicKeyAreRejected()throws Exception{KeyPair identity=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();Path pin=temp.resolve("identity.pub"),config=temp.resolve("relay.properties"),home=temp.resolve("relay6");Files.write(pin,identity.getPublic().getEncoded());Files.writeString(config,"databasePath="+temp.resolve("db/relay.db")+"\nlistenPort=0\n");assertThrows(IOException.class,()->RelayMain600.initialize(home,config,pin,"0".repeat(64),19120,System.out));assertFalse(Files.exists(home.resolve("service.key")));RelayMain600.initialize(home,config,pin,IdentityProtocol.id(identity.getPublic().getEncoded()),19120,new PrintStream(OutputStream.nullOutputStream()));byte[] original=Files.readAllBytes(home.resolve("service-public.x509"));Files.write(home.resolve("service-public.x509"),identity.getPublic().getEncoded());assertThrows(IOException.class,()->RelayMain600.start(home));Files.write(home.resolve("service-public.x509"),original);Path link=temp.resolve("link");Files.createSymbolicLink(link,home);assertThrows(IOException.class,()->RelayMain600.start(link));}
}
