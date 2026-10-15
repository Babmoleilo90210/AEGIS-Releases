package org.securemail.relay;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.Clock;
import java.security.KeyPairGenerator;
import java.util.Set;
class OpenRegistrationTest {
 @TempDir Path temp;
 @Test void openAcceptsUnlistedNicknameAndEnforcesUniqueAndLimit()throws Exception{
  Path f=temp.resolve("relay.properties");Files.writeString(f,"registrationMode=open\nmaxUsers=2\nallowedNicknames=raven\ndatabasePath="+temp.resolve("data/relay.db"));var c=RelayConfig.load(f);assertTrue(c.allowedNicknames().isEmpty());
  try(var s=new RelayStore(c,Clock.systemUTC())){byte[] pass="account password 12345".getBytes(java.nio.charset.StandardCharsets.UTF_8);var g=KeyPairGenerator.getInstance("Ed25519");s.register("arthas",pass,g.generateKeyPair().getPublic().getEncoded());assertEquals(1,s.userCount());assertEquals(4,assertThrows(Rejection.class,()->s.register("arthas",pass,g.generateKeyPair().getPublic().getEncoded())).code);s.register("friend",pass,g.generateKeyPair().getPublic().getEncoded());assertEquals(5,assertThrows(Rejection.class,()->s.register("third",pass,g.generateKeyPair().getPublic().getEncoded())).code);}
 }
 @Test void closedRejectsWithoutCreatingUser()throws Exception{
  var c=new RelayConfig(temp.resolve("data/relay.db"),"127.0.0.1",0,604800000,10000,1000000,32,32,false,Set.of());try(var s=new RelayStore(c,Clock.systemUTC())){assertEquals(2,assertThrows(Rejection.class,()->s.register("arthas","account password 12345".getBytes(),KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded())).code);assertEquals(0,s.userCount());}
 }
}
