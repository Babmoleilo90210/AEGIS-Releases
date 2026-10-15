package org.securemail.integration;
import java.nio.file.*;
import java.time.Clock;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.*;
/** This fixture is executed with the actual released 0.2.0 JARs/runtime. */
public final class LegacyVaultFixture {
 public static void main(String[] args)throws Exception{
   Path profile=Path.of(args[0]);char[] vault="existing vault password 4829".toCharArray();
   try(var store=new LocalStore(profile,vault,Clock.systemUTC(),200000,1000000)){
     store.bindNickname("blackfox");var sender=Identity.create();store.trust(new UserInfo(sender.userId(),"raven",sender.publicKey(),null));
     try(var plain=PlainMessage.text("Старое письмо АЕГИС 0.2.0")){
       var packet=new AutomaticEncryption(Clock.systemUTC()).encrypt(plain,3600,604800000,sender,"raven",new UserInfo(store.identity().userId(),"blackfox",store.identity().publicKey(),null));store.accept(packet);
     }
     Files.writeString(profile.resolve("public-fixture-id"),store.identity().userId());
   }
 }
}

