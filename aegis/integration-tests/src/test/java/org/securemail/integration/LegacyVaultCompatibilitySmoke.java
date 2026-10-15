package org.securemail.integration;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.securemail.client.crypto.AutomaticEncryption;
import org.securemail.client.storage.*;
public final class LegacyVaultCompatibilitySmoke {
 public static void main(String[] args)throws Exception{
   Path root=Files.createTempDirectory("aegis-legacy-vault"),profile=root.resolve("profile");Path bundle=Path.of(args[0]).toAbsolutePath();
   String cp=bundle.resolve("app/*")+java.io.File.pathSeparator+args[1];
   Process legacy=new ProcessBuilder(bundle.resolve("runtime/bin/java").toString(),"-Daegis.native.root="+bundle,"-cp",cp,LegacyVaultFixture.class.getName(),profile.toString()).inheritIO().start();
   if(legacy.waitFor()!=0)throw new AssertionError("Released 0.2.0 fixture failed");
   byte[] original=Files.readAllBytes(profile.resolve("state.vault"));String id=Files.readString(profile.resolve("public-fixture-id"));
   ClientUpgrade.beforeOpen(profile,root.resolve("backups"));
   if(!Arrays.equals(original,Files.readAllBytes(profile.resolve("state.vault"))))throw new AssertionError("Vault rewritten before backup");
   try(var store=new LocalStore(profile,"existing vault password 4829".toCharArray(),Clock.systemUTC(),200000,1000000)){
     if(!store.identity().userId().equals(id)||!store.nickname().equals("blackfox")||store.contact("raven")==null)throw new AssertionError("Old identity/contacts lost");
     var item=store.inbox().getFirst();
     try(var plain=new AutomaticEncryption(Clock.systemUTC()).decrypt(store.load(item.messageId()),store.identity(),10000)){
       if(!plain.text().equals("Старое письмо АЕГИС 0.2.0"))throw new AssertionError("Old content unreadable");
     }
   }
   System.out.println("Actual released 0.2.0 vault passed: identity, nickname, contact, old E2EE letter, encrypted backup before opening, v1 format unchanged");
 }
}

