package org.securemail.client.storage;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.*;

class ProfileSnapshotTest {
  @TempDir Path root;
  @Test void allControlledStateSurvivesRestoreAndTamperingStopsIt()throws Exception{
    String previous=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.toString());
    try{
      ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());String id;
      try(var vault=new LocalStore(config.storagePath(),"snapshot-account-password".toCharArray(),Clock.systemUTC(),100000,1000000)){vault.bindNickname("raven");id=vault.identity().userId();}
      for(String name:new String[]{"ui-preferences.json","theme.txt","appearance/settings.json","appearance/images/fixture.png","updates/events/fixture.json","tor-mode.txt","update-preferences.json","session/resume.enc","session/device.dpapi","tor/state/state","tor/transport-state/state","updates/stable.floor","updates/stable-1.0.0.json","updates/stable-1.0.0.sig","updates/lastAnnouncementVersion-stable"}){
        Path file=root.resolve(name);Files.createDirectories(file.getParent());Files.writeString(file,"fixture-"+name);
      }
      Files.writeString(root.resolve("tor/state/control_auth_cookie"),"never-back-up-cookie");
      Path backup=ProfileSnapshot.create(config,root.resolve("backups"));ProfileSnapshot.verify(backup,config);
      assertFalse(Files.exists(backup.resolve("app/tor/state/control_auth_cookie")));
      Files.writeString(root.resolve("ui-preferences.json"),"changed");Files.delete(root.resolve("session/resume.enc"));Files.delete(root.resolve("appearance/settings.json"));Files.delete(root.resolve("updates/events/fixture.json"));Files.delete(root.resolve("updates/stable-1.0.0.sig"));Files.writeString(root.resolve("updates/stable.floor"),"1.1.0");
      ProfileSnapshot.restore(backup,config);assertEquals("fixture-ui-preferences.json",Files.readString(root.resolve("ui-preferences.json")));
      assertEquals("fixture-appearance/settings.json",Files.readString(root.resolve("appearance/settings.json")));assertEquals("fixture-updates/events/fixture.json",Files.readString(root.resolve("updates/events/fixture.json")));
      assertEquals("fixture-session/resume.enc",Files.readString(root.resolve("session/resume.enc")));
      assertEquals("fixture-updates/stable.floor",Files.readString(root.resolve("updates/stable.floor")));assertEquals("fixture-updates/stable-1.0.0.sig",Files.readString(root.resolve("updates/stable-1.0.0.sig")));
      try(var vault=new LocalStore(config.storagePath(),"snapshot-account-password".toCharArray(),Clock.systemUTC(),100000,1000000)){assertEquals(id,vault.identity().userId());}
      Files.writeString(backup.resolve("app/theme.txt"),"tampered");assertThrows(java.io.IOException.class,()->ProfileSnapshot.restore(backup,config));
      assertEquals("fixture-theme.txt",Files.readString(root.resolve("theme.txt")));
    }finally{if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);}
  }
  @Test void first11OpenBacksUpAnAlreadyModern10VaultOnceWithoutChangingIdentity()throws Exception{
    String previous=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.toString());
    try{
      ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());String id;
      try(var vault=new LocalStore(config.storagePath(),"modern vault passphrase".toCharArray(),Clock.systemUTC(),100000,1000000)){vault.bindNickname("raven");id=vault.identity().userId();}
      assertTrue(LocalStore.modernVault(config.storagePath()));byte[] state=Files.readAllBytes(config.storagePath().resolve("state.vault"));
      Path first=ClientUpgrade.beforeOpen(config.storagePath(),root.resolve("backups"));assertNotNull(first);ProfileSnapshot.verify(first,config);
      assertArrayEquals(state,Files.readAllBytes(config.storagePath().resolve("state.vault")));assertEquals(first,ClientUpgrade.beforeOpen(config.storagePath(),root.resolve("backups")));
      try(var vault=new LocalStore(config.storagePath(),"modern vault passphrase".toCharArray(),Clock.systemUTC(),100000,1000000)){assertEquals(id,vault.identity().userId());}
    }finally{if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);}
  }
  @Test void version120SnapshotIsRepeatableAndDoesNotRewriteVault()throws Exception{
    String previous=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.toString());
    try{
      ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());
      try(var vault=new LocalStore(config.storagePath(),"modern vault passphrase".toCharArray(),Clock.systemUTC(),100000,1000000)){vault.bindNickname("raven");}
      byte[] before=Files.readAllBytes(config.storagePath().resolve("state.vault"));
      Path first=ClientUpgrade.beforeVersionOpen("1.2.0",config,root.resolve("backups"));
      assertEquals(first,ClientUpgrade.beforeVersionOpen("1.2.0",config,root.resolve("backups")));
      assertArrayEquals(before,Files.readAllBytes(config.storagePath().resolve("state.vault")));
      ProfileSnapshot.verify(first,config);assertThrows(java.io.IOException.class,()->ClientUpgrade.beforeVersionOpen("../oops",config,root.resolve("backups")));
    }finally{if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);}
  }
  @Test void version150PreservesManagedArchiveAndRestoresMissingSeparateContainer()throws Exception{
    String previous=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.toString());
    try{
      ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());
      try(var vault=new LocalStore(config.storagePath(),"snapshot-vault-password-150".toCharArray(),Clock.systemUTC(),100000,1000000)){vault.bindNickname("raven");vault.writeArchivePreferences(new byte[]{1,2,3});}
      Path archive=config.storagePath().resolveSibling(config.storagePath().getFileName()+".personal-archive"),guards=root.resolveSibling(root.getFileName()+"-guards");
      char[] secret="independent archive snapshot password".toCharArray();String item;
      try(var a=org.securemail.client.archive.EncryptedArchive.create(archive,guards,secret,false,Clock.systemUTC()).archive()){item=a.importBytes("not-visible.txt","text","snapshot content".getBytes(),"",false,org.securemail.client.archive.EncryptedArchive.QUIET,()->false).id();}
      Path restored=archive.resolveSibling(config.storagePath().getFileName()+".archive-restored-"+java.util.UUID.randomUUID());Files.createDirectories(restored);Files.write(restored.resolve("key.bin"),new byte[]{9,8,7});
      byte[] state=Files.readAllBytes(config.storagePath().resolve("state.vault"));Path backup=ClientUpgrade.beforeVersionOpen("1.5.0",config,root.resolve("backups"));assertEquals(backup,ClientUpgrade.beforeVersionOpen("1.5.0",config,root.resolve("backups")));assertArrayEquals(state,Files.readAllBytes(config.storagePath().resolve("state.vault")));
      Files.delete(restored.resolve("key.bin"));Files.delete(restored);Files.write(archive.resolve("catalog.enc"),new byte[]{0});ProfileSnapshot.restore(backup,config);assertArrayEquals(new byte[]{9,8,7},Files.readAllBytes(restored.resolve("key.bin")));
      try(var a=org.securemail.client.archive.EncryptedArchive.open(archive,guards,secret,false,Clock.systemUTC())){assertEquals("snapshot content",new String(a.previewBytes(item,100)));}
    }finally{if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);}
  }

}
