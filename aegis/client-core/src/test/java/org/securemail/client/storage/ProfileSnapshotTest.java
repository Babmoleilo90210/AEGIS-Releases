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
      for(String name:new String[]{"ui-preferences.json","theme.txt","tor-mode.txt","update-preferences.json","session/resume.enc","session/device.dpapi","tor/state/state","tor/transport-state/state"}){
        Path file=root.resolve(name);Files.createDirectories(file.getParent());Files.writeString(file,"fixture-"+name);
      }
      Files.writeString(root.resolve("tor/state/control_auth_cookie"),"never-back-up-cookie");
      Path backup=ProfileSnapshot.create(config,root.resolve("backups"));ProfileSnapshot.verify(backup,config);
      assertFalse(Files.exists(backup.resolve("app/tor/state/control_auth_cookie")));
      Files.writeString(root.resolve("ui-preferences.json"),"changed");Files.delete(root.resolve("session/resume.enc"));
      ProfileSnapshot.restore(backup,config);assertEquals("fixture-ui-preferences.json",Files.readString(root.resolve("ui-preferences.json")));
      assertEquals("fixture-session/resume.enc",Files.readString(root.resolve("session/resume.enc")));
      try(var vault=new LocalStore(config.storagePath(),"snapshot-account-password".toCharArray(),Clock.systemUTC(),100000,1000000)){assertEquals(id,vault.identity().userId());}
      Files.writeString(backup.resolve("app/theme.txt"),"tampered");assertThrows(java.io.IOException.class,()->ProfileSnapshot.restore(backup,config));
      assertEquals("fixture-theme.txt",Files.readString(root.resolve("theme.txt")));
    }finally{if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);}
  }
}
