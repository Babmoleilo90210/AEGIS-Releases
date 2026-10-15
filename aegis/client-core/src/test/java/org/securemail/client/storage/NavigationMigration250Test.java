package org.securemail.client.storage;

import static org.junit.jupiter.api.Assertions.*;
import static org.securemail.client.appearance.Appearance.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.securemail.client.AppPaths;
import org.securemail.client.ClientConfig;
import org.securemail.client.appearance.AppearanceStore;
import org.securemail.client.archive.EncryptedArchive;
import org.securemail.client.crypto.AutomaticEncryption;
import org.securemail.client.crypto.Identity;
import org.securemail.client.crypto.PlainMessage;
import org.securemail.client.update.JsonData;
import org.securemail.protocol.UserInfo;

/** Real persisted 1.5/2.0 layouts and encrypted state; no native installer acceptance is implied. */
class NavigationMigration250Test {
  @TempDir Path root;
  static Stream<Arguments> previousOrders(){return Stream.of(
      Arguments.of(List.of("settings","letters","archive","contacts","profile","search"),List.of("settings","letters","archive","safeweb","glas","contacts","profile","search")),
      Arguments.of(List.of("settings","safeweb","contacts","archive","letters","profile","search"),List.of("settings","safeweb","glas","contacts","archive","letters","profile","search")));
  }
  private static void oldNavigation(Path settings,List<String> order)throws Exception {
    JsonObject document=JsonData.object(Files.readAllBytes(settings),MAX_JSON);JsonArray values=new JsonArray();order.forEach(values::add);
    document.getAsJsonObject("current").getAsJsonObject("layout").add("order",values.deepCopy());
    for(var entry:document.getAsJsonArray("layouts"))entry.getAsJsonObject().getAsJsonObject("layout").add("order",values.deepCopy());
    Files.write(settings,JsonData.encode(document));
  }

  @ParameterizedTest @MethodSource("previousOrders")
  void sixAndSevenSectionsMigrateWithoutReorderingExistingSections(List<String> before,List<String> expected)throws Exception {
    AppearanceStore initial=new AppearanceStore(root.resolve("profile"));initial.apply(initial.current().manual("forest-green"));initial.saveLayout("Мой макет",initial.current().layout().panels(18,35).below(true));
    Path settings=initial.root().resolve("settings.json");oldNavigation(settings,before);byte[] exactOld=Files.readAllBytes(settings);
    AppearanceStore migrated=new AppearanceStore(root.resolve("profile"));assertEquals("",migrated.recovery());assertEquals(expected,migrated.current().layout().order());assertEquals(expected,migrated.layouts().get("Мой макет").order());
    assertEquals(before,expected.stream().filter(before::contains).toList());assertEquals(expected.indexOf("safeweb")+1,expected.indexOf("glas"));
    assertEquals(8,expected.size());assertEquals(1,expected.stream().filter("safeweb"::equals).count());assertFalse(expected.contains("vzor"),"The Vzor label keeps the persisted safeweb ID");
    assertEquals("forest-green",migrated.current().theme());assertTrue(migrated.layouts().get("Мой макет").previewBelow());assertEquals(18,migrated.layouts().get("Мой макет").foldersPercent());assertArrayEquals(exactOld,Files.readAllBytes(settings));
    migrated.apply(migrated.current());AppearanceStore reopened=new AppearanceStore(root.resolve("profile"));assertEquals(migrated.current(),reopened.current());assertEquals(migrated.layouts(),reopened.layouts());
    Path exchange=root.resolve("layout.json");reopened.exportLayout("Мой макет",exchange);AppearanceStore receiver=new AppearanceStore(root.resolve("receiver"));receiver.importLayout(exchange);receiver.importLayout(exchange);
    assertEquals(1,receiver.layouts().size());assertEquals(reopened.layouts().get("Мой макет"),receiver.layouts().get("Мой макет"));assertEquals(expected,Layout.parse(receiver.layouts().get("Мой макет").json()).order());
  }

  @Test void anAlreadyCustomizedEightSectionOrderIsNotResetOnReopen()throws Exception {
    List<String> custom=List.of("glas","settings","letters","profile","archive","search","contacts","safeweb");AppearanceStore initial=new AppearanceStore(root);
    Path settings=initial.root().resolve("settings.json");oldNavigation(settings,custom);AppearanceStore reopened=new AppearanceStore(root);assertEquals(custom,reopened.current().layout().order());
    reopened.apply(reopened.current());assertEquals(custom,new AppearanceStore(root).current().layout().order());
  }

  @Test void snapshotBeforeEightSectionMigrationRetainsIdentityMailAndIndependentEncryptedArchive()throws Exception {
    String previous=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.toString());
    char[] password="migration-250-vault-password".toCharArray(),archivePassword="migration-250-independent-archive".toCharArray();
    try{
      ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());String identityId,messageId,entryId;byte[] publicKey,privateKey,packetDigest;
      try(LocalStore local=new LocalStore(config.storagePath(),password,Clock.systemUTC(),1_000_000,8_000_000)){
        local.bindNickname("alice");identityId=local.identity().userId();publicKey=local.identity().publicKey();privateKey=local.identity().privateKey();Identity bob=Identity.create();local.trust(new UserInfo(bob.userId(),"bob",bob.publicKey(),null));
        try(PlainMessage message=PlainMessage.text("Encrypted mail remains unchanged by eight-section migration")){
          var packet=new AutomaticEncryption(Clock.systemUTC()).encrypt(message,86400,604800000,bob,"bob",new UserInfo(identityId,"alice",publicKey,null));local.accept(packet);messageId=packet.messageId();packetDigest=Identity.digest(packet);
        }
      }
      AppearanceStore appearance=new AppearanceStore(root);appearance.apply(appearance.current().manual("forest-green"));appearance.saveLayout("До обновления",appearance.current().layout().panels(18,35).below(true));
      Path settings=appearance.root().resolve("settings.json");List<String> seven=List.of("settings","archive","contacts","safeweb","letters","profile","search");oldNavigation(settings,seven);byte[] oldSettings=Files.readAllBytes(settings);
      Path archive=config.storagePath().resolveSibling(config.storagePath().getFileName()+".personal-archive"),guards=root.resolve("archive-guards");
      try(EncryptedArchive container=EncryptedArchive.create(archive,guards,archivePassword,false,Clock.systemUTC()).archive()){
        entryId=container.importBytes("keep.txt","text","Independent encrypted archive survives navigation migration".getBytes(StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false).id();
      }
      Map<String,byte[]> vaultBefore=files(config.storagePath()),archiveBefore=files(archive);
      Path snapshot=ClientUpgrade.beforeVersionOpen("2.5.0",config,root.resolve("backups"));ProfileSnapshot.verify(snapshot,config);assertArrayEquals(oldSettings,Files.readAllBytes(snapshot.resolve("app/appearance/settings.json")));
      AppearanceStore migrated=new AppearanceStore(root);assertEquals(List.of("settings","archive","contacts","safeweb","glas","letters","profile","search"),migrated.current().layout().order());migrated.apply(migrated.current());
      assertEquals(snapshot,ClientUpgrade.beforeVersionOpen("2.5.0",config,root.resolve("backups")));ProfileSnapshot.verify(snapshot,config);assertFiles(vaultBefore,files(config.storagePath()));assertFiles(archiveBefore,files(archive));assertArrayEquals(oldSettings,Files.readAllBytes(snapshot.resolve("app/appearance/settings.json")));
      try(LocalStore local=new LocalStore(config.storagePath(),password,Clock.systemUTC(),1_000_000,8_000_000)){
        assertEquals(identityId,local.identity().userId());assertArrayEquals(publicKey,local.identity().publicKey());assertArrayEquals(privateKey,local.identity().privateKey());assertEquals(1,local.inbox().size());assertNotNull(local.contact("bob"));assertArrayEquals(packetDigest,Identity.digest(local.load(messageId)));
      }
      try(EncryptedArchive container=EncryptedArchive.open(archive,guards,archivePassword,false,Clock.systemUTC())){assertEquals("Independent encrypted archive survives navigation migration",new String(container.previewBytes(entryId,1024),StandardCharsets.UTF_8));}
      AppearanceStore reopened=new AppearanceStore(root);assertEquals("forest-green",reopened.current().theme());assertTrue(reopened.layouts().get("До обновления").previewBelow());
    }finally{if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);}
  }
  @Test void interruptedVersionBackupIsRejectedAndNeverRewritesProfile()throws Exception {
    String previous=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.toString());
    try {
      var config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());Files.createDirectories(config.storagePath());
      byte[] ciphertext={1,7,3,9,2,8};Path data=config.storagePath().resolve("state.vault");Files.write(data,ciphertext);
      Path backups=root.resolve("backups");Path good=ClientUpgrade.beforeVersionOpen("2.5.0",config,backups);
      assertEquals(good,ClientUpgrade.beforeVersionOpen("2.5.0",config,backups));
      Path metadata=good.resolve("snapshot.properties");assertTrue(Files.exists(metadata));Files.writeString(metadata,"interrupted snapshot metadata");
      assertThrows(java.io.IOException.class,()->ClientUpgrade.beforeVersionOpen("2.5.0",config,backups));
      assertArrayEquals(ciphertext,Files.readAllBytes(data));assertTrue(Files.exists(good));
    } finally {if(previous==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",previous);}
  }
  private static Map<String,byte[]> files(Path folder)throws Exception {
    Map<String,byte[]> result=new LinkedHashMap<>();try(var paths=Files.walk(folder)){for(Path file:paths.filter(Files::isRegularFile).sorted().toList())if(!file.getFileName().toString().endsWith(".lock"))result.put(folder.relativize(file).toString(),Files.readAllBytes(file));}return result;
  }
  private static void assertFiles(Map<String,byte[]> expected,Map<String,byte[]> actual){assertEquals(expected.keySet(),actual.keySet());expected.forEach((name,bytes)->assertArrayEquals(bytes,actual.get(name),name));}
}
