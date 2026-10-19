package org.securemail.client.ecosystem;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.Binary;
class MailProfileMigration600Test {
 @TempDir Path root;private String prior;private ClientConfig config;private static final char[] PASSWORD="public runtime migration fixture password".toCharArray();
 @BeforeEach void profile()throws Exception{prior=System.getProperty("aegis.profile");System.setProperty("aegis.profile",root.resolve("app").toString());config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());try(var store=new LocalStore(config.storagePath(),PASSWORD,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage())){store.bindNickname("raven");}}
 @AfterEach void restore(){if(prior==null)System.clearProperty("aegis.profile");else System.setProperty("aegis.profile",prior);}
 @Test void wrongPasswordOrCancellationCannotSwitchConfigOrChangeOldCiphertexts()throws Exception{byte[] old=Files.readAllBytes(config.storagePath().resolve("state.vault"));assertThrows(java.io.IOException.class,()->MailProfileMigration600.beforeOpen(config,"public wrong password fixture".toCharArray(),new char[0],()->false));assertArrayEquals(old,Files.readAllBytes(config.storagePath().resolve("state.vault")));assertEquals(config.storagePath(),ClientConfig.load(AppPaths.config()).storagePath());assertThrows(java.io.InterruptedIOException.class,()->MailProfileMigration600.beforeOpen(config,PASSWORD,new char[0],()->true));assertFalse(Files.exists(MailProfileMigration600.destination()));assertArrayEquals(old,Files.readAllBytes(config.storagePath().resolve("state.vault")));}
 @Test void externalArchivePathBlocksSwitchExplicitlyAndLeavesOriginalData()throws Exception{try(var store=new LocalStore(config.storagePath(),PASSWORD,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage())){store.writeArchivePreferences(Binary.encode(out->{out.writeInt(1);Binary.text(out,root.resolve("external-archive").toString());Binary.text(out,"LIST");Binary.text(out,"NAME");out.writeDouble(.2);out.writeDouble(.7);}));}byte[] old=Files.readAllBytes(config.storagePath().resolve("state.vault"));var failure=assertThrows(MailProfileMigration600.ExternalArchiveRequired.class,()->MailProfileMigration600.beforeOpen(config,PASSWORD,new char[0],()->false));assertTrue(failure.getMessage().contains("Внешний архив"));assertFalse(Files.exists(MailProfileMigration600.destination()));assertEquals(config.storagePath(),ClientConfig.load(AppPaths.config()).storagePath());assertArrayEquals(old,Files.readAllBytes(config.storagePath().resolve("state.vault")));}
}
