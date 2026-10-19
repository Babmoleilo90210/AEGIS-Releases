package org.securemail.client.ecosystemauth;
import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class CoreNotificationPreferences600Test {
  @TempDir Path root;
  @Test void missingFileUsesNeutralPrivateDefaultsWithoutCreatingAnything()throws Exception{Path file=root.resolve("prefs.json");assertEquals(new CoreNotificationPreferences600.Settings(false,true,true),new CoreNotificationPreferences600(file).load());assertFalse(Files.exists(file));}
  @Test void atomicRoundTripContainsOnlyThreePresentationBooleans()throws Exception{Path file=root.resolve("private/prefs.json");var store=new CoreNotificationPreferences600(file);var requested=new CoreNotificationPreferences600.Settings(true,false,false);store.save(requested);assertEquals(requested,store.load());try(var files=Files.list(file.getParent())){assertEquals(Set.of("prefs.json"),new HashSet<>(files.map(p->p.getFileName().toString()).toList()));}assertEquals("{\"schema\":1,\"sound\":true,\"banner\":false,\"hideDetails\":false}",Files.readString(file));}
  @Test void rejectsAmbiguousTypesUnknownFieldsDuplicateKeysAndOversizeWithoutOverwriting()throws Exception{Path file=root.resolve("prefs.json");var store=new CoreNotificationPreferences600(file);
    for(String bad:List.of("{\"schema\":1,\"sound\":\"true\",\"banner\":true,\"hideDetails\":true}","{\"schema\":1,\"sound\":false,\"banner\":true,\"hideDetails\":true,\"title\":\"private\"}","{\"schema\":1,\"sound\":true,\"sound\":false,\"banner\":true,\"hideDetails\":true}","{\"schema\":1.1,\"sound\":false,\"banner\":true,\"hideDetails\":true}","x".repeat(2049))){Files.writeString(file,bad);assertThrows(IOException.class,store::load);assertEquals(bad,Files.readString(file));}}
  @Test void linkedSettingsCannotReadOrReplaceAnotherFile()throws Exception{Path target=root.resolve("other.json"),link=root.resolve("linked.json");Files.writeString(target,"keep");try{Files.createSymbolicLink(link,target);}catch(UnsupportedOperationException|FileSystemException unavailable){Assumptions.abort("Host cannot create symlinks");}var store=new CoreNotificationPreferences600(link);assertThrows(IOException.class,store::load);assertThrows(IOException.class,()->store.save(CoreNotificationPreferences600.Settings.defaults()));assertEquals("keep",Files.readString(target));}
  @Test void failedPersistenceCanKeepOnlyMoreRestrictiveInMemoryChoices(){var current=new CoreNotificationPreferences600.Settings(true,true,false);assertEquals(new CoreNotificationPreferences600.Settings(false,false,true),current.restrictWith(new CoreNotificationPreferences600.Settings(false,false,true)));assertEquals(CoreNotificationPreferences600.Settings.defaults(),CoreNotificationPreferences600.Settings.defaults().restrictWith(new CoreNotificationPreferences600.Settings(true,true,false)));}
}
