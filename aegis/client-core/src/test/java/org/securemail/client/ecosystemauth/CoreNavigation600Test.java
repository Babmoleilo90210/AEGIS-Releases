package org.securemail.client.ecosystemauth;

import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class CoreNavigation600Test {
  @TempDir Path dir;
  @Test void migratesRelativeOrderWithoutWritingOldLayoutThenRoundtrips()throws Exception {
    Path old=dir.resolve("appearance.json");Files.writeString(old,"unchanged old layout");var store=new CoreNavigation600(dir.resolve("core/navigation.json"));var state=store.load(List.of("letters","news","archive","library","organizations"),true);assertEquals(List.of("news","organizations"),state.groups().get(0));assertEquals(List.of("library","applications"),state.groups().get(1));assertTrue(state.collapsed());
    var moved=state.move("news",1).collapsed(false);store.save(moved);assertEquals(moved,store.load(List.of(),true));assertEquals("unchanged old layout",Files.readString(old));assertSame(moved,moved.move("news",1));
  }
  @Test void disallowsDuplicatesUnknownSectionsAndCrossBlockMoves()throws Exception {
    assertThrows(IllegalArgumentException.class,()->new CoreNavigation600.State(List.of(List.of("news","news"),List.of("applications","library"),List.of("settings")),false));
    assertThrows(IllegalArgumentException.class,()->new CoreNavigation600.State(List.of(List.of("applications","news"),List.of("organizations","library"),List.of("settings")),false));
    assertThrows(IllegalArgumentException.class,()->new CoreNavigation600.State(CoreNavigation600.GROUPS,false).move("hidden-admin",1));
  }
  @Test void rejectsSymlinksAndCorruptStateWithoutOverwriting()throws Exception {
    Path path=dir.resolve("navigation.json");Files.writeString(path,"{\"schema\":2}");var store=new CoreNavigation600(path);assertThrows(java.io.IOException.class,()->store.load(List.of(),false));assertEquals("{\"schema\":2}",Files.readString(path));Files.delete(path);Path other=dir.resolve("other");Files.writeString(other,"unchanged");Files.createSymbolicLink(path,other);assertThrows(java.io.IOException.class,()->store.save(new CoreNavigation600.State(CoreNavigation600.GROUPS,false)));assertEquals("unchanged",Files.readString(other));
  }
}
