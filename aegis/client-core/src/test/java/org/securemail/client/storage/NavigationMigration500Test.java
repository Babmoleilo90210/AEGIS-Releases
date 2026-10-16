package org.securemail.client.storage;

import static org.junit.jupiter.api.Assertions.*;
import static org.securemail.client.appearance.Appearance.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.appearance.AppearanceStore;
import org.securemail.client.update.JsonData;

/** Actual settings serialization; this does not claim native installer acceptance. */
class NavigationMigration500Test {
  @TempDir Path root;
  @Test void customized250LayoutGroupsWithoutLosingWithinBlockOrderAndIsIdempotent()throws Exception {
    var store=new AppearanceStore(root);store.apply(store.current().manual("forest-green"));store.saveLayout("До 5.0",store.current().layout().below(true));
    Path settings=store.root().resolve("settings.json");JsonObject document=JsonData.object(Files.readAllBytes(settings),MAX_JSON);List<String> before=List.of("settings","glas","archive","letters","safeweb","contacts","search","profile");JsonArray old=new JsonArray();before.forEach(old::add);
    document.getAsJsonObject("current").getAsJsonObject("layout").add("order",old.deepCopy());document.getAsJsonArray("layouts").get(0).getAsJsonObject().getAsJsonObject("layout").add("order",old.deepCopy());Files.write(settings,JsonData.encode(document));byte[] original=Files.readAllBytes(settings);
    var migrated=new AppearanceStore(root);List<String> expected=List.of("archive","letters","contacts","search","profile","glas","safeweb","organizations","news","library","settings");assertEquals(expected,migrated.current().layout().order());assertEquals(expected,migrated.layouts().get("До 5.0").order());assertArrayEquals(original,Files.readAllBytes(settings));assertTrue(migrated.layouts().get("До 5.0").previewBelow());assertEquals("forest-green",migrated.current().theme());
    migrated.apply(migrated.current());var reopened=new AppearanceStore(root);assertEquals(migrated.current(),reopened.current());assertEquals(migrated.layouts(),reopened.layouts());assertEquals(11,new HashSet<>(expected).size());assertEquals("settings",expected.getLast());
  }
  @Test void currentBlockOrdersRemainCustomAndMalformedImportsAreRejected()throws Exception {
    JsonObject layout=defaults().layout().json();JsonArray custom=new JsonArray();List<String> expected=List.of("archive","search","letters","profile","contacts","library","news","organizations","glas","safeweb","settings");expected.forEach(custom::add);layout.add("order",custom);
    assertEquals(expected,Layout.parse(layout).order());assertEquals(expected,Layout.parse(Layout.parse(layout).json()).order());
    JsonArray unknown=custom.deepCopy();unknown.set(0,new JsonPrimitive("private-material"));layout.add("order",unknown);assertThrows(java.io.IOException.class,()->Layout.parse(layout));
    JsonArray duplicate=custom.deepCopy();duplicate.set(0,new JsonPrimitive("search"));layout.add("order",duplicate);assertThrows(java.io.IOException.class,()->Layout.parse(layout));
  }
}
