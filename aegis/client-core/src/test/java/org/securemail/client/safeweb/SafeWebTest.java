package org.securemail.client.safeweb;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import org.securemail.client.appearance.Appearance;
import static org.junit.jupiter.api.Assertions.*;
class SafeWebTest {
 @TempDir Path root;
 @Test void acceptsWebUrlsWithoutExecutingOrResolvingThem(){assertEquals("https://example.org/a?q=x#part",SafeWebUrl.parse("https://example.org/a?q=x#part").toString());assertEquals("http",SafeWebUrl.parse("http://"+"a".repeat(56)+".onion/").getScheme());}
 @Test void rejectsCommandsLocalDestinationsCredentialsAndAmbiguousInputs(){for(String value:List.of("--profile /home/user","file:///etc/passwd","javascript:alert(1)","data:text/html,x","ftp://example.org/a","http://example.org/","https://a:b@example.org/","https://localhost/","https://127.0.0.1/","https://[::1]/","https://example.org/\n--remote","https://example.org/ ","https://example.org\\@evil.org/","http://old.onion/","https://example.org:99999/"))assertThrows(IllegalArgumentException.class,()->SafeWebUrl.parse(value),value);}
 @Test void missingVerificationFailsClosed(){assertThrows(java.io.IOException.class,()->new SafeWebProcess(root).open(SafeWebSessions.Mode.PERSISTENT,"https://example.org/"));}
 @Test void migrationPreservesCustomNavigationAndIsIdempotent()throws Exception{var json=Appearance.defaults().layout().json();var order=new com.google.gson.JsonArray();for(String name:List.of("settings","archive","contacts","profile","search","letters"))order.add(name);json.add("order",order);var migrated=Appearance.Layout.parse(json);assertEquals(List.of("settings","archive","safeweb","glas","contacts","profile","search","letters"),migrated.order());assertEquals(migrated,Appearance.Layout.parse(migrated.json()));}
}
