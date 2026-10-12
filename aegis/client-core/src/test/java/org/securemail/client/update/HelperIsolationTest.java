package org.securemail.client.update;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class HelperIsolationTest {
  @TempDir Path root;
  @Test void helperCannotLoadJavaFxOrClientUi()throws Exception{
    Path src=Files.createDirectory(root.resolve("src")),out=root.resolve("helper");
    for(String n:new String[]{"client-core-1.2.0.jar","common-protocol-0.2.0.jar","gson.jar","client-ui-1.2.0.jar","javafx-graphics.jar","javafx-controls.jar","relay-server-0.3.0.jar","aegis-tests.jar"})Files.write(src.resolve(n),new byte[]{1});
    UpdateInstaller.copyHelperLibraries(src,out);
    try(var files=Files.list(out)){assertEquals(3,files.count());}
    assertTrue(Files.exists(out.resolve("client-core-1.2.0.jar")));assertFalse(Files.exists(out.resolve("client-ui-1.2.0.jar")));assertFalse(Files.exists(out.resolve("javafx-graphics.jar")));
  }
}
