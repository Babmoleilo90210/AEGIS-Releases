package org.securemail.client;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.storage.*;
class UpdateSupportTest {
 @TempDir Path root;
 @Test void atomicAppImageReplacementAndShortcutThenRollbackOnFailure()throws Exception{
  String prior=System.getProperty("user.home");System.setProperty("user.home",root.toString());
  try{
   Path installed=UpdateSupport.installedImage();Files.createDirectories(installed.getParent());Files.writeString(installed,"old-image");Path downloaded=root.resolve("downloaded.AppImage"),icon=root.resolve("icon.png"),desktop=root.resolve(".local/share/applications/aegis.desktop");Files.writeString(downloaded,"new-image");Files.write(icon,new byte[]{1,2,3});
   UpdateSupport.installLinux(downloaded,installed,desktop,icon);assertEquals("new-image",Files.readString(installed));assertTrue(Files.isExecutable(installed));assertTrue(Files.readString(desktop).contains(installed.toString()));assertEquals("old-image",Files.readString(installed.resolveSibling("AEGIS.pre-1.1.0.AppImage")));
   Files.writeString(downloaded,"failed-image");assertThrows(java.io.IOException.class,()->UpdateSupport.installLinux(downloaded,installed,desktop,root.resolve("missing-icon")));assertEquals("new-image",Files.readString(installed));assertTrue(Files.readString(desktop).contains("X-AEGIS-Version=1.1.0"));
  }finally{System.setProperty("user.home",prior);}
 }
 @Test void backupCannotRecursivelyCopyItself()throws Exception{
  Path source=root.resolve("profile");Files.createDirectory(source);assertThrows(java.io.IOException.class,()->ClientUpgrade.snapshot(source,source.resolve("backup")));assertFalse(Files.exists(source.resolve("backup")));
 }
}
