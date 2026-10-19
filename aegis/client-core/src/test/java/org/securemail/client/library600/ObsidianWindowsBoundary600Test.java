package org.securemail.client.safeweb;
import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;
/** Fixed guest policy only. NOT a Windows VM/native Obsidian acceptance test. */
class ObsidianWindowsBoundary600Test {
 @Test void vmConfigUsesOnlyReadOnlyMappingsAndNoHostNetworkClipboardOrAudio()throws Exception {
  String config=ObsidianWindowsBoundary600.configuration(Path.of("/owner/official"),Path.of("/owner/allowed-notes"),Path.of("/owner/runtime"));
  var factory=DocumentBuilderFactory.newInstance();factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);var doc=factory.newDocumentBuilder().parse(new ByteArrayInputStream(config.getBytes(StandardCharsets.UTF_8)));
  for(String key:new String[]{"Networking","ClipboardRedirection","AudioInput","VideoInput","PrinterRedirection","VGpu"})assertEquals("Disable",doc.getElementsByTagName(key).item(0).getTextContent());
  assertEquals("Enable",doc.getElementsByTagName("ProtectedClient").item(0).getTextContent());assertEquals(3,doc.getElementsByTagName("MappedFolder").getLength());for(int n=0;n<3;n++)assertEquals("true",doc.getElementsByTagName("ReadOnly").item(n).getTextContent());assertFalse(config.contains("AppData"));assertFalse(config.contains("Downloads"));
 }
 @Test void personalVmHasOnlyTwoNarrowWritablePersonalMappingsAndNoProtectedProfile()throws Exception {
  String config=ObsidianWindowsBoundary600.personalConfiguration(Path.of("/official"),Path.of("/personal-vault"),Path.of("/personal-profile"),Path.of("/controller-runtime"));assertTrue(config.contains("<Networking>Enable</Networking>"));assertEquals(2,config.split("<ReadOnly>false</ReadOnly>",-1).length-1);assertFalse(config.contains("ApprovedProjection"));assertTrue(config.contains("C:\\PersonalVault"));assertTrue(config.contains("<ClipboardRedirection>Disable</ClipboardRedirection>"));String script=ObsidianWindowsBoundary600.personalBootstrap("Obsidian-1.14.4.exe");assertFalse(script.contains("New-Item -ItemType Junction"));assertTrue(script.contains("--user-data-dir=C:\\PersonalProfile"));
 }
 @Test void guestBootstrapHasFixedInstallerArgumentsIndependentProfileAndLeaseButNoHostCommandInput(){
  String script=ObsidianWindowsBoundary600.bootstrap("Obsidian-1.14.4.exe");assertTrue(script.contains("/D=C:\\AEGISObsidian"));assertTrue(script.contains("--user-data-dir=C:\\AEGISProfile"));assertTrue(script.contains("TotalSeconds -gt 20"));assertFalse(script.contains("--no-sandbox"));assertFalse(script.contains("-Verb RunAs"));assertThrows(IllegalArgumentException.class,()->ObsidianWindowsBoundary600.bootstrap("Obsidian.exe'; malicious"));
 }
}
