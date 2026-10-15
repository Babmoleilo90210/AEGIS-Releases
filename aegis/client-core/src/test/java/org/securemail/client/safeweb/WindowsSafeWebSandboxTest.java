package org.securemail.client.safeweb;

import org.junit.jupiter.api.Test;
import org.w3c.dom.*;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.*;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class WindowsSafeWebSandboxTest {
  @Test void mapsOnlyDedicatedBundleAndDisablesHostChannels()throws Exception {
    Path bundle=Path.of("C:\\Users\\Nick & Family\\AppData\\Local\\AEGIS-SafeWeb\\bundles\\normal-1234");
    String xml=WindowsSafeWebSandbox.configuration(bundle,"12345678-1234-1234-1234-123456789abc");
    DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
    Document document=factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    assertEquals(1,document.getElementsByTagName("HostFolder").getLength());
    assertEquals(bundle.toString(),text(document,"HostFolder"));
    assertEquals("C:\\SafeWeb",text(document,"SandboxFolder"));
    assertEquals("false",text(document,"ReadOnly"));
    for(String name:new String[]{"vGPU","AudioInput","VideoInput","PrinterRedirection","ClipboardRedirection"})
      assertEquals("Disable",text(document,name));
    assertEquals("Enable",text(document,"ProtectedClient"));
    assertEquals("Enable",text(document,"Networking"));
    String command=text(document,"Command");
    assertTrue(command.endsWith("aegis-bootstrap\\12345678-1234-1234-1234-123456789abc\\start.ps1"));
    assertFalse(command.contains("-Command"));assertFalse(command.contains("https://"));
  }
  @Test void rejectsUnsupportedEditionsAndInjectedSessionCommands()throws Exception {
    for(String edition:new String[]{"Professional","ProfessionalN","ProfessionalEducation","ProfessionalWorkstation","Enterprise","EnterpriseS","EnterpriseN","Education","EducationN"})
      assertDoesNotThrow(()->WindowsSafeWebSandbox.requireSupportedEdition(edition));
    for(String edition:new String[]{"Core","CoreN","CoreSingleLanguage","ServerStandard","Unknown"})
      assertThrows(IOException.class,()->WindowsSafeWebSandbox.requireSupportedEdition(edition));
    assertThrows(IllegalArgumentException.class,()->WindowsSafeWebSandbox.configuration(Path.of("bundle"),"x\" & calc.exe"));
  }
  @Test void guestBootstrapIsPackagedAndUsesDataRatherThanCommandInterpolation()throws Exception {
    byte[] bytes=WindowsSafeWebSandbox.bootstrap();assertTrue(bytes.length>1000);assertTrue(bytes.length<65536);
    String script=new String(bytes,StandardCharsets.UTF_8);
    assertTrue(script.contains("FromBase64String"));assertTrue(script.contains("CreateProcess("));
    assertFalse(script.contains("Invoke-Expression"));assertFalse(script.contains("MOZ_DISABLE"));
    assertFalse(script.contains("TOR_SKIP_LAUNCH"));
  }
  @Test void hostListIsStrictAndUnknownVmStateRemainsActive()throws Exception {
    String id="12345678-1234-1234-1234-123456789abc";
    assertTrue(WindowsSandboxCli.parseList("{\"WindowsSandboxEnvironments\":[{\"Id\":\""+id+"\"}]}").get(id));
    assertFalse(WindowsSandboxCli.parseList("{\"WindowsSandboxEnvironments\":[{\"Id\":\""+id+"\",\"Status\":\"Stopped\"}]}").get(id));
    assertThrows(IOException.class,()->WindowsSandboxCli.parseList("{}"));
    assertThrows(IOException.class,()->WindowsSandboxCli.parseList("{\"WindowsSandboxEnvironments\":[{\"Id\":\"foreign;stopall\"}]}"));
    assertThrows(IOException.class,()->WindowsSandboxCli.parseList("{\"WindowsSandboxEnvironments\":[{\"Id\":\""+id+"\"},{\"Id\":\""+id+"\"}]}"));
  }
  @Test void executionAliasMustBindOfficialPackageAndProtectedTarget()throws Exception {
    String packageName="MicrosoftWindows.WindowsSandbox_0.8.107.0_x64__cw5n1h2txyewy";
    String app="MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy!App";
    String target="C:\\Program Files\\WindowsApps\\"+packageName+"\\wsb.exe";
    String family="MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy";
    assertDoesNotThrow(()->WindowsSandboxCli.validateAlias(alias(family,app,target),"C:\\Program Files"));
    assertThrows(IOException.class,()->WindowsSandboxCli.validateAlias(alias(family,app,"C:\\Users\\Public\\wsb.exe"),"C:\\Program Files"));
    assertThrows(IOException.class,()->WindowsSandboxCli.validateAlias(alias("Unrelated_1_x64__attacker",app,target),"C:\\Program Files"));
    byte[] wrongTag=alias(family,app,target);wrongTag[0]=0;
    assertThrows(IOException.class,()->WindowsSandboxCli.validateAlias(wrongTag,"C:\\Program Files"));
  }
  @Test void failedStartRetainsTheExactOwnerUntilVmCleanupIsProved()throws Exception {
    Object owned=new Object();AtomicBoolean retained=new AtomicBoolean();IOException failure=new IOException("start failed");
    Object returned=WindowsSafeWebSandbox.retainOnUnverifiedStop(owned,failure,
      ()->{throw new IOException("host stop not proved");},()->retained.set(true));
    assertSame(owned,returned);assertTrue(retained.get());assertEquals(1,failure.getSuppressed().length);
    IOException verifiedFailure=new IOException("start failed, cleanup succeeded");
    assertSame(verifiedFailure,assertThrows(IOException.class,()->WindowsSafeWebSandbox.retainOnUnverifiedStop(
      owned,verifiedFailure,()->{},()->fail("A stopped VM needs no retained running owner"))));
  }
  private static byte[] alias(String name,String app,String target) {
    byte[] payload=(name+'\0'+app+'\0'+target+'\0').getBytes(StandardCharsets.UTF_16LE);
    ByteBuffer raw=ByteBuffer.allocate(12+payload.length).order(ByteOrder.LITTLE_ENDIAN);
    raw.putInt(0x8000001b).putShort((short)(payload.length+4)).putShort((short)0).putInt(3).put(payload);return raw.array();
  }
  private static String text(Document document,String name){return document.getElementsByTagName(name).item(0).getTextContent();}
}
