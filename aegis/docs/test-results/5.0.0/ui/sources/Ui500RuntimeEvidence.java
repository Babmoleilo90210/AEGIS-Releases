package org.securemail.ui;

import java.io.InputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Test-only provenance of the classes actually selected by the JVM. */
final class Ui500RuntimeEvidence {
 static Map<String,Object> capture()throws Exception{
  Map<String,Object> types=new LinkedHashMap<>();String smoke=location(Ui500RuntimeEvidence.class);boolean collocated=false;
  for(String name:List.of("org.securemail.ui.MessengerApp","org.securemail.ui.ArchiveView","org.securemail.ui.CommunityUi","org.securemail.ui.DocumentEditor","org.securemail.ui.EventsCalendar","org.securemail.ui.KnowledgeLibraryView","org.securemail.ui.GlasView","org.securemail.client.ClientSession","org.securemail.client.community.CommunityClient","org.securemail.client.community.CommunityJson","org.securemail.client.appearance.Appearance","org.securemail.protocol.UserInfo","org.securemail.community.content.ContentService","org.securemail.community.admin.AdminService","org.securemail.community.http.StrictJson")){
   try{Class<?> type=Class.forName(name);String origin=location(type);Map<String,Object> item=new LinkedHashMap<>();item.put("codeSource",origin);String resource="/"+name.replace('.','/')+".class";try(InputStream bytes=type.getResourceAsStream(resource)){if(bytes==null)throw new IllegalStateException("Class resource unavailable: "+name);item.put("classSha256",sha(bytes.readAllBytes()));}if(type.getProtectionDomain().getCodeSource()!=null&&type.getProtectionDomain().getCodeSource().getLocation().getProtocol().equals("file")){Path path=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());if(Files.isRegularFile(path))item.put("containerSha256",sha(Files.readAllBytes(path)));}types.put(name,item);if(origin.equals(smoke))collocated=true;}catch(ClassNotFoundException absent){types.put(name,Map.of("status","NOT_ON_CLASSPATH"));}
  }
  return Map.of("smokeCodeSource",smoke,"productionClassCollocatedWithSmokeOutput",collocated,"actualClasses",types,"note","Production classes must resolve from frozen application JARs; isolated smoke classes are separate. This record is not native or network acceptance.");
 }
 private static String location(Class<?> type){return type.getProtectionDomain().getCodeSource()==null?"UNAVAILABLE":type.getProtectionDomain().getCodeSource().getLocation().toExternalForm();}
 private static String sha(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
}
