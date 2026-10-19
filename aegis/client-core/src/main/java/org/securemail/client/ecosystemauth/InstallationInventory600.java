package org.securemail.client.ecosystemauth;

import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.securemail.client.community.CommunityJson;
import org.securemail.client.ecosystem.ComponentInstallation;
import org.securemail.client.storage.AtomicFiles;

/** Release-inventory file must itself be included in the signed release artifact inventory. */
public final class InstallationInventory600 {
  private InstallationInventory600(){}
  public static ComponentInstallation load(Path bundle)throws IOException {
    Path root=bundle.toAbsolutePath().normalize();
    try {
      JsonObject json=CommunityJson.parse(AtomicFiles.read(root.resolve("components600.json"),32768));
      if(!json.keySet().equals(Set.of("schema","java","jars"))||json.get("schema").getAsInt()!=1)throw new IOException("Некорректный состав установки");
      JsonObject runtime=json.getAsJsonObject("java");if(!runtime.keySet().equals(Set.of("path","sha256")))throw new IOException("Некорректный состав JVM");
      String executable=runtime.get("path").getAsString();if(!Set.of("runtime/bin/java","runtime/bin/java.exe").contains(executable))throw new IOException("Недопустимая JVM");
      JsonObject jars=json.getAsJsonObject("jars");if(jars.size()<3||jars.size()>96)throw new IOException("Некорректный состав библиотек");
      LinkedHashMap<Path,String> entries=new LinkedHashMap<>();for(var entry:jars.entrySet()){
        if(!entry.getKey().matches("app/[A-Za-z0-9_.-]{1,150}\\.jar"))throw new IOException("Недопустимый путь библиотеки");entries.put(root.resolve(entry.getKey()),entry.getValue().getAsString());
      }
      var installation=new ComponentInstallation(root.resolve(executable),runtime.get("sha256").getAsString(),entries);installation.verify();return installation;
    }catch(IllegalArgumentException|IllegalStateException|NullPointerException invalid){throw new IOException("Установленный комплект повреждён. Требуется проверенная переустановка.",invalid);}
  }
  /** Packaging step only: hashes fixed already-built files; does not confer authenticity without owner signature. */
  public static void writeForPackaging(Path bundle)throws IOException {
    Path root=bundle.toAbsolutePath().normalize();JsonObject json=new JsonObject();json.addProperty("schema",1);JsonObject runtime=new JsonObject();String java=Files.isRegularFile(root.resolve("runtime/bin/java.exe"))?"runtime/bin/java.exe":"runtime/bin/java";runtime.addProperty("path",java);runtime.addProperty("sha256",ComponentInstallation.sha256(root.resolve(java)));json.add("java",runtime);
    JsonObject jars=new JsonObject();try(var files=Files.list(root.resolve("app"))){for(Path file:files.filter(p->p.getFileName().toString().endsWith(".jar")).sorted().toList()){if(Files.isSymbolicLink(file))throw new IOException("Ссылка в установленном комплекте");jars.addProperty("app/"+file.getFileName(),ComponentInstallation.sha256(file));}}
    json.add("jars",jars);AtomicFiles.write(root.resolve("components600.json"),json.toString().getBytes(StandardCharsets.UTF_8));
  }
}
