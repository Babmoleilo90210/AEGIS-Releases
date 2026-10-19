package org.securemail.client.ecosystemauth;

import com.google.gson.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Set;
import org.securemail.client.AppPaths;
import org.securemail.client.community.CommunityJson;
import org.securemail.client.storage.AtomicFiles;

/** Local presentation choices only. No event titles, account identifiers or secrets are persisted. */
public final class CoreNotificationPreferences600 {
  private static final int MAX_BYTES=2048;
  public record Settings(boolean sound,boolean banner,boolean hideDetails){
    public static Settings defaults(){return new Settings(false,true,true);}
    /** Restrictive clicks take effect even if persistence later fails; enabling needs a successful save. */
    public Settings restrictWith(Settings requested){return new Settings(sound&&requested.sound,banner&&requested.banner,hideDetails||requested.hideDetails);}
  }
  private final Path file;
  public CoreNotificationPreferences600(Path file){this.file=file.toAbsolutePath().normalize();}
  public static Path defaultFile(){return AppPaths.root().resolve("core600/notification-preferences.json");}
  public Settings load()throws IOException{
    checkPath();if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS))return Settings.defaults();
    JsonObject json=CommunityJson.parse(AtomicFiles.read(file,MAX_BYTES));
    try{
      if(!json.keySet().equals(Set.of("schema","sound","banner","hideDetails"))||!json.get("schema").isJsonPrimitive()||!json.get("schema").getAsJsonPrimitive().isNumber()||json.get("schema").getAsBigDecimal().intValueExact()!=1)throw invalid();
      return new Settings(bool(json,"sound"),bool(json,"banner"),bool(json,"hideDetails"));
    }catch(IllegalStateException|IllegalArgumentException|ArithmeticException bad){throw invalid();}
  }
  public void save(Settings settings)throws IOException{
    if(settings==null)throw new IllegalArgumentException("Параметры уведомлений не заданы");checkPath();AtomicFiles.directory(file.getParent());checkPath();
    JsonObject json=new JsonObject();json.addProperty("schema",1);json.addProperty("sound",settings.sound());json.addProperty("banner",settings.banner());json.addProperty("hideDetails",settings.hideDetails());
    AtomicFiles.write(file,json.toString().getBytes(StandardCharsets.UTF_8));
  }
  private void checkPath()throws IOException{for(Path path=file;path!=null;path=path.getParent())if(Files.isSymbolicLink(path))throw invalid();}
  private static boolean bool(JsonObject json,String name)throws IOException{JsonElement value=json.get(name);if(value==null||!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isBoolean())throw invalid();return value.getAsBoolean();}
  private static IOException invalid(){return new IOException("Некорректные локальные параметры уведомлений");}
}
