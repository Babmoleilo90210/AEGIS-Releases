package org.securemail.client.update;
import com.google.gson.JsonObject;
import java.io.*;
import java.nio.file.*;
import java.util.Set;
import org.securemail.client.storage.AtomicFiles;

public record UpdatePreferences(String channel,boolean automaticCheck,boolean automaticDownload,boolean installAtExit) {
  public UpdatePreferences{if(!Set.of("stable","beta").contains(channel))throw new IllegalArgumentException("Invalid update channel");}
  public static UpdatePreferences load(Path profile)throws IOException {
    Path p=profile.resolve("update-preferences.json");if(!Files.exists(p))return new UpdatePreferences("stable",true,true,false);JsonObject o=JsonData.object(AtomicFiles.read(p,4096),4096);JsonData.fields(o,"channel","automaticCheck","automaticDownload","installAtExit");return new UpdatePreferences(JsonData.text(o,"channel",8),JsonData.bool(o,"automaticCheck"),JsonData.bool(o,"automaticDownload"),JsonData.bool(o,"installAtExit"));
  }
  public void save(Path profile)throws IOException {AtomicFiles.directory(profile);JsonObject o=new JsonObject();o.addProperty("channel",channel);o.addProperty("automaticCheck",automaticCheck);o.addProperty("automaticDownload",automaticDownload);o.addProperty("installAtExit",installAtExit);AtomicFiles.write(profile.resolve("update-preferences.json"),JsonData.encode(o));}
}
