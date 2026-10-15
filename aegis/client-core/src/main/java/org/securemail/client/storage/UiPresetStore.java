package org.securemail.client.storage;

import com.google.gson.*;
import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.util.*;
import org.securemail.client.update.JsonData;

public final class UiPresetStore {
  private final Path file;private UiPreferences current=UiPreferences.builtins().get("Компактный");private final LinkedHashMap<String,UiPreferences> custom=new LinkedHashMap<>();
  public UiPresetStore(Path profile)throws IOException{AtomicFiles.directory(profile);file=profile.resolve("ui-preferences.json");if(Files.exists(file)){JsonObject o=JsonData.object(AtomicFiles.read(file,32768),32768);JsonData.fields(o,"schema","current","presets");if(JsonData.number(o,"schema")!=1)throw new IOException("Unsupported UI settings");current=UiPreferences.parse(o.getAsJsonObject("current"));JsonArray entries=o.getAsJsonArray("presets");if(entries.size()>20)throw new IOException("Too many UI presets");for(JsonElement e:entries){JsonObject p=e.getAsJsonObject();JsonData.fields(p,"name","layout");String name=name(JsonData.text(p,"name",40));if(custom.putIfAbsent(name,UiPreferences.parse(p.getAsJsonObject("layout")))!=null)throw new IOException("Duplicate preset name");}}}
  public UiPreferences current(){return current;}public Map<String,UiPreferences> presets(){LinkedHashMap<String,UiPreferences> values=UiPreferences.builtins();values.putAll(custom);return Collections.unmodifiableMap(values);}public Set<String> customNames(){return Set.copyOf(custom.keySet());}
  public void apply(UiPreferences p)throws IOException{current=Objects.requireNonNull(p);save();}
  public void add(String name,UiPreferences p)throws IOException{name=name(name);if(custom.size()>=20||custom.containsKey(name))throw new IOException("Preset already exists or limit reached");custom.put(name,p);save();}
  public void rename(String old,String next)throws IOException{next=name(next);if(!custom.containsKey(old)||custom.containsKey(next))throw new IOException("Invalid preset name");UiPreferences p=custom.remove(old);custom.put(next,p);save();}
  public void remove(String name)throws IOException{if(custom.remove(name)==null)throw new IOException("Only custom presets can be removed");save();}
  private static String name(String value)throws IOException {String name=value.trim();if(name.isEmpty()||name.length()>40||name.chars().anyMatch(Character::isISOControl)||UiPreferences.builtins().containsKey(name))throw new IOException("Invalid custom preset name");return name;}
  private void save()throws IOException{JsonObject o=new JsonObject();o.addProperty("schema",1);o.add("current",current.json());JsonArray array=new JsonArray();custom.forEach((name,value)->{JsonObject p=new JsonObject();p.addProperty("name",name);p.add("layout",value.json());array.add(p);});o.add("presets",array);AtomicFiles.write(file,JsonData.encode(o));}
  public void exportPreset(String name,Path path)throws IOException {UiPreferences p=presets().get(name);if(p==null)throw new IOException("Unknown preset");JsonObject o=new JsonObject();o.addProperty("schema",1);o.addProperty("name",name);o.add("layout",p.json());byte[] bytes=JsonData.encode(o);try(var ch=FileChannel.open(path,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.exportAttributes(path.toAbsolutePath().getParent()))){java.nio.ByteBuffer b=java.nio.ByteBuffer.wrap(bytes);while(b.hasRemaining())ch.write(b);ch.force(true);}}
  public void importPreset(Path path)throws IOException {JsonObject o=JsonData.object(AtomicFiles.read(path,32768),32768);JsonData.fields(o,"schema","name","layout");if(JsonData.number(o,"schema")!=1)throw new IOException("Unsupported UI preset");String proposed=JsonData.text(o,"name",40);if(UiPreferences.builtins().containsKey(proposed))proposed+=" (копия)";add(proposed,UiPreferences.parse(o.getAsJsonObject("layout")));}
}
