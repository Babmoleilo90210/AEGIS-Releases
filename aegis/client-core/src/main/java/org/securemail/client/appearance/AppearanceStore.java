package org.securemail.client.appearance;

import com.google.gson.*;
import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.securemail.client.storage.*;
import org.securemail.client.update.JsonData;
import static org.securemail.client.appearance.Appearance.*;

/** Local-only, atomic appearance persistence. Corrupt state is retained for recovery. */
public final class AppearanceStore {
  private final Path root,file;private Settings current=defaults();private String recovery="";
  private final LinkedHashMap<String,Theme> custom=new LinkedHashMap<>();
  private final LinkedHashMap<String,Settings> customSettings=new LinkedHashMap<>();
  private final LinkedHashMap<String,Layout> layouts=new LinkedHashMap<>();private final Set<String> favorites=new LinkedHashSet<>();
  public AppearanceStore(Path profile)throws IOException{
    root=profile.resolve("appearance");AtomicFiles.directory(root);file=root.resolve("settings.json");
    if(Files.exists(file,LinkOption.NOFOLLOW_LINKS)){try{read(JsonData.object(AtomicFiles.read(file,MAX_JSON),MAX_JSON));}catch(IOException|RuntimeException invalid){recover("Сохранённое оформление повреждено. Используется безопасная тема.");}}
    else migrate(profile);
  }
  public Path root(){return root;}
  public synchronized Settings current(){return current;}
  public synchronized String recovery(){return recovery;}
  public synchronized void recover(String reason){current=defaults();custom.clear();customSettings.clear();layouts.clear();favorites.clear();recovery=reason;}
  public synchronized Map<String,Theme> themes(){var result=new LinkedHashMap<>(PresetLibrary.builtins());result.putAll(custom);return Collections.unmodifiableMap(result);}
  public synchronized Map<String,Layout> layouts(){return Collections.unmodifiableMap(new LinkedHashMap<>(layouts));}
  public synchronized Set<String> favorites(){return Set.copyOf(favorites);}
  public synchronized Theme theme(String id){return themes().get(id);}
  public synchronized Settings template(String id,Settings fallback){Settings saved=customSettings.get(id);return saved!=null?saved.manual(id):fallback.manual(id);}
  public synchronized void apply(Settings value)throws IOException{validate(value);backup();Settings old=current;current=value;try{save();recovery="";}catch(IOException error){current=old;throw error;}}
  public synchronized void favorite(String id,boolean enabled)throws IOException{if(theme(id)==null)throw new IOException("Неизвестная тема");backup();boolean before=favorites.contains(id);if(enabled)favorites.add(id);else favorites.remove(id);try{save();}catch(IOException e){if(before)favorites.add(id);else favorites.remove(id);throw e;}}
  public synchronized Theme addTheme(Theme theme,Settings settings)throws IOException{
    if(theme.category()!=Category.CUSTOM||!theme.id().startsWith("user-")||themes().containsKey(theme.id())||custom.size()>=32||custom.values().stream().anyMatch(t->t.name().equals(theme.name())))throw new IOException("Название уже существует или достигнут лимит тем");
    backup();custom.put(theme.id(),theme);customSettings.put(theme.id(),settings.manual(theme.id()));try{save();}catch(IOException e){custom.remove(theme.id());customSettings.remove(theme.id());throw e;}return theme;
  }
  public synchronized void renameTheme(String id,String name)throws IOException{Theme old=custom.get(id);if(old==null)throw new IOException("Встроенные темы неизменяемы");name=label(name);String next=name;if(custom.values().stream().anyMatch(t->!t.id().equals(id)&&t.name().equals(next)))throw new IOException("Название уже существует");backup();custom.put(id,old.rename(name));try{save();}catch(IOException e){custom.put(id,old);throw e;}}
  public synchronized void updateTheme(Theme value,Settings settings)throws IOException{Theme old=custom.get(value.id());if(old==null||value.category()!=Category.CUSTOM)throw new IOException("Встроенные темы неизменяемы");if(custom.values().stream().anyMatch(t->!t.id().equals(value.id())&&t.name().equals(value.name())))throw new IOException("Название уже существует");backup();Settings previous=customSettings.get(value.id());custom.put(value.id(),value);customSettings.put(value.id(),settings.manual(value.id()));try{save();}catch(IOException e){custom.put(value.id(),old);customSettings.put(value.id(),previous);throw e;}}
  public synchronized void removeTheme(String id)throws IOException{if(!custom.containsKey(id))throw new IOException("Встроенные темы неизменяемы");backup();Theme old=custom.remove(id);Settings template=customSettings.remove(id);boolean favorite=favorites.remove(id);Settings before=current;if(current.theme().equals(id)||current.lightTheme().equals(id)||current.darkTheme().equals(id))current=defaults();try{save();}catch(IOException e){custom.put(id,old);customSettings.put(id,template);current=before;if(favorite)favorites.add(id);throw e;}}
  public synchronized void saveLayout(String name,Layout value)throws IOException{name=label(name);if(!layouts.containsKey(name)&&layouts.size()>=20)throw new IOException("Достигнут лимит макетов");backup();Layout old=layouts.put(name,value);try{save();}catch(IOException e){if(old==null)layouts.remove(name);else layouts.put(name,old);throw e;}}
  public synchronized void renameLayout(String old,String name)throws IOException{if(!layouts.containsKey(old))throw new IOException("Выберите сохранённый макет");name=label(name);if(layouts.containsKey(name))throw new IOException("Название уже существует");backup();var before=new LinkedHashMap<>(layouts);layouts.put(name,layouts.remove(old));try{save();}catch(IOException e){layouts.clear();layouts.putAll(before);throw e;}}
  public synchronized void removeLayout(String name)throws IOException{if(!layouts.containsKey(name))throw new IOException("Выберите сохранённый макет");backup();var before=new LinkedHashMap<>(layouts);layouts.remove(name);try{save();}catch(IOException e){layouts.clear();layouts.putAll(before);throw e;}}
  public synchronized String image(byte[] normalized)throws IOException{
    byte[] clean=BackgroundCodec.checkStored(normalized);try{String id=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(clean));Path images=root.resolve("images");AtomicFiles.directory(images);Path p=images.resolve(id+".png");if(!Files.exists(p))AtomicFiles.write(p,clean);return id;}catch(GeneralSecurityException impossible){throw new IOException(impossible);}finally{Arrays.fill(clean,(byte)0);}
  }
  public Path imagePath(String id)throws IOException{if(id==null||!id.matches("[a-f0-9]{64}"))throw new IOException("Недопустимое изображение");Path p=root.resolve("images").resolve(id+".png");if(Files.isSymbolicLink(p.getParent())||Files.isSymbolicLink(p)||!Files.isRegularFile(p)||Files.size(p)>BackgroundCodec.MAX_OUTPUT)throw new IOException("Фоновое изображение недоступно");return p;}
  public synchronized void exportTheme(String id,Path path)throws IOException{Theme theme=theme(id);if(theme==null)throw new IOException("Выберите тему");Settings settings=template(id,current).manual(id);if(settings.backdrop().mode()==Background.IMAGE)settings=settings.backdrop(new Backdrop(Background.SOLID,settings.backdrop().color(),settings.backdrop().gradient(),""));JsonObject o=new JsonObject();o.addProperty("schema",SCHEMA);o.addProperty("kind","aegis-theme");o.add("theme",theme.json());o.add("settings",settings.json());export(path,JsonData.encode(o));}
  public synchronized Theme importTheme(Path path)throws IOException{JsonObject o=JsonData.object(AtomicFiles.read(path,MAX_JSON),MAX_JSON);JsonData.fields(o,"schema","kind","theme","settings");envelope(o,"aegis-theme");Theme parsed=Theme.parse(object(o,"theme"));Settings settings=Settings.parse(object(o,"settings"));if(settings.backdrop().mode()==Background.IMAGE||!settings.backdrop().image().isEmpty())throw new IOException("Фон выберите локально после импорта");Theme copy=parsed.copy(parsed.name().substring(0,Math.min(40,parsed.name().length()))+" (копия)");return addTheme(copy,settings.manual(copy.id()));}
  public synchronized void exportLayout(String name,Path path)throws IOException{Layout value=layouts.get(name);if(value==null)throw new IOException("Выберите сохранённый макет");JsonObject o=new JsonObject();o.addProperty("schema",SCHEMA);o.addProperty("kind","aegis-layout");o.addProperty("name",name);o.add("layout",value.json());export(path,JsonData.encode(o));}
  public synchronized void importLayout(Path path)throws IOException{JsonObject o=JsonData.object(AtomicFiles.read(path,MAX_JSON),MAX_JSON);JsonData.fields(o,"schema","kind","name","layout");envelope(o,"aegis-layout");saveLayout(JsonData.text(o,"name",48),Layout.parse(object(o,"layout")));}
  public synchronized void restoreBackup()throws IOException{Path backup=root.resolve("settings.backup.json");JsonObject previous=JsonData.object(AtomicFiles.read(backup,MAX_JSON),MAX_JSON);byte[] failed=Files.exists(file)?AtomicFiles.read(file,MAX_JSON):null;read(previous);if(failed!=null)AtomicFiles.write(root.resolve("settings.failed.json"),failed);AtomicFiles.write(file,JsonData.encode(previous));recovery="";}
  private void migrate(Path profile)throws IOException{
    Path backups=root.resolve("migration-1.1.1");AtomicFiles.directory(backups);
    try{
      for(String name:List.of("theme.txt","ui-preferences.json")){Path old=profile.resolve(name),copy=backups.resolve(name);if(Files.exists(old,LinkOption.NOFOLLOW_LINKS)&&!Files.exists(copy)){byte[] exact=AtomicFiles.read(old,32768);AtomicFiles.write(copy,exact);}}
      UiPreferences old=new UiPresetStore(profile).current();String theme="SYSTEM";if(Files.exists(profile.resolve("theme.txt")))theme=new String(AtomicFiles.read(profile.resolve("theme.txt"),100),java.nio.charset.StandardCharsets.US_ASCII).trim();
      current=legacy(old,theme);Path ui=profile.resolve("ui-preferences.json");if(Files.exists(ui)){JsonObject o=JsonData.object(AtomicFiles.read(ui,32768),32768);for(JsonElement p:o.getAsJsonArray("presets")){JsonObject entry=p.getAsJsonObject();UiPreferences former=UiPreferences.parse(object(entry,"layout"));layouts.put(label(JsonData.text(entry,"name",40)),legacy(former,theme).layout());}}
      save();AtomicFiles.write(root.resolve("migration-complete"),"1\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }catch(IOException|RuntimeException broken){recover("Старые настройки не удалось перенести. Они сохранены; используется безопасная тема.");}
  }
  private void validate(Settings value)throws IOException{for(String id:List.of(value.theme(),value.lightTheme(),value.darkTheme()))if(theme(id)==null)throw new IOException("Тема недоступна");if(value.backdrop().mode()==Background.IMAGE)imagePath(value.backdrop().image());else if(value.mode()==Mode.MANUAL){Palette p=theme(value.theme()).palette();if(Appearance.contrast(p.text(),value.backdrop().color())<4.5||value.backdrop().mode()==Background.GRADIENT&&Appearance.contrast(p.text(),value.backdrop().gradient())<4.5)throw new IOException("Фон слишком близок к цвету текста");}}
  private void backup()throws IOException{if(Files.exists(file,LinkOption.NOFOLLOW_LINKS))AtomicFiles.write(root.resolve(recovery.isEmpty()?"settings.backup.json":"settings.failed.json"),AtomicFiles.read(file,MAX_JSON));}
  private void save()throws IOException{JsonObject o=new JsonObject();o.addProperty("schema",SCHEMA);o.add("current",current.json());JsonArray themes=new JsonArray();custom.forEach((id,theme)->{JsonObject entry=new JsonObject();entry.add("theme",theme.json());entry.add("settings",customSettings.get(id).json());themes.add(entry);});o.add("themes",themes);JsonArray values=new JsonArray();layouts.forEach((name,layout)->{JsonObject p=new JsonObject();p.addProperty("name",name);p.add("layout",layout.json());values.add(p);});o.add("layouts",values);JsonArray pins=new JsonArray();favorites.forEach(pins::add);o.add("favorites",pins);byte[] bytes=JsonData.encode(o);if(bytes.length>MAX_JSON)throw new IOException("Достигнут лимит настроек оформления");AtomicFiles.write(file,bytes);}
  private void read(JsonObject o)throws IOException{
    JsonData.fields(o,"schema","current","themes","layouts","favorites");if(JsonData.number(o,"schema")!=SCHEMA)throw new IOException("Unsupported appearance schema");Settings candidate=Settings.parse(object(o,"current"));var nextThemes=new LinkedHashMap<String,Theme>();var nextDetails=new LinkedHashMap<String,Settings>();var nextLayouts=new LinkedHashMap<String,Layout>();var nextFavorites=new LinkedHashSet<String>();
    JsonArray themes=array(o,"themes",32),panels=array(o,"layouts",20),pins=array(o,"favorites",54);
    for(JsonElement p:themes){if(!p.isJsonObject())throw new IOException("Invalid theme");JsonObject entry=p.getAsJsonObject();JsonData.fields(entry,"theme","settings");Theme theme=Theme.parse(object(entry,"theme"));Settings details=Settings.parse(object(entry,"settings"));if(theme.category()!=Category.CUSTOM||!theme.id().startsWith("user-")||PresetLibrary.get(theme.id())!=null||nextThemes.putIfAbsent(theme.id(),theme)!=null||!details.theme().equals(theme.id()))throw new IOException("Invalid custom theme");nextDetails.put(theme.id(),details);}
    for(JsonElement p:panels){if(!p.isJsonObject())throw new IOException("Invalid layout");JsonObject entry=p.getAsJsonObject();JsonData.fields(entry,"name","layout");String name=label(JsonData.text(entry,"name",48));if(nextLayouts.putIfAbsent(name,Layout.parse(object(entry,"layout")))!=null)throw new IOException("Duplicate layout");}
    var available=new HashSet<>(PresetLibrary.builtins().keySet());available.addAll(nextThemes.keySet());for(JsonElement p:pins){if(!p.isJsonPrimitive()||!p.getAsJsonPrimitive().isString()||!available.contains(p.getAsString())||!nextFavorites.add(p.getAsString()))throw new IOException("Invalid favorite");}
    for(String id:List.of(candidate.theme(),candidate.lightTheme(),candidate.darkTheme()))if(!available.contains(id))throw new IOException("Missing appearance theme");if(candidate.backdrop().mode()==Background.IMAGE)imagePath(candidate.backdrop().image());
    custom.clear();custom.putAll(nextThemes);customSettings.clear();customSettings.putAll(nextDetails);layouts.clear();layouts.putAll(nextLayouts);favorites.clear();favorites.addAll(nextFavorites);current=candidate;
  }
  private static JsonArray array(JsonObject o,String name,int max)throws IOException{JsonElement p=o.get(name);if(p==null||!p.isJsonArray()||p.getAsJsonArray().size()>max)throw new IOException("Appearance resource limit");return p.getAsJsonArray();}
  private static void envelope(JsonObject o,String kind)throws IOException{if(JsonData.number(o,"schema")!=SCHEMA||!JsonData.text(o,"kind",20).equals(kind))throw new IOException("Unsupported appearance exchange schema");}
  private static void export(Path path,byte[] data)throws IOException{try(var channel=FileChannel.open(path,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.exportAttributes(path.toAbsolutePath().getParent()))){ByteBuffer buffer=ByteBuffer.wrap(data);while(buffer.hasRemaining())channel.write(buffer);channel.force(true);}}
}
