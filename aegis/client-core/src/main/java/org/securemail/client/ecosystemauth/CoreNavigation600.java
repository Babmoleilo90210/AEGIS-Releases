package org.securemail.client.ecosystemauth;

import com.google.gson.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.client.update.JsonData;

/** Core-only layout. Legacy Mail appearance/layout files are never rewritten. */
public final class CoreNavigation600 {
  public static final List<List<String>> GROUPS=List.of(List.of("organizations","news"),List.of("applications","library"),List.of("settings"));
  public record State(List<List<String>> groups,boolean collapsed){
    public State {
      if(groups.size()!=GROUPS.size())throw new IllegalArgumentException("Недопустимая навигация");
      List<List<String>> copy=new ArrayList<>();for(int i=0;i<groups.size();i++){var group=groups.get(i);if(group.size()!=GROUPS.get(i).size()||!new HashSet<>(group).equals(new HashSet<>(GROUPS.get(i))))throw new IllegalArgumentException("Раздел перенесён в другой блок");copy.add(List.copyOf(group));}groups=List.copyOf(copy);
    }
    public State move(String section,int direction){if(direction!=-1&&direction!=1)throw new IllegalArgumentException("Недопустимое направление");List<List<String>> next=new ArrayList<>(groups);for(int i=0;i<groups.size();i++){var list=new ArrayList<>(groups.get(i));int index=list.indexOf(section);if(index<0)continue;int target=index+direction;if(target<0||target>=list.size())return this;Collections.swap(list,index,target);next.set(i,list);return new State(next,collapsed);}throw new IllegalArgumentException("Неизвестный раздел");}
    public State collapsed(boolean value){return new State(groups,value);}
  }
  private final Path file;
  public CoreNavigation600(Path file){this.file=file.toAbsolutePath().normalize();}
  public State load(List<String> legacyOrder,boolean legacyCollapsed)throws IOException {
    checkPath();if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS)){List<List<String>> groups=new ArrayList<>();for(var original:GROUPS){List<String> order=new ArrayList<>();for(String id:legacyOrder)if(original.contains(id)&&!order.contains(id))order.add(id);for(String id:original)if(!order.contains(id))order.add(id);groups.add(order);}return new State(groups,legacyCollapsed);}
    try{JsonObject json=JsonData.object(AtomicFiles.read(file,2048),2048);JsonData.fields(json,"schema","collapsed","groups");if(JsonData.number(json,"schema")!=1)throw new IOException("Неизвестная версия навигации");JsonArray outer=json.getAsJsonArray("groups");if(outer==null||outer.size()!=3)throw new IOException("Повреждена навигация");List<List<String>> groups=new ArrayList<>();for(JsonElement group:outer){if(!group.isJsonArray()||group.getAsJsonArray().size()>2)throw new IOException("Повреждена навигация");List<String> ids=new ArrayList<>();for(JsonElement id:group.getAsJsonArray()){if(!id.isJsonPrimitive()||!id.getAsJsonPrimitive().isString())throw new IOException("Повреждена навигация");ids.add(id.getAsString());}groups.add(ids);}return new State(groups,JsonData.bool(json,"collapsed"));}catch(IllegalArgumentException|IllegalStateException invalid){throw new IOException("Повреждены настройки навигации",invalid);}
  }
  public void save(State state)throws IOException {checkPath();AtomicFiles.directory(file.getParent());JsonObject json=new JsonObject();json.addProperty("schema",1);json.addProperty("collapsed",state.collapsed());JsonArray groups=new JsonArray();for(var group:state.groups()){JsonArray ids=new JsonArray();group.forEach(ids::add);groups.add(ids);}json.add("groups",groups);AtomicFiles.write(file,JsonData.encode(json));}
  private void checkPath()throws IOException {for(Path path=file;path!=null;path=path.getParent())if(Files.isSymbolicLink(path))throw new IOException("Ссылка в настройках навигации");}
}
