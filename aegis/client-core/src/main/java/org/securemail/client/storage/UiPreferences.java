package org.securemail.client.storage;

import com.google.gson.*;
import java.io.*;
import java.util.*;
import org.securemail.client.update.JsonData;

/** Non-secret layout preferences; no arbitrary CSS, URLs or executable preset fields. */
public record UiPreferences(int scale,Density density,boolean sidebar,Avatars avatars,Preview preview,boolean subject,boolean date) {
  public enum Density{COMPACT,NORMAL,LARGE;public String toString(){return switch(this){case COMPACT->"Компактная";case NORMAL->"Обычная";case LARGE->"Крупная";};}}
  public enum Avatars{OFF,SMALL,MEDIUM;public String toString(){return switch(this){case OFF->"Выключены";case SMALL->"Маленькие";case MEDIUM->"Средние";};}}
  public enum Preview{RIGHT,BOTTOM,OFF;public String toString(){return switch(this){case RIGHT->"Справа";case BOTTOM->"Снизу";case OFF->"Выключен";};}}
  public UiPreferences{if(scale<80||scale>200||density==null||avatars==null||preview==null)throw new IllegalArgumentException("Invalid UI preferences");}
  public static LinkedHashMap<String,UiPreferences> builtins(){LinkedHashMap<String,UiPreferences> m=new LinkedHashMap<>();m.put("Компактный",new UiPreferences(90,Density.COMPACT,true,Avatars.SMALL,Preview.RIGHT,true,true));m.put("Стандартный",new UiPreferences(100,Density.NORMAL,true,Avatars.SMALL,Preview.RIGHT,true,true));m.put("Просторный",new UiPreferences(110,Density.LARGE,true,Avatars.MEDIUM,Preview.RIGHT,true,true));m.put("Почта",new UiPreferences(100,Density.COMPACT,true,Avatars.SMALL,Preview.BOTTOM,true,true));m.put("Минималистичный",new UiPreferences(90,Density.COMPACT,false,Avatars.OFF,Preview.OFF,true,false));return m;}
  public JsonObject json(){JsonObject o=new JsonObject();o.addProperty("scale",scale);o.addProperty("density",density.name());o.addProperty("sidebar",sidebar);o.addProperty("avatars",avatars.name());o.addProperty("preview",preview.name());o.addProperty("subject",subject);o.addProperty("date",date);return o;}
  public static UiPreferences parse(JsonObject o)throws IOException {
    JsonData.fields(o,"scale","density","sidebar","avatars","preview","subject","date");try{return new UiPreferences(Math.toIntExact(JsonData.number(o,"scale")),Density.valueOf(JsonData.text(o,"density",10)),JsonData.bool(o,"sidebar"),Avatars.valueOf(JsonData.text(o,"avatars",10)),Preview.valueOf(JsonData.text(o,"preview",10)),JsonData.bool(o,"subject"),JsonData.bool(o,"date"));}catch(IllegalArgumentException|ArithmeticException e){throw new IOException("Invalid UI preset",e);}
  }
}
