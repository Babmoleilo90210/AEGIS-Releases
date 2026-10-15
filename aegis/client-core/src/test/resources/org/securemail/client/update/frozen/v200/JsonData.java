package org.securemail.client.update;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.*;
import java.nio.charset.*;
import java.util.*;

/** Bounded strict JSON, including duplicate-name rejection. Never Java serialization. */
public final class JsonData {
  private JsonData() {}
  public static JsonObject object(byte[] bytes, int limit) throws IOException {
    if(bytes.length==0||bytes.length>limit)throw new IOException("Invalid JSON size");
    try {
      String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString();
      JsonReader reader=new JsonReader(new StringReader(text));reader.setStrictness(Strictness.STRICT);
      JsonElement value=read(reader,0,new int[]{0});
      if(reader.peek()!=JsonToken.END_DOCUMENT||!value.isJsonObject())throw new IOException("Invalid JSON document");
      return value.getAsJsonObject();
    }catch(IllegalStateException|NumberFormatException e){throw new IOException("Invalid JSON document",e);}
  }
  private static JsonElement read(JsonReader r,int depth,int[] count)throws IOException {
    if(depth>16||++count[0]>4096)throw new IOException("JSON resource limit");
    return switch(r.peek()) {
      case BEGIN_OBJECT -> {r.beginObject();JsonObject o=new JsonObject();while(r.hasNext()){String name=r.nextName();if(o.has(name))throw new IOException("Duplicate JSON field");o.add(name,read(r,depth+1,count));}r.endObject();yield o;}
      case BEGIN_ARRAY -> {r.beginArray();JsonArray a=new JsonArray();while(r.hasNext())a.add(read(r,depth+1,count));r.endArray();yield a;}
      case STRING -> new JsonPrimitive(r.nextString());
      case NUMBER -> new JsonPrimitive(new java.math.BigDecimal(r.nextString()));
      case BOOLEAN -> new JsonPrimitive(r.nextBoolean());
      case NULL -> {r.nextNull();yield JsonNull.INSTANCE;}
      default -> throw new IOException("Invalid JSON token");
    };
  }
  public static void fields(JsonObject o,String... names)throws IOException {
    if(!o.keySet().equals(Set.of(names)))throw new IOException("Unknown or missing JSON field");
  }
  public static String text(JsonObject o,String name,int max)throws IOException {
    JsonElement e=o.get(name);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isString())throw new IOException("Expected JSON string");
    String value=e.getAsString();if(value.length()>max||value.chars().anyMatch(c->c==0))throw new IOException("Invalid JSON string");return value;
  }
  public static long number(JsonObject o,String name)throws IOException {
    try{JsonElement e=o.get(name);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isNumber())throw new IOException("Expected JSON number");return e.getAsBigDecimal().longValueExact();}catch(ArithmeticException|NumberFormatException e){throw new IOException("Invalid integer",e);}
  }
  public static boolean bool(JsonObject o,String name)throws IOException {
    JsonElement e=o.get(name);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isBoolean())throw new IOException("Expected JSON boolean");return e.getAsBoolean();
  }
  public static byte[] encode(JsonObject object){return (new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(object)+"\n").getBytes(StandardCharsets.UTF_8);}
}
