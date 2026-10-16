package org.securemail.client.community;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.math.BigDecimal;

/** Bounded authenticated-response and encrypted-cache JSON. Rejects ambiguous documents. */
public final class CommunityJson {
    public static final int MAX_BYTES=8*1024*1024;
    private static final int MAX_STRING_BYTES=6*1024*1024,MAX_DEPTH=16,MAX_NODES=8192;
    private CommunityJson(){}
    public static JsonObject parse(byte[] bytes)throws IOException {
        if(bytes==null||bytes.length==0||bytes.length>MAX_BYTES)throw invalid();
        try {
            String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            JsonReader reader=new JsonReader(new StringReader(text));reader.setStrictness(Strictness.STRICT);
            JsonElement value=read(reader,0,new int[]{0});
            if(!value.isJsonObject()||reader.peek()!=JsonToken.END_DOCUMENT)throw invalid();
            return value.getAsJsonObject();
        } catch(IllegalStateException|IllegalArgumentException e) {throw invalid();}
    }
    private static JsonElement read(JsonReader r,int depth,int[] nodes)throws IOException {
        if(depth>MAX_DEPTH||++nodes[0]>MAX_NODES)throw invalid();
        return switch(r.peek()){
            case BEGIN_OBJECT -> {
                r.beginObject();JsonObject object=new JsonObject();
                while(r.hasNext()){String name=r.nextName();validString(name,256);if(object.has(name))throw invalid();object.add(name,read(r,depth+1,nodes));}
                r.endObject();yield object;
            }
            case BEGIN_ARRAY -> {r.beginArray();JsonArray array=new JsonArray();while(r.hasNext())array.add(read(r,depth+1,nodes));r.endArray();yield array;}
            case STRING -> {String value=r.nextString();validString(value,MAX_STRING_BYTES);yield new JsonPrimitive(value);}
            case NUMBER -> {
                String lexical=r.nextString();if(lexical.length()>128)throw invalid();BigDecimal value=new BigDecimal(lexical);
                if(value.precision()>128||value.scale() < -308||value.scale()>512)throw invalid();yield new JsonPrimitive(value);
            }
            case BOOLEAN -> new JsonPrimitive(r.nextBoolean());
            case NULL -> {r.nextNull();yield JsonNull.INSTANCE;}
            default -> throw invalid();
        };
    }
    private static void validString(String value,int bytes)throws IOException {
        if(value.length()>bytes)throw invalid();
        for(int i=0;i<value.length();i++){char ch=value.charAt(i);if(Character.isHighSurrogate(ch)){if(i+1>=value.length()||!Character.isLowSurrogate(value.charAt(++i)))throw invalid();}else if(Character.isLowSurrogate(ch))throw invalid();}
        if(value.getBytes(StandardCharsets.UTF_8).length>bytes)throw invalid();
    }
    private static IOException invalid(){return new IOException("Некорректный или слишком большой JSON общей системы");}
}
