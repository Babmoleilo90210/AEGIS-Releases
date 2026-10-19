package org.securemail.identity;
import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;
/** Small protocol input; duplicate keys, precision loss, malformed UTF-8 and deep trees are refused. */
final class IdentityJson {
    private static final Gson GSON=new GsonBuilder().disableHtmlEscaping().create();
    private IdentityJson() { }
    static Map<String,Object> parse(byte[] bytes)throws IOException {if(bytes.length<2||bytes.length>65536)throw new IOException("Size");String text;try{text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();}catch(CharacterCodingException e){throw new IOException("UTF8",e);}try(JsonReader reader=new JsonReader(new StringReader(text))){reader.setStrictness(Strictness.STRICT);int[] nodes={0};Object value=read(reader,0,nodes);if(reader.peek()!=JsonToken.END_DOCUMENT||!(value instanceof Map<?,?>))throw new IOException("Object");@SuppressWarnings("unchecked") Map<String,Object> object=(Map<String,Object>)value;return object;}}
    private static Object read(JsonReader r,int depth,int[] nodes)throws IOException {if(depth>12||++nodes[0]>512)throw new IOException("Budget");return switch(r.peek()){case BEGIN_OBJECT->{Map<String,Object> map=new LinkedHashMap<>();r.beginObject();while(r.hasNext()){String key=r.nextName();if(key.length()>80||map.containsKey(key))throw new IOException("Duplicate/key");map.put(key,read(r,depth+1,nodes));}r.endObject();yield map;}case BEGIN_ARRAY->{List<Object> list=new ArrayList<>();r.beginArray();while(r.hasNext())list.add(read(r,depth+1,nodes));r.endArray();yield list;}case STRING->{String s=r.nextString();if(s.length()>49152)throw new IOException("String");for(int i=0;i<s.length();i++){char c=s.charAt(i);if(Character.isHighSurrogate(c)){if(++i>=s.length()||!Character.isLowSurrogate(s.charAt(i)))throw new IOException("Surrogate");}else if(Character.isLowSurrogate(c))throw new IOException("Surrogate");}yield s;}case NUMBER->{String s=r.nextString();if(!s.matches("0|[1-9][0-9]{0,18}"))throw new IOException("Integer");try{yield Long.parseLong(s);}catch(NumberFormatException e){throw new IOException("Integer",e);}}case BOOLEAN->r.nextBoolean();case NULL->{r.nextNull();yield null;}default->throw new IOException("Token");};}
    static byte[] bytes(Object value){return GSON.toJson(value).getBytes(StandardCharsets.UTF_8);}
    static String text(Map<String,Object> map,String key,int max){Object value=map.get(key);if(!(value instanceof String s)||s.length()>max)throw new IdentityException("INVALID");return s;}
    static long number(Map<String,Object> map,String key){Object value=map.get(key);if(!(value instanceof Long n)||n<0)throw new IdentityException("INVALID");return n;}
    static void keys(Map<String,Object> map,String... keys){if(!map.keySet().equals(Set.of(keys)))throw new IdentityException("INVALID");}
    static byte[] binary(Map<String,Object> map,String key,int size){byte[] b=org.securemail.ecosystem.protocol.IdentityProtocol.unb64(text(map,key,((size+2)/3)*4),size);if(b.length!=size)throw new IdentityException("INVALID");return b;}
}
