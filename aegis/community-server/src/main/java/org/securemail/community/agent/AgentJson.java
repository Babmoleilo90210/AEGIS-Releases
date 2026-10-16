package org.securemail.community.agent;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Strict bounded data-only JSON for worker messages. No polymorphic deserialization. */
public final class AgentJson {
  private AgentJson() {}
  public static Map<String,Object> object(byte[] data,int limit)throws IOException {
    if(data.length==0||data.length>limit)throw new IOException("Размер JSON превышен");
    String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data)).toString();
    Reader r=new Reader(text);Object v=r.value(0);r.space();
    if(r.i!=text.length()||!(v instanceof Map<?,?>))throw new IOException("Некорректный JSON");
    @SuppressWarnings("unchecked") Map<String,Object> result=(Map<String,Object>)v;return result;
  }
  public static byte[] bytes(Object value){StringBuilder s=new StringBuilder();write(s,value,0);return s.toString().getBytes(StandardCharsets.UTF_8);}
  public static String text(Map<String,Object> m,String k,int max)throws IOException {Object o=m.get(k);if(!(o instanceof String s)||s.length()>max||s.indexOf(0)>=0)throw new IOException("Некорректное поле: "+k);return s;}
  public static long number(Map<String,Object> m,String k,long min,long max)throws IOException {Object o=m.get(k);try{long n=o instanceof Number?new BigDecimal(o.toString()).longValueExact():Long.MIN_VALUE;if(n<min||n>max)throw new IOException("Некорректное поле: "+k);return n;}catch(NumberFormatException|ArithmeticException e){throw new IOException("Некорректное число",e);}}
  public static boolean bool(Map<String,Object> m,String k)throws IOException {if(!(m.get(k) instanceof Boolean b))throw new IOException("Некорректное поле: "+k);return b;}
  private static void write(StringBuilder s,Object v,int d){if(d>20)throw new IllegalArgumentException("JSON depth");if(v==null)s.append("null");else if(v instanceof String t){s.append('"');for(int i=0;i<t.length();i++){char c=t.charAt(i);switch(c){case '"' ->s.append("\\\"");case '\\' ->s.append("\\\\");case '\n' ->s.append("\\n");case '\r' ->s.append("\\r");case '\t' ->s.append("\\t");default ->{if(c<32||Character.isSurrogate(c))s.append(String.format(Locale.ROOT,"\\u%04x",(int)c));else s.append(c);}}}s.append('"');}else if(v instanceof Boolean||v instanceof Number){String n=v.toString();if(n.equals("NaN")||n.contains("Infinity"))throw new IllegalArgumentException("JSON number");s.append(n);}else if(v instanceof Map<?,?> m){s.append('{');boolean first=true;for(var e:m.entrySet()){if(!(e.getKey() instanceof String))throw new IllegalArgumentException("JSON key");if(!first)s.append(',');first=false;write(s,e.getKey(),d+1);s.append(':');write(s,e.getValue(),d+1);}s.append('}');}else if(v instanceof Collection<?> a){s.append('[');boolean first=true;for(Object o:a){if(!first)s.append(',');first=false;write(s,o,d+1);}s.append(']');}else throw new IllegalArgumentException("JSON type");}
  private static final class Reader {
    final String s;int i,nodes;Reader(String s){this.s=s;}
    void space(){while(i<s.length()&&" \t\r\n".indexOf(s.charAt(i))>=0)i++;}
    IOException bad(){return new IOException("Некорректный JSON");}
    Object value(int d)throws IOException{space();if(d>16||++nodes>8192||i>=s.length())throw bad();char c=s.charAt(i);if(c=='"')return string();if(c=='{'){i++;Map<String,Object> m=new LinkedHashMap<>();space();if(take('}'))return m;do{space();if(i>=s.length()||s.charAt(i)!='"')throw bad();String k=string();space();if(!take(':')||m.containsKey(k))throw bad();m.put(k,value(d+1));space();if(take('}'))return m;}while(take(','));throw bad();}if(c=='['){i++;List<Object>a=new ArrayList<>();space();if(take(']'))return a;do{a.add(value(d+1));space();if(take(']'))return a;}while(take(','));throw bad();}for(String literal:List.of("true","false","null"))if(s.startsWith(literal,i)){i+=literal.length();return literal.equals("null")?null:Boolean.valueOf(literal);}int start=i;if(take('-')){}if(take('0')){if(i<s.length()&&(s.charAt(i)>='0'&&s.charAt(i)<='9'))throw bad();}else{if(i>=s.length()||s.charAt(i)<'1'||s.charAt(i)>'9')throw bad();while(i<s.length()&&(s.charAt(i)>='0'&&s.charAt(i)<='9'))i++;}if(take('.')){int p=i;while(i<s.length()&&(s.charAt(i)>='0'&&s.charAt(i)<='9'))i++;if(p==i)throw bad();}if(take('e')||take('E')){if(take('+')){}else take('-');int p=i;while(i<s.length()&&(s.charAt(i)>='0'&&s.charAt(i)<='9'))i++;if(p==i)throw bad();}if(i-start>128)throw bad();try{BigDecimal number=new BigDecimal(s.substring(start,i));if(Math.abs((long)number.scale())>10000||number.precision()>128)throw bad();return number;}catch(NumberFormatException e){throw bad();}}
    boolean take(char c){if(i<s.length()&&s.charAt(i)==c){i++;return true;}return false;}
    String string()throws IOException{if(!take('"'))throw bad();StringBuilder b=new StringBuilder();while(i<s.length()){char c=s.charAt(i++);if(c=='"'){String result=b.toString();for(int j=0;j<result.length();j++)if(Character.isSurrogate(result.charAt(j))){if(!Character.isHighSurrogate(result.charAt(j))||j+1>=result.length()||!Character.isLowSurrogate(result.charAt(++j)))throw bad();}return result;}if(c<32)throw bad();if(c=='\\'){if(i>=s.length())throw bad();char e=s.charAt(i++);c=switch(e){case '"','\\','/' ->e;case 'b' ->'\b';case 'f' ->'\f';case 'n' ->'\n';case 'r' ->'\r';case 't' ->'\t';case 'u' ->{if(i+4>s.length())throw bad();try{String hex=s.substring(i,i+4);for(int h=0;h<4;h++){char digit=hex.charAt(h);if(!(digit>='0'&&digit<='9'||digit>='a'&&digit<='f'||digit>='A'&&digit<='F'))throw bad();}char u=(char)Integer.parseInt(hex,16);i+=4;yield u;}catch(NumberFormatException x){throw bad();}}default ->throw bad();};}b.append(c);if(b.length()>131072)throw bad();}throw bad();}
  }
}
