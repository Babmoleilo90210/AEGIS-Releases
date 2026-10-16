package org.securemail.community.core;
import java.util.*;
/** Bounded deterministic serialization for critical operation commitments (not a crypto primitive). */
public final class CanonicalJson {
 private CanonicalJson(){}
 public static String encode(Object value)throws CommunityException{StringBuilder b=new StringBuilder();write(b,value,0);if(b.length()>65536)throw CommunityException.invalid();return b.toString();}
 private static void write(StringBuilder b,Object v,int depth)throws CommunityException{
  if(depth>16||b.length()>65536)throw CommunityException.invalid();
  if(v==null)b.append("null");else if(v instanceof String s){for(int i=0;i<s.length();i++){char c=s.charAt(i);if(Character.isHighSurrogate(c)){if(i+1>=s.length()||!Character.isLowSurrogate(s.charAt(++i)))throw CommunityException.invalid();}else if(Character.isLowSurrogate(c))throw CommunityException.invalid();}b.append('"');for(char c:s.toCharArray())switch(c){case '"'->b.append("\\\"");case '\\'->b.append("\\\\");case '\n'->b.append("\\n");case '\r'->b.append("\\r");case '\t'->b.append("\\t");default->{if(c<32)b.append(String.format(Locale.ROOT,"\\u%04x",(int)c));else b.append(c);}}b.append('"');}
  else if(v instanceof Boolean)b.append(v);else if(v instanceof Number n){try{java.math.BigDecimal value=new java.math.BigDecimal(n.toString());if(value.precision()>128||value.scale()< -128||value.scale()>128)throw CommunityException.invalid();b.append(value.stripTrailingZeros().toPlainString());}catch(NumberFormatException|ArithmeticException e){throw CommunityException.invalid();}}
  else if(v instanceof Map<?,?>m){if(m.size()>128)throw CommunityException.invalid();TreeMap<String,Object>sorted=new TreeMap<>();for(var e:m.entrySet()){if(!(e.getKey() instanceof String s))throw CommunityException.invalid();sorted.put(s,e.getValue());}b.append('{');boolean comma=false;for(var e:sorted.entrySet()){if(comma)b.append(',');write(b,e.getKey(),depth+1);b.append(':');write(b,e.getValue(),depth+1);comma=true;}b.append('}');}
  else if(v instanceof Collection<?>a){if(a.size()>256)throw CommunityException.invalid();b.append('[');boolean comma=false;for(Object x:a){if(comma)b.append(',');write(b,x,depth+1);comma=true;}b.append(']');}else throw CommunityException.invalid();
 }
 public static Map<String,Object> operationFields(Map<String,Object>data){Map<String,Object>copy=new TreeMap<>(data);copy.remove("stepUp");copy.remove("requestId");return copy;}
}
