package org.securemail.community.core;
import java.util.*;
/** Typed bounded RPC extraction; no automatic mass assignment of fields. */
public final class Values {
 private Values(){}
 public static String string(Map<String,Object>m,String key,int max)throws CommunityException{Object o=m.get(key);if(!(o instanceof String s)||s.isBlank()||s.length()>max||s.indexOf('\0')>=0)throw CommunityException.invalid();return s;}
 public static String optional(Map<String,Object>m,String key,int max)throws CommunityException{Object o=m.get(key);if(o==null)return "";if(!(o instanceof String s)||s.length()>max||s.indexOf('\0')>=0)throw CommunityException.invalid();return s;}
 public static long number(Map<String,Object>m,String key)throws CommunityException{Object o=m.get(key);if(!(o instanceof Number n))throw CommunityException.invalid();try{java.math.BigDecimal value=new java.math.BigDecimal(n.toString());if(value.precision()>128||value.scale()< -128||value.scale()>128)throw CommunityException.invalid();return value.longValueExact();}catch(NumberFormatException|ArithmeticException e){throw CommunityException.invalid();}}
 public static boolean bool(Map<String,Object>m,String key,boolean fallback)throws CommunityException{Object o=m.get(key);if(o==null)return fallback;if(!(o instanceof Boolean b))throw CommunityException.invalid();return b;}
 public static Set<String> strings(Map<String,Object>m,String key,int max)throws CommunityException{Object o=m.get(key);if(o==null)return Set.of();if(!(o instanceof List<?> a)||a.size()>max)throw CommunityException.invalid();Set<String>s=new TreeSet<>();for(Object v:a){if(!(v instanceof String x)||x.isBlank()||x.length()>160)throw CommunityException.invalid();s.add(x);}return Set.copyOf(s);}
 public static String identity(String s)throws CommunityException{if(s==null||!s.matches("[a-f0-9]{64}"))throw CommunityException.invalid();return s;}
 public static String scope(String s)throws CommunityException{if(!"GLOBAL".equals(s)&&!s.matches("ORG:[a-f0-9-]{36}"))throw CommunityException.invalid();return s;}
 public static String permission(String s)throws CommunityException{if(s==null||!s.matches("[A-Z][A-Z0-9_]{1,63}"))throw CommunityException.invalid();return s;}
}
