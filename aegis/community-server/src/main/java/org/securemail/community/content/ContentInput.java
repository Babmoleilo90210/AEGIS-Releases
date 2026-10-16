package org.securemail.community.content;

import org.securemail.community.core.CommunityException;
import org.securemail.community.core.Values;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounds and canonical identifiers at the untrusted RPC boundary. No HTML is executed. */
final class ContentInput {
    private ContentInput() {}
    static CommunityException bad() { return new CommunityException("INVALID", "Некорректные параметры материала"); }
    static String text(Map<String,Object> m, String k, int max, boolean required) throws CommunityException {
        Object o=m.get(k); if(o==null) { if(required) throw bad(); return ""; }
        if(!(o instanceof String s) || s.length()>max || s.indexOf('\0')>=0 || s.codePoints().anyMatch(c->c<32&&c!='\n'&&c!='\t'&&c!='\r')) throw bad();
        if(required&&s.isBlank()) throw bad(); return s.strip();
    }
    static String id(Map<String,Object> m,String k) throws CommunityException { String s=text(m,k,80,true); if(!s.matches("[A-Za-z0-9_-]{1,80}")) throw bad();return s; }
    static long number(Map<String,Object> m,String k,long def,long min,long max)throws CommunityException {
        Object o=m.get(k); if(o==null)return def;
        long v=Values.number(m,k);if(v<min||v>max)throw bad();return v;
    }
    static boolean bool(Map<String,Object> m,String k,boolean def)throws CommunityException {Object o=m.get(k);if(o==null)return def;if(!(o instanceof Boolean b))throw bad();return b;}
    static void keys(Map<String,Object> m,String... allowed)throws CommunityException {Set<String>s=Set.of(allowed);if(m.size()>32||m.keySet().stream().anyMatch(k->!s.contains(k)))throw bad();}
    static String city(Map<String,Object> m)throws CommunityException {String s=text(m,"cityId",160,false);if(!s.isEmpty()&&!s.matches("[a-z]{2}/[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9_-]{0,87}"))throw bad();return s;}
    static Set<String> strings(Object o,int count,int length)throws CommunityException {if(o==null)return Set.of();if(!(o instanceof List<?> list)||list.size()>count)throw bad();Set<String>s=new LinkedHashSet<>();for(Object x:list){if(!(x instanceof String v)||v.isBlank()||v.length()>length||v.contains("\n")||v.contains("\r")||v.indexOf('\0')>=0)throw bad();s.add(v);}return Set.copyOf(s);}
    static List<String> sources(Object o)throws CommunityException {Set<String> list=strings(o,20,2048);for(String s:list){try{URI u=URI.create(s);if(!"https".equalsIgnoreCase(u.getScheme())||u.getHost()==null||u.getUserInfo()!=null||u.getFragment()!=null||u.getPort()!=-1&&u.getPort()!=443)throw bad();}catch(IllegalArgumentException e){throw bad();}}return List.copyOf(list);}
    static String join(Collection<String>s){return String.join("\n",new TreeSet<>(s));}
    static Set<String> split(String s){return s==null||s.isEmpty()?Set.of():Set.copyOf(Arrays.asList(s.split("\n")));}
    static String newId(){return UUID.randomUUID().toString();}
    static String body(Map<String,Object>m)throws CommunityException {text(m,"body",250_000,true);return safeMarkdown((String)m.get("body"));}
    static String safeMarkdown(String body)throws CommunityException {
        // Store source faithfully; clients must render inert text/Markdown, never a WebView with active HTML.
        if(body.getBytes(StandardCharsets.UTF_8).length>512_000)throw bad();return body;
    }
}
