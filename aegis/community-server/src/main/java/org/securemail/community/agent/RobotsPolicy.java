package org.securemail.community.agent;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Conservative robots gate: a matching Disallow wins; no CAPTCHA/paywall/auth bypass. */
public final class RobotsPolicy {
  private RobotsPolicy() {}
  public static void check(PublicSourceHttp http,URI source,Set<String> hosts)throws IOException{check(http,source,hosts,0);}
  public static void check(PublicSourceHttp http,URI source,Set<String> hosts,long minimumIntervalSeconds)throws IOException{
    URI robots=URI.create("https://"+source.getHost()+"/robots.txt");var response=http.get(robots,hosts,100000);
    if(response.status()==404)return;if(response.status()!=200)throw new IOException("Правила доступа источника недоступны");
    String path=source.getRawPath();if(path==null||path.isEmpty())path="/";
    if(!allows(new String(response.body(),StandardCharsets.UTF_8),path,minimumIntervalSeconds))throw new IOException("Обход источника запрещён robots.txt");
  }
  public static boolean allows(String rules,String path){return allows(rules,path,0);}
  public static boolean allows(String rules,String path,long intervalSeconds){
    boolean relevant=false,seenDirective=false;String[] lines=rules.split("\\r?\\n");if(lines.length>5000)return false;
    for(String raw:lines){String line=raw.split("#",2)[0].trim();int colon=line.indexOf(':');if(colon<0)continue;String key=line.substring(0,colon).strip().toLowerCase(Locale.ROOT),value=line.substring(colon+1).strip();
      if(key.equals("user-agent")){if(seenDirective){relevant=false;seenDirective=false;}if(value.equals("*")||value.toLowerCase(Locale.ROOT).startsWith("aegis-news"))relevant=true;continue;}
      seenDirective=true;if(!relevant)continue;
      if(key.equals("crawl-delay")){try{double delay=Double.parseDouble(value);if(!Double.isFinite(delay)||delay<0||delay>intervalSeconds)return false;}catch(NumberFormatException e){return false;}}
      if(key.equals("disallow")&&!value.isEmpty()){boolean anchor=value.endsWith("$");if(anchor)value=value.substring(0,value.length()-1);StringJoiner parts=new StringJoiner(".*");for(String part:value.split("\\*",-1))parts.add(java.util.regex.Pattern.quote(part));String regex=parts+(anchor?"":".*");if(path.matches(regex))return false;}
    }
    return true;
  }
}
