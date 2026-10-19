package org.aegis.android;
import java.net.*;
import java.util.*;
/** Bounded local domain deny rules; no telemetry or promise of complete tracker coverage. */
final class DomainRules {
    final String canonical;private final Set<String> blocked;
    DomainRules(String source){if(source==null||source.length()>65536)throw new IllegalArgumentException("Не более 64 КиБ правил");TreeSet<String> names=new TreeSet<>();for(String line:source.split("\\s+")){if(line.isEmpty())continue;String name=domain(line);if(!names.add(name))continue;if(names.size()>1024)throw new IllegalArgumentException("Не более 1024 доменных правил");}blocked=Collections.unmodifiableSet(names);canonical=String.join("\n",names);}
    static String domain(String raw){if(raw==null||raw.length()<1||raw.length()>253||!raw.matches("[A-Za-z0-9.-]+"))throw new IllegalArgumentException("Нужен ASCII/Punycode домен");String name=raw.toLowerCase(Locale.ROOT);if(name.endsWith("."))name=name.substring(0,name.length()-1);for(String label:name.split("\\.",-1))if(label.isEmpty()||label.length()>63||label.startsWith("-")||label.endsWith("-"))throw new IllegalArgumentException("Некорректный домен");if(!name.contains(".")||name.endsWith(".local")||name.endsWith(".localhost")||name.equals("localhost"))throw new IllegalArgumentException("Локальное имя запрещено");return name;}
    boolean allowed(String raw){try{String name=domain(raw);for(String value=name;value.contains(".");value=value.substring(value.indexOf('.')+1))if(blocked.contains(value))return false;return true;}catch(IllegalArgumentException invalid){return false;}}
    static boolean publicAddress(InetAddress ip){byte[] b=ip.getAddress();if(ip.isAnyLocalAddress()||ip.isLoopbackAddress()||ip.isLinkLocalAddress()||ip.isSiteLocalAddress()||ip.isMulticastAddress())return false;if(b.length==4){int a=b[0]&255,c=b[1]&255;return a!=0&&a!=127&&a<224&&!(a==100&&c>=64&&c<=127)&&!(a==198&&(c==18||c==19))&&!(a==169&&c==254);}return b.length==16&&(b[0]&0xfe)!=0xfc;}
}
