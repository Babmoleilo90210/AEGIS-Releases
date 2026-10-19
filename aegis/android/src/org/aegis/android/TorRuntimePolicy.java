package org.aegis.android;
import java.io.*;
import java.util.*;
/** Fixed local Tor configuration and strict listener parsing shared with host checks. */
public final class TorRuntimePolicy {
  private TorRuntimePolicy(){}
  public static final String CONFIG="ClientOnly 1\nAvoidDiskWrites 1\nSocksPort auto IPv4Only SessionGroup=100 IsolateSOCKSAuth\nSocksPort auto IPv4Only SessionGroup=101 IsolateSOCKSAuth\nSocksPort auto IPv4Only SessionGroup=102 IsolateSOCKSAuth\nHTTPTunnelPort 0\nDNSPort 0\n";
  public static int[] ports(String bootstrap,String listeners)throws IOException {
    if(bootstrap==null||bootstrap.length()>1024||listeners==null||listeners.length()>512)throw new IOException("Размер статуса Tor");
    if(!java.util.regex.Pattern.compile("(?:^| )PROGRESS=100(?: |$)").matcher(bootstrap).find())return new int[0];
    ArrayList<Integer> found=new ArrayList<>();for(String token:listeners.split(" ")){if(token.isEmpty())continue;if(!token.matches("\"127\\.0\\.0\\.1:[0-9]{1,5}\""))throw new IOException("Неожиданный слушатель Tor");int port=Integer.parseInt(token.substring(token.indexOf(':')+1,token.length()-1));if(port<1||port>65535||found.contains(port))throw new IOException("Недопустимый порт Tor");found.add(port);}
    if(found.size()!=3)throw new IOException("Не подтверждены три независимых контекста SOCKS");return new int[]{found.get(0),found.get(1),found.get(2)};
  }
}
