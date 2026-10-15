package org.securemail.client.net;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
public final class OnionAddress {
  private OnionAddress(){}
  public static String normalize(String value) {
    try {
      String text=value.strip();if(text.chars().anyMatch(Character::isWhitespace))throw new IllegalArgumentException();
      URI uri=URI.create(text.contains("://")?text:"http://"+text);
      if(!Set.of("http","https").contains(uri.getScheme().toLowerCase(Locale.ROOT))||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null||uri.getPort()!=-1&&uri.getPort()!=80||!Set.of("","/").contains(uri.getPath()))throw new IllegalArgumentException();
      String host=Objects.requireNonNull(uri.getHost()).toLowerCase(Locale.ROOT);
      if(!host.matches("[a-z2-7]{56}\\.onion"))throw new IllegalArgumentException();
      byte[] raw=new byte[35];int bits=0,acc=0,index=0;
      for(char c:host.substring(0,56).toCharArray()){int n="abcdefghijklmnopqrstuvwxyz234567".indexOf(c);acc=(acc<<5)|n;bits+=5;if(bits>=8){bits-=8;raw[index++]=(byte)(acc>>bits);}}
      if(raw[34]!=3)throw new IllegalArgumentException();
      var hash=MessageDigest.getInstance("SHA3-256");hash.update(".onion checksum".getBytes(StandardCharsets.US_ASCII));hash.update(raw,0,32);hash.update((byte)3);byte[] check=hash.digest();
      if(raw[32]!=check[0]||raw[33]!=check[1])throw new IllegalArgumentException();return host;
    }catch(Exception e){throw new IllegalArgumentException("Проверьте адрес сервера .onion");}
  }
}
