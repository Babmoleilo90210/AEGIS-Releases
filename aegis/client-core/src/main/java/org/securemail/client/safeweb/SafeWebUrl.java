package org.securemail.client.safeweb;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/** An explicit web URL, never an executable, filename, browser switch or IPC payload. */
public final class SafeWebUrl {
  private SafeWebUrl() {}
  public static URI parse(String value) {
    if(value==null||value.isBlank()||value.length()>4096||!value.equals(value.strip())||value.codePoints().anyMatch(c->Character.isISOControl(c)||Character.isWhitespace(c))||value.indexOf('\\')>=0)
      throw new IllegalArgumentException("Введите полный HTTPS-адрес или HTTP-адрес onion-сайта");
    try {
      URI uri=new URI(value);String host=uri.getHost(),scheme=uri.getScheme();
      if(host==null||scheme==null||uri.getRawUserInfo()!=null||uri.getPort()==0||uri.getPort()>65535)throw new URISyntaxException("","URL");
      host=host.toLowerCase(Locale.ROOT);scheme=scheme.toLowerCase(Locale.ROOT);
      boolean onion=host.matches("(?:[a-z0-9-]+\\.)*[a-z2-7]{56}\\.onion");
      if(!scheme.equals("https")&&!(scheme.equals("http")&&onion))throw new URISyntaxException("","Scheme");
      if(host.equals("localhost")||host.endsWith(".localhost")||host.indexOf(':')>=0||host.startsWith("[")||host.matches("[0-9.]+")||!host.contains(".")||host.endsWith(".onion")&&!onion)throw new URISyntaxException("","Host");
      return uri;
    }catch(URISyntaxException invalid){throw new IllegalArgumentException("Разрешены HTTPS-сайты и onion v3; локальные адреса, команды и URL с паролями запрещены");}
  }
}
