package org.securemail.community.agent;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Server-side public-source HTTPS only. DNS is resolved once, checked, then pinned to the socket. */
public final class PublicSourceHttp {
  @FunctionalInterface public interface Resolver { InetAddress[] resolve(String host)throws IOException; }
  @FunctionalInterface public interface Exchange { Response request(URI uri,InetAddress address,int maxBytes)throws IOException; }
  public record Response(int status,Map<String,String> headers,byte[] body,URI uri) {
    public Response {headers=Map.copyOf(headers);body=body.clone();}
    @Override public byte[] body(){return body.clone();}
  }
  private final Resolver resolver;private final Exchange exchange;
  public PublicSourceHttp(){this(InetAddress::getAllByName,PublicSourceHttp::https);}
  public PublicSourceHttp(Resolver resolver,Exchange exchange){this.resolver=resolver;this.exchange=exchange;}
  public Response get(URI initial,Set<String> allowedHosts,int maxBytes)throws IOException {
    if(maxBytes<1||maxBytes>2_000_000)throw new IOException("Ограничение ответа");
    URI uri=initial;
    for(int n=0;n<=3;n++){
      uri=validate(uri,allowedHosts);InetAddress[] addresses=resolver.resolve(uri.getHost());
      if(addresses.length==0||addresses.length>32)throw new IOException("Некорректный DNS");
      for(InetAddress a:addresses)if(!publicAddress(a))throw new IOException("Источник указывает на непубличный адрес");
      // Never call URL.openConnection: it would resolve the hostname again after validation.
      Response response=exchange.request(uri,addresses[0],maxBytes);
      if(Set.of(301,302,303,307,308).contains(response.status())){
        String location=response.headers().get("location");if(location==null||location.length()>2048||n==3)throw new IOException("Перенаправление источника отклонено");
        try{uri=uri.resolve(location);}catch(IllegalArgumentException e){throw new IOException("Некорректное перенаправление",e);}continue;
      }
      return response;
    }
    throw new IOException("Слишком много перенаправлений");
  }
  public static URI validate(URI uri,Set<String> hosts)throws IOException {
    if(uri==null||!"https".equalsIgnoreCase(uri.getScheme())||uri.getRawUserInfo()!=null||uri.getRawFragment()!=null||uri.getHost()==null||(uri.getPort()!=-1&&uri.getPort()!=443)||uri.toASCIIString().length()>2048)throw new IOException("Разрешены только публичные HTTPS-источники");
    String host=uri.getHost().toLowerCase(Locale.ROOT);
    if(!host.matches("[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")||host.endsWith(".onion")||host.endsWith(".local")||host.equals("localhost")||host.indexOf('.')<0||host.matches("[0-9.]+")||!hosts.contains(host))throw new IOException("Источник отсутствует в списке разрешённых");
    if(uri.getRawPath()!=null&&(uri.getRawPath().contains("\\")||uri.getRawPath().contains("%00")))throw new IOException("Некорректный путь источника");
    return uri.normalize();
  }
  public static boolean publicAddress(InetAddress address){
    if(address.isAnyLocalAddress()||address.isLoopbackAddress()||address.isLinkLocalAddress()||address.isSiteLocalAddress()||address.isMulticastAddress())return false;
    byte[] b=address.getAddress();
    if(b.length==4){int a=b[0]&255,c=b[1]&255,d=b[2]&255;return a!=0&&a!=10&&a!=127&&a<224&&!(a==100&&c>=64&&c<=127)&&!(a==169&&c==254)&&!(a==172&&c>=16&&c<=31)&&!(a==192&&(c==0||c==168||c==88&&d==99))&&!(a==198&&(c==18||c==19||c==51&&d==100))&&!(a==203&&c==0&&d==113);}
    // IPv4-mapped, ULA, link-local, 6to4, Teredo, documentation and special-use IPv6 are refused.
    return b.length==16&&(b[0]&0xe0)==0x20&&!((b[0]&255)==0x20&&(b[1]&255)==0x02)&&!((b[0]&255)==0x20&&(b[1]&255)==0x01&&(((b[2]&255)&0xfe)==0||(b[2]&255)==0x0d&&(b[3]&255)==0xb8))&&!((b[0]&255)==0x3f&&(b[1]&255)==0xff&&((b[2]&255)&0xf0)==0);
  }
  public static Response postModel(URI uri,Map<String,String> headers,byte[] body,int maxBytes)throws IOException {
    validate(uri,Set.of(uri.getHost().toLowerCase(Locale.ROOT)));if(body.length>100000)throw new IOException("Запрос модели слишком большой");
    InetAddress[] addresses=InetAddress.getAllByName(uri.getHost());if(addresses.length==0||addresses.length>32)throw new IOException("Некорректный DNS модели");for(InetAddress a:addresses)if(!publicAddress(a))throw new IOException("Модель указывает на непубличный адрес");
    return https(uri,addresses[0],maxBytes,"POST",headers,body);
  }
  private static Response https(URI uri,InetAddress ip,int maxBytes)throws IOException {return https(uri,ip,maxBytes,"GET",Map.of(),new byte[0]);}
  private static Response https(URI uri,InetAddress ip,int maxBytes,String method,Map<String,String> extra,byte[] body)throws IOException {
    Socket raw=new Socket();raw.connect(new InetSocketAddress(ip,443),8000);raw.setSoTimeout(12000);
    try(SSLSocket socket=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(raw,uri.getHost(),443,true)){
      SSLParameters parameters=socket.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");parameters.setServerNames(List.of(new SNIHostName(uri.getHost())));parameters.setProtocols(new String[]{"TLSv1.3","TLSv1.2"});socket.setSSLParameters(parameters);socket.startHandshake();
      String target=uri.getRawPath();if(target==null||target.isEmpty())target="/";if(uri.getRawQuery()!=null)target+="?"+uri.getRawQuery();
      if(target.chars().anyMatch(c->c<33||c>126))throw new IOException("Некорректный HTTP-путь");
      StringBuilder request=new StringBuilder(method+" "+target+" HTTP/1.1\r\nHost: "+uri.getHost()+"\r\nUser-Agent: AEGIS-News/5.0 (+administrator-configured-public-sources)\r\nAccept: application/json, application/atom+xml, application/rss+xml, text/html, application/xml, text/plain\r\nAccept-Encoding: identity\r\nConnection: close\r\n");
      for(var header:extra.entrySet()){if(!Set.of("Content-Type","Authorization").contains(header.getKey())||header.getValue().chars().anyMatch(c->c<32||c>126))throw new IOException("Некорректный заголовок модели");request.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");}
      if(method.equals("POST"))request.append("Content-Length: ").append(body.length).append("\r\n");request.append("\r\n");OutputStream out=socket.getOutputStream();out.write(request.toString().getBytes(StandardCharsets.US_ASCII));out.write(body);out.flush();
      long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(method.equals("POST")?60:20);
      InputStream timed=new FilterInputStream(socket.getInputStream()){@Override public int read()throws IOException{check();int n=super.read();check();return n;}@Override public int read(byte[] b,int off,int len)throws IOException{check();int n=super.read(b,off,len);check();return n;}void check()throws IOException{if(System.nanoTime()>deadline)throw new IOException("Время запроса источника превышено");}};
      return readResponse(timed,uri,maxBytes);
    }finally{raw.close();}
  }
  public static Response readResponse(InputStream in,URI uri,int max)throws IOException {
    String first=line(in,4096);if(!first.matches("HTTP/1\\.[01] [0-9]{3}(?: .*)?"))throw new IOException("Некорректный ответ источника");int status=Integer.parseInt(first.substring(9,12));
    Map<String,String> headers=new HashMap<>();int headerBytes=first.length();for(int n=0;;n++){String l=line(in,8192);headerBytes+=l.length();if(l.isEmpty())break;if(n>=64||headerBytes>32768||l.charAt(0)==' '||l.charAt(0)=='\t')throw new IOException("Заголовки источника превышены");int colon=l.indexOf(':');if(colon<1)throw new IOException("Некорректный HTTP-заголовок");String k=l.substring(0,colon).toLowerCase(Locale.ROOT),v=l.substring(colon+1).trim();if(!k.matches("[a-z0-9-]+")||headers.putIfAbsent(k,v)!=null)throw new IOException("Повторный HTTP-заголовок");}
    if(!headers.getOrDefault("content-encoding","identity").equalsIgnoreCase("identity"))throw new IOException("Сжатый ответ источника запрещён");
    ByteArrayOutputStream body=new ByteArrayOutputStream();String transfer=headers.get("transfer-encoding");
    if(transfer!=null){if(headers.containsKey("content-length")||!transfer.equalsIgnoreCase("chunked"))throw new IOException("Неоднозначный размер ответа");for(int chunks=0;;chunks++){if(chunks>10000)throw new IOException("Слишком много HTTP-частей");String size=line(in,128);if(!size.matches("[a-fA-F0-9]{1,8}"))throw new IOException("Некорректная HTTP-часть");long count=Long.parseLong(size,16);if(count==0){if(!line(in,1024).isEmpty())throw new IOException("HTTP trailers запрещены");break;}if(count>max-body.size())throw new IOException("Ответ источника слишком большой");copy(in,body,(int)count);if(!line(in,2).isEmpty())throw new IOException("Некорректная HTTP-часть");}}
    else if(headers.containsKey("content-length")){try{long count=Long.parseLong(headers.get("content-length"));if(count<0||count>max)throw new IOException("Ответ источника слишком большой");copy(in,body,(int)count);}catch(NumberFormatException e){throw new IOException("Некорректный размер ответа",e);}}
    else{byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1){if(n>max-body.size())throw new IOException("Ответ источника слишком большой");body.write(b,0,n);}}
    return new Response(status,headers,body.toByteArray(),uri);
  }
  private static void copy(InputStream in,OutputStream out,int count)throws IOException{byte[] b=new byte[4096];while(count>0){int n=in.read(b,0,Math.min(b.length,count));if(n<0)throw new EOFException("Неполный ответ источника");out.write(b,0,n);count-=n;}}
  private static String line(InputStream in,int max)throws IOException{ByteArrayOutputStream s=new ByteArrayOutputStream();for(;;){int c=in.read();if(c<0)throw new EOFException("Неполный HTTP-заголовок");if(c=='\r'){if(in.read()!='\n')throw new IOException("Некорректный HTTP-разделитель");return s.toString(StandardCharsets.ISO_8859_1);}if(c<32&&c!='\t'||s.size()>=max)throw new IOException("Некорректный HTTP-заголовок");s.write(c);}}
}
