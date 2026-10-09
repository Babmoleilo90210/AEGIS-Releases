package org.securemail.client.update;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.function.*;
import javax.net.ssl.*;
import org.securemail.client.net.TorTransport;
import org.securemail.client.storage.AtomicFiles;

/** HTTPS over an explicit loopback SOCKS5 tunnel; no global proxy or DNS fallback. */
public final class TorHttpsClient implements UpdateService.Downloads {
  private final TorTransport transport;
  public TorHttpsClient(int socksPort){transport=new TorTransport("127.0.0.1",socksPort);}
  @Override public boolean resumable(){return true;}
  static void destination(URI uri)throws IOException {
    if(!"https".equals(uri.getScheme())||uri.getUserInfo()!=null||uri.getFragment()!=null||uri.getPort()!=-1&&uri.getPort()!=443||!Set.of("github.com","raw.githubusercontent.com","release-assets.githubusercontent.com","objects.githubusercontent.com").contains(uri.getHost()))throw new IOException("Update HTTPS destination rejected");
    if(uri.toASCIIString().length()>8192)throw new IOException("Update URL too long");
  }
  public byte[] bytes(URI uri,int max)throws IOException {
    ByteArrayOutputStream out=new ByteArrayOutputStream();transfer(uri,out,max,0,()->{},()->false,(n,total)->{});return out.toByteArray();
  }
  public void file(SignedManifest.Asset asset,Path target,BooleanSupplier cancelled,UpdateService.Progress progress)throws IOException {
    if(Files.isSymbolicLink(target)||Files.exists(target,LinkOption.NOFOLLOW_LINKS)&&!Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS))throw new IOException("Unsafe update staging file");
    long offset=Files.exists(target)?Files.size(target):0;if(offset>asset.size()){Files.delete(target);offset=0;}if(offset==asset.size())return;
    try(var out=java.nio.channels.FileChannel.open(target,Set.of(StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),AtomicFiles.exportAttributes(target.toAbsolutePath().getParent()))) {
      out.position(offset);
      try{transfer(asset.url(),java.nio.channels.Channels.newOutputStream(out),asset.size(),offset,()->{out.truncate(0);out.position(0);},cancelled,(n,total)->progress.accept(n,asset.size()));}
      finally{out.force(true);}
    }
    if(Files.size(target)!=asset.size())throw new IOException("Incomplete update download");
  }
  @FunctionalInterface private interface Restart{void run()throws IOException;}
  static void checkRange(String header,long offset,long total)throws IOException {
    if(header==null||!header.matches("bytes [0-9]+-[0-9]+/[0-9]+"))throw new IOException("Invalid resume range");
    try{String[] parts=header.substring(6).split("[-/]");if(Long.parseLong(parts[0])!=offset||Long.parseLong(parts[1])!=total-1||Long.parseLong(parts[2])!=total)throw new IOException("Resume range mismatch");}
    catch(NumberFormatException failure){throw new IOException("Invalid resume range",failure);}
  }
  private void transfer(URI uri,OutputStream out,long limit,long offset,Restart restart,BooleanSupplier cancelled,UpdateService.Progress progress)throws IOException {
    for(int redirect=0;redirect<=5;redirect++) {
      destination(uri);if(cancelled.getAsBoolean())throw new InterruptedIOException("Update cancelled");
      try(var tunnel=transport.connectUpdate(uri.getHost());var tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(tunnel,uri.getHost(),443,true)) {
        SSLParameters parameters=tls.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");parameters.setServerNames(List.of(new SNIHostName(uri.getHost())));tls.setSSLParameters(parameters);tls.setEnabledProtocols(new String[]{"TLSv1.3","TLSv1.2"});tls.setSoTimeout(20000);tls.startHandshake();
        String path=uri.getRawPath();if(path==null||path.isEmpty())path="/";if(uri.getRawQuery()!=null)path+="?"+uri.getRawQuery();
        if(path.contains("\r")||path.contains("\n"))throw new IOException("Invalid request path");
        tls.getOutputStream().write(("GET "+path+" HTTP/1.1\r\nHost: "+uri.getHost()+"\r\nUser-Agent: AEGIS/"+SignedManifest.CURRENT+"\r\nAccept-Encoding: identity\r\n"+(offset>0?"Range: bytes="+offset+"-\r\n":"")+"Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));tls.getOutputStream().flush();
        InputStream in=new BufferedInputStream(tls.getInputStream());String status=line(in,8192);if(!status.matches("HTTP/1\\.[01] [0-9]{3}.*"))throw new IOException("Invalid HTTPS response");int code=Integer.parseInt(status.substring(9,12));Map<String,String> headers=new HashMap<>();int headerBytes=status.length();
        for(int n=0;n<100;n++){String line=line(in,8192);headerBytes+=line.length();if(headerBytes>65536)throw new IOException("HTTP headers too large");if(line.isEmpty())break;int at=line.indexOf(':');if(at<1||n==99)throw new IOException("Invalid HTTP header");String name=line.substring(0,at).toLowerCase(Locale.ROOT);if(headers.putIfAbsent(name,line.substring(at+1).trim())!=null)throw new IOException("Duplicate HTTP header");}
        if(Set.of(301,302,303,307,308).contains(code)){String location=headers.get("location");if(location==null||redirect==5)throw new UpdateDiagnostic.Failure(UpdateDiagnostic.Category.HTTP,"REDIRECT_REJECTED");try{uri=uri.resolve(location);}catch(IllegalArgumentException e){throw new UpdateDiagnostic.Failure(UpdateDiagnostic.Category.HTTP,"REDIRECT_REJECTED");}continue;}
        if(code==206&&offset>0)checkRange(headers.get("content-range"),offset,limit);
        else if(code==200){if(offset>0){restart.run();offset=0;}}
        else throw new UpdateDiagnostic.Failure(UpdateDiagnostic.Category.HTTP,code==404?"FEED_NOT_FOUND":"HTTP_STATUS_REJECTED");
        if(headers.containsKey("content-encoding")&&!headers.get("content-encoding").equalsIgnoreCase("identity"))throw new IOException("Compressed update response rejected");
        long declared=-1;try{if(headers.containsKey("content-length"))declared=Long.parseLong(headers.get("content-length"));}catch(NumberFormatException e){throw new IOException("Invalid response length",e);}
        if(declared>limit-offset||declared< -1||code==206&&declared!=-1&&declared!=limit-offset)throw new IOException("Oversized update response");
        boolean chunks=headers.containsKey("transfer-encoding");if(chunks&&!headers.get("transfer-encoding").equalsIgnoreCase("chunked")||chunks&&declared!=-1)throw new IOException("Ambiguous update response");
        long count=offset;byte[] buffer=new byte[65536];
        if(chunks){
          while(true){String length=line(in,256);if(!length.matches("[0-9a-fA-F]{1,12}"))throw new IOException("Invalid chunk");long n=Long.parseLong(length,16);if(n==0){for(int t=0;t<32;t++){if(line(in,8192).isEmpty())return;if(t==31)throw new IOException("Invalid trailers");}}if(count+n>limit)throw new IOException("Oversized update response");count=copy(in,out,n,count,limit,cancelled,progress,buffer);if(!line(in,2).isEmpty())throw new IOException("Invalid chunk terminator");}
        }else {
          while(true){if(cancelled.getAsBoolean())throw new InterruptedIOException("Update cancelled");int n=in.read(buffer,0,(int)Math.min(buffer.length,Math.max(1,limit-count+1)));if(n<0)break;count+=n;if(count>limit)throw new IOException("Oversized update response");out.write(buffer,0,n);progress.accept(count,declared);}
          if(declared!=-1&&count-offset!=declared)throw new EOFException("Interrupted HTTPS response");return;
        }
      }
    }throw new IOException("Too many redirects");
  }
  private static long copy(InputStream in,OutputStream out,long left,long count,long limit,BooleanSupplier cancel,UpdateService.Progress progress,byte[] buffer)throws IOException {
    while(left>0){if(cancel.getAsBoolean())throw new InterruptedIOException("Update cancelled");int n=in.read(buffer,0,(int)Math.min(left,buffer.length));if(n<0)throw new EOFException("Interrupted chunk");out.write(buffer,0,n);left-=n;count+=n;if(count>limit)throw new IOException("Oversized download");progress.accept(count,limit);}return count;
  }
  private static String line(InputStream in,int max)throws IOException {
    ByteArrayOutputStream out=new ByteArrayOutputStream();int previous=-1;
    while(out.size()<=max){int c=in.read();if(c<0)throw new EOFException("Interrupted HTTP header");if(previous==13&&c==10){byte[] data=out.toByteArray();return new String(data,0,data.length-1,StandardCharsets.US_ASCII);}out.write(c);previous=c;}throw new IOException("HTTP line too long");
  }
}
