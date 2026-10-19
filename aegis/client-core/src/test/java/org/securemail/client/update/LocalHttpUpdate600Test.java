package org.securemail.client.update;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;
/** Actual loopback HTTP test channel + production state/file/hash policy. Test-only ephemeral signature verifier.
 * Does not replace production Tor HTTPS, use an owner key, or prove native install/restart E2E. */
class LocalHttpUpdate600Test {
 @TempDir Path home;UpdateSecurityTest f;HttpServer server;ExecutorService worker;Channel downloads;AtomicInteger files;List<String> ranges;
 @BeforeEach void setup()throws Exception{f=new UpdateSecurityTest();f.root=home;f.setup();files=new AtomicInteger();ranges=new CopyOnWriteArrayList<>();server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),4);worker=Executors.newFixedThreadPool(2);server.setExecutor(worker);downloads=new Channel();server.createContext("/",downloads::respond);server.start();}
 @AfterEach void close(){server.stop(0);worker.shutdownNow();}
 final class Channel implements UpdateService.Downloads{
  final HttpClient http=HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(2)).build();boolean truncate,changed,invalidSignature;
  void respond(HttpExchange x){try{String name=x.getRequestURI().getPath();byte[] body;if(name.endsWith(".sig"))body=invalidSignature?new byte[64]:f.sign(JsonData.encode(f.doc()));else if(name.endsWith(".json"))body=JsonData.encode(f.doc());else{files.incrementAndGet();body=f.archive.clone();if(changed)body[body.length/2]^=1;}String range=x.getRequestHeaders().getFirst("Range");int offset=0;if(range!=null){ranges.add(range);if(!range.matches("bytes=[0-9]+-"))throw new IOException();offset=Integer.parseInt(range.substring(6,range.length()-1));x.getResponseHeaders().set("Content-Range","bytes "+offset+"-"+(body.length-1)+"/"+body.length);}int length=body.length-offset;x.sendResponseHeaders(offset>0?206:200,length);if(!name.endsWith(".json")&&!name.endsWith(".sig")&&truncate&&files.get()==1)length/=2;x.getResponseBody().write(body,offset,length);}catch(Exception ignored){}finally{x.close();}}
  HttpRequest.Builder request(URI uri){return HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+server.getAddress().getPort()+uri.getRawPath())).timeout(java.time.Duration.ofSeconds(4));}
  public boolean resumable(){return true;}
  public byte[] bytes(URI uri,int max)throws IOException{try{HttpResponse<byte[]> r=http.send(request(uri).GET().build(),HttpResponse.BodyHandlers.ofByteArray());if(r.statusCode()!=200||r.body().length>max)throw new IOException();return r.body();}catch(InterruptedException e){Thread.currentThread().interrupt();throw new InterruptedIOException();}}
  public void file(SignedManifest.Asset asset,Path target,java.util.function.BooleanSupplier cancel,UpdateService.Progress progress)throws IOException{
   long offset=Files.exists(target)?Files.size(target):0;HttpRequest.Builder q=request(asset.url());if(offset>0)q.header("Range","bytes="+offset+"-");try{HttpResponse<InputStream> r=http.send(q.GET().build(),HttpResponse.BodyHandlers.ofInputStream());if(r.statusCode()==206)TorHttpsClient.checkRange(r.headers().firstValue("Content-Range").orElse(null),offset,asset.size());else if(r.statusCode()!=200||offset!=0)throw new IOException();try(InputStream input=r.body();OutputStream out=Files.newOutputStream(target,StandardOpenOption.CREATE,StandardOpenOption.APPEND)){byte[] b=new byte[256];long n=offset;for(int count;(count=input.read(b))!=-1;){if(cancel.getAsBoolean())throw new InterruptedIOException();if(n+count>asset.size())throw new IOException("Oversized test channel");out.write(b,0,count);n+=count;progress.accept(n,asset.size());}if(n!=asset.size())throw new EOFException("Interrupted test HTTP response");}}catch(InterruptedException e){Thread.currentThread().interrupt();throw new InterruptedIOException();}}
 }
 UpdateService service()throws Exception{return f.service(downloads);}
 @Test void interruptedActualHttpDownloadResumesWithExactRangeAndVerifiedSha()throws Exception{downloads.truncate=true;try(UpdateService service=service()){service.check(true);f.await(service,UpdateService.State.FAILED);Path partial;try(var entries=Files.list(home.resolve("updates"))){partial=entries.filter(p->p.toString().endsWith(".part")).findFirst().orElseThrow();}long offset=Files.size(partial);assertTrue(offset>0&&offset<f.archive.length);long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);while(service.snapshot().state()==UpdateService.State.FAILED&&System.nanoTime()<end){service.download();Thread.sleep(10);}f.await(service,UpdateService.State.READY_TO_INSTALL);assertEquals(List.of("bytes="+offset+"-"),ranges);UpdateService.verifyFile(partial,service.snapshot().manifest().clientAsset(true));}}
 @Test void actualHttpSameSizeChangedBytesCannotReachReadyOrTouchInstalledBinary()throws Exception{downloads.changed=true;Path installed=home.resolve("AEGIS.exe");Files.writeString(installed,"old installed fixture");try(UpdateService service=service()){service.check(true);f.await(service,UpdateService.State.FAILED);assertEquals("old installed fixture",Files.readString(installed));try(var entries=Files.list(home.resolve("updates"))){assertFalse(entries.anyMatch(p->p.toString().endsWith(".part")));}assertNotEquals(UpdateService.State.READY_TO_INSTALL,service.snapshot().state());}}
 @Test void actualHttpSignedVersionBelowFloorNeverDownloadsAnyAsset()throws Exception{Files.createDirectories(home.resolve("updates"));Files.writeString(home.resolve("updates/stable.floor"),"6.2.0\n");try(UpdateService service=service()){service.check(true);f.await(service,UpdateService.State.FAILED);assertEquals("VERSION_ROLLBACK",service.snapshot().diagnostic().code());assertEquals(0,files.get());assertEquals("6.2.0\n",Files.readString(home.resolve("updates/stable.floor")));}}
 @Test void actualHttpUntrustedSignatureIsRejectedBeforeArtifactDownloadOrHistory()throws Exception{downloads.invalidSignature=true;try(UpdateService service=service()){service.check(true);f.await(service,UpdateService.State.FAILED);assertEquals(UpdateDiagnostic.Category.SIGNATURE,service.snapshot().diagnostic().category());assertEquals(0,files.get());assertFalse(Files.exists(home.resolve("updates/stable.floor")));}}
}
