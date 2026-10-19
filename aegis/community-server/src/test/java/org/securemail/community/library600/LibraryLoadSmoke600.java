package org.securemail.community.library600;

import com.google.gson.*;
import org.securemail.client.library600.HttpLibraryTransport600;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** Measured local HTTP/SQLite load. Explicit loopback SOCKS fixture, not Tor/native capacity. */
public final class LibraryLoadSmoke600 {
 public static void main(String[]args)throws Exception {
  Path output=Path.of(args[0]);Files.createDirectories(output);LibraryHttpIntegration600Test fixture=new LibraryHttpIntegration600Test();fixture.dir=Files.createTempDirectory("library-load600-");fixture.setup();
  try {
   List<Map<String,Object>>publicDocuments=new ArrayList<>();Set<String>closed=new HashSet<>();for(int i=0;i<100;i++)publicDocuments.add(fixture.document(false,false));for(int i=0;i<20;i++)closed.add((String)fixture.document(true,false).get("id"));
   List<Map<String,Object>>runs=new ArrayList<>();for(int concurrency:List.of(4,16)){
    List<HttpLibraryTransport600>clients=new ArrayList<>();for(int i=0;i<concurrency;i++)clients.add(fixture.client(fixture.reader));ExecutorService workers=Executors.newFixedThreadPool(concurrency);List<Future<List<Long>>>jobs=new ArrayList<>();long heapBefore=used(),started=System.nanoTime();
    try{for(int worker=0;worker<concurrency;worker++){int index=worker;var client=clients.get(worker);jobs.add(workers.submit(()->{List<Long>latency=new ArrayList<>();for(int iteration=0;iteration<5;iteration++){String op=switch(iteration%3){case 0->"graph";case 1->"catalog";default->"read";};Map<String,Object>request=op.equals("read")?Map.of("id",publicDocuments.get((index*5+iteration)%publicDocuments.size()).get("id")):Map.of("limit",50);long before=System.nanoTime();Map<String,Object>data=fixture.call(client,op,request);latency.add(System.nanoTime()-before);if(op.equals("graph")){for(Object node:(List<?>)data.get("nodes"))if(closed.contains(((Map<?,?>)node).get("id")))throw new AssertionError("Closed graph node leaked");if(((List<?>)data.get("nodes")).size()>50)throw new AssertionError("Unbounded graph");}if(op.equals("catalog")){for(Object item:(List<?>)data.get("items"))if(closed.contains(((Map<?,?>)item).get("id")))throw new AssertionError("Closed catalog entry leaked");if(!((List<?>)data.get("locked")).isEmpty())throw new AssertionError("Implicit title discovery");}if(op.equals("read")&&!"Русский текст".equals(data.get("body")))throw new AssertionError("Read mismatch");}return latency;}));}
     List<Long>times=new ArrayList<>();for(var job:jobs)times.addAll(job.get(90,TimeUnit.SECONDS));Collections.sort(times);long duration=System.nanoTime()-started;runs.add(Map.of("concurrency",concurrency,"requests",times.size(),"elapsedMillis",duration/1_000_000.0,"p50Millis",times.get((times.size()-1)/2)/1_000_000.0,"p95Millis",times.get(Math.min(times.size()-1,(int)Math.ceil(times.size()*.95)-1))/1_000_000.0,"heapBeforeBytes",heapBefore,"heapAfterBytes",used(),"graphPageBound",50,"closedNodesLeaked",0));
    }finally{workers.shutdownNow();for(var client:clients)client.close();}
   }
   var client=fixture.client(fixture.reader);String hidden=closed.iterator().next();if(!"NOT_FOUND".equals(org.junit.jupiter.api.Assertions.assertThrows(HttpLibraryTransport600.Rejected.class,()->fixture.call(client,"read",Map.of("id",hidden))).code()))throw new AssertionError("Closed read not uniform");
   Map<String,Object>doc=publicDocuments.getFirst();var changed=fixture.content.handle(fixture.editor.session().accountId(),"content.library.update",Map.of("id",doc.get("id"),"revision",doc.get("revision"),"title","Отозвано","body","Закрыто","policy",Map.of("users",List.of(fixture.editor.session().accountId()))));fixture.content.handle(fixture.editor.session().accountId(),"content.library.publish",Map.of("id",changed.get("id"),"revision",changed.get("revision")));org.junit.jupiter.api.Assertions.assertThrows(HttpLibraryTransport600.Rejected.class,()->fixture.call(client,"read.authorize",Map.of("id",doc.get("id"))));
   Files.writeString(output.resolve("RESULT.json"),new GsonBuilder().setPrettyPrinting().create().toJson(Map.of("status","PASS_LOCAL_MEASUREMENT","scope","Actual Identity/Library HTTP, signatures, SQLite and production client through loopback SOCKS; NOT Tor/native throughput or production target","publicDocuments",100,"closedDocuments",20,"runs",runs,"closedReadDenied",true,"materialRevocationDenied",true,"java",System.getProperty("java.version"),"processors",Runtime.getRuntime().availableProcessors(),"maxHeapBytes",Runtime.getRuntime().maxMemory())));System.out.println(Files.readString(output.resolve("RESULT.json")));
  }finally{fixture.close();}
 }
 private static long used(){return Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();}
}
