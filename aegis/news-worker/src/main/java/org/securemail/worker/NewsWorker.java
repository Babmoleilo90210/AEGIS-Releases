package org.securemail.worker;
import org.securemail.community.agent.NewsModel;
import org.securemail.community.agent.HttpNewsModel;
import org.securemail.community.agent.PublicSourceHttp;
import org.securemail.community.agent.SourceParser;
import org.securemail.community.agent.RobotsPolicy;

import org.securemail.community.agent.AgentJson;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.concurrent.*;

/** Bounded public collector. Model output cannot grant permissions, choose URLs or run commands. */
public final class NewsWorker implements AutoCloseable {
  @FunctionalInterface public interface Coordinator{Map<String,Object>call(String action,Map<String,Object>data)throws Exception;}
  @FunctionalInterface public interface ModelFactory{NewsModel create(Map<String,Object>policy)throws Exception;}
  private final Coordinator coordinator;private final PublicSourceHttp http;private final ModelFactory models;
  private final ExecutorService collectors=new ThreadPoolExecutor(4,4,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(20),r->{Thread t=new Thread(r,"aegis-public-source");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  public NewsWorker(Coordinator coordinator,PublicSourceHttp http,ModelFactory models){this.coordinator=coordinator;this.http=http;this.models=models;}
  public boolean runOnce()throws Exception{
    Map<String,Object> claim=coordinator.call("agent.worker.claim",Map.of());Map<String,Object> job=map(claim.get("job"));if(job.isEmpty())return false;
    String id=AgentJson.text(job,"id",36),lease=AgentJson.text(job,"leaseToken",64);List<Map<String,Object>> observations=new ArrayList<>();List<String> fetched=new ArrayList<>();String failure="SOURCE_UNAVAILABLE";
    try{
      List<Map<String,Object>> sources=maps(job.get("sources"),20);List<Future<Fetch>> futures=new ArrayList<>();for(Map<String,Object> source:sources)futures.add(collectors.submit(()->fetch(source)));
      int bytes=0;for(int n=0;n<futures.size();n++){try{Fetch result=futures.get(n).get(45,TimeUnit.SECONDS);fetched.add(result.sourceId);for(Map<String,Object> item:result.items){int size=AgentJson.bytes(item).length;if(observations.size()>=200||bytes+size>75000)break;observations.add(item);bytes+=size;}}catch(ExecutionException|TimeoutException e){futures.get(n).cancel(true);}}
      if(observations.isEmpty())throw new IOException("Нет доступных публичных материалов");failure="MODEL_UNAVAILABLE";Map<String,Object> policy=map(job.get("modelPolicy"));
      try(NewsModel model=models.create(policy)){NewsModel.Result result=model.analyze(observations);failure="INVALID_MODEL_RESPONSE";Map<String,Object> complete=new LinkedHashMap<>();complete.put("jobId",id);complete.put("leaseToken",lease);complete.put("observations",observations);complete.put("analysis",result.document());complete.put("inputTokens",result.inputTokens());complete.put("outputTokens",result.outputTokens());complete.put("fetchedSourceIds",fetched);coordinator.call("agent.worker.complete",complete);return true;}
    }catch(InterruptedException e){Thread.currentThread().interrupt();coordinator.call("agent.worker.fail",Map.of("jobId",id,"leaseToken",lease,"reason","CANCELLED"));throw e;}catch(Exception e){coordinator.call("agent.worker.fail",Map.of("jobId",id,"leaseToken",lease,"reason",failure));return false;}
  }
  private record Fetch(String sourceId,List<Map<String,Object>>items){}
  private Fetch fetch(Map<String,Object> source)throws Exception{String id=AgentJson.text(source,"id",36),group=AgentJson.text(source,"independenceGroup",120),city=AgentJson.text(source,"cityId",160);URI url=URI.create(AgentJson.text(source,"url",2048));Set<String> hosts=Set.of(url.getHost().toLowerCase(Locale.ROOT));RobotsPolicy.check(http,url,hosts,AgentJson.number(source,"minIntervalMinutes",15,10080)*60);var response=http.get(url,hosts,1000000);if(response.status()!=200)throw new IOException("Источник недоступен");String contentType=response.headers().getOrDefault("content-type","");List<Map<String,Object>> items=new ArrayList<>();for(var observation:new SourceParser().parse(id,group,AgentJson.bool(source,"official"),city,response.uri(),contentType,response.body())){Map<String,Object> item=new LinkedHashMap<>(observation.map());item.put("publicSource",true);items.add(item);}return new Fetch(id,items);}
  @SuppressWarnings("unchecked")private static Map<String,Object>map(Object v)throws IOException{if(!(v instanceof Map<?,?> m)||m.keySet().stream().anyMatch(k->!(k instanceof String)))throw new IOException("Некорректное задание");return(Map<String,Object>)m;}
  private static List<Map<String,Object>>maps(Object v,int max)throws IOException{if(!(v instanceof List<?>l)||l.size()>max)throw new IOException("Ограничение задания");List<Map<String,Object>>out=new ArrayList<>();for(Object item:l)out.add(map(item));return out;}
  @Override public void close(){collectors.shutdownNow();}
}
