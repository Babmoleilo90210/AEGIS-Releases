package org.securemail.worker;
import org.securemail.community.agent.NewsModel;
import org.securemail.community.agent.HttpNewsModel;
import org.junit.jupiter.api.Test;
import org.securemail.community.agent.*;
import org.securemail.community.agent.PublicSourceHttp;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

final class NewsWorkerTest{
 @Test void actualCollectorPipelineParsesAllowlistedRssAndPassesOnlyPublicDataToModel()throws Exception{
  var policy=Map.<String,Object>of("id",UUID.randomUUID().toString(),"url","https://source.example/rss","independenceGroup","owner","official",true,"minIntervalMinutes",15,"cityId","ru/ru-mow/moscow");String xml="<rss><channel><item><title>Новость</title><link>https://source.example/a</link><description>Событие города</description><pubDate>Thu, 15 Oct 2026 12:00:00 GMT</pubDate></item></channel></rss>";
  var http=new PublicSourceHttp(h->new InetAddress[]{InetAddress.getByName("8.8.8.8")},(u,ip,max)->new PublicSourceHttp.Response(u.getPath().equals("/robots.txt")?404:200,Map.of("content-type","application/rss+xml"),u.getPath().equals("/robots.txt")?new byte[0]:xml.getBytes(StandardCharsets.UTF_8),u));AtomicReference<Map<String,Object>>completed=new AtomicReference<>();
  NewsWorker.Coordinator coordinator=(action,d)->{if(action.equals("agent.worker.claim"))return Map.of("job",Map.of("id",UUID.randomUUID().toString(),"leaseToken","fixturelease","sources",List.of(policy),"modelPolicy",Map.of()));if(action.equals("agent.worker.complete")){completed.set(d);return Map.of("accepted",true);}throw new AssertionError("No failure expected");};
  try(var worker=new NewsWorker(coordinator,http,p->observations->{assertEquals(1,observations.size());assertEquals(true,observations.get(0).get("publicSource"));assertFalse(observations.get(0).containsKey("privateKey"));return new NewsModel.Result(Map.of("candidates",List.of()),50,5,"fixture","fixture");})){assertTrue(worker.runOnce());assertNotNull(completed.get());assertEquals(1,((List<?>)completed.get().get("fetchedSourceIds")).size());}
 }
 @Test void missingModelProducesExplicitRetryWithoutPretendPublication()throws Exception{var policy=Map.<String,Object>of("id",UUID.randomUUID().toString(),"url","https://source.example/rss","independenceGroup","owner","official",true,"minIntervalMinutes",15,"cityId","ru/ru-mow/moscow");String xml="<rss><channel><item><title>a</title><link>https://source.example/a</link><description>b</description></item></channel></rss>";var http=new PublicSourceHttp(h->new InetAddress[]{InetAddress.getByName("8.8.8.8")},(u,ip,max)->new PublicSourceHttp.Response(u.getPath().equals("/robots.txt")?404:200,Map.of("content-type","application/rss+xml"),xml.getBytes(StandardCharsets.UTF_8),u));AtomicReference<String>reason=new AtomicReference<>();try(var worker=new NewsWorker((a,d)->{if(a.equals("agent.worker.claim"))return Map.of("job",Map.of("id",UUID.randomUUID().toString(),"leaseToken","fixture","sources",List.of(policy),"modelPolicy",Map.of()));if(a.equals("agent.worker.fail")){reason.set(d.get("reason").toString());return Map.of();}throw new AssertionError("No fake publication");},http,p->{throw new java.io.IOException("No model configured");})){assertFalse(worker.runOnce());assertEquals("MODEL_UNAVAILABLE",reason.get());}}
}
