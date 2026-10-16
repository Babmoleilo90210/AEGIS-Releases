package org.securemail.ui;

import com.google.gson.*;
import javafx.application.Platform;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.securemail.ui.CommunityUi.*;

/** Synthetic, strictly decoded page fixtures exercise UI state limits, not server ACL or network acceptance. */
final class Ui500GraphBoundsChecks {
 private static <T>T fx(Callable<T> task)throws Exception{CompletableFuture<T> result=new CompletableFuture<>();Platform.runLater(()->{try{result.complete(task.call());}catch(Throwable failure){result.completeExceptionally(failure);}});return result.get(30,TimeUnit.SECONDS);}
 private static Object get(Object value,String name)throws Exception{var field=value.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(value);}
 private static String id(String text){return UUID.nameUUIDFromBytes(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();}
 private static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
 private static void until(Callable<Boolean> condition)throws Exception{long limit=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);while(System.nanoTime()<limit){if(condition.call())return;Thread.sleep(30);}throw new AssertionError("Synthetic bounded-page UI did not settle");}
 private static void more(KnowledgeLibraryView view)throws Exception{fx(()->{view.node().lookupAll(".button").stream().filter(n->n instanceof Button b&&b.getText().equals("Загрузить ещё")).map(n->(Button)n).findFirst().orElseThrow().fire();return null;});}
 private static int count(KnowledgeLibraryView view,String field)throws Exception{return fx(()->((List<?>)get(view,field)).size());}
 static void run(MessengerApp app,Stage stage)throws Exception{
  ThemeManager themes=(ThemeManager)fx(()->get(app,"themes"));BorderPane workspace=(BorderPane)fx(()->get(app,"root"));
  AtomicInteger requests=new AtomicInteger();AtomicInteger continuationLimit=new AtomicInteger();
  CommunityUi nodeApi=fx(()->new CommunityUi(themes,(action,args)->{if(!action.equals("content.library.graph"))throw new java.io.IOException("Synthetic fixture has no other services");int page=requests.getAndIncrement();JsonArray nodes=new JsonArray(),edges=new JsonArray();if(page<5){for(int i=page*100;i<page*100+100;i++)nodes.add(obj("id",id("node"+i),"title","Синтетический узел "+i,"type","NOTE"));}else{continuationLimit.set((int)number(args,"limit"));nodes.add(obj("id",id("node499"),"title","Синтетический узел 499","type","NOTE"));edges.add(obj("id",id("one-edge"),"from",id("node0"),"to",id("node499")));}return org.securemail.client.community.CommunityJson.parse(obj("nodes",nodes,"edges",edges,"nextCursor",page<4?id("cursor"+page):page==4?"E:"+id("node499")+":":"").toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));},(password,otp)->{throw new AssertionError("No authentication in a synthetic layout fixture");},url->{}));
  try{KnowledgeLibraryView view=fx(()->{KnowledgeLibraryView value=new KnowledgeLibraryView(nodeApi,"");workspace.setCenter(value.node());return value;});until(()->count(view,"nodes")==100);for(int page=1;page<5;page++){more(view);int expected=(page+1)*100;until(()->count(view,"nodes")==expected);}check(fx(()->((Label)view.node().lookup("#library-fragment-warning")).isManaged()),"500-node view omitted its persistent fragment warning");more(view);until(()->count(view,"edges")==1);check(continuationLimit.get()==1,"500-node view blocked or over-requested E: edge continuation");check(count(view,"nodes")==500,"Opaque edge continuation duplicated a node");int before=requests.get();more(view);check(requests.get()==before,"Node cap fetched another ordinary node page");}finally{fx(()->{nodeApi.close();return null;});}
  AtomicInteger edgeRequests=new AtomicInteger();List<JsonObject> dense=new ArrayList<>();for(int from=0;from<64;from++)for(int to=from+1;to<64;to++)dense.add(obj("id",id("edge"+from+":"+to),"from",id("dense"+from),"to",id("dense"+to),"explanation","Синтетическая связь","state","APPROVED","ai",false));
  CommunityUi edgeApi=fx(()->new CommunityUi(themes,(action,args)->{if(!action.equals("content.library.graph"))throw new java.io.IOException("Synthetic fixture has no other services");int page=edgeRequests.getAndIncrement();JsonArray nodes=new JsonArray(),edges=new JsonArray();if(page==0)for(int i=0;i<64;i++)nodes.add(obj("id",id("dense"+i),"title","Синтетический узел "+i,"type","NOTE"));for(int i=page*800;i<Math.min((page+1)*800,dense.size());i++)edges.add(dense.get(i));return org.securemail.client.community.CommunityJson.parse(obj("nodes",nodes,"edges",edges,"nextCursor",page<2?"E:"+id("dense63")+":"+id("cursor"+page):"").toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));},(password,otp)->{throw new AssertionError("No authentication in a synthetic layout fixture");},url->{}));
  try{KnowledgeLibraryView view=fx(()->{KnowledgeLibraryView value=new KnowledgeLibraryView(edgeApi,"");workspace.setCenter(value.node());return value;});until(()->count(view,"edges")==800);more(view);until(()->count(view,"edges")==1600);more(view);until(()->count(view,"edges")==2000);Label warning=fx(()->(Label)view.node().lookup("#library-fragment-warning"));check(fx(()->warning.isManaged()&&warning.isVisible()&&warning.getText().contains("только часть доступного графа")),"2016-edge input was silently presented as complete");int before=edgeRequests.get();more(view);check(edgeRequests.get()==before,"Edge cap continued fetching unusable pages");check(count(view,"nodes")==64,"Dense edge pages lost or duplicated nodes");}finally{fx(()->{edgeApi.close();return null;});}
 }
}
