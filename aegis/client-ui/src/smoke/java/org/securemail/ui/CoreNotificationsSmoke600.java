package org.securemail.ui;

import com.google.gson.*;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.stage.Stage;
import org.securemail.client.community600.CommunityClient600;
import org.securemail.client.net.TorTransport;
import org.securemail.community.access.AccessControl;
import org.securemail.community.agent.AgentService;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.CommunityStore;
import org.securemail.community.gateway600.*;
import org.securemail.community.org.OrgAdminService;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.identity.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Actual JavaFX + signed Identity/Community HTTP + SQLite through an explicit SOCKS fixture.
 * No real Tor, native platform, Mail/Glas content or production deployment. */
public final class CoreNotificationsSmoke600 {
 static final String ONION="b".repeat(56)+".onion";
 static <T>T fx(Callable<T>task)throws Exception{var result=new CompletableFuture<T>();Platform.runLater(()->{try{result.complete(task.call());}catch(Throwable e){result.completeExceptionally(e);}});return result.get(15,TimeUnit.SECONDS);}
 static void await(Callable<Boolean>condition)throws Exception{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(20);while(!condition.call()){if(System.nanoTime()>until)throw new AssertionError("Condition timeout");Thread.sleep(20);}}
 static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}static KeyPair pair()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}static byte[]key(KeyPair p){return p.getPublic().getEncoded();}
 static void sql(java.sql.Connection db,String text,Object...values)throws Exception{try(var q=db.prepareStatement(text)){for(int i=0;i<values.length;i++)q.setObject(i+1,values[i]);q.executeUpdate();}}
 static long count(CommunityStore store,String text,Object...values)throws Exception{return store.tx(db->{try(var q=db.prepareStatement(text)){for(int i=0;i<values.length;i++)q.setObject(i+1,values[i]);try(var rows=q.executeQuery()){rows.next();return rows.getLong(1);}}});}
 static void capture(Stage stage,Path file)throws Exception{stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();var image=stage.getScene().snapshot(null);var png=new java.awt.image.BufferedImage((int)image.getWidth(),(int)image.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);for(int y=0;y<png.getHeight();y++)for(int x=0;x<png.getWidth();x++)png.setRGB(x,y,image.getPixelReader().getArgb(x,y));javax.imageio.ImageIO.write(png,"png",file.toFile());}
 public static void main(String[]args)throws Exception{
  Path dir=Files.createTempDirectory("aegis-notifications600-"),output=Path.of(args[0]);Files.createDirectories(output);System.setProperty("aegis.profile",dir.resolve("profile").toString());KeyPair root=pair(),device=pair(),recovery=pair(),app=pair(),identityKey=pair(),communityKey=pair(),editor=pair();
  try(var identity=new IdentityStore(dir.resolve("identity.db"),identityKey,new byte[32],Clock.systemUTC());var ih=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),identity,identityKey);var store=new CommunityStore(dir.resolve("community.db"));var access=new AccessControl(store,new byte[32])){
   ih.start();String nonce=IdentityProtocol.nonce();long time=System.currentTimeMillis();byte[]body=IdentityProtocol.registration(identity.audience(),key(root),key(device),key(recovery),"Читатель уведомлений",time,nonce);var session=identity.register(key(root),key(device),key(recovery),"Читатель уведомлений",time,nonce,IdentityProtocol.sign(root.getPrivate(),body),IdentityProtocol.sign(device.getPrivate(),body));
   var scopes=Set.of(IdentityProtocol.Scope.ACCOUNT_READ);nonce=IdentityProtocol.nonce();time=System.currentTimeMillis();body=IdentityProtocol.capabilityRequest(identity.audience(),session.accountId(),session.deviceId(),session.generation(),IdentityProtocol.App.AEGIS,key(app),scopes,600000,time,nonce);var cap=identity.issueCapability(session.accountId(),session.deviceId(),session.generation(),IdentityProtocol.App.AEGIS,key(app),scopes,600000,time,nonce,IdentityProtocol.sign(device.getPrivate(),body),IdentityProtocol.sign(app.getPrivate(),body));
   ContentService content=new ContentService(store,access);store.bindServiceIdentity(IdentityProtocol.id(key(communityKey)));String reader=store.ensureIdentity(key(root),"Читатель уведомлений"),author=store.ensureIdentity(key(editor),"Автор");store.tx(db->{String role=UUID.randomUUID().toString();sql(db,"INSERT INTO roles(id,scope,name) VALUES(?,'GLOBAL',?)",role,role);for(String permission:Set.of("LIBRARY_CREATE","LIBRARY_PUBLISH"))sql(db,"INSERT INTO role_permissions VALUES(?,?)",role,permission);sql(db,"INSERT INTO assignments VALUES(?,?)",author,role);return null;});
   var hidden=content.handle(author,"content.library.create",Map.of("title","CLOSED_TITLE_MUST_NOT_APPEAR","body","private","policy",Map.of("users",List.of(author))));content.handle(author,"content.library.publish",Map.of("id",hidden.get("id"),"revision",hidden.get("revision")));store.tx(db->{sql(db,"INSERT INTO content_notification VALUES(?,?,?,?,?,0)",UUID.randomUUID().toString(),reader,hidden.get("id"),"LIBRARY",System.currentTimeMillis());return null;});
   for(int i=0;i<120;i++)content.notifyAccount(reader,"NEWS","Доступное событие "+i);
   try(var agent=new AgentService(store,access,content::ingestAi);var bridge=new CommunityIdentityBridge600(ih.port(),key(identityKey),key(communityKey),access,store);var server=new CommunityHttpGateway600(new InetSocketAddress("127.0.0.1",0),store,access,content,new OrgAdminService(store,access,store.clock()),agent,communityKey,bridge)){
    server.start();try(var socks=new Socks(server.port());var client=new CommunityClient600(ONION,80,key(communityKey),key(identityKey),IdentityProtocol.encodeCapability(cap),app.getPrivate(),new TorTransport("127.0.0.1",socks.port()))){
     Platform.startup(()->Platform.setImplicitExit(false));ThemeManager themes=fx(ThemeManager::new);AtomicBoolean hold=new AtomicBoolean();CountDownLatch fetched=new CountDownLatch(1),release=new CountDownLatch(1);CommunityUi api=fx(()->new CommunityUi(themes,(action,data)->{JsonObject result=client.call(action,data);if(action.equals("content.notifications.list")&&hold.get()){fetched.countDown();release.await(10,TimeUnit.SECONDS);}return result;},(CommunityUi.DelegatedStepUp)()->{throw new AssertionError("Notifications must not request root/step-up");},url->{throw new AssertionError("Unexpected external link");}));CoreNotificationsView600 view=fx(()->new CoreNotificationsView600(api,()->{},()->{}));Stage stage=fx(()->{themes.initialize();Stage value=new Stage();value.setScene(new Scene(view,1024,768));value.getScene().getStylesheets().add(Objects.requireNonNull(CoreNotificationsView600.class.getResource("messenger.css")).toExternalForm());themes.apply(view);value.show();return value;});
     try{
      await(()->fx(()->view.lookupAll(".label").stream().anyMatch(n->n instanceof Label l&&l.getText().equals("Доступных событий: 50"))));check(fx(()->view.lookupAll(".label").stream().noneMatch(n->n instanceof Label l&&l.getText().contains("CLOSED_TITLE_MUST_NOT_APPEAR"))),"Closed notification title leaked");
      fx(()->{((Button)view.lookup("#core600-notifications-more")).fire();return null;});await(()->fx(()->view.lookupAll(".label").stream().anyMatch(n->n instanceof Label l&&l.getText().equals("Доступных событий: 100"))));fx(()->{((Button)view.lookup("#core600-notifications-more")).fire();return null;});await(()->fx(()->view.lookupAll(".label").stream().anyMatch(n->n instanceof Label l&&l.getText().equals("Доступных событий: 120"))));
      String marked=fx(()->{for(Node node:view.lookupAll(".button"))if(node instanceof Button button&&button.getId()!=null&&button.getId().startsWith("notification600-read-")){String id=button.getId().substring("notification600-read-".length());button.fire();return id;}throw new AssertionError("No mark-read action");});await(()->count(store,"SELECT count(*) FROM content_account_notification WHERE id=? AND actor=? AND seen=1",marked,reader)==1);
      fx(()->{((TitledPane)view.lookup("#core600-notification-preferences")).setExpanded(true);return null;});await(()->fx(()->view.lookup("#notification600-preference-SECURITY")!=null));fx(()->{((CheckBox)view.lookup("#notification600-preference-SECURITY")).fire();return null;});await(()->count(store,"SELECT count(*) FROM content_notification_settings WHERE actor=? AND category='SECURITY' AND enabled=0",reader)==1);long before=count(store,"SELECT count(*) FROM content_account_notification WHERE actor=?",reader);content.notifyAccount(reader,"SECURITY","Не должно создаться");check(count(store,"SELECT count(*) FROM content_account_notification WHERE actor=?",reader)==before,"Disabled category persisted a notification");
      for(int i=0;i<450;i++)content.notifyAccount(reader,"NEWS","Дополнительное доступное событие "+i);fx(()->{((Button)view.lookup("#core600-notifications-refresh")).fire();return null;});await(()->fx(()->view.lookupAll(".label").stream().anyMatch(n->n instanceof Label l&&l.getText().equals("Доступных событий: 50"))));
      for(int page=2;page<=10;page++){int expected=page*50;fx(()->{((Button)view.lookup("#core600-notifications-more")).fire();return null;});await(()->fx(()->view.lookupAll(".label").stream().anyMatch(n->n instanceof Label l&&(expected==500?l.getText().startsWith("Показаны первые 500 событий"):l.getText().equals("Доступных событий: "+expected)))));}
      check(fx(()->((Button)view.lookup("#core600-notifications-more")).isDisabled()),"Pagination exceeded 500-event limit");
      fx(()->{capture(stage,output.resolve("notifications600.png"));return null;});hold.set(true);fx(()->{((Button)view.lookup("#core600-notifications-refresh")).fire();return null;});check(fetched.await(10,TimeUnit.SECONDS),"Actual HTTP list response did not stall");fx(()->{view.lock();return null;});release.countDown();Thread.sleep(100);fx(()->{check(view.lookupAll(".label").stream().noneMatch(n->n instanceof Label l&&l.getText().startsWith("Доступное событие")),"Stale notification response redrew after lock");capture(stage,output.resolve("notifications600-locked.png"));return null;});
      Files.writeString(output.resolve("RESULT.json"),new GsonBuilder().setPrettyPrinting().create().toJson(Map.of("status","PASS_HEADLESS","scope","Actual Identity and Community signed HTTP + SQLite + JavaFX through loopback SOCKS fixture; NOT real Tor/native acceptance","pagination",500,"closedTitleFilteredByServer",true,"readPersistedSql",true,"categoryPreferencePersistedSql",true,"disabledCategoryNotEmitted",true,"staleResponseAfterLockRejected",true,"screenshots",List.of("notifications600.png","notifications600-locked.png"))));System.out.println("PASS_HEADLESS notifications: actual HTTP/SQL pagination, ACL, read, settings, stale response lock");
     }finally{release.countDown();fx(()->{view.close();api.close();themes.close();stage.close();Platform.exit();return null;});}
    }
   }
  }
 }
 static final class Socks implements AutoCloseable{
  final ServerSocket server;final int target;final ExecutorService workers=Executors.newFixedThreadPool(4);final Thread accepting;
  Socks(int target)throws IOException{this.target=target;server=new ServerSocket(0,8,InetAddress.getByAddress(new byte[]{127,0,0,1}));accepting=new Thread(()->{while(!server.isClosed())try{Socket socket=server.accept();workers.execute(()->forward(socket));}catch(IOException ignored){}},"notification-socks-fixture");accepting.setDaemon(true);accepting.start();}int port(){return server.getLocalPort();}
  void forward(Socket client){try(client){client.setSoTimeout(15000);DataInputStream in=new DataInputStream(client.getInputStream());OutputStream out=client.getOutputStream();check(in.readUnsignedByte()==5,"SOCKS greeting");in.readNBytes(in.readUnsignedByte());out.write(new byte[]{5,0});out.flush();check(in.readUnsignedByte()==5&&in.readUnsignedByte()==1&&in.readUnsignedByte()==0&&in.readUnsignedByte()==3,"Remote DNS SOCKS");check(new String(in.readNBytes(in.readUnsignedByte()),StandardCharsets.US_ASCII).equals(ONION)&&in.readUnsignedShort()==80,"Wrong onion route");try(Socket remote=new Socket(Proxy.NO_PROXY)){remote.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),target),1000);out.write(new byte[]{5,0,0,1,127,0,0,1,0,0});out.flush();ByteArrayOutputStream head=new ByteArrayOutputStream();int end=0;byte[]marker={13,10,13,10};while(end<4){int value=in.read();if(value<0)throw new EOFException();head.write(value);end=value==marker[end]?end+1:(value==13?1:0);if(head.size()>16384)throw new IOException("Headers");}int length=-1;for(String line:head.toString(StandardCharsets.US_ASCII).split("\r\n"))if(line.toLowerCase(Locale.ROOT).startsWith("content-length:"))length=Integer.parseInt(line.substring(line.indexOf(':')+1).strip());if(length<0||length>8*1024*1024)throw new IOException("Size");remote.getOutputStream().write(head.toByteArray());remote.getOutputStream().write(in.readNBytes(length));remote.getOutputStream().flush();remote.getInputStream().transferTo(out);out.flush();}}catch(Exception error){throw new RuntimeException(error);}}
  public void close()throws Exception{server.close();workers.shutdownNow();accepting.join(1000);}
 }
}
