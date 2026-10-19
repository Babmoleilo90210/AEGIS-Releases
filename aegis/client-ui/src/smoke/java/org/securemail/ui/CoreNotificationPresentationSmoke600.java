package org.securemail.ui;

import com.google.gson.*;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.stage.Stage;
import org.securemail.client.community600.CommunityClient600;
import org.securemail.client.ecosystemauth.*;
import org.securemail.client.net.TorTransport;
import org.securemail.community.access.AccessControl;
import org.securemail.community.agent.AgentService;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.CommunityStore;
import org.securemail.community.gateway600.*;
import org.securemail.community.org.OrgAdminService;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.identity.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.securemail.ui.CoreNotificationsSmoke600.*;

/** Real signed local HTTP/SQL/JavaFX presentation test. Injected beep requests are not native audible-audio acceptance. */
public final class CoreNotificationPresentationSmoke600 {
  private CoreNotificationPresentationSmoke600(){}
  private static void refresh(CoreNotificationsView600 view,int count)throws Exception{
    fx(()->{((Button)view.lookup("#core600-notifications-refresh")).fire();return null;});
    await(()->fx(()->view.lookupAll(".label").stream().anyMatch(n->n instanceof Label label&&label.getText().equals("Доступных событий: "+count))));
  }
  private static void option(CoreNotificationsView600 view,String name,boolean value,CoreNotificationPreferences600 store)throws Exception{
    fx(()->{CheckBox box=(CheckBox)view.lookup("#notification600-local-"+name);check(box!=null&&!box.isDisabled(),"Presentation option unavailable");if(box.isSelected()!=value)box.fire();return null;});
    await(()->{var settings=store.load();boolean actual=switch(name){case "sound"->settings.sound();case "banner"->settings.banner();case "privacy"->settings.hideDetails();default->throw new AssertionError();};return actual==value&&fx(()->!((CheckBox)view.lookup("#notification600-local-"+name)).isDisabled());});
  }
  private static boolean banner(CoreNotificationsView600 view)throws Exception{return fx(()->view.lookup("#notification600-banner").isVisible());}
  public static void main(String[]args)throws Exception{
    Path output=Path.of(args[0]);Files.createDirectories(output);Path dir=Files.createTempDirectory("aegis-presentation600-");System.setProperty("aegis.profile",dir.resolve("profile").toString());
    KeyPair root=pair(),device=pair(),recovery=pair(),app=pair(),identityKey=pair(),communityKey=pair();
    try(var identity=new IdentityStore(dir.resolve("identity.db"),identityKey,new byte[32],Clock.systemUTC());var ih=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),identity,identityKey);var store=new CommunityStore(dir.resolve("community.db"));var access=new AccessControl(store,new byte[32])){
      ih.start();String nickname="Испытатель показа уведомлений",nonce=IdentityProtocol.nonce();long time=System.currentTimeMillis();byte[] body=IdentityProtocol.registration(identity.audience(),key(root),key(device),key(recovery),nickname,time,nonce);
      var session=identity.register(key(root),key(device),key(recovery),nickname,time,nonce,IdentityProtocol.sign(root.getPrivate(),body),IdentityProtocol.sign(device.getPrivate(),body));var scopes=Set.of(IdentityProtocol.Scope.ACCOUNT_READ);nonce=IdentityProtocol.nonce();time=System.currentTimeMillis();body=IdentityProtocol.capabilityRequest(identity.audience(),session.accountId(),session.deviceId(),session.generation(),IdentityProtocol.App.AEGIS,key(app),scopes,600000,time,nonce);
      var cap=identity.issueCapability(session.accountId(),session.deviceId(),session.generation(),IdentityProtocol.App.AEGIS,key(app),scopes,600000,time,nonce,IdentityProtocol.sign(device.getPrivate(),body),IdentityProtocol.sign(app.getPrivate(),body));
      ContentService content=new ContentService(store,access);store.bindServiceIdentity(IdentityProtocol.id(key(communityKey)));String reader=store.ensureIdentity(key(root),nickname);
      try(var agent=new AgentService(store,access,content::ingestAi);var bridge=new CommunityIdentityBridge600(ih.port(),key(identityKey),key(communityKey),access,store);var server=new CommunityHttpGateway600(new InetSocketAddress("127.0.0.1",0),store,access,content,new OrgAdminService(store,access,store.clock()),agent,communityKey,bridge)){
        server.start();try(var socks=new Socks(server.port());var client=new CommunityClient600(ONION,80,key(communityKey),key(identityKey),IdentityProtocol.encodeCapability(cap),app.getPrivate(),new TorTransport("127.0.0.1",socks.port()))){
          Platform.startup(()->Platform.setImplicitExit(false));ThemeManager themes=fx(()->{ThemeManager value=new ThemeManager();value.initialize();return value;});AtomicBoolean hold=new AtomicBoolean();CountDownLatch fetched=new CountDownLatch(1),release=new CountDownLatch(1);
          CommunityUi api=fx(()->new CommunityUi(themes,(action,data)->{JsonObject result=client.call(action,data);if(action.equals("content.notifications.list")&&hold.get()){fetched.countDown();release.await(10,TimeUnit.SECONDS);}return result;},(CommunityUi.DelegatedStepUp)()->{throw new AssertionError("Presentation must not request privileged credentials");},url->{throw new AssertionError("Unexpected URL");}));
          AtomicInteger sounds=new AtomicInteger();List<CoreNotificationArrivals600.Presentation> events=new CopyOnWriteArrayList<>();Path file=CoreNotificationPreferences600.defaultFile();var preferences=new CoreNotificationPreferences600(file);
          CoreNotificationsView600 view=fx(()->new CoreNotificationsView600(api,()->{},()->{},file,sounds::incrementAndGet,events::add));Stage stage=fx(()->{Stage window=new Stage();window.setWidth(1024);window.setHeight(768);window.setScene(new Scene(view,1024,768));themes.apply(view);window.show();return window;});CoreNotificationsView600 reopened=null;
          try{
            fx(()->{((TitledPane)view.lookup("#notification600-local-preferences")).setExpanded(true);return null;});
            await(()->fx(()->view.lookupAll(".label").stream().anyMatch(n->n instanceof Label label&&label.getText().equals("Доступных событий: 0"))&&!((CheckBox)view.lookup("#notification600-local-sound")).isDisabled()));check(events.isEmpty()&&sounds.get()==0&&!banner(view),"Initial page generated a presentation");
            content.notifyAccount(reader,"NEWS","НЕПОКАЗЫВАТЬ_ЗАГОЛОВОК");refresh(view,1);check(events.size()==1&&sounds.get()==0,"Default arrival failed");check(events.getFirst().text().equals("Новое уведомление АЕГИС."),"Default private title leaked");check(banner(view),"Actual in-window banner was not displayed");fx(()->{capture(stage,output.resolve("notification600-neutral.png"));return null;});refresh(view,1);check(events.size()==1,"Duplicate refresh presented old unread again");
            option(view,"sound",true,preferences);content.notifyAccount(reader,"NEWS","Второй скрытый заголовок");refresh(view,2);check(events.size()==2&&sounds.get()==1&&events.getLast().text().equals("Новое уведомление АЕГИС."),"Enabled sound request/private banner failed");
            option(view,"privacy",false,preferences);content.notifyAccount(reader,"NEWS","Открытый заголовок после согласия");refresh(view,3);check(events.size()==3&&sounds.get()==2,"Third arrival missing");check(fx(()->((Label)view.lookup("#notification600-banner-text")).getText().equals("Открытый заголовок после согласия")),"Explicit details did not render");fx(()->{capture(stage,output.resolve("notification600-explicit-details.png"));return null;});
            option(view,"banner",false,preferences);content.notifyAccount(reader,"NEWS","Только звуковой сигнал");refresh(view,4);check(events.size()==4&&sounds.get()==3&&!banner(view)&&!events.getLast().banner(),"Disabled banner was displayed");refresh(view,4);check(sounds.get()==3,"Repeated unread sounded again");option(view,"banner",true,preferences);
            content.notifyAccount(reader,"NEWS","ЗАПОЗДАЛОЕ_ПРИВАТНОЕ_СОБЫТИЕ");hold.set(true);fx(()->{((Button)view.lookup("#core600-notifications-refresh")).fire();return null;});check(fetched.await(10,TimeUnit.SECONDS),"Actual signed HTTP response did not stall");fx(()->{view.lock();return null;});release.countDown();Thread.sleep(100);fx(()->{check(events.size()==4&&sounds.get()==3,"Locked page emitted a late sound/presentation");check(!view.lookup("#notification600-banner").isVisible(),"Locked page retained banner");check(view.lookupAll(".label").stream().noneMatch(n->n instanceof Label label&&label.getText().contains("ЗАПОЗДАЛОЕ_ПРИВАТНОЕ")),"Locked page rendered delayed title");capture(stage,output.resolve("notification600-presentation-locked.png"));return null;});
            hold.set(false);AtomicInteger reopenedSounds=new AtomicInteger();List<CoreNotificationArrivals600.Presentation> reopenedEvents=new CopyOnWriteArrayList<>();reopened=fx(()->new CoreNotificationsView600(api,()->{},()->{},file,reopenedSounds::incrementAndGet,reopenedEvents::add));CoreNotificationsView600 loaded=reopened;fx(()->{stage.setScene(new Scene(loaded,1024,768));themes.apply(loaded);loaded.applyCss();loaded.layout();((TitledPane)loaded.lookup("#notification600-local-preferences")).setExpanded(true);return null;});await(()->fx(()->loaded.lookupAll(".label").stream().anyMatch(n->n instanceof Label label&&label.getText().equals("Доступных событий: 5"))&&!((CheckBox)loaded.lookup("#notification600-local-sound")).isDisabled()));check(reopenedEvents.isEmpty()&&reopenedSounds.get()==0&&!banner(loaded),"Reopened initial unread history alerted");check(preferences.load().equals(new CoreNotificationPreferences600.Settings(true,true,false)),"Presentation preferences did not persist");
            Files.writeString(output.resolve("RESULT.json"),new GsonBuilder().setPrettyPrinting().create().toJson(Map.ofEntries(Map.entry("result","PASS_HEADLESS"),Map.entry("scope","Actual signed Identity/Community HTTP + SQLite + JavaFX and explicit SOCKS fixture. Sound-request callback tested, audible native sound/Tor/Windows/CachyOS NOT_RUN."),Map.entry("initialSuppressed",true),Map.entry("newUnreadPresented",4),Map.entry("deduplicated",true),Map.entry("neutralDefault",true),Map.entry("explicitTitleOptIn",true),Map.entry("localPreferencesPersisted",true),Map.entry("soundRequests",sounds.get()),Map.entry("disabledBannerHidden",true),Map.entry("staleResponseAfterLockSuppressed",true)))+"\n");System.out.println("PASS_HEADLESS: notification sound requests, neutral banner, explicit privacy opt-in, persistence, dedup and actual delayed HTTP lock guard.");java.lang.reflect.Field worker=CommunityUi.class.getDeclaredField("work");worker.setAccessible(true);((java.util.concurrent.ExecutorService)worker.get(api)).submit(()->{}).get(10,TimeUnit.SECONDS);fx(()->null);
          }finally{release.countDown();CoreNotificationsView600 last=reopened;fx(()->{view.close();if(last!=null)last.close();api.close();themes.close();stage.close();Platform.exit();return null;});}
        }
      }
    }
  }
}
