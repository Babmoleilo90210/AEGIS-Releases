package org.securemail.ui;
import java.nio.file.*;
import java.util.*;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import org.securemail.client.*;
import org.securemail.client.storage.*;
import org.securemail.client.update.*;
/** Same actual main page and six old themes for both exact 1.1.1 and candidate. */
public final class AppearancePerformanceSmoke {
 public static void main(String[] args)throws Exception {
  Path profile=Files.createTempDirectory("aegis-visual-perf");System.setProperty("aegis.profile",profile.toString());Platform.startup(()->Platform.setImplicitExit(false));var config=ClientConfig.load(profile.resolve("config/client.properties"));var session=new ClientSession(config,"synthetic-profile-password".toCharArray());session.local().bindNickname("raven");MessengerApp app=MessengerSmoke.fx(MessengerApp::new);
  Stage stage=MessengerSmoke.fx(()->{Stage w=new Stage();w.initStyle(StageStyle.UNDECORATED);BorderPane root=new BorderPane(),outer=new BorderPane(root);outer.setTop(new WindowChrome(w));w.setScene(new Scene(outer,1280,900));InWindowDialog.bind(w,outer);MessengerSmoke.set(app,"stage",w);MessengerSmoke.set(app,"root",root);MessengerSmoke.set(app,"config",config);MessengerSmoke.set(app,"session",session);MessengerSmoke.set(app,"presets",new UiPresetStore(profile));MessengerSmoke.set(app,"updates",new UpdateService(profile,19052));MessengerSmoke.set(app,"updatePreferences",UpdatePreferences.load(profile));ThemeManager themes=(ThemeManager)MessengerSmoke.get(app,"themes");try{ThemeManager.class.getDeclaredMethod("initialize").invoke(themes);}catch(NoSuchMethodException old){}themes.apply(outer);themes.apply(root);themes.track(w.getScene());w.show();app.mainPage();return w;});
  try{System.gc();List<Long> times=MessengerSmoke.fx(()->{ThemeManager themes=(ThemeManager)MessengerSmoke.get(app,"themes");List<Long> result=new ArrayList<>();for(int n=0;n<30;n++){long start=System.nanoTime();themes.select(ThemeManager.Theme.values()[n%6]);stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();result.add((System.nanoTime()-start)/1000000);}return result;});System.gc();long heap=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();Collections.sort(times);System.out.println("{\"version\":\""+SignedManifest.CURRENT+"\",\"environment\":\"Monocle headless 1280x900 sw\",\"samples\":30,\"themeSwitchMedianMs\":"+times.get(15)+",\"themeSwitchP95Ms\":"+times.get(28)+",\"heapAfterGcBytes\":"+heap+",\"nativeAcceptance\":false}");}
  finally{MessengerSmoke.fx(()->{app.stop();return null;});}
 }
}
