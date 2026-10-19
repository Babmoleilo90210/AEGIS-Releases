package org.securemail.ui;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import org.securemail.client.*;
import org.securemail.client.ecosystem.*;
import org.securemail.client.storage.*;
import org.securemail.client.update.*;

/** Real headless JavaFX component UI; Identity capability is a local fixture, not native/Tor E2E evidence. */
public final class MailComponentModeSmoke600 {
  private MailComponentModeSmoke600(){}
  private static <T>T fx(Callable<T> work)throws Exception{var done=new CompletableFuture<T>();Platform.runLater(()->{try{done.complete(work.call());}catch(Throwable e){done.completeExceptionally(e);}});return done.get(20,TimeUnit.SECONDS);}
  private static void set(Object object,String name,Object value)throws Exception{var field=MessengerApp.class.getDeclaredField(name);field.setAccessible(true);field.set(object,value);}
  private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
  private static void screenshot(Stage stage,Path path)throws Exception{Parent root=stage.getScene().getRoot();root.applyCss();root.layout();var image=stage.getScene().snapshot(null);var pixels=image.getPixelReader();var output=new java.awt.image.BufferedImage((int)image.getWidth(),(int)image.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);for(int y=0;y<output.getHeight();y++)for(int x=0;x<output.getWidth();x++)output.setRGB(x,y,pixels.getArgb(x,y));javax.imageio.ImageIO.write(output,"png",path.toFile());}
  public static void main(String[] args)throws Exception {
    Path profile=Files.createTempDirectory("aegis-mail600-ui-"),out=Path.of(args.length==0?"build/mail600-smoke":args[0]).toAbsolutePath();Files.createDirectories(out);System.setProperty("aegis.profile",profile.toString());
    ClientConfig config=ClientConfig.load(AppPaths.config());config.save(AppPaths.config());ClientSession session=new ClientSession(config,"headless Mail fixture secret 600".toCharArray());session.local().bindNickname("raven");
    var gate=new MailComponentGate600(new ComponentLease(ComponentId.MAIL,session.local().identity().userId(),1,new byte[]{1}),lease->{});MessengerApp.configureMailComponent(gate,app->{});MessengerApp.componentSignals(()->{},count->{});MessengerApp.componentLinks(url->{});
    var started=new CompletableFuture<Void>();Platform.startup(()->{Platform.setImplicitExit(false);started.complete(null);});started.get();MessengerApp app=fx(MessengerApp::new);
    Stage stage=fx(()->{Stage window=new Stage();BorderPane root=new BorderPane();window.setScene(new Scene(root,1024,768));var themesField=MessengerApp.class.getDeclaredField("themes");themesField.setAccessible(true);ThemeManager themes=(ThemeManager)themesField.get(app);themes.initialize();themes.apply(root);window.getScene().setFill(javafx.scene.paint.Color.web(themes.visualTheme().palette().background()));window.show();set(app,"stage",window);set(app,"root",root);set(app,"config",config);set(app,"session",session);set(app,"presets",new UiPresetStore(profile));set(app,"updates",new UpdateService(profile,19052));set(app,"updatePreferences",UpdatePreferences.load(profile));var verify=MessengerApp.class.getDeclaredMethod("verifyComponentSession",ClientSession.class);verify.setAccessible(true);verify.invoke(app,session);app.mainPage();return window;});
    try {
      fx(()->{Set<String> expected=Set.of("navigation-search","navigation-contacts","navigation-letters","navigation-archive","navigation-settings");Set<String> actual=new HashSet<>();for(Node node:stage.getScene().getRoot().lookupAll(".nav-item"))actual.add(node.getId());check(actual.equals(expected),"Mail exposed another application's navigation: "+actual);screenshot(stage,out.resolve("mail-component.png"));((Button)stage.getScene().getRoot().lookup("#navigation-settings")).fire();stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();Set<String> labels=new HashSet<>();for(Node node:stage.getScene().getRoot().lookupAll(".toggle-button"))if(node instanceof ToggleButton button)labels.add(button.getText());check(labels.contains("Безопасность и данные"),"Mail settings missing");check(labels.stream().noneMatch(value->value.contains("Взор")||value.contains("Глас")||value.contains("Аккаунт")),"Mail exposed Core/Glas settings");screenshot(stage,out.resolve("mail-settings.png"));return null;});
      fx(()->{var compose=MessengerApp.class.getDeclaredMethod("composePage");compose.setAccessible(true);compose.invoke(app);var field=MessengerApp.class.getDeclaredField("composer");field.setAccessible(true);((TextArea)field.get(app)).setText("PRIVATE-DRAFT-LOCK-ROUNDTRIP-600");return null;});
      app.componentLock().get(15,TimeUnit.SECONDS);check(gate.locked(),"Core lock did not revoke Mail gate");check(session.local().identity()==null,"Mail root identity remained unlocked");
      fx(()->{check(stage.getScene().getRoot().lookupAll(".nav-item").isEmpty(),"Locked Mail retained navigation");screenshot(stage,out.resolve("mail-locked.png"));app.loginPage();check(stage.getScene().getRoot().lookupAll(".password-field").isEmpty(),"Locked Mail exposed independent login");app.stop();return null;});app.componentShutdown().get(15,TimeUnit.SECONDS);
      try(var reopened=new LocalStore(config.storagePath(),"headless Mail fixture secret 600".toCharArray(),java.time.Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage())){byte[] saved=reopened.readExtension("mail6-draft-v1",400000);check(saved!=null,"Draft queue was not persisted before lock");var decode=MessengerApp.class.getDeclaredMethod("decodeDraft600",byte[].class);decode.setAccessible(true);Object draft=decode.invoke(null,(Object)saved);var body=draft.getClass().getDeclaredField("body");body.setAccessible(true);check(body.get(draft).equals("PRIVATE-DRAFT-LOCK-ROUNDTRIP-600"),"Draft content did not survive real vault close/reopen");((AutoCloseable)draft).close();Arrays.fill(saved,(byte)0);}
      System.out.println("PASS: actual JavaFX Mail-only navigation/settings, private view removal, closed real vault, no independent unlock, awaited queue close. Scope=Monocle + local Identity fixture; native/Tor NOT_RUN.");
    }finally{try{fx(()->{app.stop();return null;});}catch(Exception ignored){}Platform.exit();}
  }
}
