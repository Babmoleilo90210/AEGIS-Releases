package org.securemail.ui;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.stage.*;
import org.securemail.client.*;
import org.securemail.client.storage.*;
import org.securemail.client.update.*;

/** Exercises the real appearance control, every page, CSS and a second process.
 * Headless runs are not native Windows DPI or KDE acceptance. Never starts Tor.
 */
public final class DarkGreenThemeSmoke {
  static void assertGreen(Parent root) {
    root.applyCss();root.layout();
    MessengerSmoke.check(root.getStyle().contains("-aegis-bg:#0c1812"),"Page missed the green palette");
    MessengerSmoke.check(root.getStyle().contains("-aegis-accent:#85c89a"),"Green accent was not applied");
  }
  public static void main(String[] args)throws Exception {
    if(args.length==2&&args[0].equals("--reopen")) {
      System.setProperty("aegis.profile",args[1]);
      Platform.startup(()->{});
      try {MessengerSmoke.fx(()->{MessengerSmoke.check(new ThemeManager().selected()==ThemeManager.Theme.DARK_GREEN,"Theme not restored in a new JVM");return null;});}
      finally{Platform.exit();}
      System.out.println("Dark-green restart persistence PASS");return;
    }
    Path profile=Files.createTempDirectory("AEGIS dark green ");System.setProperty("aegis.profile",profile.toString());
    CompletableFuture<Void> ready=new CompletableFuture<>();Platform.startup(()->{Platform.setImplicitExit(false);ready.complete(null);});ready.get(10,TimeUnit.SECONDS);
    var config=ClientConfig.load(profile.resolve("config/client.properties"));
    var session=new ClientSession(config,"synthetic-ui-vault-password".toCharArray());session.local().bindNickname("raven");
    MessengerApp app=MessengerSmoke.fx(MessengerApp::new);
    Stage stage=MessengerSmoke.fx(()->{
      Stage window=new Stage();window.initStyle(StageStyle.UNDECORATED);BorderPane root=new BorderPane();BorderPane outer=new BorderPane(root);outer.setTop(new WindowChrome(window));window.setScene(new Scene(outer,1200,900));InWindowDialog.bind(window,outer);
      MessengerSmoke.set(app,"stage",window);MessengerSmoke.set(app,"root",root);MessengerSmoke.set(app,"config",config);MessengerSmoke.set(app,"session",session);MessengerSmoke.set(app,"presets",new UiPresetStore(profile));MessengerSmoke.set(app,"updates",new UpdateService(profile,19052));MessengerSmoke.set(app,"updatePreferences",UpdatePreferences.load(profile));
      ThemeManager themes=(ThemeManager)MessengerSmoke.get(app,"themes");themes.apply(outer);themes.apply(root);themes.track(window.getScene());window.show();return window;
    });
    try {
      // Choose the preset through the existing Appearance page, not a new window.
      MessengerSmoke.fx(()->{
        ThemeManager manager=(ThemeManager)MessengerSmoke.get(app,"themes");manager.initialize();
        Aegis11UiSmoke.invoke(app,"appearance",new Class<?>[]{});
        for(String caption:List.of("Тёмно-зелёная","Применить"))stage.getScene().getRoot().lookupAll(".button").stream().filter(n->n instanceof Button b&&caption.equals(b.getText())).map(n->(Button)n).findFirst().orElseThrow().fire();return null;
      });
      MessengerSmoke.fx(()->{
        ThemeManager themes=(ThemeManager)MessengerSmoke.get(app,"themes");MessengerSmoke.check(themes.selected()==ThemeManager.Theme.DARK_GREEN,"Appearance selector did not select the new preset");
        var root=(BorderPane)MessengerSmoke.get(app,"root");
        for(Runnable page:List.<Runnable>of(app::serverPage,app::loginPage,app::registerPage,app::mainPage,app::composePage)) {page.run();assertGreen(root);MessengerSmoke.check(root.getCenter()!=null,"Empty themed page");}
        var draft=(TextArea)MessengerSmoke.get(app,"composer");draft.setText("Черновик сохраняется при смене темы");
        String text=draft.getText();for(ThemeManager.Theme previous:ThemeManager.Theme.values()) {themes.select(previous);MessengerSmoke.check(draft.getText().equals(text),"Theme selection lost the draft");}
        themes.select(ThemeManager.Theme.DARK_GREEN);assertGreen(root);
        VBox colors=new VBox();Label label=new Label("Контраст");Button incoming=new Button("Входящее"),outgoing=new Button("Исходящее");incoming.getStyleClass().add("incoming");outgoing.getStyleClass().add("outgoing");colors.getChildren().addAll(label,incoming,outgoing);
        InWindowDialog<Void> page=new InWindowDialog<>();page.initOwner(stage);page.getDialogPane().setContent(colors);themes.apply(page.getDialogPane());page.show();assertGreen(page.getDialogPane());
        MessengerSmoke.check(label.getTextFill().equals(Color.web("#edf4ee")),"Text contrast palette was not rendered");
        MessengerSmoke.check(incoming.getBackground().getFills().getFirst().getFill().equals(Color.web("#1b3024")),"Incoming bubble missed green theme");
        MessengerSmoke.check(outgoing.getBackground().getFills().getFirst().getFill().equals(Color.web("#284a35")),"Outgoing bubble missed green theme");
        MessengerSmoke.check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Theme opened another window");page.close();
        MessengerSmoke.check(draft.getText().equals(text),"Internal page lost the draft");
        Aegis11UiSmoke.invoke(app,"profile",new Class<?>[]{});assertGreen(root);MessengerSmoke.check(root.getCenter()!=null,"Profile is empty");
        themes.selectSystem();MessengerSmoke.check(Files.readString(profile.resolve("theme.txt")).equals("SYSTEM"),"System theme choice was lost");
        themes.select(ThemeManager.Theme.DARK_GREEN);return null;
      });
      String java=Path.of(System.getProperty("java.home"),"bin",AppPaths.windows()?"java.exe":"java").toString();
      List<String> command=new ArrayList<>();command.add(java);
      for(String property:List.of("glass.platform","monocle.platform","prism.order","headless.geometry")) {String value=System.getProperty(property);if(value!=null)command.add("-D"+property+"="+value);}
      command.addAll(List.of("-cp",System.getProperty("java.class.path"),DarkGreenThemeSmoke.class.getName(),"--reopen",profile.toString()));
      Process reopened=new ProcessBuilder(command).inheritIO().start();
      if(!reopened.waitFor(45,TimeUnit.SECONDS)){reopened.destroyForcibly();throw new AssertionError("Restart persistence test timed out");}
      MessengerSmoke.check(reopened.exitValue()==0,"New JVM did not restore the dark-green preset");
      System.out.println("Dark-green PASS: real Appearance selection, six themes, system choice, all main/internal pages, rendered text/bubbles, unchanged draft, one window, persisted theme in a second JVM.");
    }finally{MessengerSmoke.fx(()->{app.stop();return null;});}
  }
}
