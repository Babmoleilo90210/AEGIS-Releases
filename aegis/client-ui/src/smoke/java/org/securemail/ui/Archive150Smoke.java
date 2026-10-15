package org.securemail.ui;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import org.securemail.client.*;
import org.securemail.client.archive.*;
import org.securemail.client.appearance.*;
import org.securemail.client.storage.*;
import org.securemail.client.update.*;
import static org.securemail.ui.MessengerSmoke.*;

/** Actual one-window JavaFX archive workflow with synthetic data. Not Windows/KDE acceptance. */
public final class Archive150Smoke {
  private static Object invoke(Object target,String name,Class<?>[] types,Object...args)throws Exception{var m=target.getClass().getDeclaredMethod(name,types);m.setAccessible(true);return m.invoke(target,args);}
  private static Button button(Parent root,String label){return root.lookupAll(".button").stream().filter(n->n instanceof Button b&&label.equals(b.getText())).map(n->(Button)n).findFirst().orElseThrow(()->new AssertionError("Button missing: "+label));}
  private static void screenshot(Stage stage,String name)throws Exception{Path folder=Path.of("build/ui150-screenshots");Files.createDirectories(folder);snapshot(stage,folder.resolve(name+".png"));}
  public static void main(String[] args)throws Exception {
    Path profile=Files.createTempDirectory("AEGIS-150-UI-");System.setProperty("aegis.profile",profile.toString());Platform.startup(()->Platform.setImplicitExit(false));
    ClientConfig config=ClientConfig.load(AppPaths.config());var session=new ClientSession(config,"synthetic archive UI vault password".toCharArray());session.local().bindNickname("blackfox");MessengerApp app=fx(MessengerApp::new);
    Stage stage=fx(()->{Stage w=new Stage();w.initStyle(StageStyle.UNDECORATED);BorderPane root=new BorderPane();BorderPane outer=new BorderPane(root);outer.setTop(new WindowChrome(w));w.setScene(new Scene(outer,1280,850));InWindowDialog.bind(w,outer);set(app,"stage",w);set(app,"root",root);set(app,"config",config);set(app,"session",session);set(app,"presets",new UiPresetStore(profile));set(app,"updates",new UpdateService(profile,19052));set(app,"updatePreferences",UpdatePreferences.load(profile));ThemeManager t=(ThemeManager)get(app,"themes");t.initialize();t.apply(outer);t.apply(root);t.track(w.getScene());t.workspace(root);w.show();app.mainPage();return w;});
    try{
      ArchiveView view=fx(()->{check(stage.getScene().getRoot().lookupAll(".nav-item").size()==7,"Expected seven main sections");check(stage.getScene().getRoot().lookupAll(".nav-item").stream().noneMatch(n->"Друзья".equals(n.getAccessibleText())),"Friends section remains");app.composePage();TextArea draft=(TextArea)get(app,"composer");draft.setText("Черновик не должен исчезнуть после смены темы");ThemeManager t=(ThemeManager)get(app,"themes");t.commit(t.settings().manual("forest-green"));check(draft.getText().startsWith("Черновик"),"Appearance lost draft");invoke(app,"archivePage",new Class<?>[]{});ArchiveView a=(ArchiveView)get(app,"archiveView");Parent page=(Parent)a.node();page.lookupAll(".password-field").forEach(n->((PasswordField)n).setText("independent archive password 150"));button(page,"Создать архив").fire();return a;});
      until(()->view.unlocked()&&!((boolean)get(view,"busy")));
      Path document=profile.resolve("synthetic-document.txt");Files.writeString(document,"Секрет архива: search-token-150; Latin, кириллица, цифры 123.",StandardCharsets.UTF_8);
      fx(()->{invoke(view,"importPaths",new Class<?>[]{List.class},List.of(document));return null;});
      until(()->!((boolean)get(view,"busy"))&&((ListView<?>)get(view,"list")).getItems().size()==1);
      fx(()->{((ListView<?>)get(view,"list")).getSelectionModel().select(0);return null;});
      until(()->!((boolean)get(view,"busy"))&&((VBox)get(view,"preview")).lookupAll(".text-area").stream().anyMatch(n->n instanceof TextArea t&&t.getText().contains("search-token-150")));
      fx(()->{ThemeManager t=(ThemeManager)get(app,"themes");int count=0;for(var preset:PresetLibrary.builtins().values()){t.commit(t.settings().manual(preset.id()));stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();check(view.unlocked(),"Appearance locked archive unexpectedly");if(List.of("minimal-dark","deep-blue","frost-blue","classic-light").contains(preset.id()))screenshot(stage,"archive-"+preset.id());count++;}check(count>=16,"Built-in presets removed");
        for(Appearance.Zone zone:Appearance.Zone.values()){var j=t.settings().json();j.getAsJsonObject("layout").addProperty("zone",zone.name());t.commit(Appearance.Settings.parse(j));stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();check(stage.getScene().getRoot().lookupAll(".nav-item").stream().anyMatch(n->"Архив".equals(n.getAccessibleText())),"Archive navigation unreachable");}
        ComboBox<?> mode=(ComboBox<?>)get(view,"mode");for(Object m:mode.getItems()){@SuppressWarnings("unchecked") ComboBox<Object> pick=(ComboBox<Object>)mode;pick.setValue(m);stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();screenshot(stage,"archive-mode-"+m.toString());}
        stage.setWidth(680);stage.setHeight(560);stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();screenshot(stage,"archive-narrow");return null;});
      until(()->((SplitPane)get(view,"panels")).getItems().size()<3);
      fx(()->{screenshot(stage,"archive-narrow");stage.setWidth(1280);stage.setHeight(850);return null;});
      fx(()->{((TextField)get(view,"search")).setText("search-token-150");return null;});
      until(()->((ListView<?>)get(view,"list")).getItems().size()==1);
      fx(()->{view.lock();check(!view.unlocked(),"Lock failed");check(((ListView<?>)get(view,"list")).getItems().isEmpty(),"Locked view retained entries");check(((VBox)get(view,"preview")).getChildren().isEmpty(),"Locked view retained plaintext");check(((TextField)get(view,"search")).getText().isEmpty(),"Locked view retained query");screenshot(stage,"archive-locked");invoke(app,"settings",new Class<?>[]{});screenshot(stage,"settings");check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Second Stage created");return null;});
      TimeUnit.MILLISECONDS.sleep(350); // only gives the debounced preference writer a chance; no network readiness inference.
      byte[] prefs=session.local().readArchivePreferences();check(prefs!=null,"Archive preferences were not saved");Arrays.fill(prefs,(byte)0);
      System.out.println("Archive150Smoke PASS: actual create/import/preview/search/lock, all presets, 3 display modes, 3 navigation zones, responsive window, draft preservation, encrypted preferences, one Stage; native Windows11/KDE NOT_RUN");
    }finally{fx(()->{app.stop();return null;});}
  }
}
