package org.securemail.ui;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import javafx.geometry.Bounds;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.Text;
import javafx.stage.*;
import org.securemail.client.*;
import org.securemail.client.appearance.Appearance;
import org.securemail.client.safeweb.*;
import org.securemail.client.storage.*;
import org.securemail.client.update.*;
import static org.securemail.ui.MessengerSmoke.*;

/** Actual Safe Web JavaFX controls and idle manager operations; no browser is fabricated.
 * This test neither installs/starts Tor Browser nor proves a native OS/network sandbox.
 */
public final class SafeWeb200Smoke {
  private static Object invoke(Object target,String name,Class<?>[] types,Object...args)throws Exception{var method=target.getClass().getDeclaredMethod(name,types);method.setAccessible(true);return method.invoke(target,args);}
  private static Button button(Parent root,String text){return root.lookupAll(".button").stream().filter(n->n instanceof Button b&&text.equals(b.getText())).map(n->(Button)n).findFirst().orElseThrow(()->new AssertionError("Missing actual Safe Web control: "+text));}
  private static ScrollPane page(MessengerApp app)throws Exception{Node center=((BorderPane)get(app,"root")).getCenter();check(center instanceof ScrollPane,"Safe Web must be a scrollable page in the main window");return (ScrollPane)center;}
  @SuppressWarnings("unchecked") private static ComboBox<SafeWebSessions.Mode> modes(VBox body){return (ComboBox<SafeWebSessions.Mode>)body.getChildren().stream().filter(n->n instanceof ComboBox<?>).findFirst().orElseThrow(()->new AssertionError("Session mode selector missing"));}
  private static void layout(Stage stage){Parent scene=stage.getScene().getRoot();scene.resize(800,600);scene.applyCss();scene.layout();}
  private static void noOverlap(VBox body,ScrollPane scroll){
    check(body.getWidth()<=scroll.getViewportBounds().getWidth()+1,"Safe Web content overflows its scroll viewport horizontally");
    double previousBottom=-1;
    for(Node child:body.getChildren())if(child.isManaged()&&child.isVisible()){
      Bounds box=child.getBoundsInParent();check(box.getMinX()>=-1&&box.getMaxX()<=body.getWidth()+1,"Safe Web element overflows card: "+child.getClass().getSimpleName());
      check(previousBottom<=box.getMinY()+1,"Safe Web card rows overlap");previousBottom=box.getMaxY();
      if(child instanceof Label label)for(Node glyph:label.lookupAll(".text"))if(glyph instanceof Text text)check(text.getText().equals(label.getText()),"Safe Web label is truncated: "+label.getText());
      if(child instanceof FlowPane row){List<Node> actions=row.getChildren().stream().filter(n->n.isManaged()&&n.isVisible()).toList();
        for(int i=0;i<actions.size();i++){Node action=actions.get(i);Bounds bounds=action.getBoundsInParent();check(bounds.getMinX()>=-1&&bounds.getMaxX()<=row.getWidth()+1,"Safe Web action overflows its row: "+(action instanceof Labeled label?label.getText():action.getClass().getSimpleName()));
          for(int j=i+1;j<actions.size();j++){Bounds other=actions.get(j).getBoundsInParent();double x=Math.min(bounds.getMaxX(),other.getMaxX())-Math.max(bounds.getMinX(),other.getMinX()),y=Math.min(bounds.getMaxY(),other.getMaxY())-Math.max(bounds.getMinY(),other.getMinY());check(x<=1||y<=1,"Safe Web actions overlap");}}
      }
    }
    for(Node node:body.lookupAll(".button"))if(node instanceof Button action){check(action.getOnAction()!=null,"Decorative button without an action: "+action.getText());for(Node glyph:action.lookupAll(".text"))if(glyph instanceof Text text)check(text.getText().equals(action.getText()),"Safe Web action label is truncated: "+action.getText());}
    check(body.getHeight()>scroll.getViewportBounds().getHeight(),"Safe Web fixture does not exercise vertical scrolling");
  }
  /** A real manager monitor may be held by install/extraction. Rendering must use its
   * cached snapshot and leave filesystem operations on the background executor.
   * Holding this monitor is a synchronization probe, not a simulated installation.
   */
  private static void nonblockingManagerReads(MessengerApp app,SafeWebProcess manager)throws Exception{
    CountDownLatch locked=new CountDownLatch(1),release=new CountDownLatch(1);CompletableFuture<Void> rendered=new CompletableFuture<>();
    Thread holder=Thread.ofPlatform().daemon().name("safeweb-ui-monitor-probe").start(()->{synchronized(manager){locked.countDown();try{release.await(10,TimeUnit.SECONDS);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}}});
    check(locked.await(2,TimeUnit.SECONDS),"Could not prepare manager monitor contention");
    try{Platform.runLater(()->{try{manager.snapshot();manager.running();invoke(app,"safeWebPage",new Class<?>[]{});rendered.complete(null);}catch(Throwable failure){rendered.completeExceptionally(failure);}});rendered.get(2,TimeUnit.SECONDS);}
    finally{release.countDown();holder.join(2000);}
  }
  public static void main(String[] args)throws Exception{
    Path fixture=Files.createTempDirectory("AEGIS-safeweb-ui-200-"),profile=fixture.resolve("messenger"),browserRoot=fixture.resolve("safeweb");System.setProperty("aegis.profile",profile.toString());Platform.startup(()->Platform.setImplicitExit(false));
    ClientConfig config=ClientConfig.load(AppPaths.config());var session=new ClientSession(config,"safeweb UI fixture vault password".toCharArray());session.local().bindNickname("blackfox");MessengerApp app=fx(MessengerApp::new);SafeWebProcess manager=new SafeWebProcess(browserRoot);
    Stage stage=fx(()->{Stage window=new Stage();window.initStyle(StageStyle.UNDECORATED);BorderPane root=new BorderPane(),outer=new BorderPane(root);outer.setTop(new WindowChrome(window));window.setScene(new Scene(outer,800,600));InWindowDialog.bind(window,outer);set(app,"stage",window);set(app,"root",root);set(app,"config",config);set(app,"session",session);set(app,"safeWeb",manager);set(app,"presets",new UiPresetStore(profile));set(app,"updates",new UpdateService(profile,19052));set(app,"updatePreferences",UpdatePreferences.load(profile));ThemeManager themes=(ThemeManager)get(app,"themes");themes.initialize();themes.apply(outer);themes.apply(root);themes.track(window.getScene());themes.workspace(root);window.show();app.mainPage();return window;});
    try{
      until(()->Math.abs(stage.getScene().getWidth()-800)<1&&Math.abs(stage.getScene().getHeight()-600)<1);
      for(String theme:List.of("minimal-dark","classic-light"))for(int scale:new int[]{100,125,150,200}){
        fx(()->{ThemeManager themes=(ThemeManager)get(app,"themes");var json=themes.settings().manual(theme).json();json.addProperty("scale",scale);themes.commit(Appearance.Settings.parse(json));invoke(app,"safeWebPage",new Class<?>[]{});return null;});
        for(SafeWebSessions.Mode mode:SafeWebSessions.Mode.values())fx(()->{layout(stage);ScrollPane scroll=page(app);VBox body=(VBox)scroll.getContent();ComboBox<SafeWebSessions.Mode> selector=modes(body);check(selector.getItems().equals(List.of(SafeWebSessions.Mode.PERSISTENT,SafeWebSessions.Mode.TEMPORARY)),"Expected two actual supported session modes");selector.setValue(mode);check(selector.getValue()==mode,"Mode selection did not change");
          for(String label:List.of("Установить / обновить Tor Browser…","Открыть браузер / ссылку","Новая сессия","Закрыть браузер","Обновить загрузки","Импортировать в архив"))button(body,label);
          check(Math.abs(body.getLocalToSceneTransform().getMxx()-scale/100.)<.001,"Smoke did not apply actual JavaFX layout scale");noOverlap(body,scroll);
          TitledPane security=(TitledPane)body.getChildren().stream().filter(n->n instanceof TitledPane).findFirst().orElseThrow();security.setExpanded(true);layout(stage);noOverlap(body,scroll);
          Path folder=Path.of("build/ui200-screenshots");Files.createDirectories(folder);String name="safeweb-800x600-"+theme+"-"+scale+"-"+mode.name().toLowerCase(Locale.ROOT);scroll.setVvalue(0);layout(stage);snapshot(stage,folder.resolve(name+"-top.png"));scroll.setVvalue(1);layout(stage);snapshot(stage,folder.resolve(name+"-downloads.png"));return null;});
      }
      fx(()->{Parent scene=stage.getScene().getRoot();Button install=button(scene,"Установить / обновить Tor Browser…");Platform.runLater(()->{layout(stage);check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Package picker opened a second Stage");button(stage.getScene().getRoot(),"← Назад").fire();});install.fire();check(!manager.snapshot().installed()&&!manager.running(),"Cancelling the actual package picker changed browser installation state");return null;});
      fx(()->{VBox body=(VBox)page(app).getContent();TextField address=(TextField)get(app,"safeWebAddress");address.setText("file:///tmp/never-launch-local-commands");button(body,"Открыть браузер / ссылку").fire();check(((Label)get(app,"inlineStatus")).isVisible(),"Invalid URL did not produce an in-app rejection");button(body,"Новая сессия").fire();check(!manager.running(),"Rejected URL started a browser");button(body,"Обновить загрузки").fire();return null;});
      until(()->!button((VBox)page(app).getContent(),"Обновить загрузки").isDisabled());
      fx(()->{VBox body=(VBox)page(app).getContent();ListView<?> downloads=(ListView<?>)body.getChildren().stream().filter(n->n instanceof ListView<?>).findFirst().orElseThrow();check(downloads.getItems().isEmpty(),"Uninstalled test manager returned downloads");button(body,"Импортировать в архив").fire();check(get(app,"archiveView")==null,"Empty selection opened the archive");button(body,"Закрыть браузер").fire();return null;});
      until(()->!button((VBox)page(app).getContent(),"Закрыть браузер").isDisabled());
      nonblockingManagerReads(app,manager);
      fx(()->{check(!manager.running()&&!manager.snapshot().installed(),"UI fixture unexpectedly installed or started Tor Browser");check(get(app,"session")==session,"Safe Web idle controls changed the messenger session");check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Safe Web UI created a second application Stage");return null;});
      System.out.println("SafeWeb200Smoke PASS_HEADLESS: actual Safe Web controls at 800x600, 100/125/150/200%, 2 themes and 2 modes; non-overlap/scrolling; real picker cancellation, invalid URL rejection, idle download/close actions, cached manager-read responsiveness. Browser install/launch/network/native sandbox NOT_RUN.");
    }finally{fx(()->{app.stop();return null;});}
  }
}
