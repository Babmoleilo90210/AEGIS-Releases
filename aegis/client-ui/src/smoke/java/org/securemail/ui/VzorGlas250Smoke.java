package org.securemail.ui;

import com.google.gson.GsonBuilder;
import java.io.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javafx.application.Platform;
import javafx.geometry.Bounds;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import org.securemail.client.*;
import org.securemail.client.appearance.Appearance;
import org.securemail.client.crypto.Identity;
import org.securemail.client.safeweb.*;
import org.securemail.client.storage.*;
import org.securemail.client.update.*;
import org.securemail.client.voice.VoiceCallService;
import org.securemail.protocol.UserInfo;

/** Actual current VzorView/GlasView inside MessengerApp; no Tor, browser, audio or native OS claim. */
public final class VzorGlas250Smoke {
  private static Path output;
  private static final List<String> images=new ArrayList<>();
  private static <T>T fx(Callable<T> action)throws Exception {CompletableFuture<T> result=new CompletableFuture<>();Platform.runLater(()->{try{result.complete(action.call());}catch(Throwable failure){result.completeExceptionally(failure);}});return result.get(30,TimeUnit.SECONDS);}
  private static void check(boolean condition,String reason){if(!condition)throw new AssertionError(reason);}
  private static Object get(Object object,String field)throws Exception {Field f=object.getClass().getDeclaredField(field);f.setAccessible(true);return f.get(object);}
  private static void set(MessengerApp app,String field,Object value)throws Exception {Field f=MessengerApp.class.getDeclaredField(field);f.setAccessible(true);f.set(app,value);}
  private static void page(MessengerApp app,String method)throws Exception {Method m=MessengerApp.class.getDeclaredMethod(method);m.setAccessible(true);m.invoke(app);}
  private static void until(Callable<Boolean> condition)throws Exception {long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(20);while(System.nanoTime()<end){if(fx(condition))return;Thread.sleep(40);}throw new AssertionError("Timed out waiting for actual UI operation");}
  private static void layout(Stage stage){Parent root=stage.getScene().getRoot();root.applyCss();root.layout();}
  /** Let real JavaFX expansion/scale pulses settle before measuring or capturing them. */
  private static void settle(Stage stage){Object pulse=new Object();var pause=new javafx.animation.PauseTransition(javafx.util.Duration.millis(220));pause.setOnFinished(e->Platform.exitNestedEventLoop(pulse,null));pause.play();Platform.enterNestedEventLoop(pulse);layout(stage);}
  private static Button button(Parent parent,String label){return parent.lookupAll(".button").stream().filter(n->n instanceof Button b&&b.getText().equals(label)).map(n->(Button)n).findFirst().orElseThrow(()->new AssertionError("Actual button missing: "+label));}
  private static void completeCaption(Labeled control){check(control.lookupAll(".text").stream().anyMatch(n->n instanceof javafx.scene.text.Text text&&text.getText().equals(control.getText())),"A visible action caption is truncated: "+control.getText());}
  private static void reachable(Node action,Stage stage){Bounds bounds=action.localToScene(action.getBoundsInLocal());check(bounds.getMinX()>=-1&&bounds.getMinY()>=-1&&bounds.getMaxX()<=stage.getScene().getWidth()+1&&bounds.getMaxY()<=stage.getScene().getHeight()+1,"Action exceeds actual scene pixels: "+bounds);for(Node ancestor=action;ancestor!=null;ancestor=ancestor.getParent())if(ancestor.getClip()!=null){Bounds clip=ancestor.localToScene(ancestor.getClip().getBoundsInParent());check(bounds.getMinX()>=clip.getMinX()-1&&bounds.getMinY()>=clip.getMinY()-1&&bounds.getMaxX()<=clip.getMaxX()+1&&bounds.getMaxY()<=clip.getMaxY()+1,"Action is outside an ancestor clip: "+bounds+" clip="+clip);}}
  private static String sha(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
  private static Map<String,Object> runtimeEvidence()throws Exception {Map<String,String> source=new LinkedHashMap<>(),classes=new LinkedHashMap<>();for(Class<?> type:List.of(VzorGlas250Smoke.class,VzorView.class,GlasView.class,InWindowDialog.class,InWindowFileChooser.class)){String name=type.getSimpleName();Path file=Path.of(type==VzorGlas250Smoke.class?"client-ui/src/smoke/java/org/securemail/ui/":"client-ui/src/main/java/org/securemail/ui/").resolve(name+".java");if(Files.isRegularFile(file))source.put(file.toString(),sha(Files.readAllBytes(file)));try(InputStream stream=type.getResourceAsStream(name+".class")){check(stream!=null,"Runtime class bytes are unavailable: "+name);classes.put(type.getName(),sha(stream.readAllBytes()));}}return Map.of("sourceSha256",source,"sourceShaStatus",source.isEmpty()?"NOT_AVAILABLE_IN_PACKAGED_KIT":"ACTUAL_LOCAL_SOURCE","runtimeClassSha256",classes);}
  private static TitledPane pane(Parent parent,String label){return parent.lookupAll(".titled-pane").stream().filter(n->n instanceof TitledPane p&&p.getText().equals(label)).map(n->(TitledPane)n).findFirst().orElseThrow(()->new AssertionError("Actual section missing: "+label));}
  private static void oneStage(){check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"An extra application Stage was created");}
  private static void capture(Stage stage,String name)throws Exception {
    layout(stage);var image=stage.getScene().snapshot(null);var bitmap=new java.awt.image.BufferedImage((int)image.getWidth(),(int)image.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);
    try{for(int y=0;y<bitmap.getHeight();y++)for(int x=0;x<bitmap.getWidth();x++)bitmap.setRGB(x,y,image.getPixelReader().getArgb(x,y));check(javax.imageio.ImageIO.write(bitmap,"png",output.resolve(name+".png").toFile()),"PNG encoder unavailable");images.add(name+".png");}finally{bitmap.flush();}
  }
  private static void navigation(Stage stage){
    Set<String> expected=Set.of("Поиск","Профиль","Контакты","Письма","Архив","Взор","Глас","Настройки");Set<String> actual=new HashSet<>();
    for(Node item:stage.getScene().getRoot().lookupAll(".nav-item"))actual.add(item.getAccessibleText());check(actual.equals(expected),"Eight current navigation sections missing: "+actual);oneStage();
  }
  private static void geometry(Stage stage,ScrollPane page,VBox card,int scale){
    layout(stage);check(Math.abs(stage.getScene().getWidth()-800)<1&&Math.abs(stage.getScene().getHeight()-600)<1,"Test scene is not actually 800x600");
    check(Math.abs(card.getLocalToSceneTransform().getMxx()-scale/100.)<.001,"The current page did not receive actual interface scaling");
    check(card.getWidth()<=page.getViewportBounds().getWidth()+1,"Content exceeds its viewport horizontally");double previous=-1;
    for(Node child:card.getChildren())if(child.isManaged()&&child.isVisible()){
      Bounds bounds=child.getBoundsInParent();check(bounds.getMinX()>=-1&&bounds.getMaxX()<=card.getWidth()+1,"A card row exceeds available width: "+child.getClass().getSimpleName()+" page="+page.getId()+" scale="+scale+" cardWidth="+card.getWidth()+" child="+bounds+" layout="+child.getLayoutBounds());check(previous<=bounds.getMinY()+1,"Card rows overlap");previous=bounds.getMaxY();
      if(child instanceof FlowPane row){List<Node> controls=row.getChildren().stream().filter(n->n.isManaged()&&n.isVisible()).toList();for(int i=0;i<controls.size();i++){
        Bounds a=controls.get(i).getBoundsInParent();check(a.getMinX()>=-1&&a.getMaxX()<=row.getWidth()+1,"An action exceeds its wrapping row");
        for(int j=i+1;j<controls.size();j++){Bounds b=controls.get(j).getBoundsInParent();check(Math.min(a.getMaxX(),b.getMaxX())-Math.max(a.getMinX(),b.getMinX())<=1||Math.min(a.getMaxY(),b.getMaxY())-Math.max(a.getMinY(),b.getMinY())<=1,"Wrapping actions overlap");}
      }}
      if(child instanceof TitledPane section){Parent title=(Parent)section.lookup(".title");check(title!=null&&title.lookupAll(".text").stream().anyMatch(n->n instanceof javafx.scene.text.Text text&&text.getText().equals(section.getText())),"A section heading is truncated: "+section.getText());}
    }
    check(page.isFitToWidth(),"Narrow page cannot fit its content");navigation(stage);
  }
  private static void noMicrophone(GlasView view,ClientSession session)throws Exception {
    check(session.calls().snapshot().state()==VoiceCallService.State.IDLE,"Idle setup unexpectedly started a call");check(!session.calls().snapshot().microphoneEnabled(),"Microphone enabled automatically");check(session.calls().audioStats()==null,"Idle view opened an audio session");
    check(!((AtomicBoolean)get(view,"microphoneSlot")).get(),"Idle view started a microphone test");
    Method resource=get(view,"microphoneTests").getClass().getDeclaredMethod("resource");resource.setAccessible(true);check(resource.invoke(get(view,"microphoneTests"))==null,"A microphone test owns an audio resource without consent");
    Button microphone=(Button)get(view,"microphone");check(!microphone.isVisible()&&!microphone.isManaged(),"Idle view displays the active-call microphone action");
  }
  private static void manualPicker(Stage stage,VzorView view,Path pickerHome)throws Exception {
    TitledPane advanced=pane((Parent)view.node(),"Дополнительные настройки");advanced.setExpanded(true);layout(stage);((ScrollPane)view.node()).setVvalue(1);layout(stage);
    CompletableFuture<Void> inspected=new CompletableFuture<>();
    Platform.runLater(()->{try{settle(stage);oneStage();Parent shown=stage.getScene().getRoot();for(String caption:List.of("← Назад","Отмена","Выбрать","Открыть папку"))completeCaption(button(shown,caption));
      check(shown.lookupAll(".label").stream().anyMatch(n->n instanceof Label l&&l.getText().equals("Официальный пакет Tor Browser")),"Manual package picker lost Russian title");
      check(shown.lookupAll(".button").stream().noneMatch(n->n instanceof Button b&&Set.of("Cancel","Open","Choose","Select").contains(b.getText())),"Manual picker exposed untranslated actions");
      ListView<?> files=(ListView<?>)shown.lookup(".list-view");check(files!=null&&!files.getItems().isEmpty()&&files.getItems().stream().allMatch(item->item instanceof Path p&&p.startsWith(pickerHome)),"Picker screenshot must use only synthetic fixture files");
      capture(stage,"vzor-manual-picker-russian-800x600-200");ScrollPane chooser=(ScrollPane)shown.lookup(".in-window-page > .scroll-pane");check(chooser!=null,"In-window file picker is not scrollable");chooser.setVvalue(1);settle(stage);capture(stage,"vzor-manual-picker-actions-800x600-200");for(String caption:List.of("Отмена","Выбрать"))reachable(button(shown,caption),stage);button(shown,"Отмена").fire();inspected.complete(null);
    }catch(Throwable failure){InWindowDialog.closeAll(stage);inspected.completeExceptionally(failure);}});
    String previousHome=System.getProperty("user.home");System.setProperty("user.home",pickerHome.toString());try{button((Parent)advanced.getContent(),"Импортировать официальный пакет…").fire();inspected.get(2,TimeUnit.SECONDS);oneStage();}finally{System.setProperty("user.home",previousHome);}
  }
  public static void main(String[] arguments)throws Exception {
    output=arguments.length==0?Path.of("build/vzor-glas250-screenshots").toAbsolutePath():Path.of(arguments[0]).toAbsolutePath();Files.createDirectories(output);
    Path fixture=Files.createTempDirectory("AEGIS-vzor-glas250-"),profile=fixture.resolve("messenger"),pickerHome=fixture.resolve("test-files");Files.createDirectories(pickerHome.resolve("Документы"));Files.writeString(pickerHome.resolve("synthetic-test-only.tar.xz"),"Not a browser package; cancellation-only UI fixture.");System.setProperty("aegis.profile",profile.toString());
    SandboxPrerequisites.Failure prerequisite=null;try{SandboxPrerequisites.check();}catch(SandboxPrerequisites.Failure actual){prerequisite=actual;}
    // Native-kit hosts may have every prerequisite. Skip only the unavailable-
    // prerequisite scenario there; never launch a valid URL merely to force failure.
    final String prerequisiteMessage=prerequisite==null?null:prerequisite.getMessage(),prerequisiteCode=prerequisite==null?"NOT_RUN_PREREQUISITES_AVAILABLE":prerequisite.code().name();
    Platform.startup(()->Platform.setImplicitExit(false));ClientConfig config=ClientConfig.load(AppPaths.config());ClientSession session=new ClientSession(config,"synthetic Vzor Glas UI vault password".toCharArray());session.local().bindNickname("blackfox");Identity raven=Identity.create();session.local().trust(new UserInfo(raven.userId(),"raven",raven.publicKey(),null));
    SafeWebProcess manager=new SafeWebProcess(fixture.resolve("isolated-browser"));MessengerApp app=fx(MessengerApp::new);
    Stage stage=fx(()->{Stage window=new Stage();window.initStyle(StageStyle.UNDECORATED);BorderPane workspace=new BorderPane(),outer=new BorderPane(workspace);outer.setTop(new WindowChrome(window));window.setScene(new Scene(outer,1280,850));InWindowDialog.bind(window,outer);
      set(app,"stage",window);set(app,"root",workspace);set(app,"config",config);set(app,"session",session);set(app,"safeWeb",manager);set(app,"presets",new UiPresetStore(profile));set(app,"updates",new UpdateService(profile,19052));set(app,"updatePreferences",UpdatePreferences.load(profile));ThemeManager themes=(ThemeManager)get(app,"themes");themes.initialize();themes.apply(outer);themes.apply(workspace);themes.workspace(workspace);themes.track(window.getScene());window.show();app.mainPage();return window;});
    Map<String,Object> result=new LinkedHashMap<>();int combinations=0;
    try{
      fx(()->{navigation(stage);capture(stage,"navigation-eight-sections-1280x850");stage.setWidth(800);stage.setHeight(600);page(app,"safeWebPage");return null;});until(()->!(boolean)get(get(app,"vzorView"),"busy"));
      for(String theme:List.of("minimal-dark","classic-light"))for(int scale:new int[]{100,125,150,200}){
        fx(()->{ThemeManager themes=(ThemeManager)get(app,"themes");var settings=themes.settings().manual(theme).json();settings.addProperty("scale",scale);themes.commit(Appearance.Settings.parse(settings));page(app,"safeWebPage");return null;});
        until(()->Math.abs(stage.getScene().getWidth()-800)<1&&Math.abs(stage.getScene().getHeight()-600)<1);
        fx(()->{VzorView view=(VzorView)get(app,"vzorView");ScrollPane scroll=(ScrollPane)view.node();VBox card=(VBox)((StackPane)scroll.getContent()).getChildren().getFirst();
          for(String name:List.of("Загрузки","Безопасность","Дополнительные настройки")){TitledPane section=pane(card,name);section.setExpanded(false);}scroll.setVvalue(0);settle(stage);geometry(stage,scroll,card,scale);
          check(card.lookup("#vzor-open")instanceof Button b&&b.getText().equals("Открыть Взор"),"The compact Vzor primary action is missing");check(!pane(card,"Дополнительные настройки").isExpanded(),"Advanced browser controls should be collapsed");
          check(!manager.running()&&!manager.snapshot().installed(),"Viewing Vzor installed or started a browser");capture(stage,"vzor-800x600-"+theme+"-"+scale+"-compact");
          pane(card,"Дополнительные настройки").setExpanded(true);settle(stage);scroll.setVvalue(1);layout(stage);geometry(stage,scroll,card,scale);button((Parent)pane(card,"Дополнительные настройки").getContent(),"Импортировать официальный пакет…");capture(stage,"vzor-800x600-"+theme+"-"+scale+"-advanced");
          page(app,"glasPage");GlasView glas=(GlasView)get(app,"glasView");ScrollPane calls=(ScrollPane)glas.node();VBox content=(VBox)((StackPane)calls.getContent()).getChildren().getFirst();pane(content,"Звук и входящие вызовы").setExpanded(false);calls.setVvalue(0);settle(stage);geometry(stage,calls,content,scale);noMicrophone(glas,session);
          check(((ListView<?>)get(glas,"contacts")).getItems().size()==1,"Pinned contact did not appear in actual Glas list");check(!((Button)get(glas,"call")).isDisabled(),"Selected pinned contact is not callable from idle UI");capture(stage,"glas-800x600-"+theme+"-"+scale+"-idle");
          TitledPane audio=pane(content,"Звук и входящие вызовы");audio.setExpanded(true);settle(stage);calls.setVvalue(1);layout(stage);geometry(stage,calls,content,scale);button((Parent)audio.getContent(),"Проверить микрофон");for(Node child:((VBox)audio.getContent()).getChildren())if(child instanceof Label label)completeCaption(label);noMicrophone(glas,session);capture(stage,"glas-800x600-"+theme+"-"+scale+"-settings");if(scale==200){calls.setVvalue(Math.min(1,audio.getBoundsInParent().getMinY()/Math.max(1,calls.getContent().getLayoutBounds().getHeight()-calls.getViewportBounds().getHeight())));layout(stage);capture(stage,"glas-800x600-"+theme+"-"+scale+"-audio-devices");}return null;});combinations++;
      }
      fx(()->{ThemeManager themes=(ThemeManager)get(app,"themes");var settings=themes.settings().manual("minimal-dark").json();settings.addProperty("scale",200);themes.commit(Appearance.Settings.parse(settings));page(app,"safeWebPage");manualPicker(stage,(VzorView)get(app,"vzorView"),pickerHome);check(!manager.running()&&!manager.snapshot().installed(),"Cancelling picker modified Tor Browser installation");return null;});
      fx(()->{VzorView view=(VzorView)get(app,"vzorView");view.address("file:///tmp/never-open-local-commands");((Button)get(view,"open")).fire();Label status=(Label)get(app,"inlineStatus");check(status.isVisible()&&status.getText().contains("запрещены"),"Invalid URL was not rejected by the actual handler");((ScrollPane)view.node()).setVvalue(0);capture(stage,"vzor-invalid-url-rejected");check(!manager.running(),"Invalid URL started a browser");if(prerequisiteMessage!=null){view.address("https://check.torproject.org/");((Button)get(view,"open")).fire();}return null;});
      if(prerequisiteMessage!=null)until(()->{VzorView view=(VzorView)get(app,"vzorView");return !(boolean)get(view,"busy")&&((Label)get(view,"status")).getText().equals(prerequisiteMessage);});
      fx(()->{if(prerequisiteMessage!=null)capture(stage,"vzor-real-prerequisite-rejection");check(!manager.running()&&!manager.snapshot().installed(),"Offline UI probe unexpectedly started browser installation");check(get(app,"tor")==null,"Offline probe unexpectedly initiated Tor");page(app,"glasPage");GlasView glas=(GlasView)get(app,"glasView");TitledPane audio=pane((Parent)glas.node(),"Звук и входящие вызовы");audio.setExpanded(true);Parent controls=(Parent)audio.getContent();List<Slider> sliders=controls.lookupAll(".slider").stream().filter(n->n instanceof Slider).map(n->(Slider)n).toList();check(sliders.size()==2,"Audio gain/volume settings missing");
        for(Node child:((VBox)controls).getChildren())if(child instanceof Slider slider){if(slider.getMax()>1)slider.setValue(1.25);else slider.setValue(.4);}for(Node node:controls.lookupAll(".check-box"))if(node instanceof CheckBox box&&List.of("Разрешить входящие звонки","Показывать уведомления о звонках").contains(box.getText())){if(box.isSelected())box.fire();}button(controls,"Применить настройки").fire();noMicrophone(glas,session);oneStage();return null;});
      until(()->!session.calls().incomingEnabled()&&!session.calls().notificationsEnabled()&&Math.abs(session.calls().audioConfig().inputGain()-1.25)<.001&&Math.abs(session.calls().audioConfig().speakerVolume()-.4)<.001);
      fx(()->{GlasView glas=(GlasView)get(app,"glasView");noMicrophone(glas,session);check(session.local().readVoiceState()!=null,"Actual audio preferences did not persist in encrypted sidecar");check(get(app,"session")==session,"Browser or calls setup replaced messenger session");navigation(stage);capture(stage,"glas-applied-settings-no-microphone");return null;});
      Map<String,Double> switching=new LinkedHashMap<>();fx(()->{ThemeManager themes=(ThemeManager)get(app,"themes");var settings=themes.settings().manual("minimal-dark").json();settings.addProperty("scale",100);themes.commit(Appearance.Settings.parse(settings));stage.setWidth(1280);stage.setHeight(850);settle(stage);return null;});
      for(String[] item:new String[][]{{"Поиск","search"},{"Профиль","profile"},{"Контакты","contacts"},{"Письма","letters"},{"Архив","archive"},{"Взор","vzor"},{"Глас","glas"},{"Настройки","settings"}})fx(()->{Button action=stage.getScene().getRoot().lookupAll(".nav-item").stream().filter(n->n instanceof Button b&&item[0].equals(b.getAccessibleText())).map(n->(Button)n).findFirst().orElseThrow();long started=System.nanoTime();action.fire();layout(stage);switching.put(item[1],(System.nanoTime()-started)/1_000_000.);settle(stage);navigation(stage);capture(stage,"section-"+item[1]+"-1280x850-minimal-dark-100");return null;});
      String probeStatus="Monocle".equals(System.getProperty("glass.platform"))?"PASS_HEADLESS":"PASS_UI_ONLY";
      result.put("status",probeStatus);result.put("environment",Map.of("os",System.getProperty("os.name"),"glassPlatform",System.getProperty("glass.platform","native")));result.put("actualScenePixels",List.of(800,600));result.put("themeScaleCombinations",combinations);result.put("themes",List.of("minimal-dark","classic-light"));result.put("scalesPercent",List.of(100,125,150,200));result.put("navigationSections",8);result.put("actualSandboxPrerequisiteFailure",prerequisiteCode);result.put("manualPickerRussianCancellation","PASS");result.put("invalidUrlRejection","PASS");result.put("glasIdleAndEncryptedSettings","PASS");result.put("noAutomaticMicrophone",true);result.put("showingStageCount",1);result.put("screenshots",images);result.put("realTorBrowserOrCallTransport","NOT_RUN");result.put("nativeWindows11CachyOS","NOT_RUN");result.put("productionReady",false);
      result.put("eightSectionScreenshots",List.of("search","profile","contacts","letters","archive","vzor","glas","settings"));result.put("navigationHandlerAndSynchronousLayoutMillis",switching);result.put("navigationTimingScope","Actual button handler plus synchronous JavaFX layout; excludes asynchronous data fetch, pulse settling and screenshot encoding; headless fixture measurement, not native performance acceptance.");result.put("runtimeEvidence",runtimeEvidence());
      Files.writeString(output.resolve("RESULTS.json"),new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n");
      System.out.println("VzorGlas250Smoke "+probeStatus+": actual MessengerApp 8 sections, "+combinations+" theme/scale combinations at 800x600, "+images.size()+" real JavaFX screenshots; compact/advanced Vzor, Russian picker cancellation, invalid URL; unavailable prerequisite scenario="+prerequisiteCode+"; Glas idle/audio preference save with no automatic microphone; one Stage. Tor/browser/call transport/native OS NOT_RUN.");
    }finally{fx(()->{app.stop();return null;});}
  }
}
