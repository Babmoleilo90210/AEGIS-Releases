package org.securemail.ui;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import javafx.scene.Parent;
import org.securemail.client.AppPaths;
import org.securemail.client.appearance.*;
import org.securemail.client.storage.*;
import static org.securemail.client.appearance.Appearance.*;

/** Compatibility facade for every existing page, backed by one Appearance Engine. */
final class ThemeManager implements AutoCloseable {
  enum Theme {
    BLACK("Чёрная"),DARK("Тёмно-серая"),DARK_GREEN("Тёмно-зелёная"),GREY("Серая"),LIGHT("Светло-серая"),WHITE("Белая");
    final String label;Theme(String label){this.label=label;}public String toString(){return label;}
    String id(){return "legacy-"+name().toLowerCase(Locale.ROOT).replace('_','-');}
  }
  private Theme selected=systemDefault();private UiPreferences layout=UiPreferences.builtins().get("Компактный");private AppearanceEngine engine;
  private Consumer<Settings> listener=s->{};
  private final Set<Parent> roots=Collections.newSetFromMap(new WeakHashMap<>());
  private final Set<javafx.scene.control.ComboBox<?>> popups=Collections.newSetFromMap(new WeakHashMap<>());
  private final Set<javafx.scene.layout.Region> workspaces=Collections.newSetFromMap(new WeakHashMap<>());
  private final Map<javafx.scene.Scene,java.lang.ref.WeakReference<ScaledRoot>> scenes=new WeakHashMap<>();
  private final javafx.collections.ListChangeListener<javafx.stage.Window> windows=change->{while(change.next())if(change.wasAdded())for(var window:change.getAddedSubList())track(window.getScene());};
  ThemeManager(){try{selected=Theme.valueOf(Files.readString(AppPaths.root().resolve("theme.txt")).trim());}catch(Exception ignored){}javafx.stage.Window.getWindows().addListener(windows);}
  void initialize()throws IOException{if(engine==null){engine=new AppearanceEngine(AppPaths.root(),this::refresh);layout=engine.settings().legacy();refresh();}}
  AppearanceStore store()throws IOException{initialize();return engine.store();}
  Settings settings(){return engine==null?legacy(layout,selected.name()):engine.settings();}
  Appearance.Theme visualTheme(){return engine==null?PresetLibrary.get(selected.id()):engine.theme();}
  String recovery(){return engine==null?"":engine.recovery();}
  void listener(Consumer<Settings> listener){this.listener=Objects.requireNonNull(listener);}
  void preview(Settings value)throws IOException{initialize();engine.preview(value);}
  void preview(Settings value,Appearance.Theme temporary)throws IOException{initialize();engine.preview(value,temporary);}
  void commit(Settings value)throws IOException{initialize();engine.commit(value);}
  void cancelPreview(){if(engine!=null)engine.cancel();}
  void reset()throws IOException{initialize();engine.reset();}
  void restore()throws IOException{initialize();engine.restore();}
  void workspace(javafx.scene.layout.Region value){workspaces.add(value);if(engine!=null)engine.workspace(value);}
  Theme selected(){String id=visualTheme().id();for(Theme value:Theme.values())if(value.id().equals(id))return value;return selected;}
  static Theme systemDefault(){return systemLight()?Theme.WHITE:Theme.DARK;}
  static boolean systemLight(){
    try{
      if(AppPaths.windows()){
        String key="Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
        if(com.sun.jna.platform.win32.Advapi32Util.registryValueExists(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER,key,"AppsUseLightTheme"))return com.sun.jna.platform.win32.Advapi32Util.registryGetIntValue(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER,key,"AppsUseLightTheme")!=0;
      }else{
        String location=System.getenv("XDG_CONFIG_HOME");Path kde=(location==null||location.isBlank()?Path.of(System.getProperty("user.home"),".config"):Path.of(location)).resolve("kdeglobals");
        if(Files.isRegularFile(kde)&&Files.size(kde)<65536){String section="";for(String line:Files.readAllLines(kde)){if(line.startsWith("["))section=line.trim();if(section.equals("[Colors:Window]")&&line.startsWith("BackgroundNormal=")){String[] rgb=line.substring(line.indexOf('=')+1).split(",");if(rgb.length==3)return .2126*Integer.parseInt(rgb[0])+.7152*Integer.parseInt(rgb[1])+.0722*Integer.parseInt(rgb[2])>128;}if(line.toLowerCase(Locale.ROOT).contains("colorscheme=breezelight"))return true;}}
      }
    }catch(Exception|LinkageError unavailable){/* An optional OS preference cannot block the vault. */}return false;
  }
  void selectSystem()throws IOException{AtomicFiles.write(AppPaths.root().resolve("theme.txt"),"SYSTEM".getBytes(java.nio.charset.StandardCharsets.US_ASCII));selected=systemDefault();if(engine!=null){Settings s=settings();commit(new Settings(s.theme(),Mode.SYSTEM,s.lightTheme(),s.darkTheme(),s.lightAt(),s.darkAt(),s.scale(),s.density(),s.typography(),s.components(),s.layout(),s.backdrop()));}else refresh();}
  void select(Theme value)throws IOException{AtomicFiles.write(AppPaths.root().resolve("theme.txt"),value.name().getBytes(java.nio.charset.StandardCharsets.US_ASCII));selected=value;if(engine!=null)commit(settings().manual(value.id()));else refresh();}
  void apply(Parent root){
    if(root instanceof javafx.scene.control.DialogPane dialog&&dialog.getButtonTypes().contains(javafx.scene.control.ButtonType.CLOSE)){javafx.scene.Node close=dialog.lookupButton(javafx.scene.control.ButtonType.CLOSE);if(close!=null){close.setVisible(false);close.setManaged(false);}}
    boolean first=roots.add(root);String css=Objects.requireNonNull(getClass().getResource("messenger.css")).toExternalForm();if(!root.getStylesheets().contains(css))root.getStylesheets().add(css);style(root);
    if(first)root.sceneProperty().addListener((o,a,b)->{if(b!=null)javafx.application.Platform.runLater(()->track(b));});
    if(root.getScene()!=null)javafx.application.Platform.runLater(()->track(root.getScene()));
  }
  private void style(Parent root){Settings s=settings();root.getStyleClass().removeAll("density-compact","density-normal","density-large");root.getStyleClass().add("density-"+s.density().name().toLowerCase(Locale.ROOT));root.setStyle(AppearanceEngine.paletteStyle(visualTheme(),s));
    if(engine!=null)try{String css=engine.stylesheet();root.getStylesheets().removeIf(p->p.contains("/appearance/cache/")&&!p.equals(css));if(!root.getStylesheets().contains(css))root.getStylesheets().add(css);}catch(IOException failure){engine.styleFailure();}
  }
  private void refresh(){Settings s=settings();layout=s.legacy();for(var root:new ArrayList<>(roots))style(root);for(var reference:scenes.values()){var scaled=reference.get();if(scaled!=null)scaled.scale(s.scale());}if(engine!=null)for(var workspace:new ArrayList<>(workspaces))engine.workspace(workspace);listener.accept(s);}
  void track(javafx.scene.Scene scene){
    if(scene==null||scenes.containsKey(scene))return;Parent original=scene.getRoot();
    if(original instanceof ScaledRoot scaled){scenes.put(scene,new java.lang.ref.WeakReference<>(scaled));scaled.scale(settings().scale());return;}
    if(scene.getWindow() instanceof javafx.stage.PopupWindow){if(original instanceof javafx.scene.layout.Pane pane&&!pane.getChildren().isEmpty()){var children=new ArrayList<>(pane.getChildren());pane.getChildren().clear();var body=new javafx.scene.layout.StackPane();body.getChildren().setAll(children);apply(body);var scaled=new ScaledRoot(body);pane.getChildren().add(scaled);scenes.put(scene,new java.lang.ref.WeakReference<>(scaled));scaled.scale(settings().scale());}return;}
    var scaled=new ScaledRoot(original);scene.setRoot(scaled);scenes.put(scene,new java.lang.ref.WeakReference<>(scaled));scaled.scale(settings().scale());
  }
  void layout(UiPreferences value){layout=value;if(engine==null)refresh();else{Settings s=settings();Settings next=new Settings(s.theme(),s.mode(),s.lightTheme(),s.darkTheme(),s.lightAt(),s.darkAt(),value.scale(),value.density(),s.typography(),s.components(),s.layout(),s.backdrop());engine.preview(next);}}
  void stylePopup(javafx.scene.control.ComboBox<?> combo){if(!popups.add(combo))return;Consumer<javafx.scene.control.Skin<?>> applySkin=skin->{if(skin instanceof javafx.scene.control.skin.ComboBoxListViewSkin<?> view&&view.getPopupContent() instanceof Parent popup)apply(popup);};combo.skinProperty().addListener((o,a,b)->applySkin.accept(b));if(combo.getSkin()!=null)applySkin.accept(combo.getSkin());combo.setVisibleRowCount(Math.min(8,Math.max(1,combo.getVisibleRowCount())));}
  @Override public void close(){javafx.stage.Window.getWindows().removeListener(windows);if(engine!=null)engine.close();roots.clear();scenes.clear();workspaces.clear();popups.clear();}
}
