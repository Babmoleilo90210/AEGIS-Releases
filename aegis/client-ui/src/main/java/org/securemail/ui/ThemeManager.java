package org.securemail.ui;
import java.nio.file.*;
import java.util.*;
import javafx.scene.Parent;
import org.securemail.client.AppPaths;
import org.securemail.client.storage.AtomicFiles;
final class ThemeManager {
  enum Theme {
    BLACK("Чёрная","#090b0e","#111419","#20252d","#e5e8ee","#89949f"),
    DARK("Тёмно-серая","#15191f","#20262e","#303842","#e5e9ef","#a1acb8"),
    GREY("Серая","#353a41","#424951","#535d66","#f2f4f6","#c0c8cf"),
    LIGHT("Светло-серая","#d7dce1","#e4e8ec","#c5cdd4","#1a2630","#536371"),
    WHITE("Белая","#f6f8fa","#ffffff","#e0e6eb","#19232c","#64717c");
    final String label,bg,panel,control,text,muted;
    Theme(String label,String bg,String panel,String control,String text,String muted){this.label=label;this.bg=bg;this.panel=panel;this.control=control;this.text=text;this.muted=muted;}
    public String toString(){return label;}
  }
  private Theme selected=systemDefault();
  private org.securemail.client.storage.UiPreferences layout=org.securemail.client.storage.UiPreferences.builtins().get("Компактный");
  private final Set<Parent> roots=Collections.newSetFromMap(new WeakHashMap<>());
  private final Map<javafx.scene.Scene,java.lang.ref.WeakReference<ScaledRoot>> scenes=new WeakHashMap<>();
  ThemeManager(){try{selected=Theme.valueOf(Files.readString(AppPaths.root().resolve("theme.txt")).trim());}catch(Exception ignored){}
    javafx.stage.Window.getWindows().addListener((javafx.collections.ListChangeListener<javafx.stage.Window>)change->{while(change.next())if(change.wasAdded())for(var window:change.getAddedSubList())track(window.getScene());});
  }
  Theme selected(){return selected;}
  static Theme systemDefault(){
    try{
      if(AppPaths.windows()){
        String key="Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
        if(com.sun.jna.platform.win32.Advapi32Util.registryValueExists(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER,key,"AppsUseLightTheme"))
          return com.sun.jna.platform.win32.Advapi32Util.registryGetIntValue(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER,key,"AppsUseLightTheme")==0?Theme.DARK:Theme.WHITE;
      }else{
        String location=System.getenv("XDG_CONFIG_HOME");Path kde=(location==null||location.isBlank()?Path.of(System.getProperty("user.home"),".config"):Path.of(location)).resolve("kdeglobals");
        if(Files.isRegularFile(kde)&&Files.size(kde)<65536){String value=Files.readString(kde).toLowerCase(Locale.ROOT);if(value.contains("colorscheme=")&&!value.contains("colorscheme=breezedark"))return Theme.LIGHT;}
      }
    }catch(Exception|LinkageError unavailable){/* System preference is optional; never blocks opening the vault. */}
    return Theme.DARK;
  }
  void selectSystem()throws java.io.IOException{AtomicFiles.write(AppPaths.root().resolve("theme.txt"),"SYSTEM".getBytes(java.nio.charset.StandardCharsets.US_ASCII));selected=systemDefault();for(var root:roots)style(root);}
  void apply(Parent root){
    if(root instanceof javafx.scene.control.DialogPane dialog&&dialog.getButtonTypes().contains(javafx.scene.control.ButtonType.CLOSE)){
      javafx.scene.Node close=dialog.lookupButton(javafx.scene.control.ButtonType.CLOSE);if(close!=null){close.setVisible(false);close.setManaged(false);}
    }
    roots.add(root);String css=Objects.requireNonNull(getClass().getResource("messenger.css")).toExternalForm();
    if(!root.getStylesheets().contains(css))root.getStylesheets().add(css);style(root);
    root.sceneProperty().addListener((o,a,b)->{if(b!=null)javafx.application.Platform.runLater(()->track(b));});
    if(root.getScene()!=null)javafx.application.Platform.runLater(()->track(root.getScene()));
  }
  private void style(Parent root){
    root.getStyleClass().removeAll("density-compact","density-normal","density-large");root.getStyleClass().add("density-"+layout.density().name().toLowerCase(java.util.Locale.ROOT));
    root.setStyle("-fx-base:"+selected.panel+";-aegis-bg:"+selected.bg+";-aegis-panel:"+selected.panel+";-aegis-control:"+selected.control+";-aegis-text:"+selected.text+";-aegis-muted:"+selected.muted+";-aegis-accent:"+(selected==Theme.LIGHT||selected==Theme.WHITE?"#205947":"#82cbb7")+";-fx-font-size:13px;");
  }
  void track(javafx.scene.Scene scene){
    if(scene==null||scenes.containsKey(scene))return;Parent original=scene.getRoot();
    if(original instanceof ScaledRoot scaled){scenes.put(scene,new java.lang.ref.WeakReference<>(scaled));scaled.scale(layout.scale());return;}
    // PopupWindow keeps its own root; scale its content without replacing that root.
    if(scene.getWindow() instanceof javafx.stage.PopupWindow){
      if(original instanceof javafx.scene.layout.Pane pane&&!pane.getChildren().isEmpty()){
        var children=new ArrayList<>(pane.getChildren());pane.getChildren().clear();
        var body=new javafx.scene.layout.StackPane();body.getChildren().setAll(children);
        apply(body);var scaled=new ScaledRoot(body);pane.getChildren().add(scaled);scenes.put(scene,new java.lang.ref.WeakReference<>(scaled));scaled.scale(layout.scale());
      }return;
    }
    var scaled=new ScaledRoot(original);scene.setRoot(scaled);scenes.put(scene,new java.lang.ref.WeakReference<>(scaled));scaled.scale(layout.scale());
  }
  void layout(org.securemail.client.storage.UiPreferences value){layout=value;for(var root:roots)style(root);for(var reference:scenes.values()){var scaled=reference.get();if(scaled!=null)scaled.scale(value.scale());}}
  void stylePopup(javafx.scene.control.ComboBox<?> combo){
    java.util.function.Consumer<javafx.scene.control.Skin<?>> applySkin=skin->{
      if(skin instanceof javafx.scene.control.skin.ComboBoxListViewSkin<?> view && view.getPopupContent() instanceof Parent popup)apply(popup);
    };
    combo.skinProperty().addListener((o,a,b)->applySkin.accept(b));if(combo.getSkin()!=null)applySkin.accept(combo.getSkin());
    combo.setVisibleRowCount(Math.min(8,Math.max(1,combo.getVisibleRowCount())));
  }
  void select(Theme theme)throws java.io.IOException {
    AtomicFiles.write(AppPaths.root().resolve("theme.txt"),theme.name().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    selected=theme;for(var root:roots)style(root);
  }
}

