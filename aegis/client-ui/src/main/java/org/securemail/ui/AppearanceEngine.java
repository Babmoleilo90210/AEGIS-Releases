package org.securemail.ui;

import javafx.application.*;
import javafx.animation.*;
import javafx.scene.image.Image;
import javafx.scene.layout.*;
import javafx.scene.paint.*;
import javafx.scene.text.Font;
import javafx.util.Duration;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.appearance.*;
import org.securemail.client.storage.*;
import static org.securemail.client.appearance.Appearance.*;

/** One appearance state for all pages. Never owns a session, network or cryptographic service. */
final class AppearanceEngine implements AutoCloseable {
  private final AppearanceStore store;private Settings active;private Theme theme,previewTheme;private String css="",recovery="";
  private final Set<String> fonts=new HashSet<>(Font.getFamilies());
  private final ExecutorService imageWorker=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"aegis-appearance-image");t.setDaemon(true);return t;});
  private final Runnable changed;private final Timeline clock;
  private Image image;private String imageId="";private long imageTicket;
  AppearanceEngine(Path profile,Runnable changed)throws IOException{
    this.changed=changed;store=new AppearanceStore(profile);active=store.current();
    if(!validFonts(active)){store.recover("Выбранный шрифт недоступен. Используется безопасное оформление.");active=store.current();}
    resolve();clock=new Timeline(new KeyFrame(Duration.seconds(30),event->{Theme before=theme;resolve();if(!Objects.equals(before,theme)){css="";changed.run();}}));clock.setCycleCount(Animation.INDEFINITE);clock.play();
  }
  AppearanceStore store(){return store;}
  Settings settings(){return active;}
  Theme theme(){return theme;}
  void styleFailure(){recovery="Оформление не удалось применить полностью. Выберите стандартный пресет.";}
  String recovery(){return recovery.isEmpty()?store.recovery():recovery;}
  boolean validFonts(Settings value){return List.of(value.typography().navigation(),value.typography().heading(),value.typography().mail()).stream().allMatch(t->t.family().equals("System")||fonts.contains(t.family()));}
  void preview(Settings value){preview(value,null);}
  void preview(Settings value,Theme temporary){if(!validFonts(value))throw new IllegalArgumentException("Шрифт недоступен на этом устройстве");active=value;previewTheme=temporary;css="";resolve();changed.run();}
  void cancel(){active=store.current();previewTheme=null;css="";resolve();changed.run();}
  void commit(Settings value)throws IOException{if(!validFonts(value))throw new IOException("Шрифт недоступен на этом устройстве");store.apply(value);active=value;previewTheme=null;css="";recovery="";resolve();changed.run();}
  void reset()throws IOException{commit(defaults());}
  void restore()throws IOException{store.restoreBackup();active=store.current();if(!validFonts(active)){store.recover("Шрифт из резервной копии недоступен.");active=store.current();}css="";resolve();changed.run();}
  private void resolve(){String id=effectiveTheme(active,ThemeManager.systemLight(),LocalTime.now());theme=previewTheme!=null&&previewTheme.id().equals(id)?previewTheme:store.theme(id);if(theme==null){active=defaults();theme=PresetLibrary.get(active.theme());recovery="Тема недоступна. Выберите другой пресет.";}}
  String stylesheet()throws IOException{
    if(!css.isEmpty())return css;String content=componentStyles(theme,active);String hash;
    try{hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}catch(GeneralSecurityException impossible){throw new IOException(impossible);}
    Path cache=store.root().resolve("cache");AtomicFiles.directory(cache);Path path=cache.resolve(hash+".css");if(!Files.exists(path))AtomicFiles.write(path,content.getBytes(java.nio.charset.StandardCharsets.UTF_8));css=path.toUri().toASCIIString();
    try(var files=Files.list(cache)){var old=files.filter(p->p.getFileName().toString().matches("[a-f0-9]{64}\\.css")).sorted(Comparator.comparingLong(AppearanceEngine::modified)).toList();for(int i=0;i<old.size()-32;i++)if(!old.get(i).equals(path))Files.deleteIfExists(old.get(i));}
    return css;
  }
  private static long modified(Path p){try{return Files.getLastModifiedTime(p).toMillis();}catch(IOException e){return 0;}}
  static String paletteStyle(Theme t,Settings s){Palette p=t.palette();String muted=s.components().highContrast()?p.text():p.muted();String actionText=contrast("#ffffff",p.accent())>=4.5?"#ffffff":"#101820";
    return "-fx-base:"+p.panel()+";-aegis-bg:"+p.background()+";-aegis-panel:"+p.panel()+";-aegis-control:"+p.control()+";-aegis-text:"+p.text()+";-aegis-muted:"+muted+";-aegis-accent:"+p.accent()+";-aegis-action:"+p.accent()+";-aegis-action-text:"+actionText+";-aegis-incoming:"+p.incoming()+";-aegis-outgoing:"+p.outgoing()+";-aegis-warning:"+(contrast(p.text(),"#101820")>4.5?"#f4ce81":"#744800")+";-fx-font-family: '"+s.typography().mail().family()+"';-fx-font-size:"+s.typography().mail().size()+"px;";
  }
  static String componentStyles(Theme t,Settings s){
    Components c=s.components();int radius=t.radius(),buttonRadius=c.buttons()==Shape.SQUARE?0:c.buttons()==Shape.CIRCLE?999:Math.max(5,radius);
    String panel=rgba(t.palette().panel(),c.opaque()||c.highContrast()||s.backdrop().mode()==Appearance.Background.IMAGE||!Platform.isSupported(ConditionalFeature.TRANSPARENT_WINDOW)?100:t.alpha());
    int padding=s.density()==UiPreferences.Density.COMPACT?4:s.density()==UiPreferences.Density.LARGE?12:8;int gap=c.spacing();
    String shadow=t.shadow()&&!c.highContrast()?"dropshadow(gaussian,rgba(0,0,0,0.16),8,0.1,0,2)":"null";
    return ".navigation{-fx-background-color:"+panel+";-fx-background-radius:"+radius+";-fx-spacing:"+gap+";}\n"+
      ".navigation .button{"+font(s.typography().navigation())+"-fx-padding:"+padding+" "+gap+";-fx-alignment:center-left;}\n"+
      ".heading,.brand,.mail-subject{"+font(s.typography().heading())+"}\n"+
      ".letter-body,.letter-body .content,.composer,.composer .content{"+font(s.typography().mail())+"}\n"+
      ".button{-fx-background-radius:"+buttonRadius+";-fx-border-radius:"+buttonRadius+";-fx-padding:"+(padding+2)+" "+(gap+4)+";}\n"+
      ".primary{-fx-background-color:-aegis-accent;-fx-text-fill:-aegis-action-text;-fx-font-weight:bold;}\n"+
      ".mail-card,.preset-tile,.settings-card,.system-letter,.letter-card{-fx-background-color:"+panel+";-fx-background-radius:"+radius+";-fx-border-radius:"+radius+";-fx-padding:"+(padding+gap)+";-fx-effect:"+shadow+";}\n"+
      ".mail-card:selected,.preset-tile:selected,.navigation .active{-fx-background-color:-aegis-control;}\n"+
      ".list-cell{-fx-padding:"+padding+" "+gap+";-fx-background-color:transparent;}\n"+
      ".list-cell:selected .mail-card{-fx-background-color:-aegis-control;}\n"+
      ".avatar{-fx-background-radius:"+(c.avatars()==Shape.SQUARE?0:c.avatars()==Shape.CIRCLE?999:Math.max(4,radius))+";}\n"+
      ".nav-icon{-fx-background-radius:"+(c.icons()==Shape.SQUARE?0:c.icons()==Shape.CIRCLE?999:Math.max(4,radius))+";-fx-padding:5;}\n"+
      ".nav-icon .glyph{-fx-stroke:-aegis-text;}\n"+
      ".security-warning{-fx-text-fill:-aegis-warning;-fx-font-weight:bold;}\n"+
      ".mail-folders{-fx-background-color:"+panel+";-fx-background-radius:"+radius+";-fx-padding:"+gap+";}\n"+
      ".preset-preview{-fx-background-radius:"+radius+";}\n"+
      ".muted{-fx-font-size:"+Math.max(11,s.typography().mail().size()-2)+"px;}\n"+
      ".in-window-content{-fx-padding:"+gap+" "+(gap+4)+";}\n";
  }
  private static String font(Type t){return "-fx-font-family:'"+t.family()+"';-fx-font-size:"+t.size()+"px;-fx-font-weight:"+(t.weight()==Weight.NORMAL?"normal":t.weight()==Weight.BOLD?"bold":"600")+";";}
  private static String rgba(String hex,int alpha){int n=Integer.parseInt(hex.substring(1),16);return "rgba("+((n>>16)&255)+","+((n>>8)&255)+","+(n&255)+","+(alpha/100.0)+")";}
  void workspace(Region region){
    Backdrop bg=active.backdrop();Paint fill=bg.mode()==Appearance.Background.GRADIENT?new LinearGradient(0,0,1,1,true,CycleMethod.NO_CYCLE,new Stop(0,Color.web(bg.color())),new Stop(1,Color.web(bg.gradient()))):Color.web(active.mode()==Mode.MANUAL?bg.color():theme.palette().background());
    if(bg.mode()!=Appearance.Background.IMAGE){image=null;imageId="";imageTicket++;region.setBackground(new javafx.scene.layout.Background(new BackgroundFill(fill,CornerRadii.EMPTY,javafx.geometry.Insets.EMPTY)));return;}
    if(image!=null&&imageId.equals(bg.image())){region.setBackground(new javafx.scene.layout.Background(List.of(new BackgroundFill(fill,CornerRadii.EMPTY,javafx.geometry.Insets.EMPTY)),List.of(new BackgroundImage(image,BackgroundRepeat.NO_REPEAT,BackgroundRepeat.NO_REPEAT,BackgroundPosition.CENTER,new BackgroundSize(100,100,true,true,false,true)))));return;}
    region.setBackground(new javafx.scene.layout.Background(new BackgroundFill(fill,CornerRadii.EMPTY,javafx.geometry.Insets.EMPTY)));
    if(imageId.equals(bg.image()))return;image=null;imageId=bg.image();long ticket=++imageTicket;String selected=imageId;
    imageWorker.execute(()->{try{byte[] bytes=AtomicFiles.read(store.imagePath(selected),BackgroundCodec.MAX_OUTPUT);Image decoded;try{decoded=new Image(new ByteArrayInputStream(bytes));if(decoded.isError()||decoded.getWidth()>BackgroundCodec.MAX_SIDE||decoded.getHeight()>BackgroundCodec.MAX_SIDE)throw new IOException("Background decode failed");}finally{Arrays.fill(bytes,(byte)0);}Platform.runLater(()->{if(ticket==imageTicket&&active.backdrop().image().equals(selected)){image=decoded;changed.run();}});}catch(IOException|RuntimeException broken){Platform.runLater(()->{if(ticket==imageTicket){active=active.backdrop(new Backdrop(Appearance.Background.SOLID,theme.palette().background(),theme.palette().panel(),""));image=null;imageId="";recovery="Фон повреждён. Используется однотонный фон.";changed.run();}});}});
  }
  @Override public void close(){clock.stop();imageTicket++;image=null;imageWorker.shutdownNow();}
}
