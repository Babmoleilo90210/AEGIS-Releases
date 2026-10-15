package org.securemail.ui;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.layout.*;
import javafx.scene.text.Text;
import javafx.stage.*;
import org.securemail.client.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.appearance.Appearance;
import org.securemail.client.storage.*;
import org.securemail.client.update.*;
import org.securemail.protocol.UserInfo;
import static org.securemail.ui.MessengerSmoke.*;

/** Actual JavaFX layout/scaling and signed cache display; not native OS or live Relay acceptance. */
public final class SettingsResponsive200Smoke {
  private static Object invoke(Object target,String name,Class<?>[] types,Object...args)throws Exception{var method=target.getClass().getDeclaredMethod(name,types);method.setAccessible(true);return method.invoke(target,args);}
  private static byte[] png(int color)throws Exception{var image=new BufferedImage(32,32,BufferedImage.TYPE_INT_RGB);for(int y=0;y<32;y++)for(int x=0;x<32;x++)image.setRGB(x,y,color);var bytes=new ByteArrayOutputStream();ImageIO.write(image,"png",bytes);image.flush();return AvatarCodec.normalize(bytes.toByteArray());}
  @SuppressWarnings("unchecked") private static Map<String,Image> avatars(MessengerApp app)throws Exception{return (Map<String,Image>)get(app,"avatarImages");}
  public static void main(String[] args)throws Exception{
    Path profile=Files.createTempDirectory("AEGIS-settings-200-");System.setProperty("aegis.profile",profile.toString());Platform.startup(()->Platform.setImplicitExit(false));
    ClientConfig config=ClientConfig.load(AppPaths.config());var session=new ClientSession(config,"settings responsive vault password".toCharArray());session.local().bindNickname("blackfox");MessengerApp app=fx(MessengerApp::new);
    Stage stage=fx(()->{Stage window=new Stage();window.initStyle(StageStyle.UNDECORATED);BorderPane root=new BorderPane(),outer=new BorderPane(root);outer.setTop(new WindowChrome(window));window.setScene(new Scene(outer,800,600));InWindowDialog.bind(window,outer);set(app,"stage",window);set(app,"root",root);set(app,"config",config);set(app,"session",session);set(app,"presets",new UiPresetStore(profile));set(app,"updates",new UpdateService(profile,19052));set(app,"updatePreferences",UpdatePreferences.load(profile));ThemeManager themes=(ThemeManager)get(app,"themes");themes.initialize();themes.apply(outer);themes.apply(root);themes.track(window.getScene());themes.workspace(root);window.show();app.mainPage();return window;});
    try{
      until(()->Math.abs(stage.getScene().getWidth()-800)<1&&Math.abs(stage.getScene().getHeight()-600)<1);
      for(String theme:List.of("minimal-dark","classic-light"))for(int scale:new int[]{100,125,150,200}){
        fx(()->{ThemeManager themes=(ThemeManager)get(app,"themes");var json=themes.settings().manual(theme).json();json.addProperty("scale",scale);themes.commit(Appearance.Settings.parse(json));invoke(app,"settings",new Class<?>[]{});return null;});
        // A separate FX turn allows the real ScrollPane skin and ScaledRoot to attach.
        fx(()->{Parent scene=stage.getScene().getRoot();scene.resize(800,600);scene.applyCss();scene.layout();ScrollPane scroll=(ScrollPane)scene.lookup("#settings-page");TilePane groups=(TilePane)scene.lookup("#settings-categories");Node content=scene.lookup("#settings-content");
          check(scroll!=null&&groups!=null&&content!=null,"Settings layout containers unavailable");check(groups.getChildren().size()==5,"Settings group count");check(groups.getStyleClass().contains("settings-card"),"Categories require a themed surface");
          check(groups.getWidth()<=scroll.getViewportBounds().getWidth()+1,"Settings groups overflow horizontally");check(content.localToScene(content.getBoundsInLocal()).getMinY()>=groups.localToScene(groups.getBoundsInLocal()).getMaxY(),"Settings content is beside menu");
          double height=-1;for(Node node:groups.getChildren()){ToggleButton category=(ToggleButton)node;check(category.isWrapText(),"Long Russian category cannot wrap");if(height<0)height=category.getHeight();check(Math.abs(height-category.getHeight())<1,"Unequal category button heights");for(Node label:category.lookupAll(".text"))if(label instanceof Text text)check(!text.getText().contains("…"),"Category label was truncated");}
          check(Math.abs(groups.getLocalToSceneTransform().getMxx()-scale/100.)<.001,"Test did not apply the real layout scale");
          Path folder=Path.of("build/ui200-screenshots");Files.createDirectories(folder);snapshot(stage,folder.resolve("settings-800x600-"+theme+"-"+scale+".png"));scroll.setVvalue(1);scene.layout();snapshot(stage,folder.resolve("settings-content-800x600-"+theme+"-"+scale+".png"));return null;});
      }
      var alice=Identity.create();session.local().trust(new UserInfo(alice.userId(),"alice",alice.publicKey(),null));byte[] red=png(0xaa2211),blue=png(0x2255bb);
      session.local().cacheProfile(alice.profile("alice",1,true,"Initial",red));fx(()->{avatars(app).put("alice",new Image(new ByteArrayInputStream(red)));return null;});session.local().cacheProfile(alice.profile("alice",2,true,"Updated",blue));fx(()->{invoke(app,"contactProfile",new Class<?>[]{String.class},"alice");return null;});
      until(()->{Image image=avatars(app).get("alice");return image!=null&&image.getPixelReader().getArgb(100,100)==0xff2255bb;});
      session.local().cacheProfile(alice.profile("alice",3,false,"",new byte[0]));fx(()->{invoke(app,"contactProfile",new Class<?>[]{String.class},"alice");return null;});until(()->!avatars(app).containsKey("alice"));
      fx(()->{check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Settings/profile created a second Stage");return null;});
      System.out.println("SettingsResponsive200Smoke PASS: real 800x600 layout at 100/125/150/200%, 2 themes, category wrapping/equal heights/content below/shared scrolling, offline signed avatar refresh/removal; native OS and live Relay NOT_RUN");
    }finally{fx(()->{app.stop();return null;});}
  }
}
