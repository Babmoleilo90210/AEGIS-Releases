package org.securemail.ui;

import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import org.securemail.client.appearance.Appearance;
import org.securemail.client.ecosystem.MailFilesystemBoundary600;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.Binary;

/** Actual archive saved-path regression. Headless JavaFX only, no native sandbox claim. */
public final class ArchiveBoundarySmoke600 {
  private static <T>T fx(Callable<T> action)throws Exception{var f=new CompletableFuture<T>();Platform.runLater(()->{try{f.complete(action.call());}catch(Throwable e){f.completeExceptionally(e);}});return f.get(30,TimeUnit.SECONDS);}
  private static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);}
  private static void settle(Stage stage){Object token=new Object();var pause=new javafx.animation.PauseTransition(javafx.util.Duration.millis(200));pause.setOnFinished(e->Platform.exitNestedEventLoop(token,null));pause.play();Platform.enterNestedEventLoop(token);stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();}
  private static void screenshot(Stage stage,Path out)throws Exception{var shot=stage.getScene().snapshot(null);var image=new java.awt.image.BufferedImage((int)shot.getWidth(),(int)shot.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);for(int y=0;y<image.getHeight();y++)for(int x=0;x<image.getWidth();x++)image.setRGB(x,y,shot.getPixelReader().getArgb(x,y));javax.imageio.ImageIO.write(image,"png",out.toFile());image.flush();}
  public static void main(String[]args)throws Exception {
    Path out=Path.of(args[0]).toAbsolutePath();Files.createDirectories(out);Path profile=Files.createTempDirectory("aegis-archive-boundary600-");System.setProperty("aegis.profile",profile.toString());
    Platform.startup(()->Platform.setImplicitExit(false));var local=new LocalStore(profile.resolve("mail"),"synthetic Mail vault password".toCharArray(),Clock.systemUTC(),1000000,8000000);
    Path unsafe=Path.of("/usr/aegis-private-archive-synthetic600");byte[] saved=Binary.encode(data->{data.writeInt(1);Binary.text(data,unsafe.toString());Binary.text(data,"LIST");Binary.text(data,"DATE");data.writeDouble(.18);data.writeDouble(.58);});local.writeArchivePreferences(saved);
    ThemeManager themes=fx(ThemeManager::new);BorderPane root=fx(BorderPane::new);Stage stage=fx(()->{Stage s=new Stage();s.setScene(new Scene(root,800,600));s.getScene().getStylesheets().add(Objects.requireNonNull(ArchiveView.class.getResource("messenger.css")).toExternalForm());themes.initialize();themes.apply(root);themes.workspace(root);themes.track(s.getScene());s.show();return s;});
    ArchiveView archive=fx(()->{var a=new ArchiveView(stage,themes,local,MailFilesystemBoundary600::requireArchive);root.setCenter(a.node());return a;});int[] checks={0};ArchiveView[] malformed={null};
    try{
      for(String theme:List.of("minimal-dark","classic-light"))for(int percent:new int[]{100,200})fx(()->{var settings=themes.settings().manual(theme).json();settings.addProperty("scale",percent);themes.commit(Appearance.Settings.parse(settings));settle(stage);check(root.lookup("#archive-path-blocked")!=null,"Unsafe saved path fell back to a different archive");checks[0]++;check(root.lookupAll(".password-field").isEmpty(),"Password requested for exposed archive");checks[0]++;check(!archive.unlocked(),"Unsafe archive opened");checks[0]++;check(archive.location().equals(unsafe),"Saved path silently replaced");checks[0]++;screenshot(stage,out.resolve("archive-blocked-"+theme+"-"+percent+".png"));return null;});
      check(Arrays.equals(saved,local.readArchivePreferences()),"Unsafe preferences were overwritten");checks[0]++;check(!Files.exists(unsafe),"Unsafe destination created");checks[0]++;
      fx(()->{archive.close();return null;});check(archive.awaitClosed(10),"Archive worker did not close");
      byte[] broken=Binary.encode(data->{data.writeInt(1);Binary.text(data,"relative/cross-platform-path");Binary.text(data,"LIST");Binary.text(data,"DATE");data.writeDouble(.18);data.writeDouble(.58);});local.writeArchivePreferences(broken);
      fx(()->{malformed[0]=new ArchiveView(stage,themes,local,MailFilesystemBoundary600::requireArchive);root.setCenter(malformed[0].node());root.applyCss();root.layout();check(root.lookup("#archive-path-blocked")!=null,"Malformed saved path silently fell back");checks[0]++;check(root.lookupAll(".password-field").isEmpty(),"Password shown after invalid saved prefs");checks[0]++;malformed[0].close();return null;});check(malformed[0].awaitClosed(10),"Malformed archive worker did not close");check(Arrays.equals(broken,local.readArchivePreferences()),"Malformed saved preferences overwritten");checks[0]++;
      Files.writeString(out.resolve("RESULTS.json"),new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(Map.of("status","PASS_HEADLESS","nativeAcceptance","NOT_RUN","checks",checks[0],"screenshots",4,"scope","Actual encrypted LocalStore archive preferences and JavaFX blocked page: exposed saved path retained without opening, password UI, fallback, creation or preference overwrite.")));
      System.out.println("PASS_HEADLESS: "+checks[0]+" actual archive saved-path guards; four actual JavaFX screenshots; malformed cross-platform prefs preserved");
    }finally{fx(()->{archive.close();if(malformed[0]!=null)malformed[0].close();themes.close();stage.close();Platform.exit();return null;});local.close();Arrays.fill(saved,(byte)0);}
  }
}
