package org.securemail.ui;

import java.nio.file.*;
import java.util.*;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.image.WritableImage;
import javafx.scene.input.*;
import javafx.scene.layout.*;
import javafx.scene.text.Font;
import javafx.stage.*;
import org.securemail.client.net.*;

/** Real JavaFX controls, local TTF loading and Cyrillic glyph checks; not native acceptance. */
public final class Stability120Smoke {
  public static void main(String[] args)throws Exception{
    Path profile=Files.createTempDirectory("AEGIS-120-UI-");System.setProperty("aegis.profile",profile.toString());Platform.startup(()->Platform.setImplicitExit(false));
    MessengerSmoke.fx(()->{
      ThemeManager themes=new ThemeManager();themes.initialize();BorderPane host=new BorderPane();host.setTop(new Label("АЕГИС"));
      Stage stage=new Stage();stage.setScene(new Scene(host,1024,768));InWindowDialog.bind(stage,host);themes.apply(host);stage.show();
      try{
        MessengerSmoke.check(BundledFonts.verified().values().stream().allMatch(Boolean::booleanValue)&&BundledFonts.verified().size()==5,"Incomplete licensed Cyrillic fonts");
        for(String family:BundledFonts.REQUIRED){
          MessengerSmoke.check(Font.font(family,16).getFamily().equals(family),"JavaFX silently substituted "+family);
          var settings=themes.settings().json();for(String role:List.of("navigation","heading","mail"))settings.getAsJsonObject("typography").getAsJsonObject(role).addProperty("family",family);
          themes.preview(org.securemail.client.appearance.Appearance.Settings.parse(settings));
          Label text=new Label("АЕГИС: Ёж, Щука, кириллица, Latin 123456789");host.setCenter(text);host.applyCss();host.layout();
          MessengerSmoke.check(text.getFont().getFamily().equals(family),"CSS Cyrillic font selection failed "+family);themes.cancelPreview();
        }
        ConnectionStatus status=new ConnectionStatus();ConnectionCard card=new ConnectionCard(()->{});host.setCenter(card);status.bootstrap(EmbeddedTor.Mode.DIRECT,10);card.update(status.snapshot());
        MessengerSmoke.check(card.lookupAll(".progress-bar").stream().filter(n->n instanceof ProgressBar p&&p.getProgress()==.1).count()==1,"Not real bootstrap progress");
        status.bootstrap(EmbeddedTor.Mode.SNOWFLAKE,73);card.update(status.snapshot());MessengerSmoke.check(status.snapshot().state()!=ConnectionStatus.State.FAILED,"Premature fallback failure");
        WritableImage image=new WritableImage(320,160);AvatarViewer.show(stage,themes,"raven",image);host.applyCss();host.layout();
        MessengerSmoke.check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Avatar created another Stage");
        Slider zoom=(Slider)host.lookupAll(".slider").stream().findFirst().orElseThrow();zoom.setValue(4);host.applyCss();host.layout();
        var pane=(DialogPane)host.lookupAll(".dialog-pane").stream().findFirst().orElseThrow();pane.fireEvent(new KeyEvent(KeyEvent.KEY_PRESSED,"","",KeyCode.ESCAPE,false,false,false,false));
        MessengerSmoke.check(host.getCenter()==card,"Escape did not restore main content");
        MessengerSmoke.check(ResponsiveGeometry.inset(640)>=8&&ResponsiveGeometry.inset(3840)<=24,"Unsafe responsive margins");
        MessengerSmoke.check(ResponsiveGeometry.spacing(3840,8)<=12,"Unbounded element growth");
        System.out.println("Stability120Smoke PASS: 5 actual JavaFX Cyrillic families, CSS preview/cancel, bootstrap card, in-window avatar zoom/Escape, bounded geometry. Physical DPI and native KDE/Windows11 NOT_RUN.");
      }finally{themes.close();stage.close();Platform.exit();}
      return null;
    });
  }
}
