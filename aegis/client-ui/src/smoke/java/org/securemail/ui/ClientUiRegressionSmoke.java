package org.securemail.ui;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.control.skin.ComboBoxListViewSkin;
import javafx.scene.image.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.storage.*;
import org.securemail.client.update.*;

/** Headless JavaFX regression only. Does not claim native Windows DPI/Wayland or signed-network acceptance. */
public final class ClientUiRegressionSmoke {
 public static void main(String[] args)throws Exception {
  Path profile=Files.createTempDirectory("aegis-ui-regression");System.setProperty("aegis.profile",profile.toString());CompletableFuture<Void> started=new CompletableFuture<>();Platform.startup(()->{Platform.setImplicitExit(false);started.complete(null);});started.get();
  Path out=Path.of("build/client-ui-regression");Files.createDirectories(out);
  try{for(ThemeManager.Theme theme:ThemeManager.Theme.values())for(int scale:List.of(80,90,100,110,125,150,175,200))MessengerSmoke.fx(()->{
    ThemeManager manager=new ThemeManager();manager.select(theme);manager.layout(new UiPreferences(scale,UiPreferences.Density.COMPACT,true,UiPreferences.Avatars.SMALL,UiPreferences.Preview.RIGHT,true,true));
    List<Selector<?>> selectors=new ArrayList<>();selectors.add(new Selector<>(manager,List.of("5 минут","30 минут","1 час","6 часов","1 день","3 дня","7 дней"),"1 день"));selectors.add(new Selector<>(manager,List.of(ThemeManager.Theme.values()),theme));selectors.add(new Selector<>(manager,UiPreferences.builtins().keySet(),"Компактный"));selectors.add(new Selector<>(manager,List.of(80,90,100,110,125,150,175,200),scale));selectors.add(new Selector<>(manager,List.of(UiPreferences.Avatars.values()),UiPreferences.Avatars.SMALL));selectors.add(new Selector<>(manager,List.of(UiPreferences.Preview.values()),UiPreferences.Preview.RIGHT));selectors.add(new Selector<>(manager,List.of("Stable","Beta"),"Stable"));
    PasswordField secret=new PasswordField();secret.getStyleClass().add("secret-entry");secret.setText("legacy password visual fixture");VBox body=new VBox(8,new Label("Старый пароль хранилища"),secret);body.getChildren().addAll(selectors);Node avatar=AvatarView.create("raven",Map.of(),UiPreferences.Avatars.SMALL);body.getChildren().add(avatar);manager.apply(body);Stage stage=new Stage();stage.setScene(new Scene(body,500,700));stage.show();body.applyCss();body.layout();
    for(Selector<?> selector:selectors){double height=body.getHeight();selector.show();Parent popup=(Parent)((ComboBoxListViewSkin<?>)selector.getSkin()).getPopupContent();popup.applyCss();popup.layout();MessengerSmoke.check(popup.getScene().getWindow().isShowing(),"Unified selector popup not showing");MessengerSmoke.check(popup.getScene().getWindow()!=stage,"Popup shares layout window");MessengerSmoke.check(body.getHeight()==height,"Popup changed parent layout");MessengerSmoke.check(popup.getBoundsInLocal().getWidth()>80,"Popup width collapsed");selector.hide();}
    MessengerSmoke.check(avatar.lookup(".avatar-initial")!=null,"Avatar placeholder absent");MessengerSmoke.check(secret.getBorder()!=null&&!secret.getBorder().getStrokes().isEmpty(),"Legacy password border not visible");MessengerSmoke.snapshot(stage,out.resolve(theme.name()+"-"+scale+".png"));secret.clear();stage.close();manager.close();return null;
   });
   MessengerSmoke.fx(()->{ThemeManager manager=new ThemeManager();Stage stage=new Stage();stage.setScene(new Scene(new VBox(),500,600));stage.show();try(UpdateService service=new UpdateService(profile,19050)){
     UpdatesView view=new UpdatesView(stage,manager,service,UpdatePreferences.load(profile),p->{},()->{});view.show();SignedManifest manifest=new SignedManifest("1.1.2","stable","1.0.0","optional",new SignedManifest.Announcement("Test update","UI fixture",true),new SignedManifest.Notes("2026-10-08T00:00:00Z","Fix","Signed notes display fixture"),List.of(),null,null);
     view.refresh(new UpdateService.Snapshot(UpdateService.State.DOWNLOADING,34*1048576,72*1048576,manifest,false,"Скачивание обновления"));ProgressBar progress=(ProgressBar)MessengerSmoke.get(view,"progress");Label bytes=(Label)MessengerSmoke.get(view,"bytes");MessengerSmoke.check(Math.abs(progress.getProgress()-34.0/72)<.0001&&bytes.getText().contains("47%"),"Progress is not actual byte percentage");Button install=(Button)MessengerSmoke.get(view,"action");MessengerSmoke.check(install.isDisable(),"Install enabled before verification");view.refresh(new UpdateService.Snapshot(UpdateService.State.READY_TO_INSTALL,72,72,manifest,false,"Готово"));MessengerSmoke.check(install.getText().equals("Установить и перезапустить"),"Context action did not reach installation");MessengerSmoke.check(!install.isDisable(),"Verified ready state not mapped to install");InWindowDialog<?> dialog=(InWindowDialog<?>)MessengerSmoke.get(view,"dialog");dialog.close();}stage.close();return null;});
   System.out.println("Unified selector regression passed: 7 selector types × 6 themes × 8 UI scales; separate popup window, unchanged layout, avatar placeholder, visible legacy field. Update progress 34/72 MB=47%, verification-gated install. Native OS acceptance remains pending.");
  }finally{Platform.exit();}
 }
}
