package org.securemail.ui;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.control.skin.ComboBoxListViewSkin;
import javafx.scene.layout.*;
import javafx.scene.transform.Scale;
import javafx.stage.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
/** Real JavaFX popup tests; transforms are not a substitute for Windows DPI or Wayland acceptance. */
public final class PickerSmoke {
 public static void main(String[] args)throws Exception{
  System.setProperty("aegis.profile",Files.createTempDirectory("aegis-picker-smoke").toString());CompletableFuture<Void> ready=new CompletableFuture<>();Platform.startup(()->{Platform.setImplicitExit(false);ready.complete(null);});ready.get();
  Path out=Path.of("build/picker-smoke").toAbsolutePath();Files.createDirectories(out);
  try{
   for(double scale:new double[]{1,1.25,1.5,1.75,2})for(ThemeManager.Theme theme:ThemeManager.Theme.values())MessengerSmoke.fx(()->{
    ThemeManager manager=new ThemeManager();manager.select(theme);ContactPicker picker=new ContactPicker(List.of("arthas","raven","blackfox","wolf","contact01","contact02","contact03","contact04","contact05","contact06"),manager);
    Selector<String> ttl=new Selector<>(manager);ttl.getItems().setAll("5 минут","30 минут","1 час","6 часов","1 день","3 дня","7 дней");ttl.setValue("30 минут");ttl.setVisibleRowCount(7);ttl.setPrefWidth(180);
    Button send=new Button("Зашифровать и отправить");VBox content=new VBox(12,new Label("Кому"),picker,new Label("Хранить:"),ttl,new TextField("Тема"),new TextArea("Текст письма"),new SecretField("Пароль письма"),new SecretField("Код второго слоя"),send);content.setPrefWidth(500);content.setPadding(new Insets(12));content.getTransforms().add(new Scale(scale,scale,0,0));manager.apply(content);
    Stage stage=new Stage();stage.setScene(new Scene(new Group(content),1100,820));stage.show();content.applyCss();content.layout();
    picker.show();Parent popup=(Parent)((ComboBoxListViewSkin<?>)picker.getSkin()).getPopupContent();popup.applyCss();popup.layout();MessengerSmoke.check(popup.getScene().getWindow().isShowing(),"Contact popup hidden");MessengerSmoke.check(picker.getItems().size()==10&&picker.getVisibleRowCount()==8,"Contact scrolling unavailable");
    picker.hide();picker.getEditor().setText("rav");MessengerSmoke.check(picker.getItems().equals(List.of("raven")),"Search failed");picker.getSelectionModel().selectFirst();MessengerSmoke.check(picker.getEditor().getText().equals("raven"),"Contact selection failed");picker.hide();picker.getEditor().clear();picker.getSelectionModel().clearSelection();picker.show();Parent keyPopup=(Parent)((ComboBoxListViewSkin<?>)picker.getSkin()).getPopupContent();
    javafx.event.Event.fireEvent(keyPopup,new javafx.scene.input.KeyEvent(javafx.scene.input.KeyEvent.KEY_PRESSED,"","",javafx.scene.input.KeyCode.DOWN,false,false,false,false));MessengerSmoke.check(picker.getSelectionModel().getSelectedIndex()>=0,"Keyboard contact selection failed");picker.hide();
    ttl.show();Parent ttlPopup=(Parent)((ComboBoxListViewSkin<?>)ttl.getSkin()).getPopupContent();ttlPopup.applyCss();ttlPopup.layout();Bounds popupBounds=ttlPopup.localToScreen(ttlPopup.getBoundsInLocal()),sendBounds=send.localToScreen(send.getBoundsInLocal());MessengerSmoke.check(!popupBounds.intersects(sendBounds),"TTL popup covers send");
    MessengerSmoke.snapshot(stage,out.resolve("compose-"+scale+"-"+theme.name()+".png"));ttl.hide();stage.close();return null;
   });
   System.out.println("JavaFX native contact and unified TTL popups passed: 10 contacts, search, selection, scroll, five themes and 100/125/150/175/200% scene transforms. Native Windows DPI, X11 and Wayland are not covered.");
  }finally{Platform.exit();}
 }
}
