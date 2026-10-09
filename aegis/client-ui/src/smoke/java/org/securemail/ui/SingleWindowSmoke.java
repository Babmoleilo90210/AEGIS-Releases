package org.securemail.ui;

import java.nio.file.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;

/** Real JavaFX navigation, nested file/password pages, cancellation and shutdown in one Stage. */
public final class SingleWindowSmoke {
  static Stage stage;static BorderPane frame;static ThemeManager theme;static TextArea draft;
  static void one(){MessengerSmoke.check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Another application window opened");MessengerSmoke.check(stage.getScene().getRoot().lookupAll(".window-chrome").size()==1,"Duplicate window controls");}
  static Button button(String label){return (Button)frame.lookupAll(".button").stream().filter(n->n instanceof Button b&&b.isVisible()&&b.getText().equals(label)).findFirst().orElseThrow();}
  public static void main(String[] args)throws Exception {
    System.setProperty("aegis.profile",Files.createTempDirectory("AEGIS single window ").toString());
    CompletableFuture<Void> started=new CompletableFuture<>();Platform.startup(()->{Platform.setImplicitExit(false);started.complete(null);});started.get(10,TimeUnit.SECONDS);
    MessengerSmoke.fx(()->{stage=new Stage();stage.initStyle(StageStyle.UNDECORATED);draft=new TextArea("Сохранённый черновик");frame=new BorderPane(draft);frame.setTop(new WindowChrome(stage));stage.setScene(new Scene(frame,1000,720));theme=new ThemeManager();theme.apply(frame);theme.track(stage.getScene());InWindowDialog.bind(stage,frame);stage.show();return null;});
    try {
      MessengerSmoke.fx(()->{
        InWindowDialog<Void> settings=new InWindowDialog<>();settings.initOwner(stage);settings.setTitle("Настройки");settings.getDialogPane().setContent(new Label("Внешний вид"));settings.show();one();
        InWindowDialog<Void> appearance=new InWindowDialog<>();appearance.initOwner(stage);appearance.setTitle("Внешний вид");Button component=new Button("Компонент");appearance.getDialogPane().setContent(component);appearance.show();one();
        theme.layout(new org.securemail.client.storage.UiPreferences(150,org.securemail.client.storage.UiPreferences.Density.COMPACT,false,org.securemail.client.storage.UiPreferences.Avatars.SMALL,org.securemail.client.storage.UiPreferences.Preview.RIGHT,true,true));frame.getScene().getRoot().applyCss();frame.getScene().getRoot().layout();MessengerSmoke.check(Math.abs(component.getLocalToSceneTransform().getMxx()-1.5)<.001,"Internal page did not scale");
        Platform.runLater(()->{one();((PasswordField)frame.lookup(".password-field")).setText("synthetic-password");button("OK").fire();});
        InWindowDialog<char[]> secret=new InWindowDialog<>();secret.initOwner(stage);PasswordField field=new PasswordField();secret.getDialogPane().setContent(field);secret.getDialogPane().getButtonTypes().addAll(ButtonType.OK,ButtonType.CANCEL);secret.setResultConverter(b->b==ButtonType.OK?field.getText().toCharArray():null);
        char[] value=secret.showAndWait().orElseThrow();MessengerSmoke.check(new String(value).equals("synthetic-password"),"In-window password result lost");java.util.Arrays.fill(value,'\0');field.clear();one();
        Platform.runLater(()->{one();button("← Назад").fire();});MessengerSmoke.check(new InWindowFileChooser().showOpenDialog(stage)==null,"Cancelled picker returned a file");one();
        InWindowDialog<Void> child=new InWindowDialog<>();child.initOwner(stage);child.show();settings.close();MessengerSmoke.check(!child.isShowing()&&!appearance.isShowing(),"Closing a parent left orphan pages");MessengerSmoke.check(frame.getCenter()==draft,"Did not restore original editor");MessengerSmoke.check(draft.getText().equals("Сохранённый черновик"),"Page navigation lost draft");one();
        InWindowDialog<Void> ending=new InWindowDialog<>();ending.initOwner(stage);ending.show();InWindowDialog.closeAll(stage);MessengerSmoke.check(frame.getCenter()==draft&&!ending.isShowing(),"Shutdown left a page active");return null;
      });
      System.out.println("Single-window PASS: settings, appearance, password, file picker, nested navigation, scaling, parent cancellation, preserved draft, one Stage and one title bar.");
    }finally{MessengerSmoke.fx(()->{InWindowDialog.closeAll(stage);stage.close();Platform.exit();return null;});}
  }
}
