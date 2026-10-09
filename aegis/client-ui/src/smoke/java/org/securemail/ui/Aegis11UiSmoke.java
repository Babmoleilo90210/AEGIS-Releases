package org.securemail.ui;

import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.*;
import org.securemail.client.storage.*;
import org.securemail.client.update.*;

/** Actual JavaFX scene graph regression; no claim about native Windows DPI or KDE. */
public final class Aegis11UiSmoke {
  static void invoke(Object app,String name,Class<?>[] types,Object...args)throws Exception{var m=app.getClass().getDeclaredMethod(name,types);m.setAccessible(true);m.invoke(app,args);}
  public static void main(String[] args)throws Exception{
    Path profile=Files.createTempDirectory("aegis11-ui-");System.setProperty("aegis.profile",profile.toString());
    CompletableFuture<Void> ready=new CompletableFuture<>();Platform.startup(()->{Platform.setImplicitExit(false);ready.complete(null);});ready.get(10,TimeUnit.SECONDS);
    var config=ClientConfig.load(profile.resolve("config/client.properties"));var session=new ClientSession(config,"ui-test-vault-password".toCharArray());session.local().bindNickname("raven");
    var app=MessengerSmoke.fx(MessengerApp::new);
    Stage stage=MessengerSmoke.fx(()->{
      Stage window=new Stage();window.initStyle(StageStyle.UNDECORATED);BorderPane root=new BorderPane();BorderPane outer=new BorderPane(root);outer.setTop(new WindowChrome(window));window.setScene(new Scene(outer,1200,900));window.show();
      MessengerSmoke.set(app,"stage",window);MessengerSmoke.set(app,"root",root);MessengerSmoke.set(app,"config",config);MessengerSmoke.set(app,"session",session);MessengerSmoke.set(app,"presets",new UiPresetStore(profile));MessengerSmoke.set(app,"updates",new UpdateService(profile,19052));MessengerSmoke.set(app,"updatePreferences",UpdatePreferences.load(profile));
      ThemeManager theme=(ThemeManager)MessengerSmoke.get(app,"themes");theme.apply(outer);theme.apply(root);theme.track(window.getScene());app.mainPage();app.composePage();return window;
    });
    try{
      Path attachment=profile.resolve("fixture.txt");Files.writeString(attachment,"local fixture");
      MessengerSmoke.fx(()->{((TextArea)MessengerSmoke.get(app,"composer")).setText("Черновик после смены оформления");((TextField)MessengerSmoke.get(app,"subjectField")).setText("Сохранённая тема");((TextField)MessengerSmoke.get(app,"recipientField")).setText("blackfox");((CheckBox)MessengerSmoke.get(app,"additionalProtection")).setSelected(true);((SecretField)MessengerSmoke.get(app,"letterPassword")).hidden.setText("draft-password");((SecretField)MessengerSmoke.get(app,"secondCode")).hidden.setText("draft-FF1-code");@SuppressWarnings("unchecked") var files=(List<Path>)MessengerSmoke.get(app,"attachments");files.add(attachment);return null;});
      for(int scale:List.of(80,100,125,150,200))MessengerSmoke.fx(()->{
        var settings=new UiPreferences(scale,UiPreferences.Density.COMPACT,scale!=125,UiPreferences.Avatars.SMALL,UiPreferences.Preview.RIGHT,true,true);
        invoke(app,"applyLayout",new Class<?>[]{UiPreferences.class},settings);Parent root=stage.getScene().getRoot();root.applyCss();root.layout();
        MessengerSmoke.check(root instanceof ScaledRoot,"Main scene is not scaled");
        var composer=(TextArea)MessengerSmoke.get(app,"composer");var send=(Button)MessengerSmoke.get(app,"sendButton");
        MessengerSmoke.check(Math.abs(composer.getLocalToSceneTransform().getMxx()-scale/100.0)<.0001,"Composer geometry did not scale");MessengerSmoke.check(Math.abs(send.getLocalToSceneTransform().getMxx()-scale/100.0)<.0001,"Button geometry did not scale");
        MessengerSmoke.check(composer.getText().equals("Черновик после смены оформления"),"Appearance lost draft");MessengerSmoke.check(((SecretField)MessengerSmoke.get(app,"letterPassword")).hidden.getText().equals("draft-password"),"Appearance lost manual secret");MessengerSmoke.check(new UiPresetStore(profile).current().scale()==scale,"Scale was not persisted");return null;
      });
      MessengerSmoke.fx(()->{
        invoke(app,"profile",new Class<?>[]{});var root=(BorderPane)MessengerSmoke.get(app,"root");MessengerSmoke.check(root.getCenter()!=null,"Profile page is empty");root.applyCss();root.layout();
        MessengerSmoke.check(root.getCenter().lookupAll(".text-field").stream().anyMatch(n->n instanceof TextField f&&f.getText().equals("raven")&&!f.isEditable()),"Nickname is mutable or profile did not render");
        app.composePage();MessengerSmoke.check(((TextArea)MessengerSmoke.get(app,"composer")).getText().equals("Черновик после смены оформления"),"Navigation lost draft");MessengerSmoke.check(((TextField)MessengerSmoke.get(app,"subjectField")).getText().equals("Сохранённая тема"),"Navigation lost subject");MessengerSmoke.check(((List<?>)MessengerSmoke.get(app,"attachments")).contains(attachment),"Navigation lost attachments");
        ThemeManager theme=(ThemeManager)MessengerSmoke.get(app,"themes");Dialog<Void> dialog=new Dialog<>();dialog.initOwner(stage);dialog.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);dialog.getDialogPane().setContent(new Button("Fixture"));theme.apply(dialog.getDialogPane());dialog.show();theme.track(dialog.getDialogPane().getScene());
        MessengerSmoke.check(dialog.getDialogPane().getScene().getRoot() instanceof ScaledRoot,"Dialog scene is not scaled");MessengerSmoke.check(!dialog.getDialogPane().lookupButton(ButtonType.CLOSE).isManaged(),"Duplicate close button is visible");dialog.close();
        var chrome=stage.getScene().getRoot().lookupAll(".window-chrome");MessengerSmoke.check(chrome.size()==1,"Main window has duplicate title bars");
        invoke(app,"clearCompose",new Class<?>[]{boolean.class},false);MessengerSmoke.check(MessengerSmoke.get(app,"draft")==null,"Discarded draft survived logout/close");return null;
      });
      System.out.println("AEGIS 1.1 JavaFX PASS: whole scene geometry 80/100/125/150/200%, persisted scale, same draft and manual secrets, Profile content and immutable nickname, attachment preservation, scaled dialogs, one title bar and no duplicate close. Native DPI/KDE not tested.");
    }finally{MessengerSmoke.fx(()->{app.stop();return null;});}
  }
}
