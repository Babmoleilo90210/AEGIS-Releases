package org.securemail.ui;

import java.awt.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javafx.application.Platform;
import javafx.animation.PauseTransition;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import javafx.util.Duration;

/** Only fixed neutral text. Native tray is optional; unsupported desktops retain the in-app notice. */
final class NotificationCenter implements AutoCloseable {
  enum Kind {MAIL,FRIEND_MAIL,FRIEND_EVENT,UPDATE}
  private final Stage stage;private final BorderPane root;private final AtomicBoolean closed=new AtomicBoolean();
  private TrayIcon tray;private PauseTransition hide;private Kind current;
  NotificationCenter(Stage stage,BorderPane root){this.stage=stage;this.root=root;}
  void show(Kind kind){
    if(closed.get())return;if(current==Kind.FRIEND_MAIL&&kind==Kind.MAIL)return;current=kind;
    String text=switch(kind){case MAIL,FRIEND_MAIL->"Новое письмо";case FRIEND_EVENT->"Обновлён список друзей";case UPDATE->"Доступно обновление";};
    Label label=new Label(text);label.getStyleClass().add("neutral-notice");label.setStyle("-fx-padding:8 14;");root.setBottom(label);
    if(hide!=null)hide.stop();hide=new PauseTransition(Duration.seconds(kind==Kind.FRIEND_MAIL?8:4));hide.setOnFinished(e->{if(root.getBottom()==label)root.setBottom(null);current=null;});hide.play();
    EventQueue.invokeLater(()->{if(closed.get())return;try{if(!SystemTray.isSupported())return;if(tray==null){var icon=NotificationCenter.class.getResource("icons/icon-32.png");if(icon==null)return;tray=new TrayIcon(Toolkit.getDefaultToolkit().createImage(icon),"АЕГИС");tray.setImageAutoSize(true);tray.addActionListener(e->Platform.runLater(()->{if(!closed.get()){stage.show();stage.setIconified(false);stage.toFront();}}));SystemTray.getSystemTray().add(tray);}tray.displayMessage("АЕГИС",text,TrayIcon.MessageType.INFO);}catch(Exception|LinkageError unavailable){/* In-app notification remains available on Wayland and headless systems. */}});
  }
  public void close(){if(!closed.compareAndSet(false,true))return;if(hide!=null)hide.stop();EventQueue.invokeLater(()->{if(tray!=null)try{SystemTray.getSystemTray().remove(tray);}catch(Exception ignored){}});}
}
