package org.securemail.ui;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.image.*;
import javafx.scene.layout.*;
import javafx.scene.shape.Circle;
import java.util.*;
import org.securemail.client.storage.UiPreferences;

final class AvatarView {
  private AvatarView(){}
  static Node create(String nick,Map<String,Image> images,UiPreferences.Avatars size){
    if(size==UiPreferences.Avatars.OFF)return new Region();int pixels=size==UiPreferences.Avatars.SMALL?28:40;StackPane pane=new StackPane();pane.setMinSize(pixels,pixels);pane.setMaxSize(pixels,pixels);pane.getStyleClass().add("avatar");Image image=images.get(nick);
    if(image!=null){ImageView view=new ImageView(image);view.setFitWidth(pixels);view.setFitHeight(pixels);view.setClip(new Circle(pixels/2.0,pixels/2.0,pixels/2.0));pane.getChildren().add(view);}else{Label initial=new Label(nick.isBlank()?"?":nick.substring(0,1).toUpperCase(Locale.ROOT));initial.getStyleClass().add("avatar-initial");pane.getChildren().add(initial);}return pane;
  }
  static Node create(String nick,Map<String,Image> images,UiPreferences.Avatars size,org.securemail.client.appearance.Appearance.Components components){
    if(size==UiPreferences.Avatars.OFF)return new Region();int pixels=components.avatarSize();StackPane pane=new StackPane();pane.setMinSize(pixels,pixels);pane.setMaxSize(pixels,pixels);pane.getStyleClass().add("avatar");Image image=images.get(nick);
    if(image!=null){ImageView view=new ImageView(image);view.setFitWidth(pixels);view.setFitHeight(pixels);javafx.scene.shape.Shape clip;if(components.avatars()==org.securemail.client.appearance.Appearance.Shape.CIRCLE)clip=new Circle(pixels/2.0,pixels/2.0,pixels/2.0);else{var rectangle=new javafx.scene.shape.Rectangle(pixels,pixels);if(components.avatars()==org.securemail.client.appearance.Appearance.Shape.ROUNDED){rectangle.setArcWidth(pixels*.3);rectangle.setArcHeight(pixels*.3);}clip=rectangle;}view.setClip(clip);pane.getChildren().add(view);}else{Label initial=new Label(nick.isBlank()?"?":nick.substring(0,1).toUpperCase(Locale.ROOT));initial.getStyleClass().add("avatar-initial");pane.getChildren().add(initial);}return pane;
  }
}
