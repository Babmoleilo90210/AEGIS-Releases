package org.securemail.ui;

import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.image.*;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.*;
import javafx.stage.Stage;

/** Verified local/public image only. Never fetches a URL or offers avatar editing. */
final class AvatarViewer {
  private AvatarViewer(){}
  static Node profile(String nick,Image image,Runnable open){
    StackPane square=new StackPane();square.setMinSize(128,128);square.setMaxSize(128,128);square.getStyleClass().add("avatar");
    if(image==null){Label initial=new Label(nick.isBlank()?"?":nick.substring(0,1).toUpperCase(java.util.Locale.ROOT));initial.setStyle("-fx-font-size:38px;");square.getChildren().add(initial);return square;}
    ImageView view=new ImageView(image);view.setFitWidth(128);view.setFitHeight(128);view.setPreserveRatio(true);square.getChildren().add(view);
    Button button=new Button();button.getStyleClass().add("avatar-preview");button.setGraphic(square);button.setAccessibleText("Посмотреть аватар "+nick);button.setTooltip(new Tooltip("Посмотреть аватар"));button.setOnAction(e->open.run());return button;
  }
  static void show(Stage owner,ThemeManager themes,String nick,Image image){
    if(image==null||image.isError())return;
    InWindowDialog<Void> page=new InWindowDialog<>();page.initOwner(owner);page.setTitle("Аватар · "+nick);
    ImageView view=new ImageView(image);view.setPreserveRatio(true);view.setSmooth(true);
    Slider zoom=new Slider(.25,4,1);Label amount=new Label("100%");
    Runnable apply=()->{view.setFitWidth(400*zoom.getValue());view.setFitHeight(400*zoom.getValue());amount.setText(Math.round(zoom.getValue()*100)+"%");};
    zoom.valueProperty().addListener((o,a,b)->apply.run());apply.run();
    Button minus=new Button("−"),plus=new Button("+");minus.setAccessibleText("Уменьшить аватар");plus.setAccessibleText("Увеличить аватар");minus.setOnAction(e->zoom.setValue(Math.max(.25,zoom.getValue()-.25)));plus.setOnAction(e->zoom.setValue(Math.min(4,zoom.getValue()+.25)));
    ScrollPane scroll=new ScrollPane(new StackPane(view));scroll.setPannable(true);scroll.setPrefViewportHeight(420);scroll.setPrefViewportWidth(600);
    HBox controls=new HBox(10,minus,zoom,plus,amount);controls.setAlignment(Pos.CENTER);HBox.setHgrow(zoom,Priority.ALWAYS);
    VBox body=new VBox(12,scroll,controls);VBox.setVgrow(scroll,Priority.ALWAYS);page.getDialogPane().setContent(body);
    page.getDialogPane().addEventFilter(javafx.scene.input.KeyEvent.KEY_PRESSED,e->{if(e.getCode()==KeyCode.ESCAPE){page.close();e.consume();}});
    page.onClose(()->view.setImage(null));themes.apply(page.getDialogPane());page.show();
  }
}
