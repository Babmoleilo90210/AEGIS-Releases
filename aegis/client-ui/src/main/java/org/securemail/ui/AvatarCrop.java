package org.securemail.ui;

import java.io.ByteArrayInputStream;
import java.util.*;
import javafx.geometry.Rectangle2D;
import javafx.scene.control.*;
import javafx.scene.image.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import org.securemail.client.storage.AvatarCodec;

/** Pixels stay in memory. The visible viewport and saved crop share the same coordinates. */
final class AvatarCrop {
  private AvatarCrop(){}
  static byte[] show(Stage owner,ThemeManager themes,byte[] preview)throws java.io.IOException{
    Image image=new Image(new ByteArrayInputStream(preview));if(image.isError())throw new java.io.IOException("Не удалось открыть изображение");
    InWindowDialog<byte[]> dialog=new InWindowDialog<>();dialog.initOwner(owner);dialog.setTitle("Обрезать аватар");
    ImageView view=new ImageView(image);view.setFitWidth(256);view.setFitHeight(256);
    Slider x=new Slider(0,1,.5),y=new Slider(0,1,.5),zoom=new Slider(1,4,1);
    Runnable redraw=()->{double side=Math.min(image.getWidth(),image.getHeight())/zoom.getValue();view.setViewport(new Rectangle2D((image.getWidth()-side)*x.getValue(),(image.getHeight()-side)*y.getValue(),side,side));};
    for(Slider slider:List.of(x,y,zoom))slider.valueProperty().addListener((o,a,b)->redraw.run());redraw.run();
    double[] drag=new double[4];view.setOnMousePressed(e->{drag[0]=e.getX();drag[1]=e.getY();drag[2]=x.getValue();drag[3]=y.getValue();});
    view.setOnMouseDragged(e->{x.setValue(Math.max(0,Math.min(1,drag[2]-(e.getX()-drag[0])/256)));y.setValue(Math.max(0,Math.min(1,drag[3]-(e.getY()-drag[1])/256)));});
    var content=new VBox(10,view,new Label("Масштаб"),zoom,new Label("По горизонтали"),x,new Label("По вертикали"),y);content.setStyle("-fx-padding:16;");
    dialog.getDialogPane().setContent(content);dialog.getDialogPane().getButtonTypes().addAll(ButtonType.OK,ButtonType.CANCEL);themes.apply(dialog.getDialogPane());
    double[] chosen=new double[3];dialog.setResultConverter(button->{if(button!=ButtonType.OK)return null;chosen[0]=x.getValue();chosen[1]=y.getValue();chosen[2]=zoom.getValue();return new byte[0];});
    boolean confirmed=dialog.showAndWait().isPresent();view.setImage(null);content.getChildren().clear();
    return confirmed?AvatarCodec.crop(preview,chosen[0],chosen[1],chosen[2]):null;
  }
}
