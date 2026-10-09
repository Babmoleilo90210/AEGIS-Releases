package org.securemail.ui;

import javafx.scene.Cursor;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.*;
import javafx.stage.*;

/** One application title bar, with local drag/resize and no second system close button. */
final class WindowChrome extends HBox {
  WindowChrome(Stage stage){
    getStyleClass().add("window-chrome");Label title=new Label("АЕГИС");Region drag=new Region();HBox.setHgrow(drag,Priority.ALWAYS);
    Button minimize=new Button("−"),maximize=new Button("□"),close=new Button("×");
    minimize.setAccessibleText("Свернуть");maximize.setAccessibleText("Развернуть");close.setAccessibleText("Закрыть");
    minimize.setOnAction(e->stage.setIconified(true));maximize.setOnAction(e->stage.setMaximized(!stage.isMaximized()));close.setOnAction(e->stage.fireEvent(new WindowEvent(stage,WindowEvent.WINDOW_CLOSE_REQUEST)));
    getChildren().addAll(title,drag,minimize,maximize,close);double[] origin=new double[2];
    for(var node:new javafx.scene.Node[]{title,drag}){
      node.setOnMousePressed(e->{origin[0]=e.getScreenX()-stage.getX();origin[1]=e.getScreenY()-stage.getY();});
      node.setOnMouseDragged(e->{if(!stage.isMaximized()){stage.setX(e.getScreenX()-origin[0]);stage.setY(e.getScreenY()-origin[1]);}});
      node.setOnMouseClicked(e->{if(e.getClickCount()==2)stage.setMaximized(!stage.isMaximized());});
    }
  }
  static void resize(Stage stage,Scene scene){
    double[] bounds=new double[6];int[] edge={0};
    scene.addEventFilter(MouseEvent.MOUSE_MOVED,e->{if(stage.isMaximized()){scene.setCursor(null);return;}int b=edge(e,scene);scene.setCursor(switch(b){case 1,2->Cursor.H_RESIZE;case 4,8->Cursor.V_RESIZE;case 5,10->Cursor.NW_RESIZE;case 6,9->Cursor.NE_RESIZE;default->null;});});
    scene.addEventFilter(MouseEvent.MOUSE_PRESSED,e->{edge[0]=stage.isMaximized()?0:edge(e,scene);if(edge[0]!=0){bounds[0]=e.getScreenX();bounds[1]=e.getScreenY();bounds[2]=stage.getX();bounds[3]=stage.getY();bounds[4]=stage.getWidth();bounds[5]=stage.getHeight();e.consume();}});
    scene.addEventFilter(MouseEvent.MOUSE_DRAGGED,e->{int b=edge[0];if(b==0)return;double dx=e.getScreenX()-bounds[0],dy=e.getScreenY()-bounds[1];
      if((b&1)!=0){double w=Math.max(stage.getMinWidth(),bounds[4]-dx);stage.setX(bounds[2]+bounds[4]-w);stage.setWidth(w);}if((b&2)!=0)stage.setWidth(Math.max(stage.getMinWidth(),bounds[4]+dx));
      if((b&4)!=0){double h=Math.max(stage.getMinHeight(),bounds[5]-dy);stage.setY(bounds[3]+bounds[5]-h);stage.setHeight(h);}if((b&8)!=0)stage.setHeight(Math.max(stage.getMinHeight(),bounds[5]+dy));e.consume();
    });scene.addEventFilter(MouseEvent.MOUSE_RELEASED,e->edge[0]=0);
  }
  private static int edge(MouseEvent event,Scene scene){return(event.getSceneX()<6?1:event.getSceneX()>scene.getWidth()-6?2:0)|(event.getSceneY()<6?4:event.getSceneY()>scene.getHeight()-6?8:0);}
}
