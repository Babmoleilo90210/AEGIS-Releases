package org.securemail.ui;

import java.util.*;
import java.util.function.Function;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.geometry.Insets;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;

/** A page in the existing scene. Never creates a Stage, Scene, native dialog or modal overlay. */
class InWindowDialog<R> {
  private static final Map<Stage,BorderPane> hosts=new WeakHashMap<>();
  private static final Map<Stage,List<InWindowDialog<?>>> pages=new WeakHashMap<>();
  private final DialogPane pane=new DialogPane();
  private final Label heading=new Label();
  private Stage owner;private BorderPane host;private Node previous;private BorderPane page;
  private Function<ButtonType,R> converter;private R result;private boolean showing,waiting;private Runnable hidden=()->{};
  static void bind(Stage owner,BorderPane host){hosts.put(owner,host);}
  static void closeAll(Stage owner){List<InWindowDialog<?>> stack=pages.get(owner);while(stack!=null&&!stack.isEmpty())stack.getLast().close();}
  private static Stage main(){return Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).map(w->(Stage)w).findFirst().orElseThrow(()->new IllegalStateException("Main window unavailable"));}
  private static BorderPane host(Stage owner){
    BorderPane found=hosts.get(owner);if(found!=null)return found;
    Parent root=owner.getScene().getRoot();if(root instanceof ScaledRoot scaled)root=scaled.content();
    if(root instanceof BorderPane border&&border.getTop() instanceof WindowChrome)found=border;
    else {found=new BorderPane(root);owner.getScene().setRoot(found);}
    hosts.put(owner,found);return found;
  }
  InWindowDialog(){pane.getStyleClass().add("in-window-content");}
  void initOwner(Window owner){if(!(owner instanceof Stage stage))throw new IllegalArgumentException("Main stage required");this.owner=stage;}
  void setTitle(String title){heading.setText(title);}
  void setHeaderText(String text){pane.setHeaderText(text);}
  void setContentText(String text){pane.setContentText(text);}
  DialogPane getDialogPane(){return pane;}
  void setResultConverter(Function<ButtonType,R> value){converter=value;}
  void onClose(Runnable action){hidden=action;}
  boolean isShowing(){return showing;}
  void show(){
    if(showing)return;if(owner==null)owner=main();host=host(owner);previous=host.getCenter();
    Button back=new Button("← Назад");back.setOnAction(e->close());heading.getStyleClass().add("heading");
    HBox bar=new HBox(12,back,heading);bar.setPadding(new Insets(12,16,12,16));
    ScrollPane scroll=new ScrollPane(pane);scroll.setFitToWidth(true);scroll.setFitToHeight(true);
    page=new BorderPane(scroll);page.setTop(bar);page.getStyleClass().add("in-window-page");
    for(ButtonType type:pane.getButtonTypes()){
      Node node=pane.lookupButton(type);if(node instanceof Button button)button.addEventHandler(ActionEvent.ACTION,e->{
        if(e.isConsumed())return;
        if(converter!=null)result=converter.apply(type);else { @SuppressWarnings("unchecked") R value=(R)type;result=value; }
        close();e.consume();
      });
    }
    showing=true;pages.computeIfAbsent(owner,k->new ArrayList<>()).add(this);host.setCenter(page);page.applyCss();page.layout();pane.requestFocus();
  }
  Optional<R> showAndWait(){
    show();if(!showing)return Optional.ofNullable(result);
    waiting=true;try{Platform.enterNestedEventLoop(this);}finally{waiting=false;}
    return Optional.ofNullable(result);
  }
  void close(){
    if(!showing)return;List<InWindowDialog<?>> stack=pages.get(owner);
    while(stack!=null&&!stack.isEmpty()&&stack.getLast()!=this)stack.getLast().close();
    if(stack!=null)stack.remove(this);showing=false;
    if(host.getCenter()==page)host.setCenter(previous);
    try{hidden.run();}finally{if(waiting)Platform.exitNestedEventLoop(this,null);}
  }
}
