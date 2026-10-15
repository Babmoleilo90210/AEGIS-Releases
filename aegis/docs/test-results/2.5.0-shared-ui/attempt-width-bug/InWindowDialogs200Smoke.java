package org.securemail.ui;

import java.nio.file.*;
import java.util.*;
import javafx.geometry.Bounds;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.Text;
import javafx.stage.*;
import org.securemail.client.appearance.Appearance;

/** Actual shared dialog scrolling and actions; synthetic local fixture, no native/platform claim. */
public final class InWindowDialogs200Smoke {
    private static void check(boolean condition,String why){if(!condition)throw new AssertionError(why);}
    private static void layout(Stage stage){stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();}
    private static void visibleInsideScene(Node node,Stage stage){
        Bounds bounds=node.localToScene(node.getBoundsInLocal());check(bounds.getWidth()>10&&bounds.getHeight()>10,"Action has no visible size");
        check(bounds.getMinX()>=-.5&&bounds.getMaxX()<=stage.getScene().getWidth()+.5&&bounds.getMinY()>=-.5&&bounds.getMaxY()<=stage.getScene().getHeight()+.5,"Action outside Scene: "+bounds+" scene="+stage.getScene().getWidth()+"x"+stage.getScene().getHeight());
        for(Node ancestor=node;ancestor!=null;ancestor=ancestor.getParent())if(ancestor.getClip()!=null){Bounds clip=ancestor.localToScene(ancestor.getClip().getBoundsInParent());check(bounds.getMinX()>=clip.getMinX()-.5&&bounds.getMaxX()<=clip.getMaxX()+.5&&bounds.getMinY()>=clip.getMinY()-.5&&bounds.getMaxY()<=clip.getMaxY()+.5,"Action clipped by scrolling ancestor");}
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Files.createTempDirectory("AEGIS-shared-dialog-fixture-");System.setProperty("aegis.profile",fixture.resolve("profile").toString());System.setProperty("user.home",fixture.toString());
        java.util.concurrent.CompletableFuture<Void> started=new java.util.concurrent.CompletableFuture<>();javafx.application.Platform.startup(()->{javafx.application.Platform.setImplicitExit(false);started.complete(null);});started.get();
        ThemeManager themes=MessengerSmoke.fx(ThemeManager::new);BorderPane[] host={null};TextArea[] draft={null};
        Stage stage=MessengerSmoke.fx(()->{Stage w=new Stage();w.initStyle(StageStyle.UNDECORATED);draft[0]=new TextArea("Синтетический сохранённый черновик");host[0]=new BorderPane(draft[0]);host[0].setTop(new WindowChrome(w));w.setScene(new Scene(host[0],800,600));InWindowDialog.bind(w,host[0]);themes.initialize();themes.apply(host[0]);themes.track(w.getScene());w.show();return w;});
        Path output=Path.of("build/shared-dialog250-screenshots");Files.createDirectories(output);
        try{
            for(String palette:List.of("minimal-dark","classic-light"))for(int percent:new int[]{100,125,150,200}){
                InWindowDialog<String> dialog=MessengerSmoke.fx(()->{
                    var json=themes.settings().manual(palette).json();json.addProperty("scale",percent);themes.commit(Appearance.Settings.parse(json));
                    InWindowDialog<String> d=new InWindowDialog<>();d.initOwner(stage);d.setTitle("Проверка длинного русского заголовка встроенного окна");VBox content=new VBox(8);for(int n=0;n<24;n++){Label label=new Label("Синтетическая строка "+n+": содержимое остаётся доступным при прокрутке.");label.setWrapText(true);content.getChildren().add(label);}content.setMinWidth(0);d.getDialogPane().setContent(content);d.getDialogPane().getButtonTypes().addAll(ButtonType.OK,ButtonType.CANCEL);d.setResultConverter(b->b==ButtonType.OK?"accepted":"cancelled");themes.apply(d.getDialogPane());d.show();layout(stage);return d;
                });
                MessengerSmoke.fx(()->{ScrollPane scroll=(ScrollPane)((BorderPane)host[0].getCenter()).getCenter();scroll.setVvalue(1);layout(stage);return null;});Thread.sleep(50);
                MessengerSmoke.fx(()->{
                    layout(stage);Button ok=(Button)dialog.getDialogPane().lookupButton(ButtonType.OK),cancel=(Button)dialog.getDialogPane().lookupButton(ButtonType.CANCEL);
                    System.out.println("dialog case "+palette+"/"+percent+" OK="+ok.localToScene(ok.getBoundsInLocal())+" CANCEL="+cancel.localToScene(cancel.getBoundsInLocal()));
                    MessengerSmoke.snapshot(stage,output.resolve("dialog-scroll-"+palette+"-"+percent+".png"));
                    check(ok.getText().equals("ОК")&&cancel.getText().equals("Отмена"),"Shared standard button labels are not Russian");
                    visibleInsideScene(ok,stage);visibleInsideScene(cancel,stage);for(Button b:List.of(ok,cancel)){Node text=b.lookup(".text");check(!(text instanceof Text rendered)||rendered.getText().equals(b.getText()),"Shared action caption ellipsized");}
                    check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Shared page opened a Stage");
                    MessengerSmoke.snapshot(stage,output.resolve("dialog-scroll-"+palette+"-"+percent+".png"));cancel.fire();check(!dialog.isShowing()&&host[0].getCenter()==draft[0],"Cancel failed to restore editor");check(draft[0].getText().equals("Синтетический сохранённый черновик"),"Cancel lost editor text");
                    InWindowDialog<Void> parent=new InWindowDialog<>();parent.initOwner(stage);parent.setTitle("Родительская страница");parent.show();InWindowDialog<Void> child=new InWindowDialog<>();child.initOwner(stage);child.setTitle("Вложенная страница");child.show();parent.close();check(!child.isShowing()&&!parent.isShowing()&&host[0].getCenter()==draft[0],"Parent close left orphan pages");return null;
                });
            }
            System.out.println("InWindowDialogs200Smoke PASS: actual800x600,100/125/150/200%,2themes, unclipped Russian OK/Cancel after shared scroll, preserved draft/nested cleanup/oneStage; native OS NOT_RUN");
        }finally{MessengerSmoke.fx(()->{InWindowDialog.closeAll(stage);themes.close();stage.close();javafx.application.Platform.exit();return null;});}
    }
}
