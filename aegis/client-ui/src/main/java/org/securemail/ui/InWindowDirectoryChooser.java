package org.securemail.ui;

import javafx.application.Platform;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import java.nio.file.*;
import java.util.Comparator;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/** Directory browsing stays in the existing window; bounded I/O never blocks FX. */
final class InWindowDirectoryChooser {
  Path choose(Stage owner,String title){
    InWindowDialog<Path> dialog=new InWindowDialog<>();dialog.initOwner(owner);dialog.setTitle(title);
    TextField path=new TextField(System.getProperty("user.home"));ListView<Path> directories=new ListView<>();Label status=new Label();
    ExecutorService worker=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"aegis-directory-picker");t.setDaemon(true);return t;});AtomicLong generation=new AtomicLong();
    Runnable load=()->{
      Path selected;try{selected=Path.of(path.getText()).toAbsolutePath().normalize();}catch(InvalidPathException invalid){status.setText("Выберите доступную папку");return;}
      long ticket=generation.incrementAndGet();status.setText("Загрузка…");
      worker.execute(()->{try{
        if(Files.isSymbolicLink(selected)||!Files.isDirectory(selected))throw new java.io.IOException();
        java.util.List<Path> found;try(var files=Files.list(selected)){found=files.filter(f->Files.isDirectory(f,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(f)).limit(2000).sorted(Comparator.comparing(f->f.getFileName().toString())).toList();}
        Platform.runLater(()->{if(ticket==generation.get()){directories.getItems().setAll(found);status.setText(found.size()==2000?"Показаны первые 2000 папок":"");}});
      }catch(Exception invalid){Platform.runLater(()->{if(ticket==generation.get())status.setText("Выберите доступную папку");});}});
    };
    directories.setCellFactory(v->new ListCell<>(){protected void updateItem(Path p,boolean empty){super.updateItem(p,empty);setText(empty||p==null?null:"▸ "+p.getFileName());}});
    directories.setOnMouseClicked(e->{if(e.getClickCount()==2&&directories.getSelectionModel().getSelectedItem()!=null){path.setText(directories.getSelectionModel().getSelectedItem().toString());load.run();}});
    path.setOnAction(e->load.run());Button up=new Button("Выше");up.setOnAction(e->{try{Path parent=Path.of(path.getText()).toAbsolutePath().getParent();if(parent!=null){path.setText(parent.toString());load.run();}}catch(InvalidPathException invalid){status.setText("Выберите доступную папку");}});
    HBox address=new HBox(8,path,up);HBox.setHgrow(path,Priority.ALWAYS);dialog.getDialogPane().setContent(new VBox(10,address,directories,status));dialog.getDialogPane().getButtonTypes().addAll(ButtonType.OK,ButtonType.CANCEL);
    dialog.setResultConverter(b->{if(b!=ButtonType.OK)return null;try{Path p=Path.of(path.getText()).toAbsolutePath().normalize();return Files.isDirectory(p)&&!Files.isSymbolicLink(p)?p:null;}catch(InvalidPathException invalid){return null;}});
    load.run();try{return dialog.showAndWait().orElse(null);}finally{generation.incrementAndGet();worker.shutdownNow();}
  }
}
