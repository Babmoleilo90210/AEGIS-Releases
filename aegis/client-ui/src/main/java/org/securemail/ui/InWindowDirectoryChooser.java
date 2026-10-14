package org.securemail.ui;

import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import java.nio.file.*;
import java.util.Comparator;

/** Local directory picker inside the existing window; no native dialog or new Stage. */
final class InWindowDirectoryChooser {
  Path choose(Stage owner,String title){InWindowDialog<Path>d=new InWindowDialog<>();d.initOwner(owner);d.setTitle(title);TextField path=new TextField(System.getProperty("user.home"));ListView<Path> dirs=new ListView<>();Label error=new Label();
    Runnable load=()->{try{Path p=Path.of(path.getText()).toAbsolutePath().normalize();if(Files.isSymbolicLink(p)||!Files.isDirectory(p))throw new java.io.IOException();try(var children=Files.list(p)){dirs.getItems().setAll(children.filter(f->Files.isDirectory(f,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(f)).sorted(Comparator.comparing(f->f.getFileName().toString())).limit(2000).toList());}error.setText("");}catch(Exception invalid){error.setText("Выберите доступную папку");}};
    dirs.setCellFactory(v->new ListCell<>(){protected void updateItem(Path p,boolean empty){super.updateItem(p,empty);setText(empty||p==null?null:"▸ "+p.getFileName());}});dirs.setOnMouseClicked(e->{if(e.getClickCount()==2&&dirs.getSelectionModel().getSelectedItem()!=null){path.setText(dirs.getSelectionModel().getSelectedItem().toString());load.run();}});path.setOnAction(e->load.run());Button up=new Button("Выше");up.setOnAction(e->{Path parent=Path.of(path.getText()).toAbsolutePath().getParent();if(parent!=null){path.setText(parent.toString());load.run();}});
    d.getDialogPane().setContent(new VBox(10,new HBox(8,path,up),dirs,error));d.getDialogPane().getButtonTypes().addAll(ButtonType.OK,ButtonType.CANCEL);d.setResultConverter(b->{if(b!=ButtonType.OK)return null;Path p=Path.of(path.getText()).toAbsolutePath().normalize();return Files.isDirectory(p)&&!Files.isSymbolicLink(p)?p:null;});load.run();return d.showAndWait().orElse(null);
  }
}
