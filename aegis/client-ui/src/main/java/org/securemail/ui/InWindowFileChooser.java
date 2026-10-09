package org.securemail.ui;

import java.io.File;
import java.nio.file.*;
import java.util.*;
import javafx.collections.*;
import javafx.event.ActionEvent;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;

/** Manual local file selection inside the main window; no preview, extraction or native popup. */
final class InWindowFileChooser {
  private String title="Файлы",initialName="";
  private final ObservableList<FileChooser.ExtensionFilter> filters=FXCollections.observableArrayList();
  void setTitle(String title){this.title=title;}
  void setInitialFileName(String name){initialName=name;}
  ObservableList<FileChooser.ExtensionFilter> getExtensionFilters(){return filters;}
  File showOpenDialog(Window owner){var result=choose(owner,false,false);return result==null?null:result.getFirst();}
  List<File> showOpenMultipleDialog(Window owner){return choose(owner,false,true);}
  File showSaveDialog(Window owner){var result=choose(owner,true,false);return result==null?null:result.getFirst();}
  private List<File> choose(Window owner,boolean save,boolean multiple){
    InWindowDialog<List<File>> page=new InWindowDialog<>();page.initOwner(owner);page.setTitle(title);
    Path[] directory={Path.of(System.getProperty("user.home")).toAbsolutePath()};
    TextField path=new TextField(directory[0].toString()),name=new TextField(initialName);name.setPromptText("Имя файла");
    ListView<Path> list=new ListView<>();list.getSelectionModel().setSelectionMode(multiple?SelectionMode.MULTIPLE:SelectionMode.SINGLE);
    list.setCellFactory(v->new ListCell<>(){protected void updateItem(Path p,boolean empty){super.updateItem(p,empty);setText(empty||p==null?null:(Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS)?"▸ ":"")+p.getFileName());}});
    Label status=new Label();status.getStyleClass().add("muted");
    Runnable load=()->{try{
      Path selected=Path.of(path.getText()).toAbsolutePath().normalize();if(!Files.isDirectory(selected,LinkOption.NOFOLLOW_LINKS))throw new java.io.IOException();
      var entries=new ArrayList<Path>();try(var stream=Files.newDirectoryStream(selected)){for(Path p:stream){if(entries.size()>=2000)break;if(Files.isSymbolicLink(p))continue;if(Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS)||filters.isEmpty()||filters.stream().flatMap(f->f.getExtensions().stream()).anyMatch(g->p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(g.substring(1).toLowerCase(Locale.ROOT))))entries.add(p);}}
      entries.sort(Comparator.comparing((Path p)->!Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS)).thenComparing(p->p.getFileName().toString(),String.CASE_INSENSITIVE_ORDER));directory[0]=selected;path.setText(selected.toString());list.getItems().setAll(entries);status.setText(entries.size()==2000?"Показаны первые 2000 элементов":"");
    }catch(Exception invalid){status.setText("Не удалось открыть папку");}};
    Button go=new Button("Открыть папку"),up=new Button("↑");go.setOnAction(e->load.run());path.setOnAction(e->load.run());up.setOnAction(e->{Path parent=directory[0].getParent();if(parent!=null){path.setText(parent.toString());load.run();}});
    list.setOnMouseClicked(e->{Path chosen=list.getSelectionModel().getSelectedItem();if(chosen==null)return;if(Files.isDirectory(chosen,LinkOption.NOFOLLOW_LINKS)&&e.getClickCount()==2){path.setText(chosen.toString());load.run();}else if(save&&!Files.isDirectory(chosen,LinkOption.NOFOLLOW_LINKS))name.setText(chosen.getFileName().toString());});
    HBox location=new HBox(8,up,path,go);HBox.setHgrow(path,Priority.ALWAYS);VBox body=new VBox(10,location,list,status);if(save)body.getChildren().add(name);VBox.setVgrow(list,Priority.ALWAYS);body.setPrefHeight(450);page.getDialogPane().setContent(body);
    ButtonType select=new ButtonType(save?"Сохранить":"Выбрать",ButtonBar.ButtonData.OK_DONE);page.getDialogPane().getButtonTypes().addAll(select,ButtonType.CANCEL);
    var result=new java.util.concurrent.atomic.AtomicReference<List<File>>();
    page.getDialogPane().lookupButton(select).addEventFilter(ActionEvent.ACTION,e->{try{
      List<Path> chosen;if(save){String filename=name.getText();if(filename.isBlank()||filename.contains("/")||filename.contains("\\")||filename.equals(".")||filename.equals(".."))throw new IllegalArgumentException();Path file=directory[0].resolve(filename);if(Files.exists(file,LinkOption.NOFOLLOW_LINKS)){status.setText("Файл уже существует. Выберите новое имя.");e.consume();return;}chosen=List.of(file);}
      else {chosen=List.copyOf(list.getSelectionModel().getSelectedItems());if(chosen.isEmpty()||chosen.stream().anyMatch(p->!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)))throw new IllegalArgumentException();}
      result.set(chosen.stream().map(Path::toFile).toList());
    }catch(Exception invalid){status.setText(save?"Укажите корректное имя файла":"Выберите обычный файл");e.consume();}});
    page.setResultConverter(b->b==select?result.get():null);load.run();return page.showAndWait().orElse(null);
  }
}
