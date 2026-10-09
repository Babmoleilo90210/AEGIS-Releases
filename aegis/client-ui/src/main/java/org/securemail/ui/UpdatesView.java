package org.securemail.ui;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import org.securemail.client.update.*;
import java.util.*;
import java.util.function.*;

/** UI maps to real updater states; the percent always comes from received byte count. */
final class UpdatesView {
  private final InWindowDialog<Void> dialog=new InWindowDialog<>();private final Label state=new Label(),bytes=new Label(),technical=new Label();private final ProgressBar progress=new ProgressBar();private final Button download=new Button("Скачать"),install=new Button("Обновить"),check=new Button("Проверить обновления"),notes=new Button("Что нового");
  UpdatesView(Stage owner,ThemeManager themes,UpdateService service,UpdatePreferences preferences,Consumer<UpdatePreferences> save,Runnable installAction){
    dialog.initOwner(owner);dialog.setTitle("Обновления");dialog.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
    Selector<String> channel=new Selector<>(themes,List.of("Stable","Beta"),preferences.channel().equals("stable")?"Stable":"Beta");
    CheckBox automatic=new CheckBox("Автоматически проверять обновления"),fetch=new CheckBox("Автоматически скачивать обновления"),exit=new CheckBox("Устанавливать при закрытии АЕГИС");automatic.setSelected(preferences.automaticCheck());fetch.setSelected(preferences.automaticDownload());exit.setSelected(preferences.installAtExit());
    Runnable persist=()->{try{save.accept(new UpdatePreferences(channel.getValue().toLowerCase(Locale.ROOT),automatic.isSelected(),fetch.isSelected(),exit.isSelected()));}catch(RuntimeException failure){state.setText("Не удалось изменить настройки во время операции");}};
    channel.valueProperty().addListener((o,a,b)->persist.run());automatic.setOnAction(e->persist.run());fetch.setOnAction(e->persist.run());exit.setOnAction(e->persist.run());check.setOnAction(e->service.check(fetch.isSelected()));download.setOnAction(e->service.download());install.setOnAction(e->{dialog.close();installAction.run();});
    notes.setOnAction(e->{var s=service.snapshot();if(s.manifest()!=null)notes(owner,themes,s.manifest());});Button cancel=new Button("Отменить скачивание");cancel.setOnAction(e->service.cancel());
    Button history=new Button("История");history.setOnAction(e->{try{ListView<String> items=new ListView<>();items.getItems().setAll(service.history().stream().map(m->m.version()+" · "+m.releaseNotes().publishedAt()+" · "+m.releaseNotes().type()+"\n"+m.announcement().summary()).toList());InWindowDialog<Void> view=new InWindowDialog<>();view.initOwner(owner);view.setTitle("История обновлений");view.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);view.getDialogPane().setContent(items);themes.apply(view.getDialogPane());view.showAndWait();}catch(Exception failure){state.setText("История недоступна");}});
    technical.setWrapText(true);TitledPane details=new TitledPane("Технические сведения",technical);details.setExpanded(false);progress.setMaxWidth(Double.MAX_VALUE);VBox box=new VBox(10,new Label("Текущая версия: "+SignedManifest.CURRENT),new HBox(10,new Label("Канал"),channel),automatic,fetch,exit,state,bytes,progress,new HBox(8,check,notes),new HBox(8,download,install,cancel),history,details);box.setPrefWidth(450);box.setPadding(new Insets(14));dialog.getDialogPane().setContent(box);themes.apply(dialog.getDialogPane());refresh(service.snapshot());
  }
  void refresh(UpdateService.Snapshot s){state.setText(s.message());technical.setText(s.diagnostic()==null?"Ошибка не зарегистрирована":s.diagnostic().technical());boolean fetching=s.state()==UpdateService.State.DOWNLOADING;boolean busy=Set.of(UpdateService.State.CHECKING,UpdateService.State.DOWNLOADING,UpdateService.State.VERIFYING,UpdateService.State.INSTALLING,UpdateService.State.RESTARTING).contains(s.state());check.setDisable(busy);download.setDisable(s.manifest()==null||busy||s.state()==UpdateService.State.READY_TO_INSTALL||s.state()==UpdateService.State.UP_TO_DATE);install.setDisable(s.state()!=UpdateService.State.READY_TO_INSTALL);notes.setDisable(s.manifest()==null);progress.setVisible(fetching);progress.setManaged(fetching);progress.setProgress(s.total()>0?Math.min(1,(double)s.downloaded()/s.total()):0);bytes.setText(fetching?String.format(Locale.ROOT,"%.1f MB / %.1f MB · %.0f%%",s.downloaded()/1048576.0,s.total()/1048576.0,s.total()>0?100.0*s.downloaded()/s.total():0):"");}
  void show(){dialog.show();}boolean showing(){return dialog.isShowing();}
  static void notes(Stage owner,ThemeManager themes,SignedManifest manifest){InWindowDialog<Void> d=new InWindowDialog<>();d.initOwner(owner);d.setTitle("Что нового · "+manifest.version());d.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);TextArea text=new TextArea(manifest.releaseNotes().text());text.setEditable(false);text.setWrapText(true);text.setPrefRowCount(14);d.getDialogPane().setContent(new VBox(10,new Label(manifest.announcement().title()),text));themes.apply(d.getDialogPane());d.showAndWait();}
}
