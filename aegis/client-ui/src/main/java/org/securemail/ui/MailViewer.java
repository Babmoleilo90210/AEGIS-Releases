package org.securemail.ui;
import javafx.application.Platform;
import javafx.animation.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import javafx.geometry.Insets;
import javafx.util.Duration;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.function.LongSupplier;
import javax.crypto.AEADBadTagException;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.LocalStore;

/** Memory-only view: sender and recipient follow identical secret entry steps. */
final class MailViewer implements AutoCloseable {
  interface Actions{
    void reply(LocalStore.HistoryItem item,PlainMessage plain);
    void forward(LocalStore.HistoryItem item,PlainMessage plain,String body,PlainMessage.FileBundle files);
    void original(MailContext reference);
    boolean unknown();
  }
  private final Stage stage=new Stage();
  private final PlainMessage plain;
  private final TextArea text=new TextArea();
  private final PasswordField password=new PasswordField();
  private final SecretField code=new SecretField("Код второго слоя");
  private final VBox content=new VBox(12);
  private final Label error=new Label();
  private final Timeline timer;
  private LetterEnvelope.Opened opened;
  private LiveCode live;
  private volatile boolean closed;
  private char[] archivePassword;private boolean exporting;private Button download;
  private VBox host;
  MailViewer(Stage owner,ThemeManager themes,PlainMessage plain,LocalStore.HistoryItem item,ExecutorService worker,LongSupplier now) {
    this(owner,themes,plain,item,worker,now,null);
  }
  MailViewer(Stage owner,ThemeManager themes,PlainMessage plain,LocalStore.HistoryItem item,ExecutorService worker,LongSupplier now,VBox host) {
    this(owner,themes,plain,item,worker,now,host,null);
  }
  MailViewer(Stage owner,ThemeManager themes,PlainMessage plain,LocalStore.HistoryItem item,ExecutorService worker,LongSupplier now,VBox host,Actions actions) {
    this.host=host;
    this.plain=plain;stage.initOwner(owner);stage.setTitle(plain.subject().isBlank()?"Письмо":plain.subject());
    stage.getIcons().setAll(owner.getIcons());stage.setMinWidth(520);stage.setMinHeight(400);content.setPadding(new Insets(22));
    Label heading=new Label(plain.subject().isBlank()?"Без темы":plain.subject());heading.getStyleClass().add("brand");
    Label lifetime=new Label();lifetime.getStyleClass().add("muted");
    text.setEditable(false);text.setWrapText(true);text.setPrefRowCount(16);VBox.setVgrow(text,Priority.ALWAYS);
    content.getChildren().addAll(heading,new Label((item.outgoing()?"Кому: ":"От: ")+item.contact()),lifetime);
    if(actions!=null){
      Label verification=new Label("Подпись проверена · "+(actions.unknown()?"Неизвестный отправитель":"Из контактов"));verification.getStyleClass().add("muted");content.getChildren().add(verification);
      if(plain.context()!=null){var reference=plain.context();Button original=new Button((reference.forwarded()?"Переслано: ":"Ответ на: ")+reference.author()+" · "+reference.subject());original.setTooltip(new Tooltip("Ссылка автора письма; исходное письмо проверяется на этом устройстве"));original.setOnAction(e->actions.original(reference));content.getChildren().add(original);}
      Button reply=new Button("Ответить"),forward=new Button("Переслать"),copy=new Button("Копировать");
      reply.setOnAction(e->{if(!closed&&item.expiresAt()>now.getAsLong())actions.reply(item,plain);});
      forward.setOnAction(e->{
        if(closed||item.expiresAt()<=now.getAsLong())return;
        if(plain.protectedLetter()&&(opened==null||code.value().length==0||text.getText().isEmpty())){error.setText("Сначала откройте письмо");if(!content.getChildren().contains(error))content.getChildren().add(error);return;}
        Alert confirm=new Alert(Alert.AlertType.CONFIRMATION,"Переслать открытый текст новым письмом?",ButtonType.OK,ButtonType.CANCEL);confirm.initOwner(host==null?stage:owner);confirm.setHeaderText(null);themes.apply(confirm.getDialogPane());
        CheckBox files=new CheckBox("Включить вложения");if(!plain.files().isEmpty())confirm.getDialogPane().setContent(new VBox(10,new Label("Переслать это письмо выбранному получателю?"),files));
        if(confirm.showAndWait().orElse(ButtonType.CANCEL)==ButtonType.OK&&!closed&&item.expiresAt()>now.getAsLong())actions.forward(item,plain,text.getText(),files.isSelected()?plain.copyFiles():null);
      });
      copy.setOnAction(e->{if(!closed&&!text.getText().isEmpty()){var value=new javafx.scene.input.ClipboardContent();value.putString(text.getText());javafx.scene.input.Clipboard.getSystemClipboard().setContent(value);}});
      content.getChildren().add(new HBox(8,reply,forward,copy));
    }
    if(plain.protectedLetter()) {
      password.setPromptText("Пароль письма");Button unlock=new Button("Открыть");unlock.setDefaultButton(true);
      HBox row=new HBox(10,password,unlock);HBox.setHgrow(password,Priority.ALWAYS);content.getChildren().addAll(row,error);
      unlock.setOnAction(e->{
        char[] secret=password.getText().toCharArray();password.clear();byte[] envelope=plain.letterEnvelope();
        unlock.setDisable(true);unlock.setText("Открытие…");error.setText("");
        worker.execute(()->{
          try{
            var value=LetterEnvelope.open(envelope,secret);char[] held=secret.clone();
            Platform.runLater(()->{if(closed){value.close();Arrays.fill(held,'\0');return;}opened=value;archivePassword=held;if(download!=null)download.setDisable(false);content.getChildren().removeAll(row,error);content.getChildren().addAll(text,code);
              text.setText(value.ciphertext());live=new LiveCode(value::candidate,Platform::runLater,result->{if(!closed)text.setText(result);});
              code.hidden.textProperty().addListener((o,a,b)->{if(closed)return;text.clear();live.change(code.value(),value.ciphertext());});
            });
          }catch(Exception failure){Platform.runLater(()->{if(!closed)error.setText(failure instanceof AEADBadTagException?"Неверный пароль письма.":"Не удалось открыть письмо.");});}
          finally{Arrays.fill(secret,'\0');Arrays.fill(envelope,(byte)0);Platform.runLater(()->{unlock.setDisable(false);unlock.setText("Открыть");});}
        });
      });
    }else{content.getChildren().add(text);text.setText(plain.text());}
    if(!plain.files().isEmpty()){
      Selector<String> selectedFile=new Selector<>(themes,plain.files().stream().map(PlainMessage.FileInfo::name).toList(),plain.filename());if(!plain.protectedLetter()&&plain.files().size()>1)content.getChildren().add(selectedFile);
      content.getChildren().add(new Label("Вложения: "+plain.files().size()));download=new Button(plain.protectedLetter()?"Скачать вложения":"Сохранить "+plain.filename());download.setDisable(plain.protectedLetter());
      download.setOnAction(e->{
        if(closed||item.expiresAt()<=now.getAsLong()||exporting)return;
        if(actions!=null&&actions.unknown()){
          Alert confirm=new Alert(Alert.AlertType.CONFIRMATION,"Сохранить вложение неизвестного отправителя?",ButtonType.OK,ButtonType.CANCEL);confirm.initOwner(host==null?stage:owner);confirm.setHeaderText(null);themes.apply(confirm.getDialogPane());if(confirm.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK)return;
        }
        String chosen=selectedFile.getValue();FileChooser chooser=new FileChooser();chooser.setInitialFileName(plain.protectedLetter()?"AEGIS_Documents_"+java.time.LocalDate.now()+".zip":chosen);var file=chooser.showSaveDialog(host==null?stage:owner);
        if(file==null||closed||item.expiresAt()<=now.getAsLong())return;
        if(java.nio.file.Files.exists(file.toPath())){error.setText("Файл уже существует. Выберите другое имя.");if(!content.getChildren().contains(error))content.getChildren().add(error);return;}
        char[] secret=archivePassword==null?new char[0]:archivePassword.clone();exporting=true;download.setDisable(true);download.setText("Сохранение…");
        worker.execute(()->{try{
          if(plain.protectedLetter())plain.exportEncryptedZip(file.toPath(),secret,()->!closed&&item.expiresAt()>now.getAsLong());else plain.exportTo(file.toPath(),chosen);
          Platform.runLater(()->{if(!closed)download.setText("Сохранено");});
        }catch(Exception failure){Platform.runLater(()->{if(!closed){error.setText("Не удалось сохранить архив. Выберите новое имя и проверьте доступ к папке.");if(!content.getChildren().contains(error))content.getChildren().add(error);}});}
        finally{Arrays.fill(secret,'\0');Platform.runLater(()->{exporting=false;if(closed)plain.close();else{download.setDisable(false);download.setText(plain.protectedLetter()?"Скачать вложения":"Сохранить файл");}});}});
      });content.getChildren().add(download);
    }
    themes.apply(content);if(host==null){stage.initStyle(StageStyle.UNDECORATED);BorderPane window=new BorderPane(content);window.setTop(new WindowChrome(stage));themes.apply(window);Scene scene=new Scene(window,720,600);stage.setScene(scene);WindowChrome.resize(stage,scene);}else {host.getChildren().setAll(content);VBox.setVgrow(content,Priority.ALWAYS);}
    timer=new Timeline(new KeyFrame(Duration.seconds(1),e->{long left=item.expiresAt()-now.getAsLong();if(left<=0){close();return;}lifetime.setText("Удаление через "+java.time.Duration.ofMillis(left).toMinutes()+" мин");}));
    timer.setCycleCount(Animation.INDEFINITE);timer.play();stage.setOnHidden(e->close());if(item.expiresAt()>now.getAsLong()){if(host==null)stage.show();}else close();
  }
  boolean showing(){return !closed&&(host!=null||stage.isShowing());}
  @Override public void close(){
    if(closed)return;closed=true;timer.stop();if(live!=null)live.close();if(opened!=null)opened.close();
    password.clear();code.clear();text.clear();content.getChildren().clear();if(archivePassword!=null){Arrays.fill(archivePassword,'\0');archivePassword=null;}if(!exporting)plain.close();stage.close();
  }
}

