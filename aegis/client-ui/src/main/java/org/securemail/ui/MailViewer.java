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
    default void displayed(){}
    default void prepareDisplay()throws Exception{}
    default void closed(boolean wasDisplayed){}
    default void abandonedDisplay(){}
    default void archive(LocalStore.HistoryItem item,PlainMessage plain,String displayedBody,Runnable finished){finished.run();}
    default long expiresAt(){return -1;}
  }
  private final Stage stage;private InWindowDialog<Void> page;
  private final PlainMessage plain;
  private final TextArea text=new TextArea();
  private final PasswordField password=new PasswordField();
  private final SecretField code=new SecretField("Код второго слоя");
  private final VBox content=new VBox(12);
  private final VBox metadata=new VBox(4);private HBox actionBar;private final Map<String,Button> actionButtons=new HashMap<>();
  private final Label error=new Label();
  private final Timeline timer;
  private LetterEnvelope.Opened opened;
  private LiveCode live;
  private volatile boolean closed;private boolean revealed,displayNotified;private long revealGeneration;private Actions lifecycleActions;private boolean displayScheduled,displayOffered;private PauseTransition displayPulse;
  private char[] archivePassword;private boolean exporting;private Button download;
  private VBox host;private java.util.function.LongSupplier expiry;
  MailViewer(Stage owner,ThemeManager themes,PlainMessage plain,LocalStore.HistoryItem item,ExecutorService worker,LongSupplier now) {
    this(owner,themes,plain,item,worker,now,null);
  }
  MailViewer(Stage owner,ThemeManager themes,PlainMessage plain,LocalStore.HistoryItem item,ExecutorService worker,LongSupplier now,VBox host) {
    this(owner,themes,plain,item,worker,now,host,null);
  }
  MailViewer(Stage owner,ThemeManager themes,PlainMessage plain,LocalStore.HistoryItem item,ExecutorService worker,LongSupplier now,VBox host,Actions actions) {
    this.host=host;this.lifecycleActions=actions;expiry=()->actions!=null&&actions.expiresAt()>=0?actions.expiresAt():item.expiresAt();
    this.plain=plain;stage=owner;content.setPadding(new Insets(22));
    Label heading=new Label(plain.subject().isBlank()?"Без темы":plain.subject());heading.getStyleClass().add("brand");
    Label lifetime=new Label();lifetime.getStyleClass().add("muted");
    text.getStyleClass().add("letter-body");heading.setWrapText(true);text.setEditable(false);text.setWrapText(true);text.setPrefRowCount(16);VBox.setVgrow(text,Priority.ALWAYS);
    Label author=new Label((item.outgoing()?"Кому: ":"От: ")+item.contact());author.setWrapText(true);metadata.getChildren().addAll(author,lifetime);content.getChildren().addAll(heading,metadata);
    if(actions!=null){
      Label verification=new Label("Подпись проверена · "+(actions.unknown()?"Неизвестный отправитель":"Из контактов"));verification.getStyleClass().add("muted");content.getChildren().add(verification);
      if(plain.context()!=null){var reference=plain.context();Button original=new Button((reference.forwarded()?"Переслано: ":"Ответ на: ")+reference.author()+" · "+reference.subject());original.setTooltip(new Tooltip("Ссылка автора письма; исходное письмо проверяется на этом устройстве"));original.setOnAction(e->actions.original(reference));content.getChildren().add(original);}
      Button reply=new Button("Ответить"),forward=new Button("Переслать"),copy=new Button("Копировать");
      reply.setOnAction(e->{if(!closed&&expiry.getAsLong()>now.getAsLong())actions.reply(item,plain);});
      forward.setOnAction(e->{
        if(closed||expiry.getAsLong()<=now.getAsLong())return;
        if(plain.protectedLetter()&&(opened==null||code.value().length==0||text.getText().isEmpty()||actions!=null&&!revealed)){error.setText("Сначала откройте письмо");if(!content.getChildren().contains(error))content.getChildren().add(error);return;}
        InWindowAlert confirm=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Переслать открытый текст новым письмом?",ButtonType.OK,ButtonType.CANCEL);confirm.initOwner(host==null?stage:owner);confirm.setHeaderText(null);themes.apply(confirm.getDialogPane());
        CheckBox files=new CheckBox("Включить вложения");if(!plain.files().isEmpty())confirm.getDialogPane().setContent(new VBox(10,new Label("Переслать это письмо выбранному получателю?"),files));
        if(confirm.showAndWait().orElse(ButtonType.CANCEL)==ButtonType.OK&&!closed&&expiry.getAsLong()>now.getAsLong())actions.forward(item,plain,text.getText(),files.isSelected()?plain.copyFiles():null);
      });
      copy.setOnAction(e->{if(!closed&&!text.getText().isEmpty()){var value=new javafx.scene.input.ClipboardContent();value.putString(text.getText());javafx.scene.input.Clipboard.getSystemClipboard().setContent(value);}});
      Button archive=new Button("В архив");archive.setOnAction(e->{if(closed||exporting||expiry.getAsLong()<=now.getAsLong())return;if(plain.protectedLetter()&&!revealed){error.setText("Сначала покажите расшифрованный текст");if(!content.getChildren().contains(error))content.getChildren().add(error);return;}exporting=true;archive.setDisable(true);String body=text.getText();actions.archive(item,plain,body,()->{exporting=false;if(closed)plain.close();else archive.setDisable(false);});});
      actionButtons.put("reply",reply);actionButtons.put("forward",forward);actionButtons.put("copy",copy);actionButtons.put("archive",archive);actionBar=new HBox(8,reply,forward,copy,archive);content.getChildren().add(actionBar);
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
            Platform.runLater(()->{if(closed){value.close();Arrays.fill(held,'\0');return;}opened=value;archivePassword=held;if(download!=null&&actions==null)download.setDisable(false);content.getChildren().removeAll(row,error);content.getChildren().addAll(text,code);
              text.setText(value.ciphertext());if(actions==null)live=new LiveCode(value::candidate,Platform::runLater,result->{if(!closed)text.setText(result);});
              if(actions!=null){Button reveal=new Button("Показать результат");reveal.setOnAction(event->{
                char[] entered=code.value();if(closed||entered.length==0){Arrays.fill(entered,'\0');return;}long generation=++revealGeneration;reveal.setDisable(true);reveal.setText("Открытие…");
                worker.execute(()->{try{actions.prepareDisplay();String result=value.candidate(entered);Platform.runLater(()->{if(!closed&&generation==revealGeneration){revealed=true;text.setText(result);if(download!=null)download.setDisable(false);contentDisplayed(actions);}});}catch(Exception failure){Platform.runLater(()->{if(!closed){error.setText("Не удалось показать письмо. Проверьте срок и состояние хранилища.");if(!content.getChildren().contains(error))content.getChildren().add(error);}});}finally{Arrays.fill(entered,'\0');Platform.runLater(()->{reveal.setDisable(false);reveal.setText("Показать результат");});}});
              });content.getChildren().add(reveal);}
              code.hidden.textProperty().addListener((o,a,b)->{if(closed)return;if(actions==null){text.clear();live.change(code.value(),value.ciphertext());}else{revealGeneration++;revealed=false;if(download!=null)download.setDisable(true);text.setText(value.ciphertext());}});
            });
          }catch(Exception failure){Platform.runLater(()->{if(!closed)error.setText(failure instanceof AEADBadTagException?"Неверный пароль письма.":"Не удалось открыть письмо.");});}
          finally{Arrays.fill(secret,'\0');Arrays.fill(envelope,(byte)0);Platform.runLater(()->{unlock.setDisable(false);unlock.setText("Открыть");});}
        });
      });
    }else{content.getChildren().add(text);text.setText(plain.text());if(actions!=null)Platform.runLater(()->contentDisplayed(actions));}
    if(!plain.files().isEmpty()){
      Selector<String> selectedFile=new Selector<>(themes,plain.files().stream().map(PlainMessage.FileInfo::name).toList(),plain.filename());if(!plain.protectedLetter()&&plain.files().size()>1)content.getChildren().add(selectedFile);
      content.getChildren().add(new Label("Вложения: "+plain.files().size()));download=new Button(plain.protectedLetter()?"Скачать вложения":"Сохранить "+plain.filename());download.setDisable(plain.protectedLetter());
      download.setOnAction(e->{
        if(closed||expiry.getAsLong()<=now.getAsLong()||exporting)return;
        if(actions!=null&&actions.unknown()){
          InWindowAlert confirm=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Сохранить вложение неизвестного отправителя?",ButtonType.OK,ButtonType.CANCEL);confirm.initOwner(host==null?stage:owner);confirm.setHeaderText(null);themes.apply(confirm.getDialogPane());if(confirm.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK)return;
        }
        String chosen=selectedFile.getValue();InWindowFileChooser chooser=new InWindowFileChooser();chooser.setInitialFileName(plain.protectedLetter()?"AEGIS_Documents_"+java.time.LocalDate.now()+".zip":chosen);var file=chooser.showSaveDialog(host==null?stage:owner);
        if(file==null||closed||expiry.getAsLong()<=now.getAsLong())return;
        if(java.nio.file.Files.exists(file.toPath())){error.setText("Файл уже существует. Выберите другое имя.");if(!content.getChildren().contains(error))content.getChildren().add(error);return;}
        char[] secret=archivePassword==null?new char[0]:archivePassword.clone();exporting=true;download.setDisable(true);download.setText("Сохранение…");
        worker.execute(()->{try{
          if(plain.protectedLetter())plain.exportEncryptedZip(file.toPath(),secret,()->!closed&&expiry.getAsLong()>now.getAsLong());else plain.exportTo(file.toPath(),chosen);
          Platform.runLater(()->{if(!closed)download.setText("Сохранено");});
        }catch(Exception failure){Platform.runLater(()->{if(!closed){error.setText("Не удалось сохранить архив. Выберите новое имя и проверьте доступ к папке.");if(!content.getChildren().contains(error))content.getChildren().add(error);}});}
        finally{Arrays.fill(secret,'\0');Platform.runLater(()->{exporting=false;if(closed)plain.close();else{download.setDisable(false);download.setText(plain.protectedLetter()?"Скачать вложения":"Сохранить файл");}});}});
      });content.getChildren().add(download);
    }
    appearance(themes.settings());themes.apply(content);if(host==null){page=new InWindowDialog<>();page.initOwner(owner);page.setTitle(plain.subject().isBlank()?"Письмо":plain.subject());page.getDialogPane().setContent(content);themes.apply(page.getDialogPane());page.onClose(this::close);}else{host.getChildren().setAll(content);VBox.setVgrow(content,Priority.ALWAYS);}
    timer=new Timeline(new KeyFrame(Duration.seconds(1),e->{if(actions!=null&&(!plain.protectedLetter()||revealed))contentDisplayed(actions);long left=expiry.getAsLong()-now.getAsLong();if(left<=0){close();return;}lifetime.setText(expiry.getAsLong()==Long.MAX_VALUE?"Отсчёт после показа":"Удаление через "+java.time.Duration.ofMillis(left).toMinutes()+" мин");}));
    timer.setCycleCount(Animation.INDEFINITE);timer.play();if(expiry.getAsLong()>now.getAsLong()){if(host==null)page.show();}else close();
  }
  private boolean bodyVisible(){
    if(closed||text.getScene()==null)return false;javafx.stage.Window window=text.getScene().getWindow();if(window==null||!window.isShowing()||window instanceof Stage s&&s.isIconified())return false;
    for(Node node=text;node!=null;node=node.getParent())if(!node.isVisible()||node.getOpacity()<=0)return false;
    var bounds=text.localToScene(text.getBoundsInLocal());return bounds.getMaxX()>0&&bounds.getMaxY()>0&&bounds.getMinX()<text.getScene().getWidth()&&bounds.getMinY()<text.getScene().getHeight();
  }
  private void contentDisplayed(Actions actions){
    if(displayNotified||displayScheduled||!bodyVisible())return;displayScheduled=true;displayOffered=true;
    // Give the scene a render pulse. A minimized window, detached view or password form is not a read.
    displayPulse=new PauseTransition(Duration.millis(150));displayPulse.setOnFinished(e->{displayScheduled=false;if(!displayNotified&&bodyVisible()){displayNotified=true;actions.displayed();}});displayPulse.play();
  }
  boolean showing(){return !closed&&(host!=null||page!=null&&page.isShowing());}
  void appearance(org.securemail.client.appearance.Appearance.Settings settings){if(closed)return;var layout=settings.layout();content.setPadding(new Insets(layout.viewPadding()));content.setMaxWidth(layout.textWidth());content.setMinWidth(0);text.setMinWidth(0);if(layout.viewCard()){if(!content.getStyleClass().contains("letter-card"))content.getStyleClass().add("letter-card");}else content.getStyleClass().remove("letter-card");content.getChildren().remove(metadata);if(layout.metadataTop())content.getChildren().add(Math.min(1,content.getChildren().size()),metadata);else content.getChildren().add(metadata);if(actionBar!=null){actionBar.getChildren().clear();for(String name:layout.actions()){Button button=actionButtons.get(name);if(button!=null)actionBar.getChildren().add(button);}if(actionButtons.containsKey("archive"))actionBar.getChildren().add(actionButtons.get("archive"));actionBar.setSpacing(settings.components().spacing());}}
  @Override public void close(){
    if(closed)return;closed=true;revealGeneration++;if(displayPulse!=null)displayPulse.stop();if(lifecycleActions!=null)try{if(displayOffered&&!displayNotified)lifecycleActions.abandonedDisplay();else lifecycleActions.closed(displayNotified);}catch(RuntimeException interrupted){/* Memory cleanup must complete even when the owner worker is stopping. */}timer.stop();if(live!=null)live.close();if(opened!=null)opened.close();
    password.clear();code.clear();text.clear();content.getChildren().clear();if(archivePassword!=null){Arrays.fill(archivePassword,'\0');archivePassword=null;}if(!exporting)plain.close();if(page!=null)page.close();
  }
}

