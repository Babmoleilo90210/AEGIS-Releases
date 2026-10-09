package org.securemail.ui;

import javafx.application.*;
import javafx.animation.*;
import javafx.geometry.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.*;
import javafx.stage.*;
import javafx.util.Duration;
import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.*;
import org.securemail.client.crypto.*;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;
import org.securemail.client.update.*;
import org.securemail.client.security.*;

/** Desktop UI. Work that can block is confined to a single background executor. */
public final class MessengerApp extends Application {
  private Stage stage;private BorderPane root;private ClientConfig config;private AppPaths.Instance instance;
  private TorConnection tor;private ClientSession session;private volatile boolean stopping;
  private final ExecutorService worker=Executors.newSingleThreadExecutor(r->{var t=new Thread(r,"aegis-ui-work");t.setDaemon(true);return t;});
  private final AutomaticEncryption automatic=new AutomaticEncryption(Clock.systemUTC());
  private final ThemeManager themes=new ThemeManager();
  private final List<MailViewer> viewers=new ArrayList<>();
  private ListView<String> contacts;
  private ListView<MailRow> letters;
  private TextArea composer;
  private TextField recipientField,subjectField;
  private SecretField letterPassword,secondCode;
  private Label attachmentLabel,connection;
  private final List<Path> attachments=new ArrayList<>();
  private VBox attachmentsBox;private ContactPicker recipientPicker;
  private Label networkLabel;private Button loginButton,connectButton;private volatile boolean relayReady,connectingTor;
  private final ExecutorService connectionWorker=Executors.newSingleThreadExecutor(r->{var t=new Thread(r,"aegis-connection");t.setDaemon(true);return t;});
  private String selected="",rendered="",section="";
  private boolean refreshing,mailOutgoing,notifying;private NotificationCenter notifications;
  private long viewGeneration;
  private Timeline timer;private Path pendingLinuxUpdate;
  private ComboBox<Ttl> ttl;
  private UiPresetStore presets;private UiPreferences layout=UiPreferences.builtins().get("Компактный");
  private UpdateService updates;private UpdatePreferences updatePreferences;private UpdatesView updatesView;
  private Button updateBadge,accountReconnect;private VBox previewHost;private MailViewer embeddedViewer;
  private final Map<String,Image> avatarImages=new HashMap<>();private RememberedLogin remembered;
  private boolean rememberRequested,resumeAttempted,resumingNetwork,installingUpdate;private long rememberedExpires,pendingRelayExpiry;private String pendingRelayToken="";
  private long previewTicket;private VBox accountAvatar;
  private VBox profileAvatar;private Button sendButton;private CheckBox additionalProtection;
  private Draft draft;private MailContext replyContext;
  private PlainMessage.FileBundle forwardedFiles;private boolean replyNeedsProtection;
  private static final class Draft implements AutoCloseable{
    String recipient="",subject="",body="";List<Path> files=List.of();char[] password=new char[0],code=new char[0];long ttl;boolean protectedLetter,forceProtection;MailContext context;PlainMessage.FileBundle bundle;
    public void close(){Arrays.fill(password,'\0');Arrays.fill(code,'\0');recipient="";subject="";body="";files=List.of();context=null;if(bundle!=null){bundle.close();bundle=null;}}
  }
  private TextField contactSearch;private ListView<LocalMailSearch.Result> threadResults;
  private static final class ResponsePreparation implements AutoCloseable{final MailContext context;PlainMessage.FileBundle bundle;ResponsePreparation(MailContext context,PlainMessage.FileBundle bundle){this.context=context;this.bundle=bundle;}PlainMessage.FileBundle take(){var result=bundle;bundle=null;return result;}public void close(){if(bundle!=null)bundle.close();bundle=null;}}
  private LocalMailSearch.Scope mailScope=LocalMailSearch.Scope.INBOX;private boolean threads;
  private long lastMailboxScan,lastMailboxChange;
  private long lastAvatarRevision=-1;
  private record MailRow(LocalStore.MailItem item,String subject,String file,boolean unknown,boolean signature,String thread){MailRow(LocalStore.MailItem item,String subject,String file){this(item,subject,file,false,true,item.id());}}
  private record OpenedMail(LocalStore.HistoryItem item,PlainMessage plain,boolean unknown) implements AutoCloseable {public void close(){plain.close();}}
  private record Ttl(String label,long seconds){public String toString(){return label;}}
  @FunctionalInterface private interface Work<T>{T run()throws Exception;}

  @Override public void start(Stage stage){
    this.stage=stage;stage.initStyle(StageStyle.UNDECORATED);stage.setTitle("АЕГИС");stage.setMinWidth(760);stage.setMinHeight(580);
    root=new BorderPane();notifications=new NotificationCenter(stage,root);BorderPane window=new BorderPane(root);window.setTop(new WindowChrome(stage));var scene=new Scene(window,1020,730);scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("messenger.css")).toExternalForm());themes.apply(window);themes.apply(root);stage.setScene(scene);InWindowDialog.bind(stage,window);WindowChrome.resize(stage,scene);
    root.centerProperty().addListener((o,a,b)->{if(b!=null){b.setOpacity(0);FadeTransition fade=new FadeTransition(Duration.millis(150),b);fade.setFromValue(0);fade.setToValue(1);fade.play();}});
    for(int n:new int[]{16,24,32,48,64,128,256}){var icon=getClass().getResourceAsStream("icons/icon-"+n+".png");if(icon!=null)stage.getIcons().add(new Image(icon));}
    stage.setOnCloseRequest(e->{e.consume();if(!installingUpdate&&updatePreferences!=null&&updatePreferences.installAtExit()&&updates!=null&&updates.snapshot().state()==UpdateService.State.READY_TO_INSTALL)installUpdate();else stop();});stage.show();
    try {config=ClientConfig.load(AppPaths.config());
      if(!AppPaths.windows()){
        var old=UpdateSupport.oldImage();if(old.isPresent()){
          ButtonType update=new ButtonType("Обновить до "+SignedManifest.CURRENT),skip=new ButtonType("Запустить без обновления",ButtonBar.ButtonData.CANCEL_CLOSE);
          InWindowAlert prompt=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Старый профиль и сервер сохраняются.",update,skip);prompt.setTitle("АЕГИС");prompt.setHeaderText("Обнаружена установленная версия АЕГИС");prompt.initOwner(stage);themes.apply(prompt.getDialogPane());
          if(prompt.showAndWait().orElse(skip)==update){pendingLinuxUpdate=old.get();center(form("АЕГИС",new Label("Подготовка обновления…")));worker.execute(()->{try{UpdateSupport.closeOldLinux(pendingLinuxUpdate);UpdateSupport.backup(config);Platform.runLater(this::finishStartup);}catch(Exception ex){Platform.runLater(()->{error(ex);stage.close();Platform.exit();});}});return;}
        }
      }
      finishStartup();
    }catch(Exception e){error(e);stage.close();Platform.exit();}
  }
  private void finishStartup(){
    try{instance=AppPaths.lock();
      presets=new UiPresetStore(AppPaths.root());layout=presets.current();themes.layout(layout);try{threads=Files.readString(AppPaths.root().resolve("mail-mode.txt")).trim().equals("threads");}catch(IOException ignored){}
      updatePreferences=UpdatePreferences.load(AppPaths.root());updates=new UpdateService(AppPaths.root(),config.torUpdateSocksPort());updates.channel(updatePreferences.channel());updates.listener(s->Platform.runLater(()->updateChanged(s)));
      updates.automatic(()->updatePreferences.automaticCheck(),()->updatePreferences.automaticDownload());
      // A private cookie path is always tied to this application's profile, including migrated Linux profiles.
      config=new ClientConfig("127.0.0.1",config.torSocksPort(),config.torControlPort(),config.torUpdateSocksPort(),AppPaths.root().resolve("tor/control_auth_cookie"),config.localServicePort(),config.defaultTTL(),config.relayOnionAddress(),config.relayPort(),config.storagePath(),config.maxFileSize(),config.maxLocalStorage(),config.deliveryTTL());
      ClientUpgrade.beforeOpen(config.storagePath(),AppPaths.root().resolve("backups"));
      LocalStore.cleanupLockedFiles(config.storagePath(),System.currentTimeMillis());
      startTor();
      tryRemembered();
    }catch(Exception e){error(e);stage.close();Platform.exit();}
  }
  private void page(Node body){root.getChildren().clear();root.setTop(null);root.setLeft(null);root.setBottom(null);root.setCenter(body);}
  private VBox form(String title,Node...nodes){Label heading=new Label(title);heading.getStyleClass().add("heading");VBox box=new VBox(14,heading);box.getChildren().addAll(nodes);box.setMaxWidth(350);box.setAlignment(Pos.CENTER_LEFT);box.setPadding(new Insets(24));return box;}
  private void center(Node node){StackPane pane=new StackPane(node);page(pane);}
  private Button button(String text,Runnable action){Button b=new Button(text);b.setOnAction(e->action.run());return b;}
  private TextField field(String prompt){TextField f=new TextField();f.setPromptText(prompt);return f;}
  private PasswordField password(String prompt){PasswordField f=new PasswordField();f.setPromptText(prompt);return f;}
  private <T> void work(Button button,String busy,Work<T> action,java.util.function.Consumer<T> done){
    String label=button==null?null:button.getText();if(button!=null){button.setDisable(true);button.setText(busy);}
    worker.execute(()->{try{T value=action.run();Platform.runLater(()->{if(!stopping)done.accept(value);else if(value instanceof AutoCloseable closeable)try{closeable.close();}catch(Exception ignored){}});}catch(Exception|LinkageError e){Platform.runLater(()->{if(!stopping)error(e);});}finally{Platform.runLater(()->{if(button!=null){button.setDisable(false);button.setText(label);}});}});
  }
  private void startTor(){
    if(connectingTor)return;TorConnection previous=tor;ClientSession active=session;connectingTor=true;relayReady=false;
    if(session==null){if(config.relayOnionAddress().isBlank())serverPage();else loginPage();}
    TorConnection candidate=new TorConnection(config);tor=candidate;TorTransport.requireAvailability(candidate::ready);
    connectionWorker.execute(()->{try{
      // Closing the old SAFECOOKIE/P2P channel and child process can block.
      // Availability is already fail-closed; never perform these waits on the FX thread.
      if(active!=null)active.torUnavailable();if(previous!=null)previous.close();
      candidate.start(java.time.Duration.ofSeconds(150),java.time.Duration.ofSeconds(300),(mode,n)->Platform.runLater(()->{
        if(stopping||tor!=candidate)return;networkStatus("Подключение… "+n+"%");
      }));
      Platform.runLater(()->{if(stopping||tor!=candidate)return;networkStatus("Соединение готово");if(session!=null)session.torRestarted();if(connectButton!=null)connectButton.setDisable(false);if(!config.relayOnionAddress().isBlank())preconnect();if(updatePreferences.automaticCheck())updates.check(updatePreferences.automaticDownload());});
    }catch(Exception e){candidate.close();Platform.runLater(()->{if(stopping||tor!=candidate)return;networkStatus("Нет соединения. Прямое подключение отключено.");if(loginButton!=null)loginButton.setDisable(true);});}finally{connectingTor=false;}});
  }
  private void networkStatus(String text){if(networkLabel!=null)networkLabel.setText(text);}
  private void preconnect(){
    ClientConfig candidate=config;networkStatus("Подключение к серверу…");
    connectionWorker.execute(()->{try{TechnicalLog.record(TechnicalLog.Event.RELAY_CONNECT,0);RelayProbe.check(candidate);TechnicalLog.record(TechnicalLog.Event.RELAY_CONNECTED,0);
      Platform.runLater(()->{if(stopping||candidate!=config)return;relayReady=true;networkStatus("● Подключено");if(loginButton!=null)loginButton.setDisable(false);resumeNetwork();});
    }catch(Exception failure){TechnicalLog.record(TechnicalLog.Event.RELAY_FAILED,0);Platform.runLater(()->{if(!stopping&&candidate==config){relayReady=false;networkStatus("Нет соединения с сервером");}});}});
  }
  void serverPage(){
    TextField address=field("Адрес сервера .onion");address.setText(config.relayOnionAddress());networkLabel=new Label(tor!=null&&tor.ready()?"Соединение готово":"Подключение…");networkLabel.getStyleClass().add("muted");
    Button connect=new Button("Подключиться");connectButton=connect;connect.setDisable(tor==null||!tor.ready());connect.setDefaultButton(true);connect.setOnAction(e->{try{
      ClientConfig candidate=config.withRelay(OnionAddress.normalize(address.getText()));
      work(connect,"Подключение…",()->{TechnicalLog.record(TechnicalLog.Event.RELAY_CONNECT,0);try{RelayProbe.check(candidate);}catch(Exception ex){TechnicalLog.record(TechnicalLog.Event.RELAY_FAILED,0);throw ex;}TechnicalLog.record(TechnicalLog.Event.RELAY_CONNECTED,0);candidate.save(AppPaths.config());return candidate;},value->{config=value;relayReady=true;loginPage();});
    }catch(Exception ex){error(ex);}});
    var advanced=button("Расширенные настройки",this::diagnostics);advanced.getStyleClass().add("link");VBox setup=form("АЕГИС",new Label("Адрес сервера"),address,connect,networkLabel,advanced);if(Files.exists(config.storagePath().resolve("state.vault")))setup.getChildren().add(button("Открыть без сети",this::openOffline));center(setup);
  }
  void loginPage(){
    connectButton=null;TextField nick=field("Ник");PasswordField account=password("Пароль");Button login=new Button("Войти");loginButton=login;login.setDisable(!relayReady);login.setDefaultButton(true);
    networkLabel=new Label(relayReady?"● Подключено":"Подключение…");networkLabel.getStyleClass().add("muted");
    CheckBox remember=new CheckBox("Запомнить вход на этом устройстве");
    login.setOnAction(e->{try{rememberRequested=remember.isSelected();String name=Limits.nickname(nick.getText());char[] pass=account.getText().toCharArray();account.clear();
      if(!Files.exists(config.storagePath().resolve("state.vault"))){Arrays.fill(pass,'\0');info("Восстановите резервную копию идентичности этого аккаунта.");return;}
      loginAttempt(name,pass,null,login);
    }catch(Exception ex){error(ex);}});
    var create=button("Нет аккаунта? Создать",this::registerPage);create.getStyleClass().add("link");
    var another=button("Другой сервер",this::serverPage);another.getStyleClass().add("link");
    var local=button("Открыть без сети",this::openOffline);local.setDisable(!Files.exists(config.storagePath().resolve("state.vault")));
    center(form("АЕГИС",nick,account,remember,login,create,networkLabel,local,button("Повторить подключение",()->{if(tor==null||!tor.ready())startTor();else preconnect();}),button("Восстановить резервную копию",this::restore),another));
  }
  private void openOffline(){char[] password=askPassword("Открыть хранилище","Пароль хранилища");if(password==null)return;
    work(null,"",()->{try{return AccountLogin.offline(config,password);}finally{Arrays.fill(password,'\0');}},opened->{session=opened;rememberRequested=false;afterLogin();});
  }
  private void loginAttempt(String nick,char[] account,char[] old,Button login){
    login.setDisable(true);login.setText("Вход…");
    worker.execute(()->{boolean keep=false;try{
      ClientSession opened=AccountLogin.open(config,nick,account,old);
      if(rememberRequested)saveRemembered(opened);else{Files.deleteIfExists(AppPaths.root().resolve("session/resume.enc"));rememberedExpires=0;pendingRelayToken="";try{if(remembered!=null)remembered.clear();}catch(IOException ignored){/* The encrypted resume envelope has already been removed. */}}
      Platform.runLater(()->{if(stopping){try{opened.close();}catch(IOException ignored){}return;}session=opened;afterLogin();});
    }catch(AccountLogin.OldPasswordRequired needed){keep=true;Platform.runLater(()->{
      if(stopping){Arrays.fill(account,'\0');return;}
      char[] legacy=askPassword("Обновление хранилища","Старый пароль хранилища");
      if(legacy==null)Arrays.fill(account,'\0');else loginAttempt(nick,account,legacy,login);
    });}catch(AccountLogin.MigrationFailed failure){Platform.runLater(()->{if(stopping)return;info("Не удалось обновить хранилище. Предыдущие данные сохранены.");try{if(UpdateSupport.scheduleWindowsRollback())stop();}catch(IOException rollbackFailure){error(rollbackFailure);}});
    }catch(Exception failure){Platform.runLater(()->{if(!stopping)error(failure);});}
    finally{if(!keep)Arrays.fill(account,'\0');if(old!=null)Arrays.fill(old,'\0');Platform.runLater(()->{login.setDisable(!relayReady);login.setText("Войти");});}});
  }
  void registerPage(){
    TextField nick=field("Ник");PasswordField pass=password("Пароль"),repeat=password("Повторите пароль");Button create=new Button("Создать аккаунт");
    create.setOnAction(e->{try{
      if(!relayReady){info("Соединение ещё устанавливается");return;}
      String name=Limits.nickname(nick.getText());if(name.equalsIgnoreCase("aegis"))throw new IllegalArgumentException("Этот ник зарезервирован приложением");if(!pass.getText().equals(repeat.getText())||pass.getLength()<12)throw new IllegalArgumentException("Пароли должны совпадать и содержать не менее 12 символов");
      char[] account=pass.getText().toCharArray();pass.clear();repeat.clear();Path staged=AppPaths.root().resolve("data-"+UUID.randomUUID());ClientConfig candidate=config.withStorage(staged);
      work(create,"Создание…",()->{ClientSession opened=null;try{opened=new ClientSession(candidate,account);opened.login(name,account,true);candidate.save(AppPaths.config());return opened;}
        catch(Exception ex){boolean registered=opened!=null&&opened.network().registrationAccepted();if(opened!=null)opened.close();
          if(ex instanceof RequestRejected&&!registered){try(var paths=Files.walk(staged)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
          else{candidate.save(AppPaths.config());Platform.runLater(()->{config=candidate;loginPage();});}throw ex;
        }finally{Arrays.fill(account,'\0');}},opened->{config=candidate;session=opened;afterLogin();});
    }catch(Exception ex){error(ex);}});
    center(form("Создать аккаунт",nick,pass,repeat,create,button("Назад",this::loginPage)));
  }
  private void afterLogin(){
    loadAvatars();
    if(pendingLinuxUpdate==null){mainPage();resumeNetwork();confirmHealthyStartup();return;}
    Path old=pendingLinuxUpdate;center(form("АЕГИС",new Label("Завершение обновления…")));
    work(null,"",()->{Path current=UpdateSupport.downloadedImage();if(current==null)throw new IOException("AppImage path missing");
      Path desktop=Path.of(System.getProperty("user.home"),".local/share/applications/aegis.desktop");UpdateSupport.installLinux(current,old,desktop,AppPaths.bundle().resolve("resources/aegis.png"));return UpdateSupport.installedImage();
    },installed->{pendingLinuxUpdate=null;stop();try{new ProcessBuilder(installed.toString()).start();}catch(IOException ex){/* Data and installed image remain available through the updated desktop shortcut. */}});
  }
  private void confirmHealthyStartup(){
    ClientSession active=session;if(active==null||stage.getScene()==null||!stage.isShowing())return;
    worker.execute(()->{try{active.local().checkpoint();active.local().mailboxIndex(false);active.local().mailboxIndex(true);
      // Verify native sealed-box support and AES locally before the updater commits.
      // This packet never enters NetworkService or the mailbox.
      var identity=active.local().identity();var self=new UserInfo(identity.userId(),active.local().nickname(),identity.publicKey(),null);
      try(var probe=PlainMessage.text("AEGIS local startup self-test")){
        var encrypted=automatic.encrypt(probe,60,60_000,identity,self.nickname(),self);
        try(var decoded=automatic.decrypt(encrypted,identity,config.maxFileSize())){if(!decoded.text().equals(probe.text()))throw new IOException("Startup crypto check failed");}
      }
      Platform.runLater(()->{if(!stopping&&session==active&&stage.isShowing())try{root.applyCss();root.layout();if(root.getCenter()==null||root.getWidth()<=0||root.getHeight()<=0)throw new IOException("Startup UI check failed");UpdateInstaller.confirmStartup();worker.execute(()->{try{active.activateDelivery();}catch(IOException failure){Platform.runLater(()->error(failure));}});}catch(IOException failure){error(failure);}});
    }catch(Exception failure){Platform.runLater(()->{if(!stopping)error(failure);});}});
  }
  void mainPage(){
    if(timer!=null)timer.stop();if(notifications==null)notifications=new NotificationCenter(stage,root);page(null);clearCompose();
    Label brand=new Label("АЕГИС");brand.getStyleClass().add("brand");Region space=new Region();HBox.setHgrow(space,Priority.ALWAYS);
    connection=new Label("●");connection.setOnMouseClicked(event->connectionDialog());updateBadge=button("",this::updatesPage);updateBadge.getStyleClass().add("link");updateBadge.setVisible(false);updateBadge.setManaged(false);accountReconnect=button("Войти в сеть",this::reconnectAccount);accountReconnect.setVisible(false);accountReconnect.setManaged(false);
    HBox top=new HBox(10,button("☰",()->{try{applyLayout(new UiPreferences(layout.scale(),layout.density(),!layout.sidebar(),layout.avatars(),layout.preview(),layout.subject(),layout.date()));}catch(IOException ex){error(ex);}}),brand,space,updateBadge,accountReconnect,button("Новое письмо",this::composePage),button("Настройки",this::settings),connection);top.setPadding(new Insets(8,12,8,12));root.setTop(top);
    Region filler=new Region();VBox.setVgrow(filler,Priority.ALWAYS);
    accountAvatar=new VBox(avatar(session.local().nickname()));
    VBox nav=new VBox(7,button("↓ Входящие",()->mailboxPage(false)),button("↑ Отправленные",()->mailboxPage(true)),button("♡ Друзья",this::friendsPage),button("☆ Избранное",()->mailboxPage(false,LocalMailSearch.Scope.FAVORITES)),button("⊘ Заблокированные",()->mailboxPage(false,LocalMailSearch.Scope.BLOCKED)),button("⌕ Поиск",this::searchPage),button("Контакты",this::contactsPage),button("⚙ Системные",this::systemLetters),filler,new HBox(8,accountAvatar,button(session.local().nickname(),this::profile)),button("Настройки",this::settings));
    nav.getStyleClass().add("navigation");nav.setPrefWidth(160);nav.setPadding(new Insets(10));nav.setVisible(layout.sidebar());nav.setManaged(layout.sidebar());root.setLeft(nav);
    timer=new Timeline(new KeyFrame(Duration.seconds(1),e->refresh()));timer.setCycleCount(Animation.INDEFINITE);timer.play();mailboxPage(false);updateChanged(updates.snapshot());
  }
  private void rememberDraft(){
    if(composer==null)return;if(draft!=null)draft.close();draft=new Draft();
    draft.recipient=recipientField==null?"":recipientField.getText();draft.subject=subjectField==null?"":subjectField.getText();draft.body=composer.getText();draft.files=List.copyOf(attachments);
    if(letterPassword!=null)draft.password=letterPassword.value();if(secondCode!=null)draft.code=secondCode.value();
    draft.ttl=ttl==null||ttl.getValue()==null?config.defaultTTL():ttl.getValue().seconds();draft.protectedLetter=additionalProtection!=null&&additionalProtection.isSelected();draft.context=replyContext;
    draft.forceProtection=replyNeedsProtection;draft.bundle=forwardedFiles;forwardedFiles=null;
  }
  private void clearCompose(){clearCompose(true);}
  private void clearCompose(boolean remember){
    if(remember)rememberDraft();else if(draft!=null){draft.close();draft=null;}
    previewTicket++;if(embeddedViewer!=null){embeddedViewer.close();embeddedViewer=null;}previewHost=null;
    if(composer!=null)composer.clear();if(letterPassword!=null)letterPassword.clear();if(secondCode!=null)secondCode.clear();
    composer=null;letterPassword=null;secondCode=null;additionalProtection=null;replyContext=null;sendButton=null;attachments.clear();attachmentsBox=null;attachmentLabel=null;
    replyNeedsProtection=false;if(forwardedFiles!=null){forwardedFiles.close();forwardedFiles=null;}
  }
  void mailboxPage(boolean outgoing){
    mailboxPage(outgoing,outgoing?LocalMailSearch.Scope.SENT:LocalMailSearch.Scope.INBOX);
  }
  private void mailboxPage(boolean outgoing,LocalMailSearch.Scope scope){
    mailScope=scope;
    clearCompose();section="mail";mailOutgoing=outgoing;rendered="";viewGeneration++;
    Label heading=new Label(scope==LocalMailSearch.Scope.BLOCKED?"Заблокированные":scope==LocalMailSearch.Scope.FAVORITES?"Избранное":outgoing?"Отправленные":"Входящие");heading.getStyleClass().add("brand");
    Selector<String> mode=new Selector<>(themes,List.of("Письма","Цепочки"),threads?"Цепочки":"Письма");mode.setOnAction(e->{threads=mode.getValue().equals("Цепочки");try{AtomicFiles.write(AppPaths.root().resolve("mail-mode.txt"),(threads?"threads":"letters").getBytes(java.nio.charset.StandardCharsets.US_ASCII));}catch(IOException error){error(error);}rendered="";refresh();});
    letters=new ListView<>();letters.setPlaceholder(new Label("Писем пока нет"));
    letters.setCellFactory(list->new ListCell<>(){protected void updateItem(MailRow row,boolean empty){
      super.updateItem(row,empty);setText(null);setGraphic(null);if(empty||row==null)return;
      var item=row.item();Label subject=new Label(row.subject().isBlank()?"Без темы":row.subject());subject.getStyleClass().add("mail-subject");subject.setVisible(layout.subject());subject.setManaged(layout.subject());
      String time=Instant.ofEpochMilli(item.time()).atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("dd.MM HH:mm"));
      Label meta=new Label(item.contact()+(row.unknown()?" · Неизвестный":"")+(layout.date()?" · "+time:"")+" · "+item.status());meta.getStyleClass().add("muted");meta.setTooltip(new Tooltip((row.signature()?"Подпись проверена":"Подпись не проверена")+(row.unknown()?" · Контакт не проверен":" · Из контактов")));
      Label remaining=new Label("◷ "+Math.max(0,(item.expiresAt()-session.local().now())/60000)+" мин"+(row.file().isEmpty()?"":" · "+row.file()));remaining.getStyleClass().add("muted");
      Button open=button("Открыть",()->{if(threads)threadPage(row);else openLetter(item);});
      HBox body=new HBox(8,avatar(item.contact()),new VBox(3,subject,meta,remaining));if(layout.preview()==UiPreferences.Preview.OFF)body.getChildren().add(open);body.setAlignment(Pos.CENTER_LEFT);setGraphic(body);
      MenuItem delete=new MenuItem("Удалить у меня");delete.setOnAction(e->work(null,"",()->{session.local().deleteHistory(item.id(),item.outgoing());return true;},x->{rendered="";refresh();}));
      MenuItem pin=new MenuItem(session.features().pinned("pinnedMail",item.id())?"Убрать из избранного":"В избранное");pin.setOnAction(e->work(null,"",()->{session.features().pin("pinnedMail",item.id(),!session.features().pinned("pinnedMail",item.id()));return true;},x->{rendered="";refresh();}));
      MenuItem block=new MenuItem(scope==LocalMailSearch.Scope.BLOCKED?"Разблокировать письмо":"Заблокировать письмо");block.setOnAction(e->work(null,"",()->{session.features().blockMail(item.id(),scope!=LocalMailSearch.Scope.BLOCKED);return true;},x->{rendered="";refresh();}));
      ContextMenu menu=new ContextMenu(pin,delete);if(!item.outgoing()){
        menu.getItems().add(block);MenuItem senderBlock=new MenuItem(scope==LocalMailSearch.Scope.BLOCKED?"Разблокировать отправителя":"Блокировать отправителя");senderBlock.setOnAction(e->work(null,"",()->{var packet=session.local().loadHistory(item.id(),false).packet();session.features().blockSender(packet.senderId(),scope!=LocalMailSearch.Scope.BLOCKED);return true;},done->{rendered="";refresh();}));menu.getItems().add(senderBlock);
      }setContextMenu(menu);
      MenuItem pinThread=new MenuItem("Закрепить цепочку");pinThread.setOnAction(e->work(null,"",()->{session.features().pin("pinnedThreads",row.thread(),!session.features().pinned("pinnedThreads",row.thread()));return true;},x->{rendered="";refresh();}));menu.getItems().add(pinThread);
    }});
    VBox box=new VBox(8,new HBox(12,heading,mode),letters);box.setPadding(new Insets(10));VBox.setVgrow(letters,Priority.ALWAYS);
    if(layout.preview()==UiPreferences.Preview.OFF)root.setCenter(box);
    else {previewHost=new VBox(new Label("Выберите письмо"));previewHost.setPadding(new Insets(12));SplitPane split=new SplitPane(box,previewHost);split.setOrientation(layout.preview()==UiPreferences.Preview.BOTTOM?Orientation.VERTICAL:Orientation.HORIZONTAL);split.setDividerPositions(layout.preview()==UiPreferences.Preview.BOTTOM?.45:.42);root.setCenter(split);
      letters.getSelectionModel().selectedItemProperty().addListener((o,a,b)->{if(b!=null){if(threads)threadPage(b);else openLetter(b.item());}});}
    refresh();
  }
  private void refresh(){
    if(session==null||stopping)return;
    if(session.local().avatarRevision()!=lastAvatarRevision){lastAvatarRevision=session.local().avatarRevision();loadAvatars();}
    if(rememberedExpires>0&&System.currentTimeMillis()>=rememberedExpires){rememberedExpires=0;endRemembered();return;}
    pollNotifications();
    if(accountReconnect!=null){accountReconnect.setVisible(!session.online());accountReconnect.setManaged(!session.online());}
    if(sendButton!=null)sendButton.setDisable(!session.online()||tor==null||!tor.ready());
    boolean connected=tor!=null&&tor.ready()&&session.status().contains("Relay ●");
    if(connection!=null){connection.setStyle("-fx-text-fill:"+(connected?"#469981":"#c38848"));connection.setText("●");connection.setTooltip(new Tooltip(connected?"Соединение защищено":"Нет соединения. Прямое подключение отключено."));}
    viewers.removeIf(v->!v.showing());
    if(section.equals("thread")&&threadResults!=null)threadResults.getItems().removeIf(r->r.item().expiresAt()<=session.local().now());
    if((section.equals("contacts")||section.equals("friends"))&&contactSearch!=null)fillContacts(contactSearch.getText());
    if(!section.equals("mail")||letters==null)return;
    letters.getItems().removeIf(row->row.item().expiresAt()<=session.local().now());letters.refresh();
    if(refreshing)return;refreshing=true;long generation=viewGeneration;boolean outgoing=mailOutgoing;ClientSession active=session;
    long change=active.local().changeCounter();if(!rendered.isEmpty()&&change==lastMailboxChange&&System.nanoTime()-lastMailboxScan<TimeUnit.SECONDS.toNanos(15)){refreshing=false;return;}
    worker.execute(()->{try{
      var found=LocalMailSearch.find(active.local(),active.features(),new LocalMailSearch.Query("","",0,Long.MAX_VALUE,mailScope),config.maxFileSize());
      String signature=found.stream().map(i->i.item().id()+i.item().status()+i.unknown()+i.threadId()+active.features().pinned("pinnedMail",i.item().id())).reduce("",String::concat)+threads;
      if(signature.equals(rendered)){Platform.runLater(()->{if(generation==viewGeneration){lastMailboxChange=change;lastMailboxScan=System.nanoTime();}});return;}
      var rows=new ArrayList<MailRow>();
      Set<String> groups=new HashSet<>();for(var result:found){var item=result.item();
        if(threads&&!groups.add(result.peerId()+"/"+result.threadId()))continue;
        String subject=result.subject(),file=result.fileCount()==0?"":"Вложения: "+result.fileCount();
        rows.add(new MailRow(item,subject,file,result.unknown(),result.signatureValid(),result.threadId()));
      }
      Platform.runLater(()->{if(!stopping&&session==active&&generation==viewGeneration&&section.equals("mail")){letters.getItems().setAll(rows);rendered=signature;lastMailboxChange=change;lastMailboxScan=System.nanoTime();}});
    }catch(Exception|LinkageError failure){Platform.runLater(()->{if(!stopping&&generation==viewGeneration)letters.setPlaceholder(new Label("Не удалось загрузить письма"));});}
    finally{Platform.runLater(()->refreshing=false);}});
  }
  private void pollNotifications(){
    if(notifying||session==null)return;notifying=true;ClientSession active=session;
    worker.execute(()->{try{boolean mail=false,friend=false;for(var event:active.local().drainNotices()){
      if(!active.features().notifications()||active.features().blocked(event.id(),event.senderId()))continue;
      if(active.features().friend(event.senderId())){if(active.features().friendNotifications())friend=true;}else mail=true;
    }boolean friendEvent=active.takeFriendshipEvent()&&active.features().friendEvents();boolean regular=mail,priority=friend;
    Platform.runLater(()->{if(!stopping&&session==active){if(friendEvent)notifications.show(NotificationCenter.Kind.FRIEND_EVENT);if(priority||regular)notifications.show(priority?NotificationCenter.Kind.FRIEND_MAIL:NotificationCenter.Kind.MAIL);}});
    }catch(Exception ignored){/* The durable inbox is independent of optional notifications. */}finally{Platform.runLater(()->notifying=false);}});
  }
  private void openLetter(LocalStore.MailItem item){
    long ticket=++previewTicket;VBox host=previewHost;
    if(embeddedViewer!=null){embeddedViewer.close();embeddedViewer=null;}
    if(viewers.size()>=4){info("Закройте одно из открытых писем");return;}
    work(null,"",()->{
      var stored=session.local().loadHistory(item.id(),item.outgoing());
      if(!AutomaticEncryption.supports(stored.packet()))return stored;
      return new OpenedMail(stored,automatic.decrypt(stored.packet(),session.local().identity(),config.maxFileSize()),!stored.outgoing()&&!session.local().assessSender(stored.packet()).keyMatches());
    },value->{
      if(value instanceof LocalStore.HistoryItem legacy){openLegacy(legacy);return;}
      var entry=(OpenedMail)value;
      if(stopping||ticket!=previewTicket||entry.item().expiresAt()<=session.local().now()){entry.plain().close();return;}
      MailViewer.Actions actions=new MailViewer.Actions(){
        public void reply(LocalStore.HistoryItem item,PlainMessage plain){prepareResponse(item,plain,"",null,false);}
        public void forward(LocalStore.HistoryItem item,PlainMessage plain,String body,PlainMessage.FileBundle files){prepareResponse(item,plain,body,files,true);}
        public void original(MailContext reference){openReference(reference);}
        public boolean unknown(){return entry.unknown();}
      };
      if(host!=null&&host==previewHost){embeddedViewer=new MailViewer(stage,themes,entry.plain(),entry.item(),worker,()->session.local().now(),host,actions);viewers.add(embeddedViewer);}else viewers.add(new MailViewer(stage,themes,entry.plain(),entry.item(),worker,()->session.local().now(),null,actions));
    });
  }
  private void prepareResponse(LocalStore.HistoryItem item,PlainMessage plain,String body,PlainMessage.FileBundle bundle,boolean forwarded){
    if(item.expiresAt()<=session.local().now()){if(bundle!=null)bundle.close();return;}
    if(composer!=null&&!composer.getText().isBlank()||draft!=null&&!draft.body.isBlank()){
      InWindowAlert confirm=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Заменить текущий черновик?",ButtonType.OK,ButtonType.CANCEL);confirm.initOwner(stage);confirm.setHeaderText(null);themes.apply(confirm.getDialogPane());if(confirm.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK){if(bundle!=null)bundle.close();return;}
    }
    String subject=plain.subject();MailContext source=plain.context();boolean protectedLetter=plain.protectedLetter();
    work(null,"",()->{String thread=source==null||source.forwarded()||source.threadId().isEmpty()?item.id():source.threadId();
      try{return new ResponsePreparation(new MailContext(forwarded?"":thread,item.id(),item.packet().senderNickname(),subject,item.time(),item.expiresAt(),Identity.digest(item.packet()),forwarded),bundle);}catch(Exception failure){if(bundle!=null)bundle.close();throw failure;}
    },prepared->{if(item.expiresAt()<=session.local().now()){prepared.close();return;}clearCompose(false);draft=new Draft();draft.recipient=forwarded?"":item.contact();draft.subject=(forwarded?"Fwd: ":"Re: ")+subject;draft.body=body;draft.context=prepared.context;draft.protectedLetter=protectedLetter;draft.forceProtection=protectedLetter;draft.bundle=prepared.take();draft.ttl=config.defaultTTL();composePage();});
  }
  private void openReference(MailContext reference){
    work(null,"",()->{for(boolean outgoing:new boolean[]{false,true})try{var original=session.local().loadHistory(reference.parentId(),outgoing);
      if(java.security.MessageDigest.isEqual(Identity.digest(original.packet()),reference.digest())&&Identity.verifyPacket(original.packet()))return new LocalStore.MailItem(original.id(),original.contact(),outgoing,original.status(),original.time(),original.expiresAt());
    }catch(java.nio.file.NoSuchFileException absent){}throw new IOException("Исходное письмо недоступно");},this::openLetter);
  }
  private void threadPage(MailRow selectedRow){
    clearCompose();section="thread";viewGeneration++;long generation=viewGeneration;ListView<LocalMailSearch.Result> chain=new ListView<>();threadResults=chain;chain.setCellFactory(list->new ListCell<>(){protected void updateItem(LocalMailSearch.Result r,boolean empty){super.updateItem(r,empty);setText(empty||r==null?null:(r.item().outgoing()?"Вы":r.item().contact())+" · "+r.subject());}});
    chain.setOnMouseClicked(e->{if(e.getClickCount()==2&&chain.getSelectionModel().getSelectedItem()!=null)openLetter(chain.getSelectionModel().getSelectedItem().item());});
    VBox body=new VBox(12,button("← Назад",()->mailboxPage(mailOutgoing,mailScope)),new Label("Цепочка"),chain);body.setPadding(new Insets(20));VBox.setVgrow(chain,Priority.ALWAYS);root.setCenter(body);
    work(null,"",()->LocalMailSearch.find(session.local(),session.features(),new LocalMailSearch.Query("","",0,Long.MAX_VALUE,mailScope==LocalMailSearch.Scope.BLOCKED?LocalMailSearch.Scope.BLOCKED:LocalMailSearch.Scope.ALL),config.maxFileSize()),found->{if(section.equals("thread")&&generation==viewGeneration){var anchor=found.stream().filter(r->r.item().id().equals(selectedRow.item().id())).findFirst();if(anchor.isPresent())chain.getItems().setAll(found.stream().filter(r->r.threadId().equals(selectedRow.thread())&&r.peerId().equals(anchor.get().peerId())).sorted(Comparator.comparingLong(r->r.item().time())).toList());}});
  }
  void composePage(){
    clearCompose();section="compose";viewGeneration++;
    recipientPicker=new ContactPicker(session.local().contacts().stream().map(UserInfo::nickname).toList(),themes);recipientPicker.setCellFactory(list->contactCell());recipientPicker.setButtonCell(contactCell());recipientField=recipientPicker.getEditor();recipientField.setText(selected);
    subjectField=field("Тема");composer=new TextArea();composer.setPromptText("Текст письма");composer.setWrapText(true);composer.setPrefRowCount(14);
    letterPassword=new SecretField("Пароль письма");secondCode=new SecretField("Код второго слоя");
    additionalProtection=new CheckBox("Дополнительная защита");additionalProtection.setSelected(false);
    letterPassword.visibleProperty().bind(additionalProtection.selectedProperty());letterPassword.managedProperty().bind(additionalProtection.selectedProperty());secondCode.visibleProperty().bind(additionalProtection.selectedProperty());secondCode.managedProperty().bind(additionalProtection.selectedProperty());
    ttl=new Selector<>(themes);ttl.getItems().addAll(new Ttl("5 минут",300),new Ttl("30 минут",1800),new Ttl("1 час",3600),new Ttl("6 часов",21600),new Ttl("1 день",86400),new Ttl("3 дня",259200),new Ttl("7 дней",604800));
    ttl.getSelectionModel().select(ttl.getItems().stream().filter(t->t.seconds()==config.defaultTTL()).findFirst().orElse(ttl.getItems().get(4)));
    ttl.setVisibleRowCount(7);ttl.setPrefWidth(185);themes.stylePopup(ttl);
    attachmentLabel=new Label();attachmentsBox=new VBox(5);Button send=new Button("Отправить");sendButton=send;send.setDisable(!session.online()||tor==null||!tor.ready());send.setOnAction(e->send(send));
    ScrollPane attachmentScroll=new ScrollPane(attachmentsBox);attachmentScroll.setFitToWidth(true);attachmentScroll.setMaxHeight(130);attachmentScroll.setPrefHeight(0);attachmentScroll.visibleProperty().bind(javafx.beans.binding.Bindings.isNotEmpty(attachmentsBox.getChildren()));attachmentScroll.managedProperty().bind(attachmentScroll.visibleProperty());attachmentsBox.getChildren().addListener((javafx.collections.ListChangeListener<javafx.scene.Node>)change->attachmentScroll.setPrefHeight(Math.min(130,attachmentsBox.getChildren().size()*40)));
    HBox address=new HBox(14,recipientPicker,new VBox(5,new Label("Хранить:"),ttl));HBox.setHgrow(recipientPicker,Priority.ALWAYS);address.setAlignment(Pos.BOTTOM_LEFT);
    VBox box=new VBox(12,new Label("Новое письмо"),new Label("Кому"),address,subjectField,composer,additionalProtection,letterPassword,secondCode,attachmentScroll,new HBox(10,button("+ Прикрепить",this::attach),attachmentLabel),send);
    if(draft!=null){recipientField.setText(draft.recipient);subjectField.setText(draft.subject);composer.setText(draft.body);attachments.addAll(draft.files);additionalProtection.setSelected(draft.protectedLetter);letterPassword.hidden.setText(new String(draft.password));secondCode.hidden.setText(new String(draft.code));replyContext=draft.context;replyNeedsProtection=draft.forceProtection;forwardedFiles=draft.bundle;draft.bundle=null;
      ttl.getItems().stream().filter(t->t.seconds()==draft.ttl).findFirst().ifPresent(t->ttl.setValue(t));draft.close();draft=null;
    }
    additionalProtection.setDisable(replyNeedsProtection);if(replyContext!=null)box.getChildren().add(2,new Label((replyContext.forwarded()?"Пересылка: ":"Ответ: ")+replyContext.author()+" · "+replyContext.subject()));
    showAttachments();
    box.setPadding(new Insets(22));VBox.setVgrow(composer,Priority.ALWAYS);ScrollPane scroll=new ScrollPane(box);scroll.setFitToWidth(true);scroll.setFitToHeight(true);root.setCenter(scroll);
  }
  private void send(Button button){
    try{
      if(updates.snapshot().manifest()!=null&&updates.snapshot().manifest().requiredFor(SignedManifest.CURRENT)){info("Для продолжения требуется обновление АЕГИС");updatesPage();return;}
      String nick=Limits.nickname(recipientField.getText());UserInfo recipient=session.local().contact(nick);
      if(!session.online()||tor==null||!tor.ready()){info("Войдите в сеть для отправки");return;}
      if(recipient==null){info("Сначала добавьте и проверьте контакт");return;}
      Ttl lifetime=ttl.getValue();if(lifetime==null||lifetime.seconds()<60||lifetime.seconds()>604800){info("Выберите срок хранения");return;}
      char[] password=letterPassword.value(),code=secondCode.value();
      boolean protectedLetter=additionalProtection.isSelected();
      if(protectedLetter&&(password.length<8||code.length==0)){Arrays.fill(password,'\0');Arrays.fill(code,'\0');info("Введите новый пароль письма от 8 символов и код второго слоя");return;}
      String body=composer.getText(),subject=subjectField.getText();List<Path> files=List.copyOf(attachments);long generation=viewGeneration;
      MailContext context=replyContext;
      PlainMessage.FileBundle bundle=forwardedFiles==null?null:forwardedFiles.copy();
      letterPassword.clear();secondCode.clear();
      work(button,"Шифрование…",()->{
        byte[] envelope=null;try{
          if(protectedLetter)envelope=LetterEnvelope.seal(body,password,code);
          // Ordinary single-file mail stays readable by 1.0, even after a peer downgraded.
          boolean rich=session.local().cachedProfile(nick)!=null&&(context!=null||files.size()+(bundle==null?0:bundle.info().size())>1);
          try(var plain=PlainMessage.compose(subject,body,envelope==null?new byte[0]:envelope,files,bundle,config.maxFileSize(),context,rich)){
            var packet=automatic.encrypt(plain,lifetime.seconds(),config.deliveryTTL(),session.local().identity(),session.local().nickname(),recipient);
            var result=session.network().deliverDetailed(packet);session.local().saveSent(packet,recipient.nickname(),result.confirmedAt());return result;
          }
        }finally{Arrays.fill(password,'\0');Arrays.fill(code,'\0');if(envelope!=null)Arrays.fill(envelope,(byte)0);if(bundle!=null)bundle.close();}
      },result->{if(generation==viewGeneration){clearCompose(false);mailboxPage(true);}});
    }catch(Exception failure){error(failure);}
  }
  private void contactsPage(){contactsPage(false);}
  private void contactsPage(boolean friends){
    clearCompose();section=friends?"friends":"contacts";viewGeneration++;contacts=new ListView<>();contacts.setPlaceholder(new Label("Добавьте контакт"));
    contacts.setCellFactory(list->contactCell());TextField search=field(friends?"Поиск по друзьям":"Поиск по контактам");contactSearch=search;search.textProperty().addListener((o,a,b)->fillContacts(b));
    contacts.getSelectionModel().selectedItemProperty().addListener((o,a,b)->selected=b==null?"":b);
    Button verify=button("Отпечаток",()->{if(!selected.isBlank())info(selected+"\n\n"+fingerprint(session.local().contact(selected).userId()));});
    Button remove=button(friends?"Убрать из друзей":"Удалить контакт",()->{if(!selected.isBlank()){String nick=selected;UserInfo peer=session.local().contact(nick);ClientSession active=session;work(null,"",()->{active.features().consent(peer.userId(),false);if(active.online())active.syncPublicData(peer);if(!friends)active.local().removeContact(nick);return true;},v->fillContacts(search.getText()));}});
    Button pin=button("☆ Избранное",()->{UserInfo peer=session.local().contact(selected);if(peer!=null)work(null,"",()->{session.features().pin("pinnedContacts",peer.userId(),!session.features().pinned("pinnedContacts",peer.userId()));return true;},v->fillContacts(search.getText()));});
    Button viewProfile=button("Профиль",()->{if(!selected.isBlank())contactProfile(selected);});
    VBox box=new VBox(12,search,contacts,new FlowPane(10,10,button("+ Контакт",this::addContact),verify,viewProfile,pin,remove),button("Написать письмо",this::composePage));box.setPadding(new Insets(16));VBox.setVgrow(contacts,Priority.ALWAYS);root.setCenter(box);fillContacts("");
  }
  private void friendsPage(){contactsPage(true);}
  private void searchPage(){
    clearCompose();section="search";viewGeneration++;TextField nick=field("Ник / отправитель"),subject=field("Тема");DatePicker from=new DatePicker(),to=new DatePicker();
    Selector<LocalMailSearch.Scope> scope=new Selector<>(themes,List.of(LocalMailSearch.Scope.values()),LocalMailSearch.Scope.ALL);
    ListView<LocalMailSearch.Result> results=new ListView<>();results.setCellFactory(list->new ListCell<>(){protected void updateItem(LocalMailSearch.Result r,boolean empty){super.updateItem(r,empty);setText(empty||r==null?null:r.item().contact()+" · "+(r.subject().isBlank()?"Без темы":r.subject()));}});
    results.setOnMouseClicked(e->{if(e.getClickCount()==2){var chosen=results.getSelectionModel().getSelectedItem();if(chosen!=null)openLetter(chosen.item());}});
    Button search=new Button("Найти");search.setOnAction(e->{try{long a=from.getValue()==null?0:from.getValue().atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli(),b=to.getValue()==null?Long.MAX_VALUE:to.getValue().plusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()-1;
      var query=new LocalMailSearch.Query(nick.getText(),subject.getText(),a,b,scope.getValue());long generation=viewGeneration;work(search,"Поиск…",()->LocalMailSearch.find(session.local(),session.features(),query,config.maxFileSize()),found->{if(section.equals("search")&&generation==viewGeneration)results.getItems().setAll(found);});
    }catch(Exception failure){error(failure);}});
    VBox body=new VBox(10,new Label("Поиск на устройстве"),nick,subject,new HBox(10,from,to),scope,search,results);body.setPadding(new Insets(20));VBox.setVgrow(results,Priority.ALWAYS);root.setCenter(body);
  }
  private void fillContacts(String term){
    if(contacts==null)return;String old=selected;
    contacts.getItems().setAll(session.local().contacts().stream().filter(u->!section.equals("friends")||session.features().friend(u.userId())).sorted(Comparator.comparing((UserInfo u)->!session.features().pinned("pinnedContacts",u.userId())).thenComparing(UserInfo::nickname)).map(UserInfo::nickname).filter(s->s.contains(term.toLowerCase(Locale.ROOT))).toList());
    if(!old.isEmpty())contacts.getSelectionModel().select(old);
  }
  private static String fileSize(long bytes){return String.format(Locale.ROOT,"%.1f MB",bytes/1048576.0);}
  private void showAttachments(){
    if(attachmentsBox==null)return;attachmentsBox.getChildren().clear();long total=0;
    for(Path path:List.copyOf(attachments)){long size;try{size=Files.size(path);}catch(IOException e){size=0;}total+=size;
      Label name=new Label(path.getFileName()+"  "+fileSize(size));name.setMaxWidth(Double.MAX_VALUE);HBox.setHgrow(name,Priority.ALWAYS);
      HBox row=new HBox(8,name,button("×",()->{attachments.remove(path);showAttachments();}));attachmentsBox.getChildren().add(row);
    }if(forwardedFiles!=null){total+=forwardedFiles.size();for(var file:forwardedFiles.info())attachmentsBox.getChildren().add(new Label("↪ "+file.name()+"  "+fileSize(file.size())));attachmentsBox.getChildren().add(button("Убрать пересылаемые вложения",()->{forwardedFiles.close();forwardedFiles=null;showAttachments();}));}
    attachmentLabel.setText("Общий размер: "+fileSize(total)+" / "+fileSize(config.maxFileSize()));
  }
  private void attach(){InWindowFileChooser chooser=new InWindowFileChooser();chooser.setTitle("Прикрепить файлы");var files=chooser.showOpenMultipleDialog(stage);if(files==null)return;
    try{List<Path> next=new ArrayList<>(attachments);long total=forwardedFiles==null?0:forwardedFiles.size();int forwardedCount=forwardedFiles==null?0:forwardedFiles.info().size();for(Path path:next)total+=Files.size(path);
      for(File file:files){Path path=file.toPath();PlainMessage.validateFilename(file.getName());if(Files.isSymbolicLink(path)||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Выберите обычный файл");if(next.contains(path))continue;total+=Files.size(path);if(total>config.maxFileSize())throw new PlainMessage.FileLimitException(config.maxFileSize());next.add(path);if(next.size()+forwardedCount>PlainMessage.MAX_ATTACHMENTS)throw new IllegalArgumentException("Не более 64 вложений");}
      attachments.clear();attachments.addAll(next);showAttachments();
    }catch(Exception ex){error(ex);}
  }
  private void addContact(){if(!session.online()||tor==null||!tor.ready()){info("Войдите в сеть для добавления контакта");return;}InWindowTextInput d=new InWindowTextInput();d.setTitle("Новый контакт");d.setHeaderText("Ник");d.initOwner(stage);themes.apply(d.getDialogPane());d.showAndWait().ifPresent(n->work(null,"",()->session.network().find(n),u->{var ask=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Сверьте отпечаток с контактом по другому каналу:\n\n"+fingerprint(u.userId()),ButtonType.OK,ButtonType.CANCEL);ask.initOwner(stage);ask.setHeaderText(u.nickname());themes.apply(ask.getDialogPane());if(ask.showAndWait().orElse(ButtonType.CANCEL)==ButtonType.OK)work(null,"",()->{session.local().trust(u);session.features().consent(u.userId(),true);try{session.syncPublicData(u);}catch(Exception unavailable){/* Saved contact remains usable; public sync retries separately. */}return u;},v->{fillContacts("");if(contacts!=null)contacts.getSelectionModel().select(v.nickname());loadAvatars();});}));}
  private static String fingerprint(String id){return id.replaceAll("(.{8})(?!$)","$1 ");}
  private void openLegacy(LocalStore.HistoryItem item){
    char[] pwd=askPassword("Расшифровать письмо","Ключ сообщения");if(pwd==null)return;
    work(null,"",()->{try{if(item.expiresAt()<=session.local().now())throw new IOException("Сообщение удалено");return session.crypto().decrypt(item.packet(),pwd,config.maxFileSize());}finally{Arrays.fill(pwd,'\0');}},plain->{
      InWindowDialog<Void> view=new InWindowDialog<>();view.initOwner(stage);view.setTitle("Письмо 0.1.0");view.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
      TextArea text=new TextArea(plain.text());text.setEditable(false);text.setWrapText(true);VBox content=new VBox(12,text);
      if(!plain.filename().isEmpty())content.getChildren().add(button("Сохранить "+plain.filename(),()->{if(item.expiresAt()<=session.local().now()){view.close();return;}InWindowFileChooser picker=new InWindowFileChooser();picker.setInitialFileName(plain.filename());var file=picker.showSaveDialog(stage);if(file!=null&&item.expiresAt()>session.local().now())try{plain.exportTo(file.toPath());}catch(IOException ex){error(ex);}}));
      view.getDialogPane().setContent(content);PauseTransition expiry=new PauseTransition(Duration.millis(Math.max(1,item.expiresAt()-session.local().now())));expiry.setOnFinished(e->view.close());
      try{if(item.expiresAt()>session.local().now()){expiry.play();themes.apply(view.getDialogPane());view.showAndWait();}}finally{expiry.stop();text.clear();plain.close();}
    });
  }
  private void settings(){
    InWindowDialog<Void> d=new InWindowDialog<>();d.initOwner(stage);d.setTitle("Настройки");d.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);VBox items=new VBox(9);
    items.getChildren().addAll(button("Профиль",()->{d.close();profile();}),button("Безопасность",()->info("Шифрование выполняется на устройстве. Сверяйте отпечатки контактов. Подробности — SECURITY.md.")),button("Завершить сохранённую сессию",()->{d.close();endRemembered();}),button("Уведомления",this::notificationSettings),button("Внешний вид",this::appearance),button("Обновления",this::updatesPage),button("Экспорт резервной копии идентичности",this::backup),button("О программе",()->info("АЕГИС "+SignedManifest.CURRENT+"\nАвтономная Единая Гибридная Информационная Система\n\nJava 21 · protocol 1")),button("Для разработчиков / Диагностика",this::diagnostics));items.setPadding(new Insets(14));d.getDialogPane().setContent(items);themes.apply(d.getDialogPane());d.showAndWait();
  }
  private void notificationSettings(){
    InWindowDialog<Void> dialog=new InWindowDialog<>();dialog.initOwner(stage);dialog.setTitle("Уведомления");dialog.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
    CheckBox mail=new CheckBox("Письма"),friends=new CheckBox("Приоритет писем друзей"),events=new CheckBox("События дружбы"),releases=new CheckBox("Обновления");
    var preferences=session.features();mail.setSelected(preferences.notifications());friends.setSelected(preferences.friendNotifications());events.setSelected(preferences.friendEvents());releases.setSelected(preferences.updateNotifications());
    Button save=new Button("Сохранить");save.setOnAction(e->{boolean a=mail.isSelected(),b=friends.isSelected(),c=events.isSelected(),d=releases.isSelected();work(save,"Сохранение…",()->{preferences.notifications(a,b,c,d);return true;},done->dialog.close());});
    dialog.getDialogPane().setContent(new VBox(12,mail,friends,events,releases,save));themes.apply(dialog.getDialogPane());dialog.showAndWait();
  }
  private void appearance(){
    InWindowDialog<Void> d=new InWindowDialog<>();d.initOwner(stage);d.setTitle("Внешний вид");d.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
    boolean[] loading={false};Selector<ThemeManager.Theme> theme=new Selector<>(themes,List.of(ThemeManager.Theme.values()),themes.selected());theme.valueProperty().addListener((o,a,b)->{if(loading[0]||b==null)return;try{themes.select(b);}catch(IOException e){error(e);}});
    Selector<String> preset=new Selector<>(themes,presets.presets().keySet(),null);
    Selector<Integer> scale=new Selector<>(themes,List.of(80,90,100,110,125,150,175,200),layout.scale());
    Selector<UiPreferences.Density> density=new Selector<>(themes,List.of(UiPreferences.Density.values()),layout.density());
    Selector<UiPreferences.Avatars> avatars=new Selector<>(themes,List.of(UiPreferences.Avatars.values()),layout.avatars());
    Selector<UiPreferences.Preview> preview=new Selector<>(themes,List.of(UiPreferences.Preview.values()),layout.preview());
    CheckBox sidebar=new CheckBox("Показывать боковую панель"),subject=new CheckBox("Показывать тему"),date=new CheckBox("Показывать дату");sidebar.setSelected(layout.sidebar());subject.setSelected(layout.subject());date.setSelected(layout.date());
    Runnable apply=()->{try{applyLayout(new UiPreferences(scale.getValue(),density.getValue(),sidebar.isSelected(),avatars.getValue(),preview.getValue(),subject.isSelected(),date.isSelected()));}catch(Exception e){error(e);}};
    scale.valueProperty().addListener((o,a,b)->{if(b!=null&&!loading[0])apply.run();});
    preset.setOnAction(e->{UiPreferences value=presets.presets().get(preset.getValue());if(value==null)return;try{loading[0]=true;scale.setValue(value.scale());density.setValue(value.density());avatars.setValue(value.avatars());preview.setValue(value.preview());sidebar.setSelected(value.sidebar());subject.setSelected(value.subject());date.setSelected(value.date());applyLayout(value);}catch(IOException ex){error(ex);}finally{loading[0]=false;}});
    Button save=button("Сохранить как пресет",()->new InWindowTextInput().showAndWait().ifPresent(name->{try{apply.run();presets.add(name,layout);preset.getItems().setAll(presets.presets().keySet());preset.setValue(name);}catch(IOException ex){error(ex);}}));
    Button rename=button("Переименовать",()->{String old=preset.getValue();if(!presets.customNames().contains(old))return;new InWindowTextInput(old).showAndWait().ifPresent(name->{try{presets.rename(old,name);preset.getItems().setAll(presets.presets().keySet());preset.setValue(name);}catch(IOException ex){error(ex);}});});
    Button remove=button("Удалить",()->{try{presets.remove(preset.getValue());preset.getItems().setAll(presets.presets().keySet());}catch(IOException ex){error(ex);}});
    Button export=button("Экспорт JSON",()->{InWindowFileChooser picker=new InWindowFileChooser();picker.setInitialFileName("AEGIS-preset.json");var file=picker.showSaveDialog(stage);if(file!=null)try{presets.exportPreset(preset.getValue(),file.toPath());}catch(IOException ex){error(ex);}});
    Button imports=button("Импорт JSON",()->{InWindowFileChooser picker=new InWindowFileChooser();var file=picker.showOpenDialog(stage);if(file!=null)try{presets.importPreset(file.toPath());preset.getItems().setAll(presets.presets().keySet());}catch(IOException ex){error(ex);}});
    VBox body=new VBox(8,new Label("Тема"),new HBox(8,theme,button("Как в системе",()->{try{loading[0]=true;themes.selectSystem();theme.setValue(themes.selected());}catch(IOException e){error(e);}finally{loading[0]=false;}})),new Label("Пресет"),preset,new Label("Масштаб, %"),scale,new Label("Плотность списка"),density,new Label("Аватары"),avatars,new Label("Предпросмотр"),preview,sidebar,subject,date,button("Применить",apply),save,new HBox(8,rename,remove),new HBox(8,export,imports));body.setPadding(new Insets(12));ScrollPane scroll=new ScrollPane(body);scroll.setFitToWidth(true);scroll.setPrefViewportHeight(520);d.getDialogPane().setContent(scroll);themes.apply(d.getDialogPane());d.showAndWait();
  }
  private void applyLayout(UiPreferences value)throws IOException {
    UiPreferences previous=layout;presets.apply(value);layout=value;themes.layout(value);
    // Appearance must not replace the active scene graph or clear a draft/password.
    Node sidebar=root.getLeft();if(sidebar!=null){sidebar.setVisible(value.sidebar());sidebar.setManaged(value.sidebar());}
    if(letters!=null)letters.refresh();if(contacts!=null)contacts.refresh();if(section.equals("mail")&&previous.preview()!=value.preview())mailboxPage(mailOutgoing,mailScope);
  }
  private Node avatar(String nick){return AvatarView.create(nick,avatarImages,layout.avatars());}
  private ListCell<String> contactCell(){return new ListCell<>(){protected void updateItem(String nick,boolean empty){super.updateItem(nick,empty);setText(null);setGraphic(empty||nick==null?null:new HBox(8,avatar(nick),new Label(nick)));}};}
  private void loadAvatars(){ClientSession active=session;work(null,"",()->{Map<String,Image> images=new HashMap<>();List<String> names=new ArrayList<>(active.local().contacts().stream().map(UserInfo::nickname).toList());names.add(active.local().nickname());for(String nick:names){byte[] data=null;try{data=active.local().avatar(nick);if(data!=null){byte[] bounded=AvatarCodec.normalize(data);try{Image image=new Image(new ByteArrayInputStream(bounded));if(!image.isError())images.put(nick,image);}finally{Arrays.fill(bounded,(byte)0);}}}catch(IOException|java.security.GeneralSecurityException invalidImage){/* One invalid image never suppresses other verified profiles. */}finally{if(data!=null)Arrays.fill(data,(byte)0);}}return images;},images->{if(active!=session)return;avatarImages.clear();avatarImages.putAll(images);if(contacts!=null)contacts.refresh();if(letters!=null)letters.refresh();if(accountAvatar!=null)accountAvatar.getChildren().setAll(avatar(active.local().nickname()));if(section.equals("profile")&&profileAvatar!=null)profileAvatar.getChildren().setAll(avatar(active.local().nickname()));});}
  private void chooseAvatar(String nick){
    if(!nick.equals(session.local().nickname()))return;InWindowFileChooser picker=new InWindowFileChooser();picker.setTitle("Аватар");picker.getExtensionFilters().add(new FileChooser.ExtensionFilter("JPG, PNG, WebP · до 2 МБ","*.png","*.jpg","*.jpeg","*.webp"));var file=picker.showOpenDialog(stage);if(file==null)return;ClientSession active=session;
    work(null,"",()->AvatarCodec.preview(file.toPath()),preview->{try{byte[] png=AvatarCrop.show(stage,themes,preview);if(png==null)return;work(null,"",()->{try{active.local().avatar(nick,png);active.features().profileChanged();if(active.online())active.syncPublicData(null);return true;}finally{Arrays.fill(png,(byte)0);}},v->loadAvatars());}catch(Exception e){error(e);}finally{Arrays.fill(preview,(byte)0);}});
  }
  private void contactProfile(String nick){
    clearCompose();section="contact-profile";viewGeneration++;ClientSession active=session;
    work(null,"",()->{if(active.online())try{active.syncPublicData(active.local().contact(nick));}catch(Exception unavailable){}return active.local().cachedProfile(nick);},profile->{if(session!=active||!section.equals("contact-profile"))return;UserInfo peer=active.local().contact(nick);if(peer==null)return;
      Label about=new Label(profile!=null&&profile.visible()?profile.about():"Публичные данные скрыты или недоступны");about.setWrapText(true);
      VBox content=new VBox(14,button("← Контакты",this::contactsPage),avatar(nick),new Label(nick),about,new Label(fingerprint(peer.userId())),new Label(profile==null?"Идентичность контакта проверена":"Подпись и идентичность проверены"));content.setPadding(new Insets(24));root.setCenter(content);
    });
  }
  private void profile(){
    clearCompose();section="profile";viewGeneration++;String nick=session.local().nickname();
    Label heading=new Label("Профиль");heading.getStyleClass().add("brand");TextField immutable=new TextField(nick);immutable.setEditable(false);
    TextArea about=new TextArea(session.features().about());about.setPromptText("О себе");about.setWrapText(true);about.setPrefRowCount(4);
    CheckBox visible=new CheckBox("Публичный профиль");visible.setSelected(session.features().visible());
    Label status=new Label(session.publicStatus());status.getStyleClass().add("muted");
    profileAvatar=new VBox(avatar(nick));VBox body=new VBox(12,heading,profileAvatar,immutable,new HBox(8,button("Изменить аватар",()->chooseAvatar(nick)),button("Убрать",()->work(null,"",()->{session.local().avatar(nick,null);session.features().profileChanged();return true;},v->loadAvatars()))),about,visible);
    Button save=new Button("Сохранить");save.setOnAction(e->{String text=about.getText();boolean show=visible.isSelected();ClientSession active=session;work(save,"Сохранение…",()->{active.features().profile(text,show);if(active.online())active.syncPublicData(null);return true;},v->status.setText(active.online()?active.publicStatus():"Сохранено на устройстве"));});
    body.getChildren().addAll(save,status);body.setPadding(new Insets(24));body.setMaxWidth(620);root.setCenter(new StackPane(body));
  }
  private void saveRemembered(ClientSession opened){try{remembered=new RememberedLogin(AppPaths.root(),SystemSecrets.current(AppPaths.root()),Clock.systemUTC());remembered.save(opened);rememberedExpires=System.currentTimeMillis()+RememberedLogin.LOCAL_AGE;}catch(Exception failure){rememberedExpires=0;Platform.runLater(()->{if(!stopping)info("Вход выполнен. Сохранить сессию не удалось: защищённое хранилище системы недоступно.");});}}
  private void tryRemembered(){if(resumeAttempted||config.relayOnionAddress().isBlank())return;resumeAttempted=true;worker.execute(()->{ClientSession opened=null;try{remembered=new RememberedLogin(AppPaths.root(),SystemSecrets.current(AppPaths.root()),Clock.systemUTC());var result=remembered.load(config.relayOnionAddress());if(result.isEmpty())return;try(var resume=result.get()){byte[] key=resume.vaultKey();try{LocalStore local=LocalStore.resume(config.storagePath(),key,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage());opened=new ClientSession(config,local);}finally{Arrays.fill(key,(byte)0);}ClientSession value=opened;long expires=resume.expiresAt(),relayExpires=resume.relayExpiresAt();String token=resume.token();Platform.runLater(()->{if(stopping||session!=null){try{value.close();}catch(IOException ignored){}return;}session=value;rememberedExpires=expires;pendingRelayExpiry=relayExpires;pendingRelayToken=token;afterLogin();});}}catch(Exception|LinkageError unavailable){if(opened!=null)try{opened.close();}catch(IOException ignored){}/* No unprotected fallback, the ordinary login form remains usable. */}});}
  private void resumeNetwork(){if(session==null||!relayReady||resumingNetwork||pendingRelayToken.isEmpty())return;if(System.currentTimeMillis()>=pendingRelayExpiry){pendingRelayToken="";return;}resumingNetwork=true;ClientSession active=session;String token=pendingRelayToken;pendingRelayToken="";worker.execute(()->{try{active.resume(token);}catch(Exception unavailable){/* A rebooted relay or expired token requires the account password again. */}finally{Platform.runLater(()->{resumingNetwork=false;if(active==session)refresh();});}});}
  private void reconnectAccount(){if(session==null||!relayReady){info("Нет соединения с сервером");return;}char[] password=askPassword("Войти в сеть","Пароль аккаунта");if(password==null)return;ClientSession active=session;work(accountReconnect,"Вход…",()->{try{active.reauthenticate(password);if(rememberedExpires>0)saveRemembered(active);return true;}finally{Arrays.fill(password,'\0');}},v->refresh());}
  private void endRemembered(){if(timer!=null)timer.stop();ClientSession active=session;session=null;rememberedExpires=0;pendingRelayToken="";viewGeneration++;clearCompose(false);for(var view:viewers)view.close();viewers.clear();avatarImages.clear();loginPage();worker.execute(()->{try{if(active!=null&&active.network()!=null)active.network().logout();if(active!=null)active.close();if(remembered!=null)remembered.clear();else Files.deleteIfExists(AppPaths.root().resolve("session/resume.enc"));}catch(Exception failure){Platform.runLater(()->{if(!stopping)info("Не удалось полностью удалить сохранённую сессию. Проверьте доступ к хранилищу системы.");});}});}
  private void updateChanged(UpdateService.Snapshot snapshot){if(stopping)return;if(updatesView!=null&&updatesView.showing())updatesView.refresh(snapshot);if(updateBadge!=null){boolean available=snapshot.manifest()!=null&&snapshot.manifest().newerThan(SignedManifest.CURRENT);updateBadge.setVisible(available);updateBadge.setManaged(available);updateBadge.setText(available&&snapshot.manifest().requiredFor(SignedManifest.CURRENT)?"⬇ Требуется обновление":"⬇ Обновление");}if(snapshot.announcement()&&snapshot.manifest()!=null&&session!=null){try{if(session.features().updateNotifications())notifications.show(NotificationCenter.Kind.UPDATE);updates.announcementShown();}catch(IOException ignored){/* The verified history remains available; a failed marker cannot forge a letter. */}}}
  private void updatesPage(){updatesView=new UpdatesView(stage,themes,updates,updatePreferences,p->{try{if(!p.channel().equals(updatePreferences.channel()))updates.channel(p.channel());p.save(AppPaths.root());updatePreferences=p;}catch(Exception e){throw new IllegalStateException(e);}},this::installUpdate);updatesView.show();}
  private void systemLetters(){clearCompose();section="system";viewGeneration++;long generation=viewGeneration;VBox body=new VBox(10,new Label("⚙ Системные"));body.setPadding(new Insets(14));ScrollPane scroll=new ScrollPane(body);scroll.setFitToWidth(true);root.setCenter(scroll);work(null,"",updates::history,history->{if(!section.equals("system")||viewGeneration!=generation)return;var newer=history.stream().filter(m->m.announcement().showAsLetter()&&m.newerThan(SignedManifest.CURRENT)).toList();if(newer.isEmpty())body.getChildren().add(new Label("Системных писем пока нет"));for(var release:newer){Label title=new Label(release.announcement().title()),summary=new Label(release.announcement().summary());summary.setWrapText(true);VBox letter=new VBox(7,new Label("⚙ АЕГИС · проверенная подпись"),title,summary,new HBox(8,button("Что нового",()->UpdatesView.notes(stage,themes,release)),button("Обновления",this::updatesPage)));letter.getStyleClass().add("system-letter");body.getChildren().add(letter);}});}
  private void installUpdate(){if(installingUpdate||updates.snapshot().state()!=UpdateService.State.READY_TO_INSTALL)return;InWindowAlert confirm=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Установить проверенное обновление и перезапустить АЕГИС?",ButtonType.OK,ButtonType.CANCEL);confirm.setHeaderText(null);confirm.initOwner(stage);themes.apply(confirm.getDialogPane());if(confirm.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK)return;installingUpdate=true;worker.execute(()->{try{long launcher=AppPaths.windows()?ProcessHandle.current().parent().orElseThrow().pid():0;Path job=updates.prepareInstall(AppPaths.bundle(),ProcessHandle.current().pid(),launcher);UpdateInstaller.launch(job);updates.restarting();Platform.runLater(this::stop);}catch(Exception failure){updates.installFailed();Platform.runLater(()->{installingUpdate=false;if(!stopping)info("Обновление не установлено. Текущая версия сохранена.");});}});}
  private void backup(){InWindowFileChooser chooser=new InWindowFileChooser();chooser.setInitialFileName("AEGIS-identity.aegis-backup");var file=chooser.showSaveDialog(stage);if(file!=null)work(null,"",()->{session.local().exportIdentity(file.toPath());return true;},v->info("Резервная копия сохранена. Для восстановления используется пароль аккаунта на момент экспорта."));}
  private void restore(){InWindowFileChooser chooser=new InWindowFileChooser();chooser.setTitle("Восстановить идентичность");var file=chooser.showOpenDialog(stage);if(file==null)return;char[] pass=askPassword("Восстановить идентичность","Пароль резервной копии / хранилища");if(pass==null)return;Path target=AppPaths.root().resolve("restored-"+UUID.randomUUID());work(null,"",()->{try{LocalStore.restoreIdentity(file.toPath(),target,pass,config.maxCiphertext(),config.maxLocalStorage());var c=config.withStorage(target);c.save(AppPaths.config());return c;}finally{Arrays.fill(pass,'\0');}},c->{config=c;info("Идентичность восстановлена. Войдите в аккаунт.");loginPage();});}
  private char[] askPassword(String title,String prompt){InWindowDialog<char[]> d=new InWindowDialog<>();d.initOwner(stage);d.setTitle(title);PasswordField p=password(prompt);p.getStyleClass().add("secret-entry");VBox body=form(title,new Label(prompt),p);if(title.equals("Обновление хранилища"))body.getChildren().add(new Label("Требуется один раз для переноса данных старой версии."));d.getDialogPane().setContent(body);d.getDialogPane().getButtonTypes().addAll(ButtonType.OK,ButtonType.CANCEL);d.setResultConverter(b->b==ButtonType.OK?p.getText().toCharArray():null);themes.apply(d.getDialogPane());var result=d.showAndWait().orElse(null);p.clear();return result;}
  private void connectionDialog(){
    InWindowDialog<Void> dialog=new InWindowDialog<>();dialog.initOwner(stage);dialog.setTitle("Соединение");dialog.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
    Label status=new Label(tor!=null&&tor.ready()&&relayReady?"Соединение защищено":"Нет соединения. Прямое подключение отключено.");status.setWrapText(true);
    Button retry=button(connectingTor?"Подключение…":"Повторить соединение",()->{dialog.close();if(tor==null||!tor.ready())startTor();else preconnect();});retry.setDisable(connectingTor);
    dialog.getDialogPane().setContent(new VBox(12,status,retry,button("Диагностика",this::diagnostics)));themes.apply(dialog.getDialogPane());dialog.showAndWait();
  }
  private void diagnostics(){info("Версия: "+SignedManifest.CURRENT+" · protocol 1\nTor: "+(tor!=null&&tor.ready()?"100%":"не подключён")+"\nSOCKS: 127.0.0.1:"+config.torSocksPort()+"\nОбновления SOCKS: 127.0.0.1:"+config.torUpdateSocksPort()+"\nControlPort: 127.0.0.1:"+config.torControlPort()+"\nRelay: "+config.relayOnionAddress()+"\n"+(session==null?"":session.status())+"\nРежим: "+(tor==null?"—":tor.mode())+"\nЛоги: "+AppPaths.root().resolve("logs"));}
  private void info(String text){InWindowAlert d=new InWindowAlert(Alert.AlertType.INFORMATION,text,ButtonType.OK);d.setHeaderText(null);d.setTitle("АЕГИС");d.initOwner(stage);themes.apply(d.getDialogPane());d.showAndWait();}
  private void error(Throwable error){String message;
    if(error instanceof PlainMessage.FileLimitException)message="Файл превышает допустимый размер сервера.";
    else if(error instanceof AccountLogin.OldPasswordRequired)message=error.getMessage();
    else if(error instanceof RequestRejected||error instanceof IllegalArgumentException||"АЕГИС уже запущен".equals(error.getMessage()))message=error.getMessage();
    else if(error instanceof javax.crypto.AEADBadTagException)message="Неверный пароль или локальное хранилище повреждено";
    else if(error instanceof java.security.GeneralSecurityException)message="Не удалось открыть зашифрованные данные";
    else if(error instanceof LinkageError)message="Компонент приложения недоступен. Распакуйте полный пакет АЕГИС.";
    else message="Не удалось выполнить действие. Проверьте соединение и доступ к локальным данным.";
    InWindowAlert d=new InWindowAlert(Alert.AlertType.ERROR,message,ButtonType.OK);d.initOwner(stage);d.setTitle("АЕГИС");d.setHeaderText(null);d.getDialogPane().setExpandableContent(new Label("Тип: "+error.getClass().getSimpleName()));themes.apply(d.getDialogPane());d.showAndWait();
  }
  @Override public void stop(){if(stopping)return;stopping=true;if(stage!=null)InWindowDialog.closeAll(stage);if(timer!=null)timer.stop();clearCompose(false);for(var view:viewers)view.close();viewers.clear();avatarImages.clear();pendingRelayToken="";if(updates!=null)updates.close();if(notifications!=null)notifications.close();worker.shutdownNow();connectionWorker.shutdownNow();if(session!=null)try{session.close();}catch(IOException ignored){}if(tor!=null)tor.close();if(instance!=null)try{instance.close();}catch(IOException ignored){}Platform.exit();}
}
