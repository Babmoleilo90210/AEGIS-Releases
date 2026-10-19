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
import org.securemail.client.appearance.Appearance;
import org.securemail.client.voice.VoiceCallService;

/** Desktop UI. Work that can block is confined to a single background executor. */
public final class MessengerApp extends Application {
  private static volatile org.securemail.client.ecosystem.MailComponentGate600 installedMailGate;
  private static volatile java.util.function.Consumer<MessengerApp> componentStarted;
  private static volatile java.util.function.Consumer<String> componentLinks;
  private static volatile Runnable componentActivity;private static volatile java.util.function.IntConsumer componentCounts;
  private long lastComponentActivity;private volatile org.securemail.client.ecosystem.MailNotificationCounter600 mailCounter;
  private final org.securemail.client.ecosystem.MailComponentGate600 mailGate=installedMailGate;
  private volatile boolean componentLocked;private String attachmentWarning600="";
  private final CompletableFuture<Void> componentShutdown=new CompletableFuture<>();
  public static synchronized void configureMailComponent(org.securemail.client.ecosystem.MailComponentGate600 gate,java.util.function.Consumer<MessengerApp> started){
    if(installedMailGate!=null)throw new IllegalStateException("Почта уже настроена");installedMailGate=Objects.requireNonNull(gate);componentStarted=Objects.requireNonNull(started);
  }
  public static synchronized void componentLinks(java.util.function.Consumer<String> links){componentLinks=Objects.requireNonNull(links);}
  public static void componentSignals(Runnable activity,java.util.function.IntConsumer counts){componentActivity=Objects.requireNonNull(activity);componentCounts=Objects.requireNonNull(counts);}
  private boolean mailComponent(){return mailGate!=null;}
  public CompletableFuture<Void> componentShutdown(){return componentShutdown;}

  private final ConnectionStatus connectivity=new ConnectionStatus();private ConnectionCard connectionCard,detailConnectionCard;private Node navigationNode;
  private Stage stage;private BorderPane root;private ClientConfig config;private AppPaths.Instance instance;
  private final ExecutorService safeWebWorker=Executors.newSingleThreadExecutor(r->{var t=new Thread(r,"aegis-safeweb-work");t.setDaemon(true);return t;});
  private final org.securemail.client.safeweb.SafeWebProcess safeWeb=new org.securemail.client.safeweb.SafeWebProcess();
  private CommunityUi communityUi;private VzorView vzorView;private GlasView glasView;private AutoCloseable callListener;private final HBox callBanner=new HBox(8);private String displayedCall="";private final java.util.concurrent.atomic.AtomicBoolean callUiPending=new java.util.concurrent.atomic.AtomicBoolean();
  private ArchiveView archiveView;private Label inlineStatus=new Label(),connectionText;private boolean wantsNetwork=true,networkPrompted;
  private volatile TorConnection tor;private ClientSession session;private volatile boolean stopping;
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
  private ComboBox<Ttl> ttl,expiryTTL;private CheckBox disappearing;private TextField expiryMinutes;
  private UiPresetStore presets;private UiPreferences layout=UiPreferences.builtins().get("Компактный");
  private Appearance.Settings previousAppearance;private VBox mailListColumn,mailFolders;private SplitPane mailSplit;private Selector<String> mailboxFolderChoice;private boolean changingLayout,geometryBound,narrowNavigation;private ScrollPane composeContent;private Node composeBackdrop;private StackPane composeStack;
  private UpdateService updates;private UpdatePreferences updatePreferences;private UpdatesView updatesView;
  private Button updateBadge,accountReconnect;private VBox previewHost;private MailViewer embeddedViewer;
  private final Map<String,Image> avatarImages=new HashMap<>();private RememberedLogin remembered;
  private boolean rememberRequested,resumeAttempted,resumingNetwork,installingUpdate;private long rememberedExpires,pendingRelayExpiry;private String pendingRelayToken="";
  private long previewTicket;private VBox accountAvatar;
  private VBox profileAvatar;private Button sendButton;private CheckBox additionalProtection;
  private Draft draft;private MailContext replyContext;
  private PlainMessage.FileBundle forwardedFiles;private boolean replyNeedsProtection,restoredForwardedMissing;
  private static final class Draft implements AutoCloseable{
    String recipient="",subject="",body="";List<Path> files=List.of();char[] password=new char[0],code=new char[0];long ttl,expirySeconds=86400;String expiryInput="60";boolean disappearing;boolean protectedLetter,forceProtection,forwardedMissing;MailContext context;PlainMessage.FileBundle bundle;
    public void close(){Arrays.fill(password,'\0');Arrays.fill(code,'\0');recipient="";subject="";body="";files=List.of();context=null;if(bundle!=null){bundle.close();bundle=null;}}
  }
  private TextField contactSearch;private ListView<LocalMailSearch.Result> threadResults;
  private static final class ResponsePreparation implements AutoCloseable{final MailContext context;PlainMessage.FileBundle bundle;ResponsePreparation(MailContext context,PlainMessage.FileBundle bundle){this.context=context;this.bundle=bundle;}PlainMessage.FileBundle take(){var result=bundle;bundle=null;return result;}public void close(){if(bundle!=null)bundle.close();bundle=null;}}
  private LocalMailSearch.Scope mailScope=LocalMailSearch.Scope.INBOX;private boolean threads;
  private long lastMailboxScan,lastMailboxChange;
  private long lastAvatarRevision=-1;
  private record MailRow(LocalStore.MailItem item,String subject,String file,boolean unknown,boolean signature,String thread,boolean protectedLetter,String snippet){MailRow(LocalStore.MailItem item,String subject,String file){this(item,subject,file,false,true,item.id(),true,"");}}
  private record OpenedMail(LocalStore.HistoryItem item,PlainMessage plain,boolean unknown) implements AutoCloseable {public void close(){plain.close();}}
  private record Ttl(String label,long seconds){public String toString(){return label;}}
  @FunctionalInterface private interface Work<T>{T run()throws Exception;}

  @Override public void start(Stage stage){
    Locale.setDefault(Locale.forLanguageTag("ru-RU"));
    this.stage=stage;if(mailComponent()&&componentStarted!=null)componentStarted.accept(this);stage.initStyle(StageStyle.UNDECORATED);stage.setTitle(mailComponent()?"Почта — АЕГИС":"АЕГИС");stage.setMinWidth(760);stage.setMinHeight(580);
    root=new BorderPane();notifications=new NotificationCenter(stage,root);BorderPane window=new BorderPane(root);window.setTop(new WindowChrome(stage));inlineStatus.setWrapText(true);inlineStatus.setPadding(new Insets(5,14,5,14));inlineStatus.setVisible(false);inlineStatus.setManaged(false);callBanner.setPadding(new Insets(6,12,6,12));callBanner.getStyleClass().add("settings-card");callBanner.setVisible(false);callBanner.setManaged(false);window.setBottom(new VBox(callBanner,inlineStatus));var scene=new Scene(window,1020,730);scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("messenger.css")).toExternalForm());themes.apply(window);themes.apply(root);stage.setScene(scene);if(mailComponent())scene.addEventFilter(javafx.scene.input.InputEvent.ANY,event->{long now=System.nanoTime();if(!componentLocked&&componentActivity!=null&&(lastComponentActivity==0||now-lastComponentActivity>=TimeUnit.SECONDS.toNanos(1))){lastComponentActivity=now;componentActivity.run();}});InWindowDialog.bind(stage,window);WindowChrome.resize(stage,scene);
    root.centerProperty().addListener((o,a,b)->{if(b!=null&&themes.settings().components().animations()){b.setOpacity(0);FadeTransition fade=new FadeTransition(Duration.millis(150),b);fade.setFromValue(0);fade.setToValue(1);fade.play();}});
    for(int n:new int[]{16,24,32,48,64,128,256}){var icon=getClass().getResourceAsStream("icons/icon-"+n+".png");if(icon!=null)stage.getIcons().add(new Image(icon));}
    connectivity.listener(s->Platform.runLater(()->{if(!stopping){if(connectionCard!=null)connectionCard.update(s);if(detailConnectionCard!=null)detailConnectionCard.update(s);if(connectionText!=null)connectionText.setText(s.label());}}));
    root.setCenter(new StackPane(form("АЕГИС",new Label("Подготовка приложения…"))));window.applyCss();scene.setFill(javafx.scene.paint.Color.web("#15191f"));
    stage.setOnCloseRequest(e->{e.consume();if(!installingUpdate&&updatePreferences!=null&&updatePreferences.installAtExit()&&updates!=null&&updates.snapshot().state()==UpdateService.State.READY_TO_INSTALL)installUpdate();else stop();});stage.show();
    try {config=ClientConfig.load(AppPaths.config());
      if(!AppPaths.windows()){
        var old=UpdateSupport.oldImage();if(old.isPresent()){
          ButtonType update=new ButtonType("Обновить до "+SignedManifest.CURRENT),skip=new ButtonType("Запустить без обновления",ButtonBar.ButtonData.CANCEL_CLOSE);
          InWindowAlert prompt=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Старый профиль и сервер сохраняются.",update,skip);prompt.setTitle("АЕГИС");prompt.setHeaderText("Обнаружена установленная версия АЕГИС");prompt.initOwner(stage);themes.apply(prompt.getDialogPane());
          if(prompt.showAndWait().orElse(skip)==update){pendingLinuxUpdate=old.get();center(form("АЕГИС",new Label("Подготовка обновления…")));worker.execute(()->{try{UpdateSupport.closeOldLinux(pendingLinuxUpdate);UpdateSupport.backup(config);Platform.runLater(this::finishStartup);}catch(Exception ex){Platform.runLater(()->{error(ex);stage.close();Platform.exit();});}});return;}
        }
      }
      if(componentLocked){showComponentLocked();return;}finishStartup();
    }catch(Exception e){error(e);stage.close();Platform.exit();}
  }
  private void finishStartup(){
    try{
      instance=AppPaths.lock();center(form("АЕГИС",new Label("Подготовка локальных данных…")));
      ClientConfig original=config;
      worker.execute(()->{try{
        ClientUpgrade.beforeOpen(original.storagePath(),AppPaths.root().resolve("backups"));
        ClientUpgrade.beforeVersionOpen(SignedManifest.CURRENT,original,AppPaths.root().resolve("backups"));
        LocalStore.cleanupLockedFiles(original.storagePath(),System.currentTimeMillis());
        Platform.runLater(()->{if(!stopping)finishPreparedStartup();});
      }catch(Exception failed){Platform.runLater(()->{if(!stopping){error(failed);stop();}});}});
    }catch(Exception failed){error(failed);stop();}
  }
  private void finishPreparedStartup(){
    if(componentLocked){showComponentLocked();return;}
    try{
      themes.initialize();layout=themes.settings().legacy();themes.workspace(root);themes.listener(this::appearanceChanged);try{presets=new UiPresetStore(AppPaths.root());}catch(IOException invalidOldAppearance){presets=null;}try{threads=Files.readString(AppPaths.root().resolve("mail-mode.txt")).trim().equals("threads");}catch(IOException ignored){}
      updatePreferences=UpdatePreferences.load(AppPaths.root());updates=new UpdateService(AppPaths.root(),config.torUpdateSocksPort());updates.channel(updatePreferences.channel());updates.listener(s->Platform.runLater(()->updateChanged(s)));
      updates.automatic(()->!mailComponent()&&updatePreferences.automaticCheck(),()->!mailComponent()&&updatePreferences.automaticDownload());
      // A private cookie path is always tied to this application's profile, including migrated Linux profiles.
      config=new ClientConfig("127.0.0.1",config.torSocksPort(),config.torControlPort(),config.torUpdateSocksPort(),AppPaths.root().resolve("tor/control_auth_cookie"),config.localServicePort(),config.defaultTTL(),config.relayOnionAddress(),config.relayPort(),config.storagePath(),config.maxFileSize(),config.maxLocalStorage(),config.deliveryTTL());
      startTor();tryRemembered();
    }catch(Exception failed){error(failed);stop();}
  }
  private void page(Node body){if(componentLocked){showComponentLocked();return;}root.getChildren().clear();root.setTop(null);root.setLeft(null);root.setBottom(null);root.setCenter(body);}
  private VBox form(String title,Node...nodes){Label heading=new Label(title);heading.getStyleClass().add("heading");VBox box=new VBox(14,heading);box.getChildren().addAll(nodes);box.getStyleClass().add("settings-card");box.setMaxWidth(350);box.setAlignment(Pos.CENTER_LEFT);box.setPadding(new Insets(24));return box;}
  private void center(Node node){StackPane pane=new StackPane(node);page(pane);}
  private Button button(String text,Runnable action){Button b=new Button(text);b.setOnAction(e->action.run());return b;}
  private TextField field(String prompt){TextField f=new TextField();f.setPromptText(prompt);return f;}
  private PasswordField password(String prompt){PasswordField f=new PasswordField();f.setPromptText(prompt);return f;}
  private <T> void work(Button button,String busy,Work<T> action,java.util.function.Consumer<T> done){
    String label=button==null?null:button.getText();if(button!=null){button.setDisable(true);button.setText(busy);}
    worker.execute(()->{try{if(componentLocked)throw new IOException("Почта заблокирована");T value=action.run();Platform.runLater(()->{if(!stopping&&!componentLocked)done.accept(value);else if(value instanceof AutoCloseable closeable)try{closeable.close();}catch(Exception ignored){}});}catch(Exception|LinkageError e){Platform.runLater(()->{if(!stopping)error(e);});}finally{Platform.runLater(()->{if(button!=null){button.setDisable(false);button.setText(label);}});}});
  }
  private void startTor(){
    if(componentLocked)return;
    if(connectingTor)return;TorConnection previous=tor;ClientSession active=session;connectingTor=true;relayReady=false;connectivity.bootstrap(EmbeddedTor.Mode.DIRECT,0);
    if(session==null){if(config.relayOnionAddress().isBlank())serverPage();else loginPage();}
    TorConnection candidate=new TorConnection(config);tor=candidate;TorTransport.requireAvailability(candidate::ready);
    connectionWorker.execute(()->{try{
      // Closing the old SAFECOOKIE/P2P channel and child process can block.
      // Availability is already fail-closed; never perform these waits on the FX thread.
      if(active!=null)active.torUnavailable();if(previous!=null)previous.close();
      candidate.start(java.time.Duration.ofSeconds(150),java.time.Duration.ofSeconds(300),(mode,n)->Platform.runLater(()->{
        if(stopping||tor!=candidate)return;connectivity.bootstrap(mode,n);networkStatus("Подключение… "+n+"%");
      }));
      Platform.runLater(()->{if(stopping||tor!=candidate)return;connectivity.torConnected();networkStatus("Соединение готово");if(session!=null)session.torRestarted();if(connectButton!=null)connectButton.setDisable(false);if(!config.relayOnionAddress().isBlank())preconnect();if(!mailComponent()&&updatePreferences.automaticCheck())updates.check(updatePreferences.automaticDownload());});
    }catch(Exception e){candidate.close();Platform.runLater(()->{if(stopping||tor!=candidate)return;connectivity.failed(ConnectionStatus.Failure.TOR_UNAVAILABLE);networkStatus("Нет соединения. Прямое подключение отключено.");if(loginButton!=null)loginButton.setDisable(true);});}finally{connectingTor=false;}});
  }
  private void networkStatus(String text){if(networkLabel!=null)networkLabel.setText(text);}
  private void preconnect(){
    ClientConfig candidate=config;TorConnection expectedTor=tor;if(tor==null||!tor.ready()){if(!connectingTor)startTor();return;}connectivity.relayConnecting();networkStatus("Подключение к серверу…");
    connectionWorker.execute(()->{try{TechnicalLog.record(TechnicalLog.Event.RELAY_CONNECT,0);RelayProbe.check(candidate);TechnicalLog.record(TechnicalLog.Event.RELAY_CONNECTED,0);
      Platform.runLater(()->{if(stopping||candidate!=config||expectedTor!=tor)return;relayReady=true;connectivity.connected();networkStatus("● Подключено");if(loginButton!=null)loginButton.setDisable(false);resumeNetwork();});
    }catch(Exception failure){TechnicalLog.record(TechnicalLog.Event.RELAY_FAILED,0);Platform.runLater(()->{if(!stopping&&candidate==config&&expectedTor==tor){relayReady=false;connectivity.failed(ConnectionStatus.Failure.RELAY_UNAVAILABLE);networkStatus("Нет соединения с сервером");}});}});
  }
  void serverPage(){
    if(componentLocked){showComponentLocked();return;}
    TextField address=field("Адрес сервера .onion");address.setText(config.relayOnionAddress());networkLabel=new Label(tor!=null&&tor.ready()?"Соединение готово":"Подключение…");networkLabel.getStyleClass().add("muted");
    Button connect=new Button("Подключиться");connectButton=connect;connect.setDisable(tor==null||!tor.ready());connect.setDefaultButton(true);connect.setOnAction(e->{try{
      ClientConfig candidate=config.withRelay(OnionAddress.normalize(address.getText()));
      connectivity.relayConnecting();work(connect,"Подключение…",()->{TechnicalLog.record(TechnicalLog.Event.RELAY_CONNECT,0);try{RelayProbe.check(candidate);}catch(Exception ex){TechnicalLog.record(TechnicalLog.Event.RELAY_FAILED,0);return null;}TechnicalLog.record(TechnicalLog.Event.RELAY_CONNECTED,0);candidate.save(AppPaths.config());return candidate;},value->{if(value==null){relayReady=false;connectivity.failed(ConnectionStatus.Failure.RELAY_UNAVAILABLE);}else{config=value;relayReady=true;connectivity.connected();loginPage();}});
    }catch(Exception ex){error(ex);}});
    var advanced=button("Расширенные настройки",this::diagnostics);advanced.getStyleClass().add("link");VBox setup=form("АЕГИС",new Label("Адрес сервера"),address,connect,connectionCard(),advanced);if(Files.exists(config.storagePath().resolve("state.vault")))setup.getChildren().add(button("Открыть без сети",this::openOffline));center(setup);
  }
  void loginPage(){
    if(componentLocked){showComponentLocked();return;}
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
    center(form("АЕГИС",nick,account,remember,login,create,connectionCard(),local,button("Восстановить резервную копию",this::restore),another));
  }
  private void openOffline(){if(componentLocked)return;wantsNetwork=false;char[] password=askPassword("Открыть хранилище","Пароль хранилища");if(password==null)return;
    work(null,"",()->{try{ClientSession opened=AccountLogin.offline(config,password);try{verifyComponentSession(opened);return opened;}catch(Exception rejected){opened.close();throw rejected;}}finally{Arrays.fill(password,'\0');}},opened->{session=opened;rememberRequested=false;afterLogin();});
  }
  private void loginAttempt(String nick,char[] account,char[] old,Button login){
    login.setDisable(true);login.setText("Вход…");
    worker.execute(()->{boolean keep=false;try{
      if(mailComponent()){mailGate.verify();try(var preflight=new LocalStore(config.storagePath(),LocalStore.modernVault(config.storagePath())||old==null?account:old,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage())){mailGate.verifyUnlockedVault(preflight);}catch(javax.crypto.AEADBadTagException wrong){if(!LocalStore.modernVault(config.storagePath()))throw new AccountLogin.OldPasswordRequired();throw wrong;}}
      ClientSession opened=AccountLogin.open(config,nick,account,old,this::verifyComponentSession,(store,network)->{if(mailComponent()){mailGate.verifyUnlockedVault(store);mailGate.prepareNetwork(network);}});
      try{verifyComponentSession(opened);}catch(Exception rejected){opened.close();throw rejected;}
      if(rememberRequested)saveRemembered(opened);else{Files.deleteIfExists(AppPaths.root().resolve("session/resume.enc"));rememberedExpires=0;pendingRelayToken="";try{if(remembered!=null)remembered.clear();}catch(IOException ignored){/* The encrypted resume envelope has already been removed. */}}
      Platform.runLater(()->{if(stopping||componentLocked){try{opened.close();}catch(IOException ignored){}return;}session=opened;afterLogin();});
    }catch(AccountLogin.OldPasswordRequired needed){keep=true;Platform.runLater(()->{
      if(stopping){Arrays.fill(account,'\0');return;}
      char[] legacy=askPassword("Обновление хранилища","Старый пароль хранилища");
      if(legacy==null)Arrays.fill(account,'\0');else loginAttempt(nick,account,legacy,login);
    });}catch(AccountLogin.MigrationFailed failure){Platform.runLater(()->{if(stopping)return;info("Не удалось обновить хранилище. Предыдущие данные сохранены.");try{if(UpdateSupport.scheduleWindowsRollback())stop();}catch(IOException rollbackFailure){error(rollbackFailure);}});
    }catch(Exception failure){Platform.runLater(()->{if(!stopping)error(failure);});}
    finally{if(!keep)Arrays.fill(account,'\0');if(old!=null)Arrays.fill(old,'\0');Platform.runLater(()->{login.setDisable(!relayReady);login.setText("Войти");});}});
  }
  void registerPage(){
    if(mailComponent()){info("Создание учётной записи выполняется в главном АЕГИС.");return;}
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
    if(componentLocked){showComponentLocked();return;}
    if(mailComponent()&&!mailGate.lease().accountId().equals(session.local().identity().userId())){stop();return;}
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
    if(componentLocked){showComponentLocked();return;}
    if(timer!=null)timer.stop();if(notifications==null)notifications=new NotificationCenter(stage,root);page(null);clearCompose();
    themes.listener(this::appearanceChanged);previousAppearance=themes.settings();layout=previousAppearance.legacy();
    if(!geometryBound){geometryBound=true;root.widthProperty().addListener((o,a,b)->{adaptGeometry();if(session==null||changingLayout)return;boolean narrow=b.doubleValue()<700;if(narrow!=narrowNavigation){arrangeNavigation();if(section.equals("mail"))arrangeMail();}if(section.equals("compose"))placeComposer();});}
    arrangeNavigation();if(!mailComponent())bindCalls();timer=new Timeline(new KeyFrame(Duration.seconds(1),e->refresh()));timer.setCycleCount(Animation.INDEFINITE);timer.play();mailboxPage(false);updateChanged(updates.snapshot());
  }
  private void appearanceChanged(Appearance.Settings value){
    Appearance.Settings old=previousAppearance;previousAppearance=value;layout=value.legacy();
    if(session==null)return;
    boolean navigation=old==null||!old.layout().equals(value.layout())||!old.components().equals(value.components())||old.scale()!=value.scale();
    if(navigation)arrangeNavigation();if(letters!=null)letters.refresh();if(contacts!=null)contacts.refresh();
    if(accountAvatar!=null)accountAvatar.getChildren().setAll(avatar(session.local().nickname()));
    if(section.equals("mail")&&navigation)arrangeMail();if(section.equals("compose"))placeComposer();
    for(var viewer:viewers)viewer.appearance(value);
  }
  private void arrangeNavigation(){
    if(session==null||changingLayout)return;changingLayout=true;
    try{
      var settings=themes.settings();var l=settings.layout();narrowNavigation=root.getWidth()>0&&root.getWidth()<700;
      Appearance.Labels labelMode=l.collapsed()||narrowNavigation?Appearance.Labels.ICONS:l.labels();
      Label brand=new Label("АЕГИС");brand.setVisible(false);brand.setManaged(false);brand.getStyleClass().add("brand");Region space=new Region();HBox.setHgrow(space,Priority.ALWAYS);
      connection=new Label("●");connection.setOnMouseClicked(e->connectionDialog());
      updateBadge=button("",this::updatesPage);updateBadge.getStyleClass().add("link");updateBadge.setVisible(false);updateBadge.setManaged(false);
      accountReconnect=button("Войти в сеть",this::reconnectAccount);accountReconnect.setVisible(false);accountReconnect.setManaged(false);
      Button collapse=button("☰",()->{try{var s=themes.settings();var v=s.layout();var next=new Appearance.Layout(v.zone(),v.labels(),v.order(),!v.collapsed(),v.navigationWidth(),v.mail(),v.rows(),v.foldersPercent(),v.listPercent(),v.composer(),v.textWidth(),v.viewPadding(),v.viewCard(),v.metadataTop(),v.actions(),v.fields(),v.previewBelow());themes.commit(s.layout(next));}catch(IOException ex){error(ex);}});
      collapse.setTooltip(new Tooltip("Свернуть навигацию"));collapse.setAccessibleText("Свернуть навигацию");
      connectionText=new Label(connectivity.snapshot().label());connectionText.getStyleClass().add("muted");Label nickname=new Label(session.local().nickname());nickname.getStyleClass().add("heading");HBox header=new HBox(8,nickname,space,connection,connectionText);header.setAlignment(Pos.CENTER_LEFT);header.setPadding(new Insets(8,12,8,12));header.getStyleClass().add("app-header");
      boolean vertical=l.zone()==Appearance.Zone.LEFT;
      Pane nav=vertical?new VBox(8):new FlowPane(8,6);nav.getStyleClass().add("navigation-shell");nav.setPadding(new Insets(4));
      nav.getChildren().add(collapse);
      List<List<String>> blocks=mailComponent()?List.of(List.of("search","contacts","letters","archive"),List.of("settings")):List.of(List.of("search","profile","contacts","letters","archive"),List.of("safeweb","glas","organizations","news","library"),List.of("settings"));
      for(int blockIndex=0;blockIndex<blocks.size();blockIndex++){
        List<String> allowed=blocks.get(blockIndex);List<String> ordered=new ArrayList<>();for(String id:l.order())if(allowed.contains(id))ordered.add(id);for(String id:allowed)if(!ordered.contains(id))ordered.add(id);
        Pane group=vertical?new VBox(4):new FlowPane(4,4);group.setId("navigation-block-"+(blockIndex+1));group.getStyleClass().addAll("navigation","navigation-block");group.setPadding(new Insets(6));
        for(String id:ordered){
          String name=switch(id){case "letters"->"Письма";case "contacts"->"Контакты";case "archive"->"Архив";case "safeweb"->"Взор";case "glas"->"Глас";case "organizations"->"Организации";case "news"->"Новости";case "library"->"Библиотека";case "search"->"Поиск";case "profile"->"Профиль";default->"Настройки";};
          Runnable action=switch(id){case "letters"->()->mailboxPage(false);case "contacts"->this::contactsPage;case "archive"->this::archivePage;case "safeweb"->this::safeWebPage;case "glas"->this::glasPage;case "organizations"->()->communityPage("organizations");case "news"->()->communityPage("news");case "library"->()->communityPage("library");case "search"->this::searchPage;case "profile"->this::profile;default->this::settings;};
          Button item=button(labelMode==Appearance.Labels.ICONS?"":name,action);item.setGraphicTextGap(5);item.setId("navigation-"+id);item.setAccessibleText(name);item.setTooltip(new Tooltip(name));item.getStyleClass().add("nav-item");item.setAlignment(labelMode==Appearance.Labels.BOTH?Pos.CENTER_LEFT:Pos.CENTER);item.setMinHeight(40);item.setPrefHeight(40);item.setMinWidth(0);if(labelMode!=Appearance.Labels.TEXT)item.setGraphic(NavigationGlyph.create(id,settings.components().iconSize()));if(vertical)item.setMaxWidth(Double.MAX_VALUE);group.getChildren().add(item);
        }
        nav.getChildren().add(group);
      }
      navigationNode=nav;root.setLeft(null);root.setBottom(null);root.setTop(null);
      if(l.zone()==Appearance.Zone.LEFT){nav.setPrefWidth(labelMode==Appearance.Labels.ICONS?78:l.navigationWidth());ScrollPane scroll=new ScrollPane(nav);scroll.setFitToWidth(true);scroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);scroll.setPrefWidth(labelMode==Appearance.Labels.ICONS?82:l.navigationWidth()+4);root.setLeft(scroll);root.setTop(header);}
      else if(l.zone()==Appearance.Zone.TOP)root.setTop(new VBox(header,nav));else{root.setTop(header);root.setBottom(nav);}
      adaptGeometry();accountAvatar=null;if(updates!=null)updateChanged(updates.snapshot());
    }finally{changingLayout=false;}
  }
  private void adaptGeometry(){
    if(session==null)return;double margin=ResponsiveGeometry.inset(root.getWidth());
    root.setPadding(new Insets(margin));
    if(navigationNode!=null){if(root.getLeft()!=null)BorderPane.setMargin(root.getLeft(),new Insets(0,margin,0,0));if(navigationNode instanceof VBox nav)nav.setSpacing(ResponsiveGeometry.spacing(root.getWidth(),themes.settings().components().spacing()));}
    if(letters!=null)letters.refresh();
  }
  private ConnectionCard connectionCard(){connectionCard=new ConnectionCard(()->{if(connectingTor)return;if(tor==null||!tor.ready())startTor();else preconnect();});connectionCard.update(connectivity.snapshot());return connectionCard;}
  private Button composeAction(){Button b=button(narrowNavigation?"+":"Новое письмо",this::composePage);b.setAccessibleText("Новое письмо");b.setTooltip(new Tooltip("Новое письмо"));return b;}
  private VBox folders(){
    VBox pane=new VBox(7);pane.getStyleClass().add("mail-folders");
    pane.getChildren().addAll(button("Входящие",()->mailboxPage(false)),button("Отправленные",()->mailboxPage(true)),button("Черновики",this::draftsPage),button("Избранные",()->mailboxPage(false,LocalMailSearch.Scope.FAVORITES)),button("Неизвестные",()->mailboxPage(false,LocalMailSearch.Scope.UNKNOWN)),button("Заблокированные",()->mailboxPage(false,LocalMailSearch.Scope.BLOCKED)),button("Системные",this::systemLetters));
    for(Node item:pane.getChildren())if(item instanceof Button b){b.setMaxWidth(Double.MAX_VALUE);b.setAlignment(Pos.CENTER_LEFT);}pane.setMinWidth(170);return pane;
  }
  private Selector<String> folderSelector(){
    String active=section.equals("system")?"Системные":section.equals("drafts")?"Черновики":mailScope==LocalMailSearch.Scope.FAVORITES?"Избранные":mailScope==LocalMailSearch.Scope.UNKNOWN?"Неизвестные":mailScope==LocalMailSearch.Scope.BLOCKED?"Заблокированные":mailOutgoing?"Отправленные":"Входящие";
    Selector<String> folder=new Selector<>(themes,List.of("Входящие","Отправленные","Черновики","Избранные","Неизвестные","Заблокированные","Системные"),active);folder.setOnAction(e->{switch(folder.getValue()){case "Отправленные"->mailboxPage(true);case "Черновики"->draftsPage();case "Избранные"->mailboxPage(false,LocalMailSearch.Scope.FAVORITES);case "Неизвестные"->mailboxPage(false,LocalMailSearch.Scope.UNKNOWN);case "Заблокированные"->mailboxPage(false,LocalMailSearch.Scope.BLOCKED);case "Системные"->systemLetters();default->mailboxPage(false);}});return folder;
  }
  private void draftsPage(){
    clearCompose();section="drafts";viewGeneration++;VBox box=new VBox(12,folderSelector(),new Label("Черновики"));box.setPadding(new Insets(14));
    if(draft==null||draft.body.isBlank()&&draft.subject.isBlank()&&draft.files.isEmpty())box.getChildren().add(new Label("Черновиков пока нет"));
    else{Label subject=new Label(draft.subject.isBlank()?"Без темы":draft.subject);VBox card=new VBox(8,subject,new Label(draft.recipient.isBlank()?"Получатель не выбран":draft.recipient),button("Продолжить",this::composePage));card.getStyleClass().add("mail-card");box.getChildren().add(card);}
    root.setCenter(box);
  }
  private void arrangeMail(){
    if(mailListColumn==null||previewHost==null||!section.equals("mail"))return;
    if(mailSplit!=null)mailSplit.getItems().clear();root.setCenter(null);Appearance.Layout value=themes.settings().layout();boolean narrow=root.getWidth()>0&&root.getWidth()<850;
    boolean preview=value.mail()!=Appearance.MailLayout.COMPACT&&!narrow;
    boolean foldersVisible=preview&&(value.mail()==Appearance.MailLayout.THREE||value.mail()==Appearance.MailLayout.CUSTOM)&&!narrowNavigation;if(mailboxFolderChoice!=null){mailboxFolderChoice.setVisible(!foldersVisible);mailboxFolderChoice.setManaged(!foldersVisible);}
    if(!preview){root.setCenter(mailListColumn);return;}
    if((value.mail()==Appearance.MailLayout.THREE||value.mail()==Appearance.MailLayout.CUSTOM)&&!narrowNavigation){mailFolders=folders();mailSplit=new SplitPane(mailFolders,mailListColumn,previewHost);mailSplit.setDividerPositions(value.foldersPercent()/100.0,(value.foldersPercent()+value.listPercent())/100.0);}
    else{mailSplit=new SplitPane(mailListColumn,previewHost);mailSplit.setDividerPositions(Math.min(.7,value.listPercent()/100.0));}
    mailSplit.setOrientation(value.previewBelow()?javafx.geometry.Orientation.VERTICAL:javafx.geometry.Orientation.HORIZONTAL);mailListColumn.setMinWidth(180);previewHost.setMinWidth(200);root.setCenter(mailSplit);mailSplit.setOnMouseReleased(e->{if(!e.isPrimaryButtonDown())savePanelSizes();});
  }
  private void savePanelSizes(){
    if(mailSplit==null)return;try{var s=themes.settings();var l=s.layout();double[] p=mailSplit.getDividerPositions();int f=l.foldersPercent(),n=l.listPercent();if(p.length==2){f=Math.max(12,Math.min(30,(int)Math.round(p[0]*100)));n=Math.max(25,Math.min(Math.min(55,75-f),(int)Math.round((p[1]-p[0])*100)));}else if(p.length==1)n=Math.max(25,Math.min(55,(int)Math.round(p[0]*100)));var next=l.panels(f,n);if(!next.equals(l))themes.commit(s.layout(next));}catch(IOException ex){error(ex);}
  }
  private void rememberDraft(){
    if(composer==null)return;if(draft!=null)draft.close();draft=new Draft();
    draft.recipient=recipientField==null?"":recipientField.getText();draft.subject=subjectField==null?"":subjectField.getText();draft.body=composer.getText();draft.files=List.copyOf(attachments);
    if(letterPassword!=null)draft.password=letterPassword.value();if(secondCode!=null)draft.code=secondCode.value();
    draft.disappearing=disappearing!=null&&disappearing.isSelected();draft.expirySeconds=expiryTTL==null||expiryTTL.getValue()==null?86400:expiryTTL.getValue().seconds();draft.expiryInput=expiryMinutes==null?"60":expiryMinutes.getText();
    draft.ttl=ttl==null||ttl.getValue()==null?config.defaultTTL():ttl.getValue().seconds();draft.protectedLetter=additionalProtection!=null&&additionalProtection.isSelected();draft.context=replyContext;
    draft.forceProtection=replyNeedsProtection;draft.forwardedMissing=restoredForwardedMissing;draft.bundle=forwardedFiles;forwardedFiles=null;
  }
  private void clearCompose(){clearCompose(true);}
  private void clearCompose(boolean remember){
    if(remember)rememberDraft();else if(draft!=null){draft.close();draft=null;}
    previewTicket++;if(embeddedViewer!=null){embeddedViewer.close();embeddedViewer=null;}previewHost=null;
    if(composer!=null)composer.clear();if(letterPassword!=null)letterPassword.clear();if(secondCode!=null)secondCode.clear();
    if(composeBackdrop!=null)composeBackdrop.setDisable(false);if(composeStack!=null)composeStack.getChildren().clear();composeStack=null;composeContent=null;composeBackdrop=null;
    composer=null;letterPassword=null;secondCode=null;additionalProtection=null;disappearing=null;expiryTTL=null;expiryMinutes=null;replyContext=null;sendButton=null;attachments.clear();attachmentsBox=null;attachmentLabel=null;
    replyNeedsProtection=false;restoredForwardedMissing=false;if(forwardedFiles!=null){forwardedFiles.close();forwardedFiles=null;}
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
      super.updateItem(row,empty);setText(null);setGraphic(null);setContextMenu(null);if(empty||row==null)return;
      var item=row.item();var appearance=themes.settings().layout();var fields=appearance.fields();
      VBox text=new VBox(4);text.setMinWidth(0);HBox.setHgrow(text,Priority.ALWAYS);
      Label subject=new Label(row.subject().isBlank()?"Без темы":row.subject());subject.getStyleClass().add("mail-subject");subject.setWrapText(true);if(fields.subject())text.getChildren().add(subject);
      String time=Instant.ofEpochMilli(item.time()).atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("dd.MM HH:mm"));
      String metadata=(fields.nickname()?item.contact():"")+(fields.date()?(fields.nickname()?" · ":"")+time:"")+(fields.status()?" · "+item.status():"");
      Label meta=new Label(metadata);meta.getStyleClass().add("muted");meta.setWrapText(true);meta.setTooltip(new Tooltip((row.signature()?"Подпись проверена":"Подпись не проверена")+(row.unknown()?" · Контакт не проверен":" · Из контактов")));if(!metadata.isBlank())text.getChildren().add(meta);
      if(row.unknown()||!row.signature()){Label warning=new Label(!row.signature()?"Подпись не проверена":"Неизвестный отправитель");warning.getStyleClass().add("security-warning");warning.setWrapText(true);text.getChildren().add(warning);}
      if(row.protectedLetter()){Label lock=new Label("Защищённое письмо");lock.getStyleClass().add("muted");text.getChildren().add(lock);}
      else if(fields.snippet()&&appearance.rows()==Appearance.Rows.PREVIEW&&!row.snippet().isBlank()){Label snippet=new Label(row.snippet());snippet.setWrapText(true);snippet.getStyleClass().add("mail-snippet");text.getChildren().add(snippet);}
      Label remaining=new Label("◷ "+Math.max(0,(item.expiresAt()-session.local().now())/60000)+" мин"+(!fields.attachments()||row.file().isEmpty()?"":" · "+row.file()));remaining.getStyleClass().add("muted");text.getChildren().add(remaining);
      Button open=button("Открыть",()->{if(threads)threadPage(row);else openLetter(item);});HBox body=new HBox(ResponsiveGeometry.spacing(root.getWidth(),themes.settings().components().spacing()));
      if(fields.avatar())body.getChildren().add(avatar(item.contact()));body.getChildren().add(text);if(appearance.mail()==Appearance.MailLayout.COMPACT||root.getWidth()<850)body.getChildren().add(open);body.setAlignment(Pos.CENTER_LEFT);body.setMinWidth(0);
      if(appearance.rows()==Appearance.Rows.CARDS||appearance.rows()==Appearance.Rows.PREVIEW)body.getStyleClass().add("mail-card");else body.getStyleClass().add("mail-row");
      if(appearance.rows()==Appearance.Rows.COMPACT)text.setSpacing(1);
      setGraphic(body);setOnMouseClicked(e->{if(e.getClickCount()==2){if(threads)threadPage(row);else openLetter(item);}});setOnKeyPressed(e->{if(e.getCode()==javafx.scene.input.KeyCode.ENTER){if(threads)threadPage(row);else openLetter(item);e.consume();}});
      MenuItem delete=new MenuItem("Удалить у меня");delete.setOnAction(e->work(null,"",()->{session.lifecycle().delete(item.id(),item.outgoing());return true;},x->{rendered="";refresh();}));
      MenuItem pin=new MenuItem(session.features().pinned("pinnedMail",item.id())?"Убрать из избранного":"В избранное");pin.setOnAction(e->work(null,"",()->{session.features().pin("pinnedMail",item.id(),!session.features().pinned("pinnedMail",item.id()));return true;},x->{rendered="";refresh();}));
      MenuItem block=new MenuItem(scope==LocalMailSearch.Scope.BLOCKED?"Разблокировать письмо":"Заблокировать письмо");block.setOnAction(e->work(null,"",()->{session.features().blockMail(item.id(),scope!=LocalMailSearch.Scope.BLOCKED);return true;},x->{rendered="";refresh();}));
      ContextMenu menu=new ContextMenu(pin,delete);if(!item.outgoing()){
        menu.getItems().add(block);MenuItem senderBlock=new MenuItem(scope==LocalMailSearch.Scope.BLOCKED?"Разблокировать отправителя":"Блокировать отправителя");senderBlock.setOnAction(e->work(null,"",()->{var packet=session.local().loadHistory(item.id(),false).packet();session.features().blockSender(packet.senderId(),scope!=LocalMailSearch.Scope.BLOCKED);return true;},done->{rendered="";refresh();}));menu.getItems().add(senderBlock);
      }setContextMenu(menu);
      MenuItem pinThread=new MenuItem("Закрепить цепочку");pinThread.setOnAction(e->work(null,"",()->{session.features().pin("pinnedThreads",row.thread(),!session.features().pinned("pinnedThreads",row.thread()));return true;},x->{rendered="";refresh();}));menu.getItems().add(pinThread);
    }});
    mailboxFolderChoice=folderSelector();FlowPane toolbar=new FlowPane(8,8,mailboxFolderChoice,mode);
    mailListColumn=new VBox(10,composeAction(),toolbar,letters);mailListColumn.setPadding(new Insets(12));VBox.setVgrow(letters,Priority.ALWAYS);
    previewHost=new VBox(new Label("Выберите письмо"));previewHost.setPadding(new Insets(12));
    letters.getSelectionModel().selectedItemProperty().addListener((o,a,b)->{if(b!=null&&themes.settings().layout().mail()!=Appearance.MailLayout.COMPACT&&root.getWidth()>=850){if(threads)threadPage(b);else openLetter(b.item());}});
    arrangeMail();
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
    if(tor!=null&&!tor.ready()&&!connectingTor)connectivity.offline();
    if(connectionText!=null)connectionText.setText(connected?"Соединение защищено":connectivity.snapshot().busy()?connectivity.snapshot().label():tor!=null&&tor.ready()&&session.online()?"Восстановление соединения…":"Нет соединения");
    if(connection!=null){connection.setStyle("-fx-text-fill:"+(connected?"#469981":"#c38848"));connection.setText("●");connection.setTooltip(new Tooltip(connected?"Соединение защищено":connectivity.snapshot().label()+(connectivity.snapshot().busy()?" · "+connectivity.snapshot().progress()+"%":". Прямое подключение отключено.")));}
    viewers.removeIf(v->!v.showing());
    if(section.equals("thread")&&threadResults!=null)threadResults.getItems().removeIf(r->r.item().expiresAt()<=session.local().now());
    if((section.equals("contacts")||section.equals("friends"))&&contactSearch!=null)fillContacts(contactSearch.getText());
    if(letters!=null)letters.getItems().removeIf(row->row.item().expiresAt()<=session.local().now());
    if(!section.equals("mail")||letters==null)return;
    letters.refresh();
    if(refreshing)return;refreshing=true;long generation=viewGeneration;boolean outgoing=mailOutgoing;ClientSession active=session;
    long change=active.local().changeCounter();if(!rendered.isEmpty()&&change==lastMailboxChange&&System.nanoTime()-lastMailboxScan<TimeUnit.SECONDS.toNanos(15)){refreshing=false;return;}
    worker.execute(()->{try{
      var found=LocalMailSearch.find(active.local(),active.features(),active.lifecycle(),new LocalMailSearch.Query("","",0,Long.MAX_VALUE,mailScope),config.maxFileSize());
      String signature=found.stream().map(i->i.item().id()+i.item().status()+i.unknown()+i.threadId()+active.features().pinned("pinnedMail",i.item().id())).reduce("",String::concat)+threads;
      if(signature.equals(rendered)){Platform.runLater(()->{if(generation==viewGeneration){lastMailboxChange=change;lastMailboxScan=System.nanoTime();}});return;}
      var rows=new ArrayList<MailRow>();
      Set<String> groups=new HashSet<>();for(var result:found){var item=result.item();
        if(threads&&!groups.add(result.peerId()+"/"+result.threadId()))continue;
        String subject=result.subject(),file=result.fileCount()==0?"":"Вложения: "+result.fileCount();
        rows.add(new MailRow(item,subject,file,result.unknown(),result.signatureValid(),result.threadId(),result.protectedLetter(),result.snippet()));
      }
      Platform.runLater(()->{if(!stopping&&session==active&&generation==viewGeneration&&section.equals("mail")){letters.getItems().setAll(rows);rendered=signature;lastMailboxChange=change;lastMailboxScan=System.nanoTime();}});
    }catch(Exception|LinkageError failure){Platform.runLater(()->{if(!stopping&&generation==viewGeneration)letters.setPlaceholder(new Label("Не удалось загрузить письма"));});}
    finally{Platform.runLater(()->refreshing=false);}});
  }
  private void pollNotifications(){
    if(notifying||session==null)return;notifying=true;ClientSession active=session;
    worker.execute(()->{try{boolean mail=false,friend=false;Set<String> newIds=new HashSet<>();for(var event:active.local().drainNotices()){
      if(active.features().blocked(event.id(),event.senderId()))continue;if(mailComponent())newIds.add(event.id());if(!active.features().notifications())continue;
      if(active.features().friend(event.senderId())){if(active.features().friendNotifications())friend=true;}else mail=true;
    }if(mailComponent()&&mailCounter!=null)publishComponentCount(mailCounter.add(newIds));boolean friendEvent=active.takeFriendshipEvent()&&active.features().friendEvents();boolean regular=mail,priority=friend;
    Platform.runLater(()->{if(!stopping&&session==active){/* Quiet mode: durable inbox/system history remains the source of notifications. */}});
    }catch(Exception ignored){/* The durable inbox is independent of optional notifications. */}finally{Platform.runLater(()->notifying=false);}});
  }
  private void openLetter(LocalStore.MailItem item){
    boolean mandatoryConsent=false;
    if(session.lifecycle().expired(item.id())){info("Письмо исчезло");return;}
    if(session.lifecycle().expiring(item.id())&&!item.outgoing()&&!session.lifecycle().readReceipts()){
      InWindowAlert confirm=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Для исчезающего письма подтверждение показа обязательно. Открыть письмо?",ButtonType.OK,ButtonType.CANCEL);confirm.initOwner(stage);confirm.setHeaderText(null);themes.apply(confirm.getDialogPane());if(confirm.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK)return;mandatoryConsent=true;
    }
    boolean revealConsent=mandatoryConsent;
    long ticket=++previewTicket;VBox host=section.equals("mail")&&themes.settings().layout().mail()!=Appearance.MailLayout.COMPACT&&root.getWidth()>=850?previewHost:null;
    if(embeddedViewer!=null){embeddedViewer.close();embeddedViewer=null;}
    if(viewers.size()>=4){info("Закройте одно из открытых писем");return;}
    work(null,"",()->{
      var stored=session.lifecycle().loadHistory(item.id(),item.outgoing());
      if(!AutomaticEncryption.supports(stored.packet()))return stored;
      return new OpenedMail(stored,session.lifecycle().open(stored,config.maxFileSize(),revealConsent),!stored.outgoing()&&!session.local().assessSender(stored.packet()).keyMatches());
    },value->{
      if(value instanceof LocalStore.HistoryItem legacy){openLegacy(legacy);return;}
      var entry=(OpenedMail)value;
      if(stopping||ticket!=previewTicket||entry.item().expiresAt()<=session.local().now()){entry.plain().close();return;}
      MailViewer.Actions actions=new MailViewer.Actions(){
        public void reply(LocalStore.HistoryItem item,PlainMessage plain){prepareResponse(item,plain,"",null,false);}
        public void forward(LocalStore.HistoryItem item,PlainMessage plain,String body,PlainMessage.FileBundle files){prepareResponse(item,plain,body,files,true);}
        public void original(MailContext reference){openReference(reference);}
        public void safeWeb(String url){if(mailComponent()){openComponentLink(url);return;}safeWebPage();vzorView.address(url);info("Проверьте адрес и нажмите «Открыть Взор».");}
        public void archive(LocalStore.HistoryItem item,PlainMessage plain,String body,Runnable finished){
          if(plain.streamingAttachments()){InWindowAlert warning=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Архивная копия сохранит только текст письма. Потоковые файлы сначала сохраните и добавьте в архив отдельно.",ButtonType.OK,ButtonType.CANCEL);warning.initOwner(stage);themes.apply(warning.getDialogPane());if(warning.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK){finished.run();return;}}
          if(session.lifecycle().expiring(item.id())){InWindowAlert warning=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Архивная копия может сохраняться после исчезновения оригинала. Его таймер продолжает идти. Сохранить отдельную копию?",ButtonType.OK,ButtonType.CANCEL);warning.initOwner(stage);warning.setHeaderText(null);themes.apply(warning.getDialogPane());if(warning.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK){finished.run();return;}}
          ClientSession owner=session;ArchiveView target=personalArchive();target.ensureUnlocked(()->{if(stopping||session!=owner||expiresAt()<=owner.local().now()){finished.run();if(!stopping)info("Срок письма истёк; архивная копия не создана");return;}target.archiveMail(item,plain,body,finished);},finished);
        }
        public void streamingDownload(org.securemail.client.attachments600.AttachmentManifest600 manifest,org.securemail.client.attachments600.AttachmentManifest600.File file,String candidate,Path destination,java.util.function.BooleanSupplier active,org.securemail.client.attachments600.AttachmentClient600.Progress progress)throws Exception{var manager=session.attachments600();if(manager==null)throw new IOException("Сервер вложений не настроен в главном АЕГИС");manager.download(manifest,file,candidate,entry.item().packet().senderId(),destination,active,progress);}
        public boolean unknown(){return entry.unknown();}
        public String route(){try{return switch(session.local().deliveryRoute(entry.item().id())){case "P2P"->"Прямое соединение Tor";case "RELAY"->"Через Relay";default->"";};}catch(IOException unavailable){return "";}}
        public void abandonedDisplay(){ClientSession active=session;worker.execute(()->{try{active.lifecycle().abandonDisplay(entry.item().id());}catch(Exception ignored){/* Uncertain reveal is fail closed on restart. */}});}
        public void prepareDisplay()throws Exception{session.lifecycle().prepareDisplay(entry.item().id());}
        public void closed(boolean displayed){if(!displayed){ClientSession active=session;worker.execute(()->{try{active.lifecycle().cancelUnshown(entry.item().id());}catch(Exception ignored){/* Interrupted reveal remains fail closed on restart. */}});}}
        public long expiresAt(){try{long left=session.lifecycle().remaining(entry.item().id());return left==Long.MAX_VALUE?entry.item().expiresAt():session.local().now()+left;}catch(Exception uncertain){return 0;}}
        public void displayed(){ClientSession active=session;worker.execute(()->{try{active.lifecycle().displayed(entry.item().id());if(mailComponent()&&mailCounter!=null)publishComponentCount(mailCounter.read(entry.item().id()));}catch(Exception failure){Platform.runLater(()->{if(!stopping)info("Подтверждение прочтения пока не сохранено");});}});}
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
    work(null,"",()->{for(boolean outgoing:new boolean[]{false,true})try{var original=session.lifecycle().loadHistory(reference.parentId(),outgoing);
      if(java.security.MessageDigest.isEqual(Identity.digest(original.packet()),reference.digest())&&Identity.verifyPacket(original.packet()))return new LocalStore.MailItem(original.id(),original.contact(),outgoing,original.status(),original.time(),original.expiresAt());
    }catch(java.nio.file.NoSuchFileException absent){}throw new IOException("Исходное письмо недоступно");},this::openLetter);
  }
  private void threadPage(MailRow selectedRow){
    clearCompose();section="thread";viewGeneration++;long generation=viewGeneration;ListView<LocalMailSearch.Result> chain=new ListView<>();threadResults=chain;chain.setCellFactory(list->new ListCell<>(){protected void updateItem(LocalMailSearch.Result r,boolean empty){super.updateItem(r,empty);setText(empty||r==null?null:(r.item().outgoing()?"Вы":r.item().contact())+" · "+r.subject());}});
    chain.setOnMouseClicked(e->{if(e.getClickCount()==2&&chain.getSelectionModel().getSelectedItem()!=null)openLetter(chain.getSelectionModel().getSelectedItem().item());});
    VBox body=new VBox(12,button("← Назад",()->mailboxPage(mailOutgoing,mailScope)),new Label("Цепочка"),chain);body.setPadding(new Insets(20));VBox.setVgrow(chain,Priority.ALWAYS);root.setCenter(body);
    work(null,"",()->LocalMailSearch.find(session.local(),session.features(),session.lifecycle(),new LocalMailSearch.Query("","",0,Long.MAX_VALUE,mailScope==LocalMailSearch.Scope.BLOCKED?LocalMailSearch.Scope.BLOCKED:LocalMailSearch.Scope.ALL),config.maxFileSize()),found->{if(section.equals("thread")&&generation==viewGeneration){var anchor=found.stream().filter(r->r.item().id().equals(selectedRow.item().id())).findFirst();if(anchor.isPresent())chain.getItems().setAll(found.stream().filter(r->r.threadId().equals(selectedRow.thread())&&r.peerId().equals(anchor.get().peerId())).sorted(Comparator.comparingLong(r->r.item().time())).toList());}});
  }
  void composePage(){
    Node before=section.equals("compose")?composeBackdrop:root.getCenter();clearCompose();composeBackdrop=before;section="compose";viewGeneration++;
    recipientPicker=new ContactPicker(session.local().contacts().stream().map(UserInfo::nickname).toList(),themes);recipientPicker.setCellFactory(list->contactCell());recipientPicker.setButtonCell(contactCell());recipientField=recipientPicker.getEditor();recipientField.setText(selected);
    subjectField=field("Тема");composer=new TextArea();composer.setPromptText("Текст письма");composer.setWrapText(true);composer.setPrefRowCount(14);composer.getStyleClass().add("composer");
    letterPassword=new SecretField("Пароль письма");secondCode=new SecretField("Код второго слоя");
    additionalProtection=new CheckBox("Дополнительная защита");additionalProtection.setSelected(false);
    letterPassword.visibleProperty().bind(additionalProtection.selectedProperty());letterPassword.managedProperty().bind(additionalProtection.selectedProperty());secondCode.visibleProperty().bind(additionalProtection.selectedProperty());secondCode.managedProperty().bind(additionalProtection.selectedProperty());
    ttl=new Selector<>(themes);ttl.getItems().addAll(new Ttl("5 минут",300),new Ttl("30 минут",1800),new Ttl("1 час",3600),new Ttl("6 часов",21600),new Ttl("1 день",86400),new Ttl("3 дня",259200),new Ttl("7 дней",604800));
    ttl.getSelectionModel().select(ttl.getItems().stream().filter(t->t.seconds()==config.defaultTTL()).findFirst().orElse(ttl.getItems().get(4)));
    ttl.setVisibleRowCount(7);ttl.setPrefWidth(185);themes.stylePopup(ttl);
    attachmentLabel=new Label();attachmentLabel.setWrapText(true);attachmentsBox=new VBox(5);Button send=new Button("Отправить");sendButton=send;send.setDisable(!session.online()||tor==null||!tor.ready());send.setOnAction(e->send(send));
    ScrollPane attachmentScroll=new ScrollPane(attachmentsBox);attachmentScroll.setFitToWidth(true);attachmentScroll.setMaxHeight(130);attachmentScroll.setPrefHeight(0);attachmentScroll.visibleProperty().bind(javafx.beans.binding.Bindings.isNotEmpty(attachmentsBox.getChildren()));attachmentScroll.managedProperty().bind(attachmentScroll.visibleProperty());attachmentsBox.getChildren().addListener((javafx.collections.ListChangeListener<javafx.scene.Node>)change->attachmentScroll.setPrefHeight(Math.min(130,attachmentsBox.getChildren().size()*40)));
    disappearing=new CheckBox("Исчезающее письмо");disappearing.setTooltip(new Tooltip("Отсчёт после показа на одном устройстве. Открытые письма закрываются после перезагрузки ОС или при недостоверном таймере."));
    expiryTTL=new Selector<>(themes);expiryTTL.getItems().addAll(new Ttl("5 минут",300),new Ttl("1 час",3600),new Ttl("1 день",86400),new Ttl("7 дней",604800),new Ttl("30 дней",2592000),new Ttl("Свой срок",0));expiryTTL.getSelectionModel().select(2);expiryMinutes=field("Минуты, 1–43200");expiryMinutes.setText("60");expiryMinutes.setPrefWidth(150);expiryMinutes.visibleProperty().bind(disappearing.selectedProperty().and(expiryTTL.valueProperty().isNull().not()).and(javafx.beans.binding.Bindings.createBooleanBinding(()->expiryTTL.getValue()!=null&&expiryTTL.getValue().seconds()==0,expiryTTL.valueProperty())));expiryMinutes.managedProperty().bind(expiryMinutes.visibleProperty());
    HBox address=new HBox(14,recipientPicker);HBox.setHgrow(recipientPicker,Priority.ALWAYS);address.setAlignment(Pos.BOTTOM_LEFT);
    ComboBox<String> retention=new ComboBox<>();List<Ttl> ordinary=List.copyOf(ttl.getItems()),expiring=List.copyOf(expiryTTL.getItems());for(Ttl t:ordinary)retention.getItems().add("После доставки: "+t.label());for(Ttl t:expiring)retention.getItems().add("После показа: "+t.label());
    retention.setPrefWidth(260);retention.setAccessibleText("Срок письма");retention.setTooltip(new Tooltip("После доставки — обычный TTL. После показа — исчезающее письмо на совместимом устройстве. Relay delivery deadline задаётся независимо."));
    retention.setOnAction(e->{int n=retention.getSelectionModel().getSelectedIndex();if(n<0)return;boolean after=n>=ordinary.size();disappearing.setSelected(after);if(after)expiryTTL.setValue(expiring.get(n-ordinary.size()));else ttl.setValue(ordinary.get(n));});
    VBox box=new VBox(12,new Label("Новое письмо"),new Label("Кому"),address,subjectField,composer,new HBox(8,new Label("Срок письма"),retention,expiryMinutes),additionalProtection,letterPassword,secondCode,attachmentScroll,new FlowPane(10,8,button("+ Прикрепить",this::attach),attachmentLabel,attachmentTransfers600()),send);
    if(draft!=null){recipientField.setText(draft.recipient);subjectField.setText(draft.subject);composer.setText(draft.body);attachments.addAll(draft.files);additionalProtection.setSelected(draft.protectedLetter);letterPassword.hidden.setText(new String(draft.password));secondCode.hidden.setText(new String(draft.code));replyContext=draft.context;replyNeedsProtection=draft.forceProtection;restoredForwardedMissing=draft.forwardedMissing;forwardedFiles=draft.bundle;draft.bundle=null;
      disappearing.setSelected(draft.disappearing);expiryMinutes.setText(draft.expiryInput);expiryTTL.getItems().stream().filter(t->t.seconds()==draft.expirySeconds).findFirst().ifPresent(t->expiryTTL.setValue(t));
      ttl.getItems().stream().filter(t->t.seconds()==draft.ttl).findFirst().ifPresent(t->ttl.setValue(t));draft.close();draft=null;
    }
    retention.getSelectionModel().select(disappearing.isSelected()?ordinary.size()+Math.max(0,expiring.indexOf(expiryTTL.getValue())):Math.max(0,ordinary.indexOf(ttl.getValue())));
    additionalProtection.setDisable(replyNeedsProtection);if(replyContext!=null)box.getChildren().add(2,new Label((replyContext.forwarded()?"Пересылка: ":"Ответ: ")+replyContext.author()+" · "+replyContext.subject()));
    if(restoredForwardedMissing){Label warning=new Label("Пересылаемые вложения прежнего черновика нужно прикрепить повторно. Отправка заблокирована до проверки.");warning.setWrapText(true);Button acknowledge=button("Я проверил и убираю прежние вложения",()->{restoredForwardedMissing=false;warning.setVisible(false);warning.setManaged(false);});box.getChildren().addAll(warning,acknowledge);}
    if(!attachmentWarning600.isEmpty()){Label warning=new Label(attachmentWarning600);warning.setWrapText(true);box.getChildren().add(warning);}
    showAttachments();
    box.setPadding(new Insets(18));box.getStyleClass().add("settings-card");VBox.setVgrow(composer,Priority.ALWAYS);composeContent=new ScrollPane(box);composeContent.setFitToWidth(true);composeContent.setFitToHeight(true);placeComposer();
  }
  private void placeComposer(){
    if(composeContent==null||!section.equals("compose"))return;root.setCenter(null);if(composeStack!=null)composeStack.getChildren().clear();
    boolean drawer=themes.settings().layout().composer()==Appearance.Composer.DRAWER&&root.getWidth()>=850;
    if(!drawer){if(composeBackdrop!=null)composeBackdrop.setDisable(false);composeContent.setMaxWidth(Double.MAX_VALUE);root.setCenter(composeContent);return;}
    if(composeBackdrop==null)composeBackdrop=new VBox(new Label("Письма"));composeBackdrop.setDisable(true);composeContent.setMaxWidth(Math.min(620,Math.max(420,root.getWidth()*.58)));
    composeStack=new StackPane(composeBackdrop,composeContent);StackPane.setAlignment(composeContent,Pos.CENTER_RIGHT);root.setCenter(composeStack);
  }
  private void send(Button button){
    try{
      if(restoredForwardedMissing){info("Проверьте восстановленный черновик и прикрепите пересылаемые файлы заново.");return;}
      if(updates.snapshot().manifest()!=null&&updates.snapshot().manifest().requiredFor(SignedManifest.CURRENT)){info("Для продолжения требуется обновление АЕГИС");updatesPage();return;}
      String nick=Limits.nickname(recipientField.getText());UserInfo recipient=session.local().contact(nick);
      if(!session.online()||tor==null||!tor.ready()){info("Войдите в сеть для отправки");return;}
      if(recipient==null){info("Сначала добавьте и проверьте контакт");return;}
      Ttl lifetime=ttl.getValue();if(lifetime==null||lifetime.seconds()<60||lifetime.seconds()>604800){info("Выберите срок хранения");return;}
      boolean expiring=disappearing!=null&&disappearing.isSelected();long chosenExpiry=0;
      if(expiring){try{Ttl option=expiryTTL.getValue();chosenExpiry=option.seconds()==0?Math.multiplyExact(Long.parseLong(expiryMinutes.getText().trim()),60):option.seconds();if(chosenExpiry<60||chosenExpiry>30L*86400)throw new IllegalArgumentException();}catch(Exception invalid){info("Срок исчезновения: от 1 минуты до 30 дней");return;}}
      long expirationSeconds=chosenExpiry;
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
          boolean rich=(expiring||session.local().cachedProfile(nick)!=null)&&(context!=null||files.size()+(bundle==null?0:bundle.info().size())>1);
          long selectedBytes=0;for(Path file:files)selectedBytes=Math.addExact(selectedBytes,Files.size(file));
          boolean streamed=selectedBytes>config.maxFileSize();
          if(streamed&&bundle!=null&&bundle.size()>0)throw new IOException("Сначала сохраните пересылаемые вложения и прикрепите их как файлы.");
          org.securemail.client.attachments600.AttachmentManifest600 manifest=null;byte[] manifestBytes=null;
          try{
            if(streamed){var manager=session.attachments600();if(manager==null)throw new IOException("Для вложений до 500 МиБ настройте доверенный сервер вложений в главном АЕГИС.");manifest=manager.prepare(session.network(),recipient,files,config.deliveryTTL(),protectedLetter?password:new char[0],protectedLetter?code:new char[0],(done,total)->{long completed=done,expected=total;Platform.runLater(()->{if(!stopping&&generation==viewGeneration)button.setText("Загрузка: "+fileSize(completed)+" / "+fileSize(expected));});});manifestBytes=manifest.encode();}
          try(var plain=streamed?PlainMessage.streaming(subject,body,envelope==null?new byte[0]:envelope,context,manifestBytes):PlainMessage.compose(subject,body,envelope==null?new byte[0]:envelope,files,bundle,config.maxFileSize(),context,rich)){
            if(expiring)try{session.syncPublicData(recipient);}catch(IOException unavailable){/* A current signed device capability can authorize direct delivery without Relay. */}
            var packet=expiring?session.lifecycle().encryptExpiring(plain,recipient,expirationSeconds,config.deliveryTTL()):automatic.encrypt(plain,lifetime.seconds(),config.deliveryTTL(),session.local().identity(),session.local().nickname(),recipient);
            var manager=session.attachments600();var sent=streamed?session.lifecycle().send(packet,recipient,manager::packetPersisted):session.lifecycle().send(packet,recipient);if(mailComponent())session.local().deleteExtension("mail6-draft-v1");return sent;
          }}finally{if(manifest!=null)manifest.close();if(manifestBytes!=null)Arrays.fill(manifestBytes,(byte)0);}
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
    Button remove=button(friends?"Убрать из друзей":"Удалить контакт",()->{if(!selected.isBlank()){String nick=selected;UserInfo peer=session.local().contact(nick);ClientSession active=session;work(null,"",()->{active.features().consent(peer.userId(),false);if(!friends)active.local().removeContact(nick);if(active.online())try{active.syncPublicData(null);}catch(Exception retryLater){/* Revocation is durable locally and retries separately. */}return true;},v->fillContacts(search.getText()));}});
    Button pin=button("☆ Избранное",()->{UserInfo peer=session.local().contact(selected);if(peer!=null)work(null,"",()->{session.features().pin("pinnedContacts",peer.userId(),!session.features().pinned("pinnedContacts",peer.userId()));return true;},v->fillContacts(search.getText()));});
    Button viewProfile=button("Профиль",()->{if(!selected.isBlank())contactProfile(selected);});
    MenuButton more=new MenuButton("Действия контакта");more.setMinWidth(Region.USE_PREF_SIZE);for(Button action:List.of(verify,pin,remove)){MenuItem entry=new MenuItem(action.getText());entry.setOnAction(e->action.fire());more.getItems().add(entry);}MenuItem write=new MenuItem("Написать письмо");write.setOnAction(e->{String target=selected;composePage();if(recipientField!=null)recipientField.setText(target);});more.getItems().add(1,write);VBox box=new VBox(12,search,contacts,new FlowPane(8,8,button("+ Контакт",this::addContact),viewProfile,more));box.setPadding(new Insets(16));VBox.setVgrow(contacts,Priority.ALWAYS);root.setCenter(box);fillContacts("");
  }
  private void friendsPage(){contactsPage(true);}
  private void searchPage(){
    clearCompose();section="search";viewGeneration++;TextField term=field("Имя, тема или содержимое письма"),nick=field("Отправитель"),subject=field("Тема");DatePicker from=new DatePicker(),to=new DatePicker();
    Selector<LocalMailSearch.Scope> scope=new Selector<>(themes,List.of(LocalMailSearch.Scope.ALL,LocalMailSearch.Scope.INBOX,LocalMailSearch.Scope.SENT,LocalMailSearch.Scope.UNKNOWN,LocalMailSearch.Scope.BLOCKED,LocalMailSearch.Scope.FAVORITES,LocalMailSearch.Scope.FRIENDS),LocalMailSearch.Scope.ALL);
    Selector<LocalMailSearch.Kind> kind=new Selector<>(themes,List.of(LocalMailSearch.Kind.values()),LocalMailSearch.Kind.ALL);
    ListView<LocalMailSearch.Result> results=new ListView<>();results.setCellFactory(list->new ListCell<>(){protected void updateItem(LocalMailSearch.Result r,boolean empty){super.updateItem(r,empty);setText(empty||r==null?null:r.item().contact()+" · "+(r.subject().isBlank()?"Без темы":r.subject()));}});
    results.setOnMouseClicked(e->{if(e.getClickCount()==2){var chosen=results.getSelectionModel().getSelectedItem();if(chosen!=null)openLetter(chosen.item());}});
    Button search=new Button("Найти");search.setOnAction(e->{try{long a=from.getValue()==null?0:from.getValue().atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli(),b=to.getValue()==null?Long.MAX_VALUE:to.getValue().plusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()-1;
      var query=new LocalMailSearch.Query(nick.getText(),subject.getText(),a,b,scope.getValue(),term.getText(),kind.getValue());long generation=viewGeneration;work(search,"Поиск…",()->LocalMailSearch.find(session.local(),session.features(),session.lifecycle(),query,config.maxFileSize()),found->{if(section.equals("search")&&generation==viewGeneration)results.getItems().setAll(found);});
    }catch(Exception failure){error(failure);}});
    from.setPromptText("Дата от");to.setPromptText("Дата до");nick.setAccessibleText("Отправитель");subject.setAccessibleText("Тема");from.setAccessibleText("Дата от");to.setAccessibleText("Дата до");kind.setAccessibleText("Тип письма");scope.setAccessibleText("Направление письма");
    FlowPane filters=new FlowPane(8,8,labeledFilter("Отправитель",nick),labeledFilter("Тема",subject),labeledFilter("Дата от",from),labeledFilter("Дата до",to),labeledFilter("Тип письма",kind),labeledFilter("Направление письма",scope));filters.setId("mail-search-filters");filters.getStyleClass().add("settings-card");
    ToggleButton filterToggle=new ToggleButton("Фильтры");filterToggle.setAccessibleText("Показать фильтры поиска");filters.visibleProperty().bind(filterToggle.selectedProperty());filters.managedProperty().bind(filterToggle.selectedProperty());
    FlowPane quick=new FlowPane(8,8);for(var category:List.of(LocalMailSearch.Scope.ALL,LocalMailSearch.Scope.INBOX,LocalMailSearch.Scope.SENT))quick.getChildren().add(button(category.toString(),()->{scope.setValue(category);search.fire();}));
    HBox main=new HBox(8,term,filterToggle,search);main.setMinWidth(0);term.setMinWidth(70);HBox.setHgrow(term,Priority.ALWAYS);term.setOnAction(e->search.fire());search.getStyleClass().add("primary");
    VBox body=new VBox(10,new Label("Поиск на устройстве"),main,quick,filters,results);body.setPadding(new Insets(20));VBox.setVgrow(results,Priority.ALWAYS);root.setCenter(body);
  }
  private static Node labeledFilter(String text,Region control){Label label=new Label(text);label.getStyleClass().add("muted");label.setLabelFor(control);control.setMinWidth(0);control.setMaxWidth(Double.MAX_VALUE);VBox field=new VBox(4,label,control);field.setPrefWidth(180);field.setMinWidth(120);return field;}
  private void fillContacts(String term){
    if(contacts==null)return;String old=selected;contacts.setPlaceholder(new Label(section.equals("friends")?"Ожидается взаимное добавление в контакты":"Добавьте контакт"));
    contacts.getItems().setAll(session.local().contacts().stream().filter(u->!section.equals("friends")||session.features().friend(u.userId())).sorted(Comparator.comparing((UserInfo u)->!session.features().pinned("pinnedContacts",u.userId())).thenComparing(UserInfo::nickname)).map(UserInfo::nickname).filter(s->s.contains(term.toLowerCase(Locale.ROOT))).toList());
    if(!old.isEmpty())contacts.getSelectionModel().select(old);
  }
  private static String fileSize(long bytes){return String.format(Locale.ROOT,"%.1f МиБ",bytes/1048576.0);}
  private void showAttachments(){
    if(attachmentsBox==null)return;attachmentsBox.getChildren().clear();long total=0;
    for(Path path:List.copyOf(attachments)){long size;try{size=Files.size(path);}catch(IOException e){size=0;}total+=size;
      Label name=new Label(path.getFileName()+"  "+fileSize(size));name.setMaxWidth(Double.MAX_VALUE);HBox.setHgrow(name,Priority.ALWAYS);
      HBox row=new HBox(8,name,button("×",()->{attachments.remove(path);showAttachments();}));attachmentsBox.getChildren().add(row);
    }if(forwardedFiles!=null){total+=forwardedFiles.size();for(var file:forwardedFiles.info())attachmentsBox.getChildren().add(new Label("↪ "+file.name()+"  "+fileSize(file.size())));attachmentsBox.getChildren().add(button("Убрать пересылаемые вложения",()->{forwardedFiles.close();forwardedFiles=null;showAttachments();}));}
    attachmentLabel.setText("Общий размер: "+fileSize(total)+" / "+fileSize(attachmentLimit600()));
  }
  private Node attachmentTransfers600(){MenuButton menu=new MenuButton("Передачи");MenuItem cancel=new MenuItem("Отменить передачу"),clear=new MenuItem("Очистить незавершённую очередь");cancel.setOnAction(e->{if(session!=null&&session.attachments600()!=null)session.attachments600().cancelCurrent();});clear.setOnAction(e->clearAttachmentQueue600());menu.getItems().addAll(cancel,clear);boolean visible=mailComponent()&&session!=null&&session.attachments600()!=null;menu.setVisible(visible);menu.setManaged(visible);return menu;}
  private long attachmentLimit600(){return mailComponent()&&session!=null&&session.attachments600()!=null?org.securemail.client.attachments600.StreamingAttachmentCipher.MAX_PLAINTEXT:config.maxFileSize();}
  private void clearAttachmentQueue600(){var manager=session==null?null:session.attachments600();if(manager==null)return;InWindowAlert prompt=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Отменить незавершённую загрузку? Исходные файлы сохранятся.",ButtonType.OK,ButtonType.CANCEL);prompt.initOwner(stage);themes.apply(prompt.getDialogPane());if(prompt.showAndWait().orElse(ButtonType.CANCEL)==ButtonType.OK)work(null,"Очистка очереди…",()->{manager.discardPending();return true;},ignored->info("Незавершённая загрузка отменена."));}
  private void attach(){InWindowFileChooser chooser=new InWindowFileChooser();chooser.setTitle("Прикрепить файлы");var files=chooser.showOpenMultipleDialog(stage);if(files==null)return;
    try{List<Path> next=new ArrayList<>(attachments);long total=forwardedFiles==null?0:forwardedFiles.size();int forwardedCount=forwardedFiles==null?0:forwardedFiles.info().size();for(Path path:next)total+=Files.size(path);
      for(File file:files){Path path=file.toPath();PlainMessage.validateFilename(file.getName());if(Files.isSymbolicLink(path)||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Выберите обычный файл");if(next.contains(path))continue;total+=Files.size(path);if(total>attachmentLimit600())throw new IOException("Общий размер вложений превышает "+fileSize(attachmentLimit600()));next.add(path);if(next.size()+forwardedCount>PlainMessage.MAX_ATTACHMENTS)throw new IllegalArgumentException("Не более 64 вложений");}
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
    clearCompose();section="settings";viewGeneration++;ListView<String> categories=new ListView<>();
    VBox contentArea=new VBox();contentArea.setId("settings-content");contentArea.setMinWidth(0);
    TilePane groups=new TilePane(8,8);groups.setId("settings-categories");groups.setPrefTileWidth(200);groups.setPrefTileHeight(56);groups.getStyleClass().add("settings-card");FlowPane details=new FlowPane(8,8);
    String[][] sections={{"Аккаунт и профиль","Профиль","Сессии"},{"Безопасность и конфиденциальность","Безопасность","Резервные копии","Архив"},{"Сеть, Tor и обновления","Соединение","Общий сервер","Обновления"},{"Интерфейс и уведомления","Внешний вид","Уведомления"},{"Взор и Глас","Взор","Глас"},{"О приложении","О программе","Диагностика"}};
    if(mailComponent())sections=new String[][]{{"Безопасность и данные","Почтовая безопасность","Резервные копии","Архив"},{"Сеть и обновления","Соединение","Обновления"},{"Интерфейс и уведомления","Внешний вид","Уведомления"},{"О почте","О программе","Диагностика"}};
    ToggleGroup selectedGroup=new ToggleGroup();
    for(String[] group:sections){ToggleButton tab=new ToggleButton(group[0]);tab.setToggleGroup(selectedGroup);tab.setMinHeight(36);tab.setMaxSize(Double.MAX_VALUE,Double.MAX_VALUE);tab.setWrapText(true);tab.setTextAlignment(javafx.scene.text.TextAlignment.CENTER);tab.setAccessibleText(group[0]);groups.getChildren().add(tab);tab.setOnAction(e->{tab.setSelected(true);details.getChildren().clear();for(int i=1;i<group.length;i++){String name=group[i];details.getChildren().add(button(name,()->{categories.getItems().setAll(name);categories.getSelectionModel().selectFirst();}));}categories.getItems().setAll(group[1]);categories.getSelectionModel().selectFirst();});}
    // Categories and their content share one scroll surface. At 200% the category
    // grid may fill several rows; the content below remains reachable by scrolling.
    VBox workspace=new VBox(12,groups,details,contentArea);workspace.setPadding(new Insets(14));workspace.setMinWidth(0);ScrollPane settingsScroll=new ScrollPane(workspace);settingsScroll.setId("settings-page");settingsScroll.setFitToWidth(true);
    categories.getSelectionModel().selectedItemProperty().addListener((o,a,b)->{if(b==null)return;themes.cancelPreview();Node content;
      try{switch(b){
        case "Профиль"->content=profileCard();
        case "Сессии"->{Label hint=new Label(rememberedExpires>System.currentTimeMillis()?"На этом устройстве сохранён вход до "+Instant.ofEpochMilli(rememberedExpires).atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")):"Вход на этом устройстве не сохранён");hint.setWrapText(true);content=new VBox(12,hint,button("Завершить сохранённую сессию",this::endRemembered));}
        case "Почтовая безопасность"->{Label hint=new Label("Учётной записью и поколением сессии управляет главное АЕГИС. Закрытие или блокировка главного окна закрывает доступ к почте.");hint.setWrapText(true);content=new VBox(12,hint,button("Заблокировать Почту",()->componentLock()));}
        case "Безопасность"->{Label privacy=new Label("E2EE и локальное хранилище защищают данные. Личный архив использует отдельный пароль.");privacy.setWrapText(true);content=new VBox(14,privacy,button("Завершить сохранённую сессию",this::endRemembered),secondFactorSettings());}
        case "Уведомления"->content=notificationPreferences();
        case "Внешний вид"->content=new AppearanceView(stage,themes,worker).node();
        case "Соединение"->{detailConnectionCard=new ConnectionCard(()->{wantsNetwork=true;if(connectingTor)return;if(tor==null||!tor.ready())startTor();else preconnect();});detailConnectionCard.update(connectivity.snapshot());content=new VBox(14,detailConnectionCard,button("Войти после восстановления связи",this::reconnectAccount));}
        case "Глас"->content=glasView().settingsNode();
        case "Взор"->content=new VBox(10,CommunityUi.label("Официальный браузер, изоляция, загрузки и диагностика доступны в разделе «Взор»."),button("Открыть Взор",this::safeWebPage));
        case "Общий сервер"->content=communityEndpointSettings();
        case "Управление АЕГИС"->content=new AdminView(community()).node();
        case "Обновления"->{updatesView=makeUpdatesView();content=updatesView.node();}
        case "Резервные копии"->{Label hint=new Label("Резервная копия идентичности не включает все письма. Архив имеет собственные зашифрованные копии и восстановление.");hint.setWrapText(true);content=new VBox(14,hint,button("Экспорт идентичности",this::backup),button("Открыть архив",this::archivePage));}
        case "Архив"->{Label hint=new Label("Пароль, ключ восстановления, резервные копии и восстановление контейнера доступны в управлении личным архивом.");hint.setWrapText(true);content=new VBox(12,hint,button("Открыть архив",this::archivePage));}
        case "Диагностика"->{Label data=new Label("АЕГИС "+SignedManifest.CURRENT+" · протокол 1\nTor: "+torModeLabel(connectivity.snapshot().mode())+" "+connectivity.snapshot().progress()+"%\nSOCKS: 127.0.0.1:"+config.torSocksPort()+"\nHTTPS SOCKS: 127.0.0.1:"+config.torUpdateSocksPort()+"\nControl: 127.0.0.1:"+config.torControlPort()+"\nRelay: "+config.relayOnionAddress()+"\n"+session.status());data.setWrapText(true);content=new VBox(14,data);}
        default->{Label about=new Label("АЕГИС "+SignedManifest.CURRENT+"\nАвтономная Единая Гибридная Информационная Система\nJava 21 · протокол 1");about.setWrapText(true);content=new VBox(14,about);}
      }}catch(Exception failed){error(failed);content=new Label("Раздел недоступен");}
      if(content instanceof Region region)region.setMinWidth(0);contentArea.getChildren().setAll(content);if(content instanceof Parent styled)themes.apply(styled);settingsScroll.setVvalue(0);
    });root.setCenter(settingsScroll);((ToggleButton)groups.getChildren().getFirst()).fire();
    if(mailComponent())return;
    long settingsGeneration=viewGeneration;Label adminState=CommunityUi.label("");community().call("community.me",CommunityUi.obj(),adminState,me->{if(session==null||!section.equals("settings")||settingsGeneration!=viewGeneration)return;boolean authorized=CommunityUi.administrative(me);if(authorized){Button admin=button("Управление АЕГИС",()->{categories.getItems().setAll("Управление АЕГИС");categories.getSelectionModel().selectFirst();});workspace.getChildren().add(1,admin);}});
  }
  private Node secondFactorSettings(){CommunityUi api=community();ClientSession active=session;Label status=CommunityUi.label("Одноразовые коды защищают управление организациями и административные операции.");VBox enrollment=new VBox(8);Button setup=CommunityUi.button("Настроить второй фактор",()->api.call("account.factor.status",CommunityUi.obj(),status,factor->{if(CommunityUi.str(factor,"configured").equals("true")){status.setText("Второй фактор уже включён. Восстановление или замена требуют защищённой процедуры.");return;}if(!CommunityUi.str(factor,"canEnroll").equals("true")){status.setText("Настройка доступна через защищённую процедуру администрации.");return;}PasswordField password=new PasswordField();password.setPromptText("Пароль аккаунта");InWindowDialog<String> prompt=new InWindowDialog<>();prompt.setTitle("Подтверждение настройки второго фактора");prompt.getDialogPane().setContent(new VBox(8,CommunityUi.label("Подтвердите вход, затем добавьте ключ в своё приложение одноразовых кодов."),password));prompt.getDialogPane().getButtonTypes().setAll(ButtonType.OK,ButtonType.CANCEL);prompt.setResultConverter(button->button==ButtonType.OK?password.getText():null);themes.apply(prompt.getDialogPane());Optional<String> entered=prompt.showAndWait();password.clear();if(entered.isEmpty())return;char[] secret=entered.get().toCharArray();api.task(()->{try{active.reauthenticate(secret);return active.community().rpc("account.factor.enroll.begin",CommunityUi.obj());}finally{Arrays.fill(secret,'\0');}},status,response->{if(active!=session)return;String id=CommunityUi.str(response,"enrollmentId");TextArea seed=new TextArea(CommunityUi.str(response,"seedBase32"));seed.setEditable(false);seed.setWrapText(true);seed.setPrefRowCount(2);seed.setVisible(false);seed.setManaged(false);CheckBox reveal=new CheckBox("Показать секрет настройки");reveal.setOnAction(e->{seed.setVisible(reveal.isSelected());seed.setManaged(reveal.isSelected());});TextField code=CommunityUi.field("Одноразовый код из приложения (8 цифр)");javafx.animation.PauseTransition expires=new javafx.animation.PauseTransition(Duration.minutes(5));Runnable erase=()->{seed.clear();code.clear();reveal.setSelected(false);seed.setVisible(false);seed.setManaged(false);};expires.setOnFinished(e->{erase.run();enrollment.getChildren().clear();status.setText("Время настройки истекло. Повторите процедуру.");});enrollment.getChildren().setAll(CommunityUi.label("Добавьте ключ в приложение одноразовых кодов: HMAC-SHA256, 8 цифр, период 30 секунд. Секрет не сохраняется в диагностике и не копируется автоматически."),reveal,seed,code,CommunityUi.button("Подтвердить подключение",()->{String otp=code.getText().trim();code.clear();api.call("account.factor.enroll.finish",CommunityUi.obj("enrollmentId",id,"code",otp),status,result->{expires.stop();erase.run();enrollment.getChildren().clear();status.setText("Второй фактор включён. Для следующего защищённого действия дождитесь нового одноразового кода.");});}));enrollment.sceneProperty().addListener((o,a,b)->{if(b==null){expires.stop();erase.run();enrollment.getChildren().clear();}});expires.play();});}));return CommunityUi.fold("Одноразовые коды и защищённое управление",CommunityUi.card(status,setup,enrollment));}
  private CommunityUi community(){if(communityUi==null){ClientSession active=session;communityUi=new CommunityUi(themes,(action,args)->{if(active!=session)throw new IOException("Session changed");return active.community().rpc(action,args);},active::adminStepUp,url->{if(url.startsWith("aegis-library:")){clearCompose();section="library";viewGeneration++;KnowledgeLibraryView library=new KnowledgeLibraryView(community(),"");root.setCenter(library.node());library.openId(url.substring("aegis-library:".length()));return;}if(!DocumentEditor.safe(url)){info("Разрешены HTTPS-сайты и onion v3. Локальные адреса и команды запрещены.");return;}safeWebPage();vzorView.address(url);info("Проверьте адрес и нажмите «Открыть Взор».");});}return communityUi;}
  private void communityPage(String id){clearCompose();section=id;viewGeneration++;CommunityUi api=community();Node content=switch(id){case "organizations"->new OrganizationsView(api).node();case "news"->new NewsView(api).node();default->new KnowledgeLibraryView(api,"").node();};root.setCenter(content);if(content instanceof Parent styled)themes.apply(styled);}
  private Node communityEndpointSettings(){TextField address=CommunityUi.field("Адрес onion общего сервера"),port=CommunityUi.field("Порт onion-сервиса"),key=CommunityUi.field("Проверенный публичный ключ Ed25519 (Base64)");var endpoint=session.community().settings();address.setText(endpoint.onion());port.setText(Integer.toString(endpoint.port()));key.setText(endpoint.serverPublicKey());Label state=CommunityUi.label(session.community().configured()?"Проверенный общий сервер настроен.":"Общий сервер не настроен. Получите адрес и отпечаток ключа у администрации по проверенному каналу.");Button save=button("Сохранить проверенный сервер",()->{ClientSession active=session;String host=address.getText().trim(),publicKey=key.getText().trim();int endpointPort;try{endpointPort=Integer.parseInt(port.getText());}catch(Exception invalid){state.setText("Укажите корректный порт.");return;}work(null,"",()->{active.community().configure(host,endpointPort,publicKey);return true;},r->state.setText("Сервер сохранён. Все клиентские запросы используют Tor и проверяют его криптографическую идентичность."));});return CommunityUi.card(CommunityUi.heading("Общий сервер АЕГИС"),state,address,port,key,save,CommunityUi.button("Очистить кэш общих материалов",()->{ClientSession active=session;work(null,"",()->{active.community().clearCache();return true;},r->state.setText("Зашифрованный кэш общих материалов очищен."));}));}
  private Node notificationPreferences(){
    ClientSession active=session;var preferences=active.features();CheckBox receipts=new CheckBox("Подтверждать прочтение обычных писем");receipts.setSelected(active.lifecycle().readReceipts());
    CheckBox mail=new CheckBox("Письма"),friends=new CheckBox("Приоритет писем друзей"),events=new CheckBox("События взаимного добавления в контакты"),releases=new CheckBox("Обновления");
    for(CheckBox option:List.of(mail,friends,events,releases,receipts))option.setWrapText(true);
    mail.setSelected(preferences.notifications());friends.setSelected(preferences.friendNotifications());events.setSelected(preferences.friendEvents());releases.setSelected(preferences.updateNotifications());
    Label quiet=new Label("Уведомления отображаются внутри АЕГИС. Выбор категорий сохраняется на этом устройстве.");quiet.setWrapText(true);Button save=new Button("Сохранить");save.getStyleClass().add("primary");
    save.setOnAction(e->{boolean a=mail.isSelected(),b=friends.isSelected(),c=events.isSelected(),d=releases.isSelected(),read=receipts.isSelected();work(save,"Сохранение…",()->{preferences.notifications(a,b,c,d);active.lifecycle().readReceipts(read);return true;},v->info("Настройки уведомлений сохранены"));});
    VBox content=new VBox(12,quiet,mail,friends,events,releases,receipts,save,mailComponent()?new Label("Настройки общих уведомлений доступны в главном АЕГИС."):communityNotifications());content.setMaxWidth(720);return content;
  }
  private Node communityNotifications(){CommunityUi api=community();Label status=CommunityUi.label("");ListView<com.google.gson.JsonObject> entries=CommunityUi.list("Нет доступных уведомлений общего сервера");VBox preferences=new VBox(6);Runnable refresh=()->api.call("content.notifications.list",CommunityUi.obj("limit",100),status,result->CommunityUi.fill(entries,result,"items"));Button read=CommunityUi.button("Отметить прочитанным",()->{var selected=entries.getSelectionModel().getSelectedItem();if(selected!=null)api.call("content.notifications.read",CommunityUi.obj("id",CommunityUi.str(selected,"id")),status,r->refresh.run());});api.call("content.notifications.settings",CommunityUi.obj(),null,result->{for(var setting:CommunityUi.items(result,"items")){String category=CommunityUi.str(setting,"category");CheckBox option=new CheckBox(switch(category){case "MODERATION"->"Результаты модерации";case "EVENT_CHANGED"->"Изменения мероприятий";case "EVENT_REGISTERED"->"Регистрация на мероприятия";case "ORGANIZATION"->"Организации и заявки";case "ROLE"->"Роли и полномочия";case "VERIFICATION"->"Подтверждение личности и должности";case "SECURITY"->"События безопасности";case "LIBRARY"->"Изменения библиотеки";case "NEWS"->"Новые публикации";case "AGENT"->"Работа ИИ-редактора";default->"Изменения общих материалов";});option.setWrapText(true);option.setSelected(CommunityUi.str(setting,"enabled").equals("true"));option.setOnAction(e->api.call("content.notifications.settings",CommunityUi.obj("category",category,"enabled",option.isSelected()),status,r->status.setText("Категория уведомлений сохранена на сервере.")));preferences.getChildren().add(option);}});refresh.run();return CommunityUi.fold("Центр уведомлений",CommunityUi.card(entries,CommunityUi.actions(CommunityUi.button("Обновить",refresh),read),preferences,status));}
  private <T> void safeWebWork(Button button,Work<T> action,java.util.function.Consumer<T> done){
    if(stopping||installingUpdate){if(!stopping)info("Взор недоступен во время установки обновления АЕГИС");return;}
    if(button!=null)button.setDisable(true);
    safeWebWorker.execute(()->{try{T result=action.run();Platform.runLater(()->{if(button!=null)button.setDisable(false);if(!stopping)done.accept(result);else if(result instanceof AutoCloseable closeable)try{closeable.close();}catch(Exception ignored){};});}
      catch(Exception failure){Platform.runLater(()->{if(button!=null)button.setDisable(false);if(!stopping){String message=failure.getMessage();info("Взор: "+(message==null?"не удалось выполнить действие":message.replace('\n',' ').replace('\r',' ')));}});}});
  }
  private void safeWebPage(){
    if(mailComponent()){info("Взор открывается из главного АЕГИС.");return;}
    clearCompose();section="safeweb";viewGeneration++;
    if(vzorView==null)vzorView=new VzorView(stage,themes,config,safeWeb,safeWebWorker,
      ()->tor!=null&&tor.ready(),()->{wantsNetwork=true;if(!connectingTor&&(tor==null||!tor.ready()))startTor();},
      ()->List.of(config.storagePath(),personalArchive().location()),
      file->{ArchiveView archive=personalArchive();archive.ensureUnlocked(()->safeWebWork(null,()->safeWeb.snapshotDownload(file),archive::importDownload),()->{});},this::info);
    root.setCenter(vzorView.node());
  }
  private Future<?> stopVzorForTransition(){
    if(vzorView!=null)vzorView.close();
    return safeWebWorker.submit(()->{safeWeb.close();return Boolean.TRUE;});
  }
  private GlasView glasView(){if(glasView==null)glasView=new GlasView(session,themes,worker,this::avatar,this::info);return glasView;}
  private void glasPage(){clearCompose();section="glas";viewGeneration++;root.setCenter(glasView().node());}
  private void bindCalls(){
    if(mailComponent())return;
    if(callListener!=null)try{callListener.close();}catch(Exception ignored){}
    var active=session;callListener=active.calls().listen(()->{if(callUiPending.compareAndSet(false,true))Platform.runLater(()->{callUiPending.set(false);if(!stopping&&session==active)refreshCallBanner();});});refreshCallBanner();
  }
  private void refreshCallBanner(){
    if(mailComponent())return;
    if(session==null)return;var call=session.calls().snapshot();boolean incoming=call.state()==VoiceCallService.State.INCOMING;
    boolean show=call.busy()&&(incoming?session.calls().notificationsEnabled():!section.equals("glas"));callBanner.setVisible(show);callBanner.setManaged(show);
    if(!show){callBanner.getChildren().clear();displayedCall="";return;}
    String key=call.callId()+":"+call.state()+":"+call.microphoneEnabled();
    if(key.equals(displayedCall))return;displayedCall=key;
    Label label=new Label((incoming?"Входящий звонок: ":"Глас · ")+(call.contact()==null?"Контакт":call.contact().nickname()));label.setWrapText(true);HBox.setHgrow(label,Priority.ALWAYS);
    callBanner.getChildren().setAll(label);
    if(incoming){callBanner.getChildren().add(button("Принять",()->{session.calls().accept(call.callId());glasPage();}));callBanner.getChildren().add(button("Отклонить",()->session.calls().decline(call.callId())));}
    else {callBanner.getChildren().add(button("Открыть Глас",this::glasPage));callBanner.getChildren().add(button("Завершить",()->session.calls().hangup()));}
  }
  private ArchiveView personalArchive(){if(archiveView==null)archiveView=new ArchiveView(stage,themes,session.local());return archiveView;}
  private void archivePage(){clearCompose();section="archive";viewGeneration++;root.setCenter(personalArchive().node());}
  private UpdatesView makeUpdatesView(){return new UpdatesView(stage,themes,updates,updatePreferences,p->{try{if(!p.channel().equals(updatePreferences.channel()))updates.channel(p.channel());p.save(AppPaths.root());updatePreferences=p;}catch(Exception e){throw new IllegalStateException(e);}},this::installUpdate);}
  private void notificationSettings(){
    InWindowDialog<Void> dialog=new InWindowDialog<>();dialog.initOwner(stage);dialog.setTitle("Уведомления");dialog.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
    CheckBox receipts=new CheckBox("Подтверждать прочтение обычных писем");receipts.setSelected(session.lifecycle().readReceipts());
    CheckBox mail=new CheckBox("Письма"),friends=new CheckBox("Приоритет писем друзей"),events=new CheckBox("События дружбы"),releases=new CheckBox("Обновления");
    var preferences=session.features();mail.setSelected(preferences.notifications());friends.setSelected(preferences.friendNotifications());events.setSelected(preferences.friendEvents());releases.setSelected(preferences.updateNotifications());
    Button save=new Button("Сохранить");save.setOnAction(e->{boolean a=mail.isSelected(),b=friends.isSelected(),c=events.isSelected(),d=releases.isSelected();work(save,"Сохранение…",()->{preferences.notifications(a,b,c,d);session.lifecycle().readReceipts(receipts.isSelected());return true;},done->dialog.close());});
    dialog.getDialogPane().setContent(new VBox(12,mail,friends,events,releases,receipts,save));themes.apply(dialog.getDialogPane());dialog.showAndWait();
  }
  private void appearance(){try{new AppearanceView(stage,themes,worker).show();}catch(IOException e){error(e);}}
  private void applyLayout(UiPreferences value)throws IOException {
    UiPreferences previous=layout;if(presets!=null)presets.apply(value);layout=value;themes.layout(value);
    // Appearance must not replace the active scene graph or clear a draft/password.
    Node sidebar=root.getLeft();if(sidebar!=null){sidebar.setVisible(value.sidebar());sidebar.setManaged(value.sidebar());}
    if(letters!=null)letters.refresh();if(contacts!=null)contacts.refresh();if(section.equals("mail")&&previous.preview()!=value.preview())mailboxPage(mailOutgoing,mailScope);
  }
  private Node avatar(String nick){return AvatarView.create(nick,avatarImages,layout.avatars(),themes.settings().components(),(int)Math.round(ResponsiveGeometry.avatar(root.getWidth(),themes.settings().components().avatarSize())));}
  private ListCell<String> contactCell(){return new ListCell<>(){protected void updateItem(String nick,boolean empty){super.updateItem(nick,empty);setText(null);setGraphic(null);if(empty||nick==null)return;UserInfo peer=session.local().contact(nick);String status=peer==null?"":session.features().blockedSender(peer.userId())?"Заблокирован":"Контакт";Label label=new Label(status);label.getStyleClass().add("muted");setGraphic(new HBox(8,avatar(nick),new VBox(3,new Label(nick),label)));}};}
  private static Image readAvatar(LocalStore local,String nick){byte[] data=null,bounded=null;try{data=local.avatar(nick);if(data==null)return null;bounded=AvatarCodec.normalize(data);Image image=new Image(new ByteArrayInputStream(bounded));return image.isError()?null:image;}catch(IOException|java.security.GeneralSecurityException invalidImage){return null;}finally{if(data!=null)Arrays.fill(data,(byte)0);if(bounded!=null)Arrays.fill(bounded,(byte)0);}}
  private void loadAvatars(){ClientSession active=session;work(null,"",()->{Map<String,Image> images=new HashMap<>();List<String> names=new ArrayList<>(active.local().contacts().stream().map(UserInfo::nickname).toList());names.add(active.local().nickname());for(String nick:names){Image image=readAvatar(active.local(),nick);if(image!=null)images.put(nick,image);}return images;},images->{if(active!=session)return;avatarImages.clear();avatarImages.putAll(images);if(contacts!=null)contacts.refresh();if(letters!=null)letters.refresh();if(accountAvatar!=null)accountAvatar.getChildren().setAll(avatar(active.local().nickname()));if((section.equals("profile")||section.equals("settings"))&&profileAvatar!=null&&profileAvatar.getScene()!=null)profileAvatar.getChildren().setAll(profileAvatar(active.local().nickname(),true));});}
  private Node profileAvatar(String nick,boolean permitted){Image image=permitted?avatarImages.get(nick):null;return AvatarViewer.profile(nick,image,()->AvatarViewer.show(stage,themes,nick,image));}
  private void chooseAvatar(String nick){
    if(!nick.equals(session.local().nickname()))return;InWindowFileChooser picker=new InWindowFileChooser();picker.setTitle("Аватар");picker.getExtensionFilters().add(new FileChooser.ExtensionFilter("JPG, PNG, WebP · до 2 МБ","*.png","*.jpg","*.jpeg","*.webp"));var file=picker.showOpenDialog(stage);if(file==null)return;ClientSession active=session;
    work(null,"",()->AvatarCodec.preview(file.toPath()),preview->{try{byte[] png=AvatarCrop.show(stage,themes,preview);if(png==null)return;work(null,"",()->{try{active.local().avatar(nick,png);active.features().profileChanged();if(active.online())active.syncPublicData(null);return true;}finally{Arrays.fill(png,(byte)0);}},v->loadAvatars());}catch(Exception e){error(e);}finally{Arrays.fill(preview,(byte)0);}});
  }
  private void contactProfile(String nick){
    clearCompose();section="contact-profile";long generation=++viewGeneration;ClientSession active=session;
    work(null,"",()->{if(active.online())try{active.syncPublicData(active.local().contact(nick));}catch(Exception unavailable){/* The last signed cache remains available offline. */}return new ProfilePresentation(active.local().cachedProfile(nick),readAvatar(active.local(),nick));},presentation->{if(session!=active||!section.equals("contact-profile")||generation!=viewGeneration)return;PublicProfile profile=presentation.profile();UserInfo peer=active.local().contact(nick);if(peer==null)return;
      // Use pixels read AFTER the requested sync, never the previous screen's map.
      if(presentation.avatar()==null)avatarImages.remove(nick);else avatarImages.put(nick,presentation.avatar());if(contacts!=null)contacts.refresh();if(letters!=null)letters.refresh();
      Label about=new Label(profile!=null&&profile.visible()?profile.about():"Публичные данные скрыты или недоступны");about.setWrapText(true);
      Label cache=new Label(profile==null?"Публичный профиль ещё не получен":active.online()?"Показана последняя полученная подписанная версия":"Без сети · последняя подписанная версия на устройстве");cache.setWrapText(true);cache.getStyleClass().add("muted");
      VBox content=new VBox(12,button("← Контакты",this::contactsPage),profileAvatar(nick,profile!=null&&profile.visible()),new Label(nick),officialBadge(peer.userId()),about,new Label(fingerprint(peer.userId())),new Label(profile==null?"Идентичность контакта проверена":"Подпись и идентичность проверены"),cache);content.setPadding(new Insets(20));content.setMaxWidth(680);content.getStyleClass().add("settings-card");ScrollPane scroll=new ScrollPane(content);scroll.setFitToWidth(true);root.setCenter(scroll);
    });
  }
  private Node officialBadge(String identity){Label badge=CommunityUi.label("");badge.getStyleClass().add("muted");ClientSession active=session;community().call("admin.verifications.list",CommunityUi.obj("user",identity),null,result->{if(active!=session)return;List<String> descriptions=new ArrayList<>();boolean person=false;for(var record:CommunityUi.items(result,"items")){if(!CommunityUi.str(record,"active").equals("true"))continue;String kind=CommunityUi.str(record,"kind");if(kind.equals("IDENTITY")){person=true;descriptions.add("Личность подтверждена администрацией АЕГИС");}else if(kind.equals("POSITION"))descriptions.add("Подтверждённая должность: "+CommunityUi.str(record,"value"));}badge.setText((person?"✓ ":"")+String.join(" · ",descriptions));badge.setTooltip(new Tooltip("Подтверждение получено от доверенного общего сервера. Внутренний допуск не является подтверждением личности."));});return badge;}
  private record ProfilePresentation(PublicProfile profile,Image avatar){}
  private void profile(){
    clearCompose();section="profile";viewGeneration++;ScrollPane profileScroll=new ScrollPane(profileCard());profileScroll.setFitToWidth(true);root.setCenter(profileScroll);
  }
  private Node profileCard(){
    String nick=session.local().nickname();Label heading=new Label("Профиль");heading.getStyleClass().add("brand");TextField immutable=new TextField(nick);immutable.setEditable(false);immutable.setAccessibleText("Имя аккаунта");Label nicknameHint=new Label("Имя закреплено за идентичностью на сервере. Изменение имени требует поддержки Relay; ключи аккаунта сохраняются.");nicknameHint.setWrapText(true);nicknameHint.getStyleClass().add("muted");
    TextArea about=new TextArea(session.features().about());about.setPromptText("О себе");about.setWrapText(true);about.setPrefRowCount(4);
    CheckBox visible=new CheckBox("Публичный профиль");visible.setSelected(session.features().visible());
    Label status=new Label(session.publicStatus());status.getStyleClass().add("muted");
    profileAvatar=new VBox(profileAvatar(nick,true));VBox body=new VBox(12,heading,profileAvatar,immutable,officialBadge(session.local().identity().userId()),nicknameHint,new FlowPane(8,8,button("Изменить аватар",()->chooseAvatar(nick)),button("Убрать",()->{ClientSession active=session;work(null,"",()->{active.local().avatar(nick,null);active.features().profileChanged();if(active.online())active.syncPublicData(null);return true;},v->loadAvatars());})),about,visible);
    Button save=new Button("Сохранить");save.getStyleClass().add("primary");save.setOnAction(e->{String text=about.getText();boolean show=visible.isSelected();ClientSession active=session;work(save,"Сохранение…",()->{active.features().profile(text,show);if(active.online())active.syncPublicData(null);return true;},v->status.setText(active.online()?active.publicStatus():"Сохранено на устройстве"));});
    body.getChildren().addAll(save,status);body.setPadding(new Insets(20));body.setMaxWidth(620);body.setMinWidth(0);body.setMaxHeight(Region.USE_PREF_SIZE);body.getStyleClass().add("settings-card");return body;
  }
  private void saveRemembered(ClientSession opened){try{remembered=new RememberedLogin(AppPaths.root(),SystemSecrets.current(AppPaths.root()),Clock.systemUTC());remembered.save(opened);rememberedExpires=System.currentTimeMillis()+RememberedLogin.LOCAL_AGE;}catch(Exception failure){rememberedExpires=0;Platform.runLater(()->{if(!stopping)info("Вход выполнен. Сохранить сессию не удалось: защищённое хранилище системы недоступно.");});}}
  private void tryRemembered(){if(componentLocked)return;if(resumeAttempted||config.relayOnionAddress().isBlank())return;resumeAttempted=true;worker.execute(()->{ClientSession opened=null;try{remembered=new RememberedLogin(AppPaths.root(),SystemSecrets.current(AppPaths.root()),Clock.systemUTC());var result=remembered.load(config.relayOnionAddress());if(result.isEmpty())return;try(var resume=result.get()){byte[] key=resume.vaultKey();try{LocalStore local=LocalStore.resume(config.storagePath(),key,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage());try{if(mailComponent())mailGate.verifyUnlockedVault(local);opened=new ClientSession(config,local);verifyComponentSession(opened);}catch(Exception rejected){local.close();throw rejected;}}finally{Arrays.fill(key,(byte)0);}ClientSession value=opened;long expires=resume.expiresAt(),relayExpires=resume.relayExpiresAt();String token=resume.token();Platform.runLater(()->{if(stopping||componentLocked||session!=null){try{value.close();}catch(IOException ignored){}return;}session=value;rememberedExpires=expires;pendingRelayExpiry=relayExpires;pendingRelayToken=token;afterLogin();});}}catch(Exception|LinkageError unavailable){if(opened!=null)try{opened.close();}catch(IOException ignored){}/* No unprotected fallback, the ordinary login form remains usable. */}});}
  private void resumeNetwork(){if(session==null||!relayReady||resumingNetwork)return;if(mailComponent()){pendingRelayToken="";automaticNetworkLogin();return;}if(pendingRelayToken.isEmpty()){automaticNetworkLogin();return;}if(System.currentTimeMillis()>=pendingRelayExpiry){pendingRelayToken="";automaticNetworkLogin();return;}resumingNetwork=true;ClientSession active=session;String token=pendingRelayToken;pendingRelayToken="";worker.execute(()->{try{active.resume(token);}catch(Exception unavailable){/* A rebooted relay or expired token requires the account password again. */}finally{Platform.runLater(()->{resumingNetwork=false;if(active==session){refresh();automaticNetworkLogin();}});}});}
  private void automaticNetworkLogin(){if(wantsNetwork&&!networkPrompted&&session!=null&&relayReady&&!session.online()){networkPrompted=true;Platform.runLater(this::reconnectAccount);}}
  private void reconnectAccount(){if(session==null||!relayReady){info("Нет соединения с сервером");return;}char[] password=askPassword("Войти в сеть","Пароль аккаунта");if(password==null)return;ClientSession active=session;work(accountReconnect,"Вход…",()->{try{active.reauthenticate(password);if(rememberedExpires>0)saveRemembered(active);return true;}finally{Arrays.fill(password,'\0');}},v->refresh());}
  private void endRemembered(){if(communityUi!=null){communityUi.close();communityUi=null;}Future<?> browserStopped=stopVzorForTransition();if(callListener!=null)try{callListener.close();}catch(Exception ignored){};if(glasView!=null)glasView.close();if(vzorView!=null)vzorView.close();if(stage!=null)InWindowDialog.closeAll(stage);ArchiveView endingArchive=archiveView;if(endingArchive!=null){endingArchive.close();archiveView=null;}clearRenderedMail();if(timer!=null)timer.stop();ClientSession active=session;if(active!=null)active.calls().hangup();glasView=null;vzorView=null;callListener=null;callBanner.getChildren().clear();callBanner.setVisible(false);callBanner.setManaged(false);session=null;rememberedExpires=0;pendingRelayToken="";viewGeneration++;clearCompose(false);for(var view:viewers)view.close();viewers.clear();avatarImages.clear();loginPage();worker.execute(()->{try{if(endingArchive!=null&&!endingArchive.awaitClosed(20))throw new IOException("Archive shutdown timed out");try{browserStopped.get(90,TimeUnit.SECONDS);}catch(Exception browserFailure){Platform.runLater(()->{if(!stopping)info("Закрытие Взора не подтверждено. Повторите закрытие в разделе браузера.");});}if(active!=null&&active.network()!=null)active.network().logout();if(active!=null)active.close();if(remembered!=null)remembered.clear();else Files.deleteIfExists(AppPaths.root().resolve("session/resume.enc"));}catch(Exception failure){Platform.runLater(()->{if(!stopping)info("Не удалось полностью удалить сохранённую сессию. Проверьте доступ к хранилищу системы.");});}});}
  private void updateChanged(UpdateService.Snapshot snapshot){if(stopping)return;if(updatesView!=null&&updatesView.showing())updatesView.refresh(snapshot);if(updateBadge!=null){boolean available=snapshot.manifest()!=null&&snapshot.manifest().newerThan(SignedManifest.CURRENT);updateBadge.setVisible(available);updateBadge.setManaged(available);updateBadge.setText(narrowNavigation?"↓":available&&snapshot.manifest().requiredFor(SignedManifest.CURRENT)?"⬇ Требуется обновление":"⬇ Обновление");updateBadge.setTooltip(new Tooltip(available?"Обновление АЕГИС "+snapshot.manifest().version():"Обновления"));}if(snapshot.announcement()&&snapshot.manifest()!=null&&session!=null){try{updates.announcementShown();}catch(IOException ignored){/* The verified history remains available; a failed marker cannot forge a letter. */}}}
  private void updatesPage(){clearCompose();section="updates";viewGeneration++;updatesView=makeUpdatesView();root.setCenter(updatesView.node());}
  private void systemLetters(){clearCompose();section="system";viewGeneration++;long generation=viewGeneration;
    ListView<UpdateEvents.Event> list=new ListView<>();list.setPlaceholder(new Label("Системных писем пока нет"));
    list.setCellFactory(v->new ListCell<>(){@Override protected void updateItem(UpdateEvents.Event e,boolean empty){super.updateItem(e,empty);setText(null);setGraphic(null);if(empty||e==null)return;
      Label trusted=new Label("АЕГИС · системное письмо"),title=new Label(e.title()),date=new Label(UpdatesView.channelLabel(e.channel())+" · "+UpdatesView.eventDate(e.time()));title.setWrapText(true);trusted.getStyleClass().add("muted");date.getStyleClass().add("muted");Label summary=new Label(e.kind()==UpdateEvents.Kind.INSTALLED?"Версия запущена, установка подтверждена.":e.release().announcement().summary());summary.setWrapText(true);
      Label signature=new Label("Ed25519 проверена"),changes=new Label(e.release().releaseNotes().text()),link=new Label(e.release().changelog().url().toString());changes.setWrapText(true);link.setWrapText(true);TitledPane details=new TitledPane("Изменения",new VBox(8,changes,link));details.setExpanded(false);boolean exactAvailable=e.kind()==UpdateEvents.Kind.AVAILABLE&&e.release().newerThan(SignedManifest.CURRENT)&&updates.snapshot().manifest()!=null&&e.version().equals(updates.snapshot().manifest().version())&&e.channel().equals(updates.snapshot().manifest().channel());
      VBox letter=new VBox(8,trusted,title,date,signature,summary,details,new HBox(8,button("Что нового",()->UpdatesView.notes(stage,themes,e.release())),button(exactAvailable?"Обновить":"Обновления",()->{updatesPage();if(exactAvailable&&updates.snapshot().state()==UpdateService.State.AVAILABLE)updates.download();})));letter.getStyleClass().add("system-letter");setGraphic(letter);
    }});
    VBox body=new VBox(12,new HBox(12,folderSelector(),button("История обновлений",this::updatesPage)),list);body.setPadding(new Insets(14));VBox.setVgrow(list,Priority.ALWAYS);root.setCenter(body);
    work(null,"",updates::events,history->{if(section.equals("system")&&viewGeneration==generation)list.getItems().setAll(history.stream().filter(UpdateEvents.Event::systemLetter).toList());});
  }
  private void clearRenderedMail(){if(letters!=null)letters.getItems().clear();if(threadResults!=null)threadResults.getItems().clear();letters=null;threadResults=null;mailboxFolderChoice=null;mailListColumn=null;mailFolders=null;if(mailSplit!=null)mailSplit.getItems().clear();mailSplit=null;}
  private boolean unsavedDraft(){return composer!=null&&(!composer.getText().isBlank()||!subjectField.getText().isBlank()||!recipientField.getText().isBlank()||!attachments.isEmpty()||letterPassword!=null&&!letterPassword.hidden.getText().isEmpty()||secondCode!=null&&!secondCode.hidden.getText().isEmpty())||draft!=null&&(!draft.body.isBlank()||!draft.subject.isBlank()||!draft.recipient.isBlank()||!draft.files.isEmpty()||draft.password.length>0||draft.code.length>0);}
  private void installUpdate(){if(mailComponent()){info("Установка обновления выполняется из главного АЕГИС после завершения автономных приложений.");return;}if(installingUpdate||updates.snapshot().state()!=UpdateService.State.READY_TO_INSTALL)return;if(unsavedDraft()){info("Перед обновлением завершите или очистите черновик. Он хранится в памяти устройства.");return;}InWindowAlert confirm=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Установить проверенное обновление и перезапустить АЕГИС?",ButtonType.OK,ButtonType.CANCEL);confirm.setHeaderText(null);confirm.initOwner(stage);themes.apply(confirm.getDialogPane());if(confirm.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK)return;installingUpdate=true;Future<?> browserStopped=stopVzorForTransition();ArchiveView closingArchive=archiveView;if(closingArchive!=null){closingArchive.close();archiveView=null;}worker.execute(()->{try{if(closingArchive!=null&&!closingArchive.awaitClosed(20))throw new IOException("Archive worker is still active; update stopped");session.calls().hangup();browserStopped.get(90,TimeUnit.SECONDS);long voiceDeadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(20);while(session.calls().busy()){if(System.nanoTime()>=voiceDeadline)throw new IOException("Завершение звонка не подтверждено");Thread.sleep(25);}long launcher=AppPaths.windows()?ProcessHandle.current().parent().orElseThrow().pid():0;Path job=updates.prepareInstall(AppPaths.bundle(),ProcessHandle.current().pid(),launcher);UpdateInstaller.launch(job);updates.restarting();Platform.runLater(this::stop);}catch(Exception failure){updates.installFailed();Platform.runLater(()->{installingUpdate=false;vzorView=null;if(!stopping)info("Обновление не установлено. Текущая версия сохранена.");});}});}
  private void backup(){InWindowFileChooser chooser=new InWindowFileChooser();chooser.setInitialFileName("AEGIS-identity.aegis-backup");var file=chooser.showSaveDialog(stage);if(file!=null)work(null,"",()->{session.local().exportIdentity(file.toPath());return true;},v->info("Резервная копия сохранена. Для восстановления используется пароль аккаунта на момент экспорта."));}
  private void restore(){InWindowFileChooser chooser=new InWindowFileChooser();chooser.setTitle("Восстановить идентичность");var file=chooser.showOpenDialog(stage);if(file==null)return;char[] pass=askPassword("Восстановить идентичность","Пароль резервной копии / хранилища");if(pass==null)return;Path target=AppPaths.root().resolve("restored-"+UUID.randomUUID());work(null,"",()->{try{LocalStore.restoreIdentity(file.toPath(),target,pass,config.maxCiphertext(),config.maxLocalStorage());var c=config.withStorage(target);c.save(AppPaths.config());return c;}finally{Arrays.fill(pass,'\0');}},c->{config=c;info("Идентичность восстановлена. Войдите в аккаунт.");loginPage();});}
  private char[] askPassword(String title,String prompt){InWindowDialog<char[]> d=new InWindowDialog<>();d.initOwner(stage);d.setTitle(title);PasswordField p=password(prompt);p.getStyleClass().add("secret-entry");VBox body=form(title,new Label(prompt),p);if(title.equals("Обновление хранилища"))body.getChildren().add(new Label("Требуется один раз для переноса данных старой версии."));d.getDialogPane().setContent(body);d.getDialogPane().getButtonTypes().addAll(ButtonType.OK,ButtonType.CANCEL);d.setResultConverter(b->b==ButtonType.OK?p.getText().toCharArray():null);themes.apply(d.getDialogPane());var result=d.showAndWait().orElse(null);p.clear();return result;}
  private void connectionDialog(){
    clearCompose();section="connection";viewGeneration++;detailConnectionCard=new ConnectionCard(()->{wantsNetwork=true;if(connectingTor)return;if(tor==null||!tor.ready())startTor();else preconnect();});detailConnectionCard.update(connectivity.snapshot());
    VBox page=new VBox(12,detailConnectionCard,button("Диагностика",this::diagnostics));page.setPadding(new Insets(14));root.setCenter(page);
  }
  private void diagnostics(){info("Версия: "+SignedManifest.CURRENT+" · протокол 1\nTor: "+(tor!=null&&tor.ready()?"100%":"не подключён")+"\nSOCKS: 127.0.0.1:"+config.torSocksPort()+"\nОбновления SOCKS: 127.0.0.1:"+config.torUpdateSocksPort()+"\nControlPort: 127.0.0.1:"+config.torControlPort()+"\nRelay: "+config.relayOnionAddress()+"\n"+(session==null?"":session.status())+"\nРежим: "+(tor==null?"—":torModeLabel(tor.mode()))+"\nЛоги: "+AppPaths.root().resolve("logs"));}
  private static String torModeLabel(EmbeddedTor.Mode mode){return mode==EmbeddedTor.Mode.DIRECT?"Tor Direct":"Snowflake";}
  private void info(String text){inlineStatus.setText(text);inlineStatus.setVisible(true);inlineStatus.setManaged(true);}
  private void error(Throwable error){String message;
    if(error instanceof PlainMessage.FileLimitException)message="Файл превышает допустимый размер сервера.";
    else if(error instanceof AccountLogin.OldPasswordRequired)message=error.getMessage();
    else if(error instanceof RequestRejected||error instanceof IllegalArgumentException||"АЕГИС уже запущен".equals(error.getMessage()))message=error.getMessage();
    else if(error instanceof javax.crypto.AEADBadTagException)message="Неверный пароль или локальное хранилище повреждено";
    else if(error instanceof java.security.GeneralSecurityException)message="Не удалось открыть зашифрованные данные";
    else if(error instanceof LinkageError)message="Компонент приложения недоступен. Распакуйте полный пакет АЕГИС.";
    else message="Не удалось выполнить действие. Проверьте соединение и доступ к локальным данным.";
    if(message==null||!message.matches("(?s).*[А-Яа-яЁё].*"))message="Не удалось выполнить действие. Проверьте введённые параметры и соединение.";
    info(message);inlineStatus.setTooltip(new Tooltip("Код для диагностики: "+error.getClass().getSimpleName()));
  }
  private byte[] captureDraft600(){
    if(!mailComponent())return null;rememberDraft();if(draft==null)return new byte[0];
    try{return Binary.encode(out->{out.writeInt(1);Binary.text(out,draft.recipient);Binary.text(out,draft.subject);Binary.text(out,draft.body);out.writeInt(draft.files.size());for(Path file:draft.files)Binary.text(out,file.toString());Binary.text(out,new String(draft.password));Binary.text(out,new String(draft.code));out.writeLong(draft.ttl);out.writeLong(draft.expirySeconds);Binary.text(out,draft.expiryInput);out.writeBoolean(draft.disappearing);out.writeBoolean(draft.protectedLetter);out.writeBoolean(draft.forceProtection);out.writeBoolean(draft.forwardedMissing||draft.bundle!=null);out.writeBoolean(draft.context!=null);if(draft.context!=null){MailContext c=draft.context;Binary.text(out,c.threadId());Binary.text(out,c.parentId());Binary.text(out,c.author());Binary.text(out,c.subject());out.writeLong(c.time());out.writeLong(c.expiresAt());Binary.bytes(out,c.digest());out.writeBoolean(c.forwarded());}});}
    catch(IOException failure){throw new java.io.UncheckedIOException(failure);}
  }
  private static Draft decodeDraft600(byte[] bytes)throws IOException {
    try(var input=new DataInputStream(new ByteArrayInputStream(bytes))){if(input.readInt()!=1)throw new IOException("Некорректный черновик");Draft d=new Draft();d.recipient=Binary.text(input,128);d.subject=Binary.text(input,1024);d.body=Binary.text(input,Limits.TEXT_BYTES);int count=input.readInt();if(count<0||count>64)throw new IOException("Слишком много файлов черновика");List<Path> files=new ArrayList<>();for(int n=0;n<count;n++)files.add(Path.of(Binary.text(input,4096)));d.files=List.copyOf(files);d.password=Binary.text(input,4096).toCharArray();d.code=Binary.text(input,4096).toCharArray();d.ttl=input.readLong();d.expirySeconds=input.readLong();d.expiryInput=Binary.text(input,100);d.disappearing=input.readBoolean();d.protectedLetter=input.readBoolean();d.forceProtection=input.readBoolean();d.forwardedMissing=input.readBoolean();if(input.readBoolean())d.context=new MailContext(Binary.text(input,36),Binary.text(input,36),Binary.text(input,32),Binary.text(input,1024),input.readLong(),input.readLong(),Binary.bytes(input,32),input.readBoolean());Binary.end(input);return d;}
    catch(IllegalArgumentException invalid){throw new IOException("Повреждён черновик",invalid);}
  }
  private void saveDraft600(ClientSession active,byte[] encoded)throws Exception {if(!mailComponent()||encoded==null)return;try{if(encoded.length==0)active.local().deleteExtension("mail6-draft-v1");else active.local().writeExtension("mail6-draft-v1",encoded,400000);}finally{Arrays.fill(encoded,(byte)0);}}
  private void publishComponentCount(int count){if(mailComponent()&&!componentLocked&&componentCounts!=null)componentCounts.accept(count);}
  private void openComponentLink(String value){
    try{if(componentLocked||componentLinks==null)throw new IOException("Нет соединения с главным приложением");String checked=org.securemail.client.safeweb.SafeWebUrl.parse(value).toASCIIString();componentLinks.accept(checked);info("Ссылка передана Взору через главное АЕГИС.");}
    catch(Exception rejected){info("Не удалось передать ссылку. Откройте Взор в главном АЕГИС.");}
  }
  private void verifyComponentSession(ClientSession opened)throws IOException {
    if(!mailComponent())return;mailGate.verifyUnlockedVault(opened.local());mailGate.prepareNetwork(opened.network());
    // Mail keeps its historical identity, but never runs the legacy voice endpoint in ecosystem mode.
    opened.calls().close();try{var transfers=org.securemail.client.attachments600.MailAttachmentManager600.configured(opened.local(),mailGate);if(transfers.isPresent())opened.attachments600(transfers.get());}catch(IOException|java.security.GeneralSecurityException damaged){attachmentWarning600="Потоковые вложения отключены: проверьте доверенные настройки сервера и защищённую очередь. Обычная почта доступна.";}try{mailCounter=new org.securemail.client.ecosystem.MailNotificationCounter600(opened.local());}catch(java.security.GeneralSecurityException damaged){throw new IOException("Не удалось проверить очередь уведомлений Почты",damaged);}publishComponentCount(mailCounter.count());try{byte[] previousDraft=opened.local().readExtension("mail6-draft-v1",400000);if(previousDraft!=null)try{draft=decodeDraft600(previousDraft);}finally{Arrays.fill(previousDraft,(byte)0);}}catch(java.security.GeneralSecurityException damaged){throw new IOException("Не удалось проверить сохранённый черновик",damaged);}if(componentLocked)throw new IOException("Почта заблокирована главным приложением");
  }
  private final CompletableFuture<Void> componentLockDone=new CompletableFuture<>();
  public CompletableFuture<Void> componentLock(){
    if(!mailComponent()){componentLockDone.completeExceptionally(new IOException("Это не автономная Почта"));return componentLockDone;}
    mailGate.lock();if(componentLocked)return componentLockDone;componentLocked=true;
    Runnable hide=()->{
      if(timer!=null)timer.stop();if(stage!=null)InWindowDialog.closeAll(stage);byte[] pendingDraft=captureDraft600();clearProtectedInputs(root);clearRenderedMail();clearCompose(false);
      for(var viewer:viewers)viewer.close();viewers.clear();avatarImages.clear();if(contacts!=null)contacts.getItems().clear();if(letters!=null)letters.getItems().clear();
      ArchiveView archive=archiveView;archiveView=null;if(archive!=null)archive.close();ClientSession active=session;session=null;TorConnection endingTor=tor;tor=null;
      if(communityUi!=null){communityUi.close();communityUi=null;}if(notifications!=null)notifications.close();if(updates!=null)updates.close();
      connectionWorker.shutdownNow();safeWebWorker.shutdownNow();worker.shutdown();showComponentLocked();
      Thread.ofPlatform().name("aegis-mail-lock").start(()->{try{
        if(archive!=null&&!archive.awaitClosed(12))throw new IOException("Не подтверждена блокировка архива");
        if(active!=null){try{saveDraft600(active,pendingDraft);}finally{active.close();}}if(endingTor!=null)endingTor.close();componentLockDone.complete(null);
      }catch(Exception failure){componentLockDone.completeExceptionally(failure);}});
    };
    if(Platform.isFxApplicationThread())hide.run();else Platform.runLater(hide);return componentLockDone;
  }
  private void showComponentLocked(){
    if(root==null)return;root.getChildren().clear();root.setTop(null);root.setLeft(null);root.setBottom(null);
    Label title=new Label("Почта заблокирована"),hint=new Label("Для повторного открытия подтвердите вход в главном АЕГИС.");hint.setWrapText(true);
    root.setCenter(new StackPane(new VBox(12,title,hint,button("Закрыть Почту",this::stop))));
  }
  private static void clearProtectedInputs(Node node){if(node instanceof javafx.scene.control.TextInputControl field)field.clear();if(node instanceof Parent parent)for(Node child:List.copyOf(parent.getChildrenUnmodifiable()))clearProtectedInputs(child);}
  @Override public void stop(){
    if(stopping)return;byte[] pendingDraft=captureDraft600();stopping=true;if(communityUi!=null){communityUi.close();communityUi=null;}ArchiveView endingArchive=archiveView;if(endingArchive!=null){endingArchive.close();archiveView=null;}
    if(callListener!=null)try{callListener.close();}catch(Exception ignored){};if(glasView!=null)glasView.close();if(vzorView!=null)vzorView.close();if(stage!=null)InWindowDialog.closeAll(stage);if(timer!=null)timer.stop();clearRenderedMail();clearCompose(false);for(var view:viewers)view.close();viewers.clear();avatarImages.clear();pendingRelayToken="";themes.close();if(updates!=null)updates.close();if(notifications!=null)notifications.close();worker.shutdownNow();connectionWorker.shutdownNow();safeWebWorker.shutdownNow();
    ClientSession endingSession=session;TorConnection endingTor=tor;AutoCloseable endingInstance=instance;
    Thread.ofPlatform().name("aegis-shutdown").start(()->{
      Exception failure=null;
      try{safeWeb.close();}catch(IOException e){failure=e;}
      try{if(endingArchive!=null&&!endingArchive.awaitClosed(12))throw new IOException("Не подтверждена блокировка архива");}catch(Exception e){failure=e;}
      if(endingSession!=null)try{try{saveDraft600(endingSession,pendingDraft);}finally{endingSession.close();}}catch(Exception e){failure=e;}else if(pendingDraft!=null)Arrays.fill(pendingDraft,(byte)0);
      if(endingTor!=null)endingTor.close();if(endingInstance!=null)try{endingInstance.close();}catch(Exception e){failure=e;}
      if(componentLocked)try{componentLockDone.get(12,TimeUnit.SECONDS);}catch(Exception e){failure=e;}
      if(failure==null)componentShutdown.complete(null);else componentShutdown.completeExceptionally(failure);
    });
    if(stage!=null)stage.hide();Platform.exit();
  }
}
