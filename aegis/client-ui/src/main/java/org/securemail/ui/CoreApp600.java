package org.securemail.ui;

import com.google.gson.*;
import java.io.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.*;
import javafx.application.*;
import javafx.geometry.Insets;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import org.securemail.client.*;
import org.securemail.client.ecosystem.*;
import org.securemail.client.ecosystemauth.*;
import org.securemail.client.library600.*;
import org.securemail.client.management600.ManagementClient600;
import org.securemail.client.net.*;
import org.securemail.client.safeweb600.VzorLaunch600;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.client.storage.UpdateSupport;
import org.securemail.client.update.*;
import org.securemail.client.voice600.GlasGrant600;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import org.securemail.ui.ecosystem.*;
import static org.securemail.ui.CommunityUi.*;

/** Core process: device credentials only. Mail alone opens the existing account vault and root key. */
public final class CoreApp600 extends Application {
  private Stage stage;private BorderPane root;private ThemeManager themes;private Scene scene;
  private final Label status=label("АЕГИС 6.0.0 — Экосистема"),identityLabel=label("Вход не выполнен");
  private final ThreadPoolExecutor worker=new ThreadPoolExecutor(1,1,30,TimeUnit.SECONDS,new ArrayBlockingQueue<>(8),r->{Thread t=new Thread(r,"aegis-core-work");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final ScheduledExecutorService guardWorker=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-core-session-watch");t.setDaemon(true);return t;});
  private final ThreadPoolExecutor protectedCleanup=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(4),r->{Thread t=new Thread(r,"aegis-core-protected-cleanup");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final ThreadPoolExecutor consentCleanup=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(2),r->{Thread t=new Thread(r,"aegis-core-consent-cleanup");t.setDaemon(false);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final Object consentMutex=new Object();
  private final ConcurrentMap<MailPairingBroker600,CompletableFuture<Void>> closingConsents=new ConcurrentHashMap<>();
  private CorePublicConfig600 config,connectedConfig;private TorConnection tor;private TorTransport transport;private IdentityClient600 identity;
  private UpdateService updates;private volatile UpdatePreferences updatePreferences;private UpdatesView updatesView;private boolean installingUpdate;
  private volatile CoreAccountSession600 session;private DesktopProcessBroker broker;private CoreLauncherView applications;private LibraryLauncherView600 library;private CommunityUi community;private ServerManagementView600 management;private CoreNotificationsView600 notifications;
  private OwnerAdministrationView600 ownerAdministration;
  private AuthoritySetupView600 authoritySetup;
  private IdentityAdministrationView600 identityAdministration;
  private volatile MailPairingBroker600 pairing;private ComponentInstallation installation;
  private volatile ObsidianCoordinator600 obsidian;
  private record PreparedVoice(String account,long generation,String capability,byte[] auxiliary) {PreparedVoice{auxiliary=auxiliary.clone();}}
  private volatile PreparedVoice preparedVoice;
  private IdleLockGuard idle;private DesktopLockBinding lockBinding;private AutoCloseable osLock;
  private FileChannel instanceChannel;private FileLock instance;private volatile boolean stopping;private boolean collapsed;
  private org.securemail.client.maintenance600.RuntimeLease600.Lease runtimeLease;
  private final CoreNavigation600 navigationStore=new CoreNavigation600(AppPaths.root().resolve("core600/navigation.json"));
  private CoreNavigation600.State navigation=new CoreNavigation600.State(CoreNavigation600.GROUPS,false);
  private final AtomicLong uiEpoch=new AtomicLong();
  private final Set<PasswordField> transientPasswords=Collections.newSetFromMap(new IdentityHashMap<>());
  private final DeviceCredentialStore600 credentials=new DeviceCredentialStore600(AppPaths.root().resolve("core600/device.vault"));

  @Override public void start(Stage stage)throws Exception {
    runtimeLease=org.securemail.client.maintenance600.RuntimeLease600.running();this.stage=stage;AtomicFiles.directory(AppPaths.root().resolve("core600"));
    instanceChannel=FileChannel.open(AppPaths.root().resolve("core600/core.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);
    try{instance=instanceChannel.tryLock();}catch(OverlappingFileLockException e){throw new IOException("АЕГИС уже открыт",e);}if(instance==null)throw new IOException("АЕГИС уже открыт");
    themes=new ThemeManager();themes.initialize();try{navigation=navigationStore.load(themes.settings().layout().order(),themes.settings().layout().collapsed());}catch(IOException corrupt){status.setText("Не удалось прочитать порядок разделов. Сохранённые макеты не изменены.");}collapsed=navigation.collapsed();root=new BorderPane();root.setId("aegis-core600");root.setPadding(new Insets(10));
    Button lock=button("Заблокировать",this::lock),exit=button("Выйти",this::signOut);identityLabel.setMinWidth(0);identityLabel.setMaxWidth(320);HBox.setHgrow(identityLabel,Priority.ALWAYS);
    status.setWrapText(true);status.setMaxWidth(340);FlowPane header=new FlowPane(10,8,identityLabel,status,lock,exit);header.setPadding(new Insets(6,8,12,8));root.setTop(header);
    scene=new Scene(root,1100,760);themes.apply(root);themes.workspace(root);stage.setScene(scene);stage.setTitle("АЕГИС 6.0.0 — Экосистема");stage.setMinWidth(800);stage.setMinHeight(600);
    stage.setOnCloseRequest(event->{event.consume();shutdown();});root.widthProperty().addListener((o,a,b)->{if(session!=null&&!session.locked()&&(a.doubleValue()<760)!=(b.doubleValue()<760))installNavigation();});showLogin();stage.show();
    work(()->{UpdateInstaller.confirmStartup();if(Files.exists(CorePublicConfig600.defaultFile()))return CorePublicConfig600.fromDefaultFile();return null;},value->{if(value==null)configuration();else{config=value;connectTor();}});
    guardWorker.scheduleWithFixedDelay(()->{CoreAccountSession600 current=session;if(current==null||current.locked()||identity==null||stopping)return;try{if(!identity.isActive(current.coreGrant().wire()))Platform.runLater(()->{if(session==current)revoked();});}catch(IdentityClient600.Rejected denied){Platform.runLater(()->{if(session==current)revoked();});}catch(IOException unavailable){Platform.runLater(()->{if(session!=current)return;if(current.canContinueOffline())status.setText("Identity недоступен. Доступны только ранее разрешённые данные в пределах их срока.");else lock();});}catch(RuntimeException invalid){Platform.runLater(()->{if(session==current)lock();});}},5,5,TimeUnit.SECONDS);
  }
  private void showLogin(){
    clearTransientPasswords();root.setLeft(null);PasswordField password=new PasswordField();transientPasswords.add(password);password.setPromptText("Пароль ключа устройства АЕГИС");password.setAccessibleText("Пароль ключа устройства АЕГИС");password.setMaxWidth(420);
    Label hint=label("АЕГИС хранит отдельный ключ устройства. Пароль и приватный ключ Почты вводятся только в процессе Почты.");
    Button login=button("Войти",()->{char[] secret=password.getText().toCharArray();password.clear();work(()->{try{return openExisting(secret);}finally{Arrays.fill(secret,'\0');}},value->authenticated(),()->Arrays.fill(secret,'\0'));});login.setDefaultButton(true);
    Button bind=button("Создать или привязать Почту",()->{char[] secret=password.getText().toCharArray();password.clear();work(()->{try{return enroll(secret);}finally{Arrays.fill(secret,'\0');}},value->authenticated(),()->Arrays.fill(secret,'\0'));});
    Button device=button("Запросить подтверждение устройства",()->{char[] secret=password.getText().toCharArray();password.clear();work(()->{try{requireNetwork();try(var key=credentials.unlock(secret)){return DeviceApproval600.request(identity,key);}}finally{Arrays.fill(secret,'\0');}},this::showDeviceRequest,()->Arrays.fill(secret,'\0'));});
    VBox form=card(heading("АЕГИС — Экосистема"),hint,password,actions(login,bind),device,button("Восстановить доступ на этом устройстве",this::deviceRecovery),button("Подключить Tor",this::connectTor),actions(button("Сервер Identity",this::configuration),button("Серверы приложений",this::serviceConfiguration)));form.setMaxWidth(650);BorderPane.setMargin(form,new Insets(20));root.setCenter(scroll(form));
  }
  private void deviceRecovery(){
    clearTransientPasswords();TextField account=field("Постоянный account ID восстанавливаемого аккаунта");PasswordField password=new PasswordField();transientPasswords.add(password);password.setPromptText("Пароль отдельного ключа устройства АЕГИС");password.setAccessibleText("Пароль отдельного ключа устройства АЕГИС");password.setMaxWidth(520);
    CheckBox consent=new CheckBox("Понимаю, что прежние устройства и сессии будут отозваны; закрытые полномочия потребуют одобрения администрации");consent.setWrapText(true);
    Button recover=button("Проверить набор и восстановить через Почту",()->{String target=account.getText().strip();char[] secret=password.getText().toCharArray();password.clear();long epoch=uiEpoch.get();work(()->{try{
      requireNetwork();closeSession();try(var attempt=new DeviceRecoveryClient600(identity,credentials,target,secret,()->stopping||uiEpoch.get()!=epoch)){
        var challenge=attempt.begin();var inspection=attempt.inspection();var broker=consentBroker(null,epoch);var proof=broker.beginDeviceRecovery(challenge,inspection.time(),inspection.nonce(),inspection.proof()).get(5,TimeUnit.MINUTES);attempt.recover(proof,secret);return true;
      }
    }finally{Arrays.fill(secret,'\0');}},done->{showLogin();status.setText("Устройство восстановлено. Войдите заново. Закрытые полномочия ожидают административного подтверждения.");},()->Arrays.fill(secret,'\0'));});recover.disableProperty().bind(consent.selectedProperty().not());
    VBox page=card(heading("Восстановление устройства"),label("Нужны ранее сохранённая зашифрованная копия почтовой идентичности и независимый файл восстановления .aer6. Почта проверит их и запросит свои пароли в отдельном процессе. Они не передаются АЕГИС. Один файл .aer6 не заменяет утраченный ключ аккаунта. Для нового устройства задайте пароль не короче 12 символов; если ключ устройства уже существует, введите его прежний пароль."),account,password,consent,recover,button("Назад ко входу",this::showLogin));page.setMaxWidth(800);root.setCenter(scroll(page));
  }
  private void showDeviceRequest(DeviceApproval600 request){TextArea code=new TextArea(request.encode());code.setEditable(false);code.setWrapText(true);code.setPrefRowCount(6);VBox page=card(heading("Подтверждение нового устройства"),label("Передайте этот публичный запрос на уже доверенное устройство. На нём откройте Настройки → Устройства, сравните полный отпечаток и подтвердите через Почту. Запрос действует пять минут. После одобрения войдите снова: предыдущая активная сессия будет отозвана."),label("Отпечаток нового устройства: "+request.fingerprint()),code,button("Вернуться ко входу",this::showLogin));page.setMaxWidth(780);root.setCenter(scroll(page));}
  private void devices(){
    var active=session;TextArea input=new TextArea();input.setPromptText("Публичный запрос с нового устройства");input.setWrapText(true);input.setPrefRowCount(6);input.setTextFormatter(new TextFormatter<String>(change->change.getControlNewText().length()<=2048?change:null));VBox detail=new VBox(10);Button inspect=button("Проверить запрос",()->{String encoded=input.getText();work(()->{if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");var request=DeviceApproval600.parse(encoded);request.verifyTarget(identity.audience(),active.accountId(),System.currentTimeMillis());return request;},request->{CheckBox compare=new CheckBox("Полный отпечаток совпадает с новым устройством");compare.setWrapText(true);Button approve=button("Подтвердить через Почту",()->work(()->{if(active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");reauthenticate(active);active.approveDevice(request);return true;},done->{detail.getChildren().setAll(label("Устройство одобрено. Вход с него завершит текущую активную сессию."));input.clear();}));approve.disableProperty().bind(compare.selectedProperty().not());detail.getChildren().setAll(label("Отпечаток нового устройства: "+request.fingerprint()),label("Подтверждайте только устройство, которое принадлежит вам. Никнейм не подтверждает его личность."),compare,approve);});});
    VBox page=card(heading("Доверенные устройства"),label("Новый ключ устройства становится доверенным только после вашего явного подтверждения и повторной проверки личности в Почте."),input,inspect,detail,button("Назад к настройкам",this::settings));page.setMaxWidth(780);root.setCenter(scroll(page));
  }
  private void serviceConfiguration(){
    clearTransientPasswords();
    if(session!=null){status.setText("Для смены доверенных серверов сначала выйдите из аккаунта");return;}
    var store=new CoreServiceEndpoints600(AppPaths.root().resolve("core600"));ComboBox<CoreServiceEndpoints600.Service> choice=new ComboBox<>();choice.getItems().setAll(CoreServiceEndpoints600.Service.values());choice.setMaxWidth(480);TextField onion=field("Onion-адрес"),port=field("Порт"),key=field("Открытый ключ сервиса (Base64URL)");key.setMaxWidth(700);Label fingerprint=label("");fingerprint.setWrapText(true);CheckBox compared=new CheckBox("Ключ получен у владельца сервера и сверен по независимому каналу");compared.setWrapText(true);AtomicLong selection=new AtomicLong();
    choice.valueProperty().addListener((o,a,b)->{if(b==null)return;long selected=selection.incrementAndGet();compared.setSelected(false);onion.setManaged(b.hasEndpoint());onion.setVisible(b.hasEndpoint());port.setManaged(b.hasEndpoint());port.setVisible(b.hasEndpoint());onion.clear();key.clear();port.setText(b.hasEndpoint()?"80":"");fingerprint.setText("");work(()->store.load(b),saved->{if(choice.getValue()!=b||selection.get()!=selected)return;saved.ifPresent(value->{onion.setText(value.onion());port.setText(value.port()==0?"":Integer.toString(value.port()));key.setText(IdentityProtocol.b64(value.publicKey()));fingerprint.setText("Сохранённый отпечаток: "+value.fingerprint());});});});
    Button save=button("Сохранить доверенный сервер",()->{var service=choice.getValue();String host=onion.getText().strip(),p=port.getText().strip(),pub=key.getText().strip();work(()->{if(session!=null)throw new IOException("Сначала выйдите из аккаунта");var value=new CoreServiceEndpoints600.Endpoint(service.hasEndpoint()?host:"",service.hasEndpoint()?Integer.parseInt(p):0,IdentityProtocol.unb64(pub,44));store.save(service,value);return value;},value->{fingerprint.setText("Сохранённый отпечаток: "+value.fingerprint());compared.setSelected(false);status.setText("Публичные параметры сервиса сохранены");});});save.disableProperty().bind(compared.selectedProperty().not());
    VBox page=card(heading("Серверы приложений"),label("Владелец инфраструктуры выдаёт onion-адреса и открытые ключи. Изменение ключа меняет доверенный сервис. Приватные ключи, пароли и токены здесь не вводятся. Адрес почтового Relay задаётся в Почте; здесь сохраняется только его дополнительный ключ службы 6.0.0."),choice,onion,port,key,fingerprint,compared,save,button("Назад",this::showLogin));page.setMaxWidth(780);root.setCenter(scroll(page));choice.setValue(CoreServiceEndpoints600.Service.COMMUNITY);
  }
  private void configuration(){
    clearTransientPasswords();
    if(session!=null){status.setText("Сначала выйдите из аккаунта для смены доверенного сервера");return;}
    TextField onion=field("Onion-адрес Identity"),port=field("Порт Identity"),pin=field("Открытый ключ Identity (Base64URL)"),socks=field("Локальный SOCKS-порт Core");port.setText("80");socks.setText("19350");
    if(config!=null){onion.setText(config.identityOnion());port.setText(""+config.identityPort());pin.setText(IdentityProtocol.b64(config.identityPublicKey()));socks.setText(""+config.socksPort());}
    Button save=button("Сохранить и подключить",()->{String address=onion.getText().strip(),p=port.getText().strip(),key=pin.getText().strip(),sp=socks.getText().strip();work(()->{
      var value=new CorePublicConfig600(address,Integer.parseInt(p),IdentityProtocol.unb64(key,44),Integer.parseInt(sp));if(value.socksPort()>65532)throw new IOException("Выберите SOCKS-порт не выше 65532");
      Properties properties=new Properties();properties.setProperty("identityOnion",value.identityOnion());properties.setProperty("identityPort",""+value.identityPort());properties.setProperty("identityPublicKey",IdentityProtocol.b64(value.identityPublicKey()));properties.setProperty("socksPort",""+value.socksPort());ByteArrayOutputStream bytes=new ByteArrayOutputStream();properties.store(bytes,"AEGIS Core public operator configuration");AtomicFiles.write(CorePublicConfig600.defaultFile(),bytes.toByteArray());return value;
    },value->{config=value;showLogin();connectTor();});});
    VBox form=card(heading("Доверенный сервер"),label("Адрес и открытый ключ выдаёт владелец сервера АЕГИС. Сверьте отпечаток по независимому каналу. Эти поля не содержат пользовательских секретов."),onion,port,pin,socks,actions(save,button("Назад",this::showLogin)));form.setMaxWidth(720);root.setCenter(scroll(form));
  }
  private void connectTor(){if(config==null){configuration();return;}work(()->{
    if(tor!=null&&tor.ready()&&connectedConfig==config)return true;if(updates!=null){updates.close();updates=null;}if(identity!=null){identity.close();identity=null;}if(tor!=null)tor.close();
    int base=config.socksPort();if(base>65532)throw new IOException("Недопустимый локальный порт Core");Path state=AppPaths.root().resolve("core600/tor");
    ClientConfig defaults=ClientConfig.load(AppPaths.config());ClientConfig net=new ClientConfig("127.0.0.1",base,base+1,base+2,state.resolve("control_auth_cookie"),base+3,defaults.defaultTTL(),"",80,AppPaths.root().resolve("core600/unused-mail-storage"),defaults.maxFileSize(),defaults.maxLocalStorage(),defaults.deliveryTTL());
    tor=new TorConnection(()->new EmbeddedTor(net,state),AppPaths.root().resolve("core600/tor-mode.txt"));TorTransport.requireAvailability(()->tor!=null&&tor.ready());
    tor.start(Duration.ofSeconds(150),Duration.ofSeconds(210),(mode,percent)->Platform.runLater(()->status.setText("Tor: "+percent+"%")));
    transport=new TorTransport("127.0.0.1",base);identity=new IdentityClient600(config.identityOnion(),config.identityPort(),config.identityPublicKey(),transport);
    updatePreferences=UpdatePreferences.load(AppPaths.root());updates=new UpdateService(AppPaths.root(),base+2);updates.channel(updatePreferences.channel());updates.automatic(()->updatePreferences.automaticCheck(),()->updatePreferences.automaticDownload());updates.listener(change->Platform.runLater(()->{if(!stopping&&updatesView!=null&&updatesView.showing())updatesView.refresh(change);}));connectedConfig=config;if(updatePreferences.automaticCheck())updates.check(updatePreferences.automaticDownload());return true;
  },value->status.setText("Tor подключён"));}
  private void requireNetwork()throws IOException {if(config==null||tor==null||!tor.ready()||identity==null)throw new IOException("Сначала подключите Tor");}
  private boolean openExisting(char[] password)throws Exception {
    long epoch=uiEpoch.get();requireNetwork();closeSession();DeviceCredentials600 key=credentials.unlock(password);var candidate=new CoreAccountSession600(identity,config.identityPublicKey(),key);
    try{candidate.login();synchronized(consentMutex){if(stopping||uiEpoch.get()!=epoch)throw new IOException("Вход отменён блокировкой");session=candidate;}return true;}catch(Exception error){candidate.close();throw error;}
  }
  private boolean enroll(char[] password)throws Exception {
    long epoch=uiEpoch.get();requireNetwork();closeSession();if(password.length<12)throw new IOException("Пароль ключа устройства: не менее 12 символов");
    var consent=consentBroker(null,epoch);
    DeviceCredentials600 existing=credentials.exists()?credentials.unlock(password):null;
    KeyPair device=existing==null?KeyPairGenerator.getInstance("Ed25519").generateKeyPair():null;
    byte[] publicDevice=existing==null?device.getPublic().getEncoded():existing.devicePublic();
    MailPairing600.RegistrationResult result;
    try{result=consent.beginRegistration(publicDevice).get(10,TimeUnit.MINUTES);}catch(Exception error){if(existing!=null)existing.close();throw error;}
    if(stopping||uiEpoch.get()!=epoch){if(existing!=null)existing.close();throw new IOException("Привязка отменена блокировкой");}
    DeviceCredentials600 key;
    if(existing!=null){key=existing;if(!MessageDigest.isEqual(key.accountPublic(),result.accountPublic())||!MessageDigest.isEqual(key.recoveryPublic(),result.recoveryPublic())){key.close();throw new IOException("Почта относится к другому аккаунту");}}
    else{key=new DeviceCredentials600(result.accountPublic(),device,result.recoveryPublic());credentials.create(key,password);}
    var candidate=new CoreAccountSession600(identity,config.identityPublicKey(),key);
    try{candidate.register(result.nickname(),result.time(),result.nonce(),result.accountProof());publishSession(candidate,epoch);return true;}
    catch(IdentityClient600.Rejected rejected){if(!rejected.code().equals("CONFLICT")){candidate.close();throw rejected;}candidate.close();var retry=new CoreAccountSession600(identity,config.identityPublicKey(),credentials.unlock(password));try{if(stopping||uiEpoch.get()!=epoch)throw new IOException("Вход отменён блокировкой");retry.login();publishSession(retry,epoch);return true;}catch(Exception failure){retry.close();throw failure;}}
    catch(Exception failed){candidate.close();throw failed;}
  }
  private ComponentInstallation installation()throws IOException {if(installation==null)installation=InstallationInventory600.load(AppPaths.bundle());return installation;}
  private void authenticated(){
    uiEpoch.incrementAndGet();
    var current=session;if(current==null)return;identityLabel.setText("Учётная запись: "+current.accountId().substring(0,12));
    try{broker=new DesktopProcessBroker(installation(),new SessionAuthority(){
      public ComponentLease authorize(ComponentId component)throws IOException {
        ComponentLease lease=current.authorize(component);if(component!=ComponentId.GLAS)return lease;
        byte[] secret=lease.proofPrivatePkcs8();try{var ready=preparedVoice;String token=new String(lease.capability(),StandardCharsets.US_ASCII);if(ready==null||!ready.account().equals(current.accountId())||ready.generation()!=current.generation()||!ready.capability().equals(token))throw new IOException("Сначала подтвердите разрешение Гласа в Почте");return new ComponentLease(component,lease.accountId(),lease.generation(),lease.capability(),secret,lease.proofPublicX509(),ready.auxiliary());}finally{Arrays.fill(secret,(byte)0);lease.close();}
      }
      public void validate(ComponentLease lease)throws IOException {current.validate(lease);}
    },change->{var view=applications;if(view!=null)view.accept(change);});broker.linkHandler(uri->openSafeLink(uri.toASCIIString()));}
    catch(IOException missing){status.setText("Проверьте установленный комплект: приложения пока недоступны");}
    idle=new IdleLockGuard(reason->Platform.runLater(this::lock));lockBinding=new DesktopLockBinding(scene,idle);
    var thisGuard=idle;osLock=org.securemail.client.security600.OperatingSystemLockMonitor600.start(reason->Platform.runLater(()->{if(idle==thisGuard&&session==current)thisGuard.operatingSystemLocked();}));
    brokerActivityBinding();
    installNavigation();showApplications();work(current::profile,data->{identityLabel.setText(str(data,"nickname")+(Boolean.parseBoolean(str(data,"ownerBadge"))?" ✓":""));});
  }
  private void brokerActivityBinding(){if(broker!=null)broker.activityHandler(()->{var value=idle;if(value!=null)value.userActivity();});}
  private void installNavigation(){
    boolean compact=collapsed||root.getWidth()<760;
    VBox navigation=new VBox(10);navigation.setPadding(new Insets(8));navigation.setMinWidth(0);
    Button collapse=button(compact?"↔":"Свернуть",()->changeNavigation(this.navigation.collapsed(!collapsed)));collapse.setAccessibleText("Свернуть или развернуть навигацию");navigation.getChildren().add(collapse);
    for(var group:this.navigation.groups())navigation.getChildren().add(navGroup(group,compact));
    navigation.setPrefWidth(compact?66:180);ScrollPane pane=scroll(navigation);pane.setPrefWidth(compact?80:200);pane.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);root.setLeft(pane);
  }
  private Node navGroup(List<String> sections,boolean compact){VBox group=card();group.setSpacing(6);group.setPadding(new Insets(6));for(String id:sections){String title=switch(id){case "organizations"->"Сообщества";case "news"->"Вестник";case "library"->"Библиотека";case "settings"->"Настройки";default->"Приложения";};Button button=button(compact?"":title,()->navigate(id));button.setGraphic(NavigationGlyph.create(id,22));button.setTooltip(new Tooltip(title));button.setAccessibleText(title);button.setMinHeight(40);ContextMenu order=new ContextMenu();MenuItem up=new MenuItem("Переместить выше"),down=new MenuItem("Переместить ниже");up.setDisable(sections.indexOf(id)==0);down.setDisable(sections.indexOf(id)==sections.size()-1);up.setOnAction(e->changeNavigation(navigation.move(id,-1)));down.setOnAction(e->changeNavigation(navigation.move(id,1)));order.getItems().addAll(up,down);button.setContextMenu(order);group.getChildren().add(button);}return group;}
  private void changeNavigation(CoreNavigation600.State value){navigation=value;collapsed=value.collapsed();installNavigation();work(()->{navigationStore.save(value);return true;},done->status.setText("Расположение разделов сохранено"));}
  private void navigate(String section){if(session==null||session.locked()){showLogin();return;}switch(section){case "organizations"->showCommunity(false);case "news"->showCommunity(true);case "library"->showLibrary();case "settings"->settings();default->showApplications();}}
  private void showApplications(){if(broker==null){root.setCenter(card(heading("Приложения"),label("Установленный комплект не прошёл проверку состава. Переустановите подписанный пакет.")));return;}if(applications==null)applications=new CoreLauncherView(broker,app->{if(app==CoreLauncherView.IndependentApplication.VZOR)openSafeLink("https://check.torproject.org/");else openPersonalLibrary();},this::prepareApplication);root.setCenter(scroll(applications));}
  private List<Path> protectedDataPaths()throws IOException {Path storage=ClientConfig.load(AppPaths.config()).storagePath().toAbsolutePath().normalize();if(storage.getFileName()==null)throw new IOException("Каталог Почты должен находиться отдельно от корня файловой системы");return List.of(AppPaths.root(),AppPaths.config(),storage,storage.resolveSibling(storage.getFileName()+".personal-archive"),AppPaths.root().resolveSibling("aegis-archive-guards"));}
  private synchronized ObsidianCoordinator600 obsidian()throws Exception {
    if(stopping||session==null||session.locked())throw new IOException("Сессия АЕГИС заблокирована");if(obsidian==null){requireNetwork();obsidian=new ObsidianCoordinator600(AppPaths.root(),AppPaths.bundle(),config.socksPort()+2,protectedDataPaths());}return obsidian;
  }
  private org.securemail.client.update.UpdateService.Progress obsidianProgress(CoreAccountSession600 active){
    AtomicLong last=new AtomicLong();long epoch=uiEpoch.get();return (downloaded,total)->{long now=System.nanoTime(),prior=last.get();if(downloaded!=total&&now-prior<250_000_000L)return;last.set(now);String text=total>0?"Подготовка Obsidian: "+Math.min(100,downloaded*100/total)+"%":"Проверка и подготовка Obsidian…";Platform.runLater(()->{if(!stopping&&session==active&&!active.locked()&&uiEpoch.get()==epoch)status.setText(text);});};
  }
  private void openPersonalLibrary(){var active=session;work(()->{requireNetwork();if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");var grant=active.coreGrant();identity.authorizeDigest(grant.wire(),grant.proofPrivate(),"account.read","OPEN-PERSONAL-OBSIDIAN/v1".getBytes(StandardCharsets.US_ASCII));obsidian().openPersonal(obsidianProgress(active),()->stopping||active!=session||active.locked());return true;},done->status.setText("Личная библиотека открыта отдельно"));}
  private void prepareApplication(ComponentId component)throws Exception {
    if(component!=ComponentId.GLAS||broker.isRunning(component))return;requireNetwork();var current=session;if(current==null||current.locked())throw new IOException("Сессия АЕГИС заблокирована");
    stopMailForConsent();var grant=current.grant(App.GLAS,Set.of(Scope.VOICE_CALL,Scope.CONTACTS_READ));long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] proof=IdentityProtocol.sign(grant.proofPrivate(),IdentityProtocol.requestDigest(grant.capability(),"glas.call",IdentityProtocol.digest(GlasGrant600.CONSENT_BODY),time,nonce));
    var consent=consentBroker(current);GlasGrant600 result=consent.beginVoiceDelegation(grant.wire(),time,nonce,proof).get(10,TimeUnit.MINUTES);
    var delegation=result.delegation();if(current!=session||current.locked()||!result.verify(current.accountPublic(),identity.audience(),System.currentTimeMillis())||!delegation.accountId().equals(current.accountId())||!delegation.deviceId.equals(current.deviceId())||delegation.generation!=current.generation()||!MessageDigest.isEqual(delegation.appPublic(),grant.proofPublic())||delegation.expiresAt>grant.capability().expiresAt)throw new IOException("Почта не подтвердила разрешение Гласа");
    preparedVoice=new PreparedVoice(current.accountId(),current.generation(),grant.wire(),result.encode());
  }
  private void stopMailForConsent()throws Exception {if(broker!=null&&broker.isRunning(ComponentId.MAIL)){broker.stop(ComponentId.MAIL);var receipt=broker.status(ComponentId.MAIL).orElseThrow();if(!receipt.queueFlushConfirmed())throw new IOException("Не подтверждено сохранение Почты перед проверкой личности");broker.termination(ComponentId.MAIL).toCompletableFuture().get(10,TimeUnit.SECONDS);}}
  private void showLibrary(){
    var active=session;
    if(library==null)library=new LibraryLauncherView600(()->{
      requireNetwork();if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");var grant=active.grant(App.LIBRARY,Set.of(Scope.LIBRARY_READ,Scope.LIBRARY_WRITE));Properties p=serviceConfig("library",Set.of("onion","port","publicKey"));
      var http=new HttpLibraryTransport600(p.getProperty("onion"),Integer.parseInt(p.getProperty("port")),IdentityProtocol.unb64(p.getProperty("publicKey"),44),config.identityPublicKey(),grant.wire(),grant.proofPrivate(),transport);
      Path projection=AppPaths.root().resolveSibling("aegis-library-projection600").resolve(active.accountId()).resolve(active.generation()+"-"+UUID.randomUUID());try{if(active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");AtomicFiles.directory(projection.getParent());var vault=new VaultProjection600(projection);LibraryEncryptedCache600 cache=null;try{cache=LibraryEncryptedCache600.open(AppPaths.root().resolve("core600/library-cache").resolve(active.accountId()),active.accountId(),active.deviceId(),Clock.systemUTC(),System::nanoTime);}catch(IOException unavailable){Platform.runLater(()->{if(session==active&&!active.locked())status.setText("Системное хранилище ключей недоступно. Библиотека работает только онлайн.");});}var connector=new LibraryConnector600(http,vault,grant.capability().accountId,grant.capability().deviceId,grant.capability().generation,Clock.systemUTC(),System::nanoTime,cache);return new LibraryLauncherView600.Connection(http,connector,()->{if(active!=session||active.locked())return false;try{return identity.isActive(grant.wire());}catch(IdentityClient600.Rejected denied){return false;}catch(IOException uncertain){return active.canContinueOffline();}});}catch(Exception error){http.close();throw error;}
    },new LibraryLauncherView600.ProtectedLauncher(){
      public void open(Path file)throws Exception {if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");obsidian().openProtected(file,obsidianProgress(active),()->stopping||active!=session||active.locked());}
      public void close()throws Exception {var coordinator=obsidian;if(coordinator!=null)coordinator.closeProtected();}
    },this::openSafeLink);root.setCenter(library.node());
  }
  private CommunityUi community(){
    if(community==null){var active=session;community=new CommunityUi(themes,(action,data)->communityCall(active,action,data),(CommunityUi.DelegatedStepUp)()->{reauthenticate(active);return "";},this::openSafeLink);}
    return community;
  }
  private void showCommunity(boolean news){var api=community();root.setCenter(news?new NewsView(api).node():new OrganizationsView(api).node());}
  private void notifications(){if(notifications==null)notifications=new CoreNotificationsView600(community(),this::showApplications,this::updatesPage);root.setCenter(notifications.node());}
  private JsonObject communityCall(String action,JsonObject data)throws Exception {
    return communityCall(session,action,data);
  }
  private JsonObject communityCall(CoreAccountSession600 active,String action,JsonObject data)throws Exception {
    requireNetwork();if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");Properties p=serviceConfig("community",Set.of("onion","port","publicKey"));
    JsonObject profile=active.profile();boolean administrator=Boolean.parseBoolean(str(profile,"ownerBadge"))||Boolean.parseBoolean(str(profile,"delegatedAdministrator"));
    if(administrator){try{var grant=active.grant(App.AEGIS,EnumSet.of(Scope.ACCOUNT_READ,Scope.ADMIN));return gateway(p,grant,action,data);}catch(IdentityClient600.Rejected denied){/* Fresh Mail consent is required before administrative grants. */}}
    return gateway(p,active.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ)),action,data);
  }
  private JsonObject gateway(Properties p,CoreAccountSession600.AppGrant grant,String action,JsonObject data)throws Exception {
    try(var client=new org.securemail.client.community600.CommunityClient600(p.getProperty("onion"),Integer.parseInt(p.getProperty("port")),IdentityProtocol.unb64(p.getProperty("publicKey"),44),config.identityPublicKey(),grant.wire(),grant.proofPrivate(),transport)){return client.call(action,data);}
  }
  private void reauthenticate()throws Exception {
    reauthenticate(session);
  }
  private void reauthenticate(CoreAccountSession600 current)throws Exception {
    requireNetwork();if(current==null||current!=session||current.locked())throw new IOException("Сессия АЕГИС заблокирована");
    stopMailForConsent();
    var grant=current.coreGrant();long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] proof=IdentityProtocol.sign(grant.proofPrivate(),IdentityProtocol.request(grant.capability(),"account.read",new byte[0],time,nonce));
    var consent=consentBroker(current);var answer=consent.beginStepUp(grant.wire(),time,nonce,proof).get(10,TimeUnit.MINUTES);
    if(!current.accountId().equals(answer.accountId())||!current.deviceId().equals(answer.deviceId())||current.generation()!=answer.generation())throw new IOException("Подтверждение относится к другой сессии");current.completeStepUp(answer.challenge(),answer.expiresAt(),answer.accountProof());
  }
  private void settings(){
    Button appearance=button("Оформление и макеты",()->{try{root.setCenter(new AppearanceView(stage,themes,worker).node());}catch(IOException error){status.setText("Не удалось открыть оформление");}});
    Button admin=button("Управление АЕГИС",this::administration);
    VBox page=card(heading("Настройки"),actions(button("Аккаунт",()->work(session::profile,p->root.setCenter(card(heading(str(p,"nickname")),label("Идентификатор аккаунта: "+str(p,"accountId")),label(str(p,"systemRole")))))),button("Устройства",this::devices),button("Подтверждения полномочий",this::ownerAdministration),appearance,button("Уведомления",this::notifications),button("Обновления",this::updatesPage),admin,button("Службы сервера",this::serverManagement)),label("Ключ аккаунта и личный архив принадлежат Почте. Настройки браузера и личного Obsidian хранятся отдельно."),actions(button("Сервер Identity",this::configuration),button("Серверы приложений",this::serviceConfiguration)));page.setMaxWidth(1000);root.setCenter(scroll(page));
  }
  private void ownerAdministration(){
    if(ownerAdministration!=null&&authoritySetup!=null){authorityPage();return;}var active=session;
    authoritySetup=new AuthoritySetupView600(new AuthoritySetupView600.Operations(){
      private void live()throws IOException {requireNetwork();if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");}
      public String bootstrap(OwnerBootstrap request)throws Exception {
        live();var flow=new OwnerBootstrapFlow600(identity,active);var bootstrap=flow.inspect(request);stopMailForConsent();live();var grant=active.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ));long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] body=IdentityProtocol.ownerBootstrapInspection(identity.audience(),bootstrap.challenge,time,nonce),proof=IdentityProtocol.sign(grant.proofPrivate(),IdentityProtocol.requestDigest(grant.capability(),"account.read",IdentityProtocol.digest(body),time,nonce));
        var consent=consentBroker(active);var answer=consent.beginOwnerBootstrap(grant.wire(),bootstrap,time,nonce,proof).get(5,TimeUnit.MINUTES);live();return flow.publicCliProof(bootstrap,answer.accountProof());
      }
      public FirstDelegationFlow600.Request prepare(String target,String role)throws Exception {live();reauthenticate(active);return new FirstDelegationFlow600(identity,active).prepare(target,role);}
      public FirstDelegationFlow600.Consent consent(FirstDelegationFlow600.Request request)throws Exception {
        live();var flow=new FirstDelegationFlow600(identity,active);var delegation=flow.inspect(request);FirstDelegateRole role;if(active.accountId().equals(delegation.ownerAccountId))role=FirstDelegateRole.OWNER_APPROVE;else if(active.accountId().equals(delegation.targetAccountId))role=FirstDelegateRole.DELEGATE_ACCEPT;else throw new IOException("Делегирование относится к другим участникам");stopMailForConsent();live();
        var grant=active.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ));long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] body=IdentityProtocol.firstDelegationInspection(identity.audience(),delegation.challenge,time,nonce),proof=IdentityProtocol.sign(grant.proofPrivate(),IdentityProtocol.requestDigest(grant.capability(),"account.read",IdentityProtocol.digest(body),time,nonce));
        var consent=consentBroker(active);var answer=consent.beginFirstDelegate(grant.wire(),delegation,role,time,nonce,proof).get(2,TimeUnit.MINUTES);live();return flow.consent(request,role,answer.accountProof());
      }
      public void complete(FirstDelegationFlow600.Consent owner,FirstDelegationFlow600.Consent target)throws Exception {live();reauthenticate(active);new FirstDelegationFlow600(identity,active).complete(owner,target);}
    },(task,done)->work(task,done));
    ownerAdministration=new OwnerAdministrationView600(new OwnerAdministrationView600.Operations(){
      private OwnerTransferFlow600 flow()throws IOException {requireNetwork();if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");return new OwnerTransferFlow600(identity,active);}
      public OwnerTransferFlow600.Request prepare(String target)throws Exception {var flow=flow();reauthenticate(active);return flow.prepare(target);}
      public OwnerTransferFlow600.Consent consent(OwnerTransferFlow600.Request request)throws Exception {
        var flow=flow();var transfer=flow.inspect(request);OwnerTransferRole role;if(active.accountId().equals(transfer.ownerAccountId))role=OwnerTransferRole.OWNER_APPROVE;else if(active.accountId().equals(transfer.targetAccountId))role=OwnerTransferRole.SUCCESSOR_ACCEPT;else throw new IOException("Запрос относится к другим участникам");reauthenticate(active);flow();
        var grant=active.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ));long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] body=IdentityProtocol.ownerTransferInspection(identity.audience(),transfer.challenge,time,nonce),proof=IdentityProtocol.sign(grant.proofPrivate(),IdentityProtocol.requestDigest(grant.capability(),"account.read",IdentityProtocol.digest(body),time,nonce));
        var consent=consentBroker(active);var answer=consent.beginOwnerTransfer(grant.wire(),transfer,role,time,nonce,proof).get(2,TimeUnit.MINUTES);flow();return flow.consent(request,role,answer.accountProof());
      }
      public void approve(OwnerTransferFlow600.Request request)throws Exception {var flow=flow();reauthenticate(active);flow.approve(request);}
      public void complete(OwnerTransferFlow600.Consent owner,OwnerTransferFlow600.Consent successor)throws Exception {var flow=flow();reauthenticate(active);flow.complete(owner,successor);}
    },(task,done)->work(task,done),done->revoked());authorityPage();
  }
  private void authorityPage(){VBox page=new VBox(12,authoritySetup.node(),fold("Передача статуса владельца",ownerAdministration.node()));page.setMinWidth(0);page.setMaxWidth(980);root.setCenter(scroll(page));}
  private void administration(){var active=session;work(()->{if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");return active.profile();},profile->{if(!Boolean.parseBoolean(str(profile,"ownerBadge"))&&!Boolean.parseBoolean(str(profile,"delegatedAdministrator"))){status.setText("Нет действующих административных полномочий Identity");return;}VBox page=card(heading("Управление АЕГИС"),label("Полномочия и восстановление аккаунтов проверяет Identity. Управление сообществами использует отдельный сервер."),actions(button("Полномочия и восстановление",this::identityAdministration),button("Сообщества, публикации и аудит",()->{var api=community();work(()->{reauthenticate();return communityCall("community.me",obj());},me->{if(!administrative(me)){status.setText("Нет действующих полномочий управления сообществами");return;}root.setCenter(new AdminView(api,this::identityAdministration).node());});})));page.setMaxWidth(900);root.setCenter(scroll(page));});}
  private void identityAdministration(){var active=session;work(()->{if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");return active.profile();},profile->{if(!Boolean.parseBoolean(str(profile,"ownerBadge"))&&!Boolean.parseBoolean(str(profile,"delegatedAdministrator"))){status.setText("Нет действующих административных полномочий Identity");return;}if(identityAdministration!=null)identityAdministration.close();identityAdministration=new IdentityAdministrationView600(new IdentityAdministrationFlow600(identity,active),()->{if(active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");reauthenticate(active);},(task,done)->work(task,done));root.setCenter(scroll(identityAdministration.node()));});}
  private void serverManagement(){var active=session;work(()->{requireNetwork();if(active==null||active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");var endpoint=ManagementClient600.Config.load(ManagementClient600.Config.defaultFile());return new ManagementClient600(transport,endpoint,config.identityPublicKey());},client->{if(management!=null)management.close();management=new ServerManagementView600(client,request->{if(active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");reauthenticate(active);var grant=active.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ,Scope.ADMIN));if(active!=session||active.locked())throw new IOException("Сессия АЕГИС заблокирована");return new ManagementClient600.Grant(grant.wire(),grant.proofPrivate());});root.setCenter(management);});}
  private void updatesPage(){VBox page=new VBox(12);page.setMaxWidth(980);if(updates==null)page.getChildren().addAll(heading("Обновления"),label("Для поиска и загрузки подписанных обновлений подключите Tor."),button("Подключить Tor",this::connectTor));else{updatesView=new UpdatesView(stage,themes,updates,updatePreferences,value->{try{value.save(AppPaths.root());updatePreferences=value;}catch(IOException failure){throw new UncheckedIOException(failure);}},this::installUpdate);page.getChildren().add(updatesView.node());}if(AppPaths.windows()){Button rollback=button("Вернуть предыдущую установленную версию",this::rollbackProgram);rollback.setDisable(true);page.getChildren().add(fold("Восстановление программы",card(label("Доступно для сохранённой установщиком предыдущей версии. Данные Почты и резервные копии сохраняются. Перед откатом закройте Взор и личный Obsidian."),rollback)));work(()->!UpdateSupport.canWindowsRollback600(),rollback::setDisable);}root.setCenter(scroll(page));}
  private void rollbackProgram(){if(installingUpdate)return;InWindowAlert confirm=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Вернуть сохранённую предыдущую программу? АЕГИС, Почта и Глас завершатся. Закройте Взор и личный Obsidian. Новые данные не удаляются; совместимость прежней версии требует проверки резервной копии.",ButtonType.OK,ButtonType.CANCEL);confirm.initOwner(stage);confirm.setHeaderText(null);themes.apply(confirm.getDialogPane());if(confirm.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK)return;installingUpdate=true;lock();work(()->{try{closeSession();if(!UpdateSupport.scheduleWindowsRollback600())throw new IOException("Сохранённая предыдущая программа недоступна для отката");return true;}catch(Exception failed){Platform.runLater(()->installingUpdate=false);throw failed;}},done->shutdown());}

  private void installUpdate(){
    if(installingUpdate||updates==null||updates.snapshot().state()!=UpdateService.State.READY_TO_INSTALL)return;
    InWindowAlert confirm=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Установить проверенное обновление и перезапустить АЕГИС? Почта и Глас сохранят очереди и закроются. Перед заменой файлов установщик проверит независимые приложения.",ButtonType.OK,ButtonType.CANCEL);confirm.initOwner(stage);confirm.setHeaderText(null);themes.apply(confirm.getDialogPane());if(confirm.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK)return;
    installingUpdate=true;lock();work(()->{try{closeSession();long launcher=AppPaths.windows()?ProcessHandle.current().parent().orElseThrow().pid():0;Path job=updates.prepareInstall(AppPaths.bundle(),ProcessHandle.current().pid(),launcher);UpdateInstaller.launch(job);updates.restarting();return true;}catch(Exception failed){updates.installFailed();Platform.runLater(()->installingUpdate=false);throw failed;}},done->shutdown());
  }
  private Properties serviceConfig(String service,Set<String> keys)throws IOException {Path file=AppPaths.root().resolve("core600/"+service+".properties");for(Path p=file;p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылка в конфигурации сервиса");Properties props=new Properties();try(var in=new ByteArrayInputStream(AtomicFiles.read(file,16384))){props.load(in);}if(!props.stringPropertyNames().equals(keys))throw new IOException("Сервис не настроен");return props;}
  private void openSafeLink(String address){work(()->{requireNetwork();var grant=session.coreGrant();identity.authorizeDigest(grant.wire(),grant.proofPrivate(),"account.read",("OPEN-VZOR/v1\n"+address).getBytes(StandardCharsets.UTF_8));VzorLaunch600.requireHiddenData(protectedDataPaths());return VzorLaunch600.openAuthorized(AppPaths.bundle(),address);},result->status.setText(result.status()==VzorLaunch600.Status.STARTED?"Взор открыт отдельно":"Взор уже открыт"));}
  private void lock(){
    CoreAccountSession600 current;MailPairingBroker600 consent;
    synchronized(consentMutex){if(stopping)return;uiEpoch.incrementAndGet();current=session;if(current!=null)current.lock();consent=pairing;pairing=null;}
    cancelPairing(consent);
    var coordinator=obsidian;if(coordinator!=null)try{protectedCleanup.execute(()->{try{coordinator.closeProtected();}catch(Exception failed){Platform.runLater(()->{if(session==current&&(current==null||current.locked()))status.setText("Не подтверждено завершение защищённой Библиотеки");});}});}catch(RejectedExecutionException busy){status.setText("Не подтверждена очистка защищённой Библиотеки");}
    if(broker!=null)broker.lock();if(library!=null)library.lock();if(management!=null){management.close();management=null;}if(notifications!=null){notifications.close();notifications=null;}if(ownerAdministration!=null){ownerAdministration.close();ownerAdministration=null;}if(authoritySetup!=null){authoritySetup.close();authoritySetup=null;}if(identityAdministration!=null){identityAdministration.close();identityAdministration=null;}if(community!=null){community.close();community=null;}if(applications!=null)applications.locked();identityLabel.setText("АЕГИС заблокирован");showLogin();status.setText("Для продолжения подтвердите вход");
  }
  private void publishSession(CoreAccountSession600 candidate,long epoch)throws IOException {synchronized(consentMutex){if(stopping||uiEpoch.get()!=epoch)throw new IOException("Вход отменён блокировкой");session=candidate;}}
  private MailPairingBroker600 consentBroker(CoreAccountSession600 active)throws IOException {return consentBroker(active,uiEpoch.get());}
  private MailPairingBroker600 consentBroker(CoreAccountSession600 active,long epoch)throws IOException {
    var next=new MailPairingBroker600(installation(),config);MailPairingBroker600 previous;
    synchronized(consentMutex){if(stopping||uiEpoch.get()!=epoch||active!=session||active!=null&&active.locked()){next.close();throw new IOException("Подтверждение отменено блокировкой");}previous=pairing;pairing=next;}
    if(previous!=null)previous.close();return next;
  }
  /** Called on FX; owned child shutdown/wait always runs on the independent bounded cleanup lane. */
  private void cancelPairing(MailPairingBroker600 consent){
    if(consent==null)return;var done=new CompletableFuture<Void>();closingConsents.put(consent,done);
    try{consentCleanup.execute(()->{try{consent.close();done.complete(null);}catch(RuntimeException failed){done.completeExceptionally(failed);}finally{if(done.isDone()&&!done.isCompletedExceptionally())closingConsents.remove(consent,done);}});}
    catch(RejectedExecutionException busy){done.completeExceptionally(new IOException("Не подтверждено закрытие Почты",busy));status.setText("Закрытие подтверждения Почты не подтверждено. Завершите приложение перед следующим входом.");/* closeSession still drains the tracked child, and fails closed on this receipt. */}
  }

  private void revoked(){lock();work(()->{closeSession();return true;},v->{showLogin();status.setText("Сессия отозвана: выполните вход снова");});}
  private void signOut(){lock();work(()->{closeSession();return true;},v->{identityLabel.setText("Вход не выполнен");root.setLeft(null);showLogin();});}
  private void closeSession()throws IOException {
    if(notifications!=null){notifications.close();notifications=null;}if(ownerAdministration!=null){ownerAdministration.close();ownerAdministration=null;}if(authoritySetup!=null){authoritySetup.close();authoritySetup=null;}if(identityAdministration!=null){identityAdministration.close();identityAdministration=null;}
    IOException cleanupFailure=null;var coordinator=obsidian;obsidian=null;if(coordinator!=null)try{coordinator.close();}catch(Exception failed){cleanupFailure=new IOException("Не подтверждено завершение защищённой Библиотеки",failed);}if(management!=null){management.close();management=null;}preparedVoice=null;MailPairingBroker600 consent;synchronized(consentMutex){consent=pairing;pairing=null;}if(consent!=null)consent.close();for(var pending:closingConsents.entrySet()){try{pending.getKey().close();pending.getValue().get(5,TimeUnit.SECONDS);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();cleanupFailure=new IOException("Закрытие подтверждения Почты прервано",interrupted);}catch(ExecutionException|TimeoutException failed){cleanupFailure=new IOException("Не подтверждено закрытие Почты",failed);}finally{if(pending.getValue().isDone()&&!pending.getValue().isCompletedExceptionally())closingConsents.remove(pending.getKey(),pending.getValue());}}if(broker!=null){broker.close();broker=null;}
    var oldLibrary=library;library=null;if(oldLibrary!=null){oldLibrary.close();try{oldLibrary.closedFuture().toCompletableFuture().get(5,TimeUnit.SECONDS);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();cleanupFailure=new IOException("Очистка защищённой Библиотеки прервана",interrupted);}catch(ExecutionException|TimeoutException failed){cleanupFailure=new IOException("Не удалось подтвердить очистку защищённой Библиотеки",failed);}}
    if(community!=null){community.close();community=null;}if(applications!=null){applications.close();applications=null;}var old=session;session=null;if(old!=null)old.close();var oldBinding=lockBinding;lockBinding=null;if(oldBinding!=null)Platform.runLater(oldBinding::close);if(osLock!=null)try{osLock.close();}catch(Exception ignored){}osLock=null;
    if(cleanupFailure!=null)throw cleanupFailure;
  }
  private <T>void work(Callable<T> task,Consumer<T> done){work(task,done,()->{});}
  private <T>void work(Callable<T> task,Consumer<T> done,Runnable skipped){
    if(stopping){skipped.run();return;}long epoch=uiEpoch.get();if(Platform.isFxApplicationThread())status.setText("Выполняется…");else Platform.runLater(()->status.setText("Выполняется…"));
    try{worker.execute(()->{if(stopping||uiEpoch.get()!=epoch){skipped.run();return;}try{T value=task.call();Platform.runLater(()->{if(!stopping&&uiEpoch.get()==epoch){status.setText("Готово");done.accept(value);}});}catch(Exception failure){Platform.runLater(()->{if(!stopping&&uiEpoch.get()==epoch)status.setText(safeError(failure));});}});}catch(RejectedExecutionException busy){skipped.run();Platform.runLater(()->status.setText("Дождитесь завершения текущего действия"));}
  }

  private String safeError(Exception failure){Throwable e=failure instanceof ExecutionException?failure.getCause():failure;if(e instanceof IdentityClient600.Rejected)return "Сервер отклонил запрос. Проверьте доверенное устройство и разрешения.";if(e instanceof IOException io){String message=io.getMessage();if(message!=null&&message.matches("[\\p{IsCyrillic}А-Яа-яЁё0-9 .,!:—-]{1,180}"))return message;}return "Операция не завершена. Проверьте Tor, доверенные параметры сервера и установленный комплект.";}
  private void clearTransientPasswords(){for(var field:transientPasswords)field.clear();transientPasswords.clear();}
  private void shutdown(){if(stopping)return;if(Platform.isFxApplicationThread())clearTransientPasswords();else Platform.runLater(this::clearTransientPasswords);stopping=true;var active=session;if(active!=null)active.lock();stage.hide();guardWorker.shutdownNow();Thread shutdown=new Thread(()->{try{closeSession();}catch(Exception failed){System.err.println("АЕГИС: завершение защищённых компонентов не подтверждено полностью.");}finally{var coordinator=obsidian;if(coordinator!=null)try{coordinator.close();}catch(Exception failed){System.err.println("АЕГИС: не подтверждено завершение защищённой Библиотеки.");}protectedCleanup.shutdownNow();consentCleanup.shutdown();if(updates!=null)updates.close();if(identity!=null)identity.close();if(tor!=null)tor.close();try{if(instance!=null)instance.release();if(instanceChannel!=null)instanceChannel.close();}catch(IOException failed){System.err.println("АЕГИС: не подтверждено освобождение блокировки процесса.");}worker.shutdownNow();Platform.runLater(()->{try{themes.close();}catch(Exception failed){System.err.println("АЕГИС: не подтверждено завершение оформления.");}finally{/* The Core lease intentionally remains held until JVM exit. Timed-out native cleanup must still block replacement. */Platform.exit();}});}},"aegis-core-shutdown");shutdown.setDaemon(false);shutdown.start();}
  @Override public void stop(){if(!stopping)shutdown();}
}
