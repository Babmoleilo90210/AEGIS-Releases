package org.securemail.ui;

import java.io.*;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.function.*;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import org.securemail.client.*;
import org.securemail.client.safeweb.*;

/** In-window browser preparation and controls. Network and installation never run on FX. */
final class VzorView implements AutoCloseable {
  private final Stage owner; private final ThemeManager themes;
  private final ClientConfig config; private final SafeWebProcess browser;
  private final ExecutorService worker; private final BooleanSupplier torReady;
  private final Runnable connect; private final Supplier<List<Path>> privatePaths;
  private final Consumer<Path> importFile; private final Consumer<String> notice;
  private final TextField address=new TextField("https://check.torproject.org/");
  private final Label status=new Label(),detail=new Label();
  private final ProgressBar progress=new ProgressBar(-1);
  private final Button open=new Button("Открыть Взор"),cancel=new Button("Отменить"),fresh=new Button("Новая сессия"),stop=new Button("Закрыть");
  private final Selector<SafeWebSessions.Mode> mode;
  private final ScrollPane page;
  private volatile TorBrowserDownloadService.Cancellation cancellation;
  private volatile boolean closed,busy;private volatile long operationGeneration;
  private record UiProgress(long generation,String message,double amount){}
  private final java.util.concurrent.atomic.AtomicReference<UiProgress> latestProgress=new java.util.concurrent.atomic.AtomicReference<>();
  private final java.util.concurrent.atomic.AtomicBoolean progressQueued=new java.util.concurrent.atomic.AtomicBoolean();

  VzorView(Stage owner,ThemeManager themes,ClientConfig config,SafeWebProcess browser,
      ExecutorService worker,BooleanSupplier torReady,Runnable connect,
      Supplier<List<Path>> privatePaths,Consumer<Path> importFile,Consumer<String> notice) {
    this.owner=owner;this.themes=themes;this.config=config;this.browser=browser;this.worker=worker;
    this.torReady=torReady;this.connect=connect;this.privatePaths=privatePaths;this.importFile=importFile;this.notice=notice;
    Label title=new Label("Взор");title.getStyleClass().add("heading");
    status.setWrapText(true);status.setText(browser.snapshot().status());status.setId("vzor-status");
    open.getStyleClass().add("primary");open.setId("vzor-open");open.setOnAction(e->launch(false));
    fresh.setOnAction(e->launch(true));stop.setOnAction(e->operation(()->{browser.close();return null;},v->{}));
    cancel.setOnAction(e->{var active=cancellation;if(active!=null){active.cancel();status.setText("Отмена подготовки…");}});
    cancel.setVisible(false);cancel.setManaged(false);
    progress.setMaxWidth(Double.MAX_VALUE);progress.setVisible(false);progress.setManaged(false);progress.setId("vzor-progress");
    mode=new Selector<>(themes,List.of(SafeWebSessions.Mode.values()),SafeWebSessions.Mode.PERSISTENT);
    mode.setAccessibleText("Тип сессии Взора");
    mode.setTooltip(new Tooltip("Обычная сессия сохраняет закладки и настройки. Временная удаляется после подтверждённого закрытия."));
    address.setPromptText("Адрес HTTPS или onion");address.setAccessibleText("Адрес сайта");address.setOnAction(e->launch(false));address.setMinWidth(0);
    FlowPane sessions=new FlowPane(8,8,new Label("Сессия"),mode);sessions.setMinWidth(0);
    // FlowPane measures children at preferred width. Bound the selector itself so
    // a long session name cannot force the whole controls column wider at 200%.
    mode.maxWidthProperty().bind(sessions.widthProperty());
    Label preparation=wrapped("При необходимости система предложит установить компоненты изоляции: bubblewrap, slirp4netns и Xephyr в CachyOS либо Windows Sandbox. Подтверждение выполняется штатным Polkit или UAC.");TitledPane systemComponents=new TitledPane("Системные компоненты",preparation);systemComponents.setExpanded(false);
    VBox controls=new VBox(10,title,status,new FlowPane(8,8,open,fresh,stop,cancel),address,
        sessions,progress,systemComponents);
    controls.setId("vzor-controls");controls.setMinWidth(0);
    ListView<Path> downloads=new ListView<>();downloads.setPrefHeight(130);downloads.setMinHeight(70);
    downloads.setCellFactory(v->new ListCell<>(){protected void updateItem(Path file,boolean empty){super.updateItem(file,empty);setText(empty||file==null?null:file.getFileName().toString());}});
    Button refresh=new Button("Обновить список"),save=new Button("Импортировать в архив");
    refresh.setOnAction(e->operation(browser::downloads,files->downloads.getItems().setAll(files)));
    save.setOnAction(e->{Path selected=downloads.getSelectionModel().getSelectedItem();if(selected!=null)importFile.accept(selected);});
    Label downloadHelp=wrapped("Файлы хранятся отдельно. Импорт в зашифрованный архив выполняется только по вашему выбору.");
    TitledPane files=new TitledPane("Загрузки",new VBox(8,downloadHelp,downloads,new FlowPane(8,8,refresh,save)));files.setExpanded(false);
    Label security=wrapped("Взор использует официальный Tor Browser с собственным Tor и отдельным профилем. Подключение и уровень безопасности отображаются в окне браузера.\n\nLinux: bubblewrap, slirp4netns и Xephyr. Windows: Windows 11 24H2+ Pro, Enterprise или Education с актуальным Windows Sandbox CLI. Без поддерживаемой изоляции запуск запрещён; Windows Home этим механизмом не поддерживается.\n\nКаталоги АЕГИС и буфер обмена не передаются браузеру. Автоматического перехода на прямую сеть нет. Уровень безопасности и «Новая личность» доступны в штатном меню Tor Browser.");
    TitledPane protection=new TitledPane("Безопасность",security);protection.setExpanded(false);
    Button manual=new Button("Импортировать официальный пакет…");manual.setWrapText(true);manual.getStyleClass().add("wrapped-action");
    manual.setOnAction(e->manualInstall());
    detail.setWrapText(true);detail.getStyleClass().add("muted");
    Button discover=new Button("Найти установленный Tor Browser");discover.setWrapText(true);discover.getStyleClass().add("wrapped-action");
    discover.setOnAction(e->operation(TorBrowserDiscovery::discover,found->detail.setText(found.isEmpty()?"Других установок не найдено. При открытии будет подготовлена официальная копия.":"Найдена установка Tor Browser. Для Взора будет загружена проверенная официальная копия; существующий профиль, пароли и история не переносятся.")));
    TitledPane advanced=new TitledPane("Дополнительные настройки",new VBox(8,
        wrapped("При первом открытии официальный пакет и подпись загружаются автоматически через Tor. Ручной импорт — резервный способ."),manual,discover,detail));advanced.setExpanded(false);
    VBox body=new VBox(12,controls,files,protection,advanced);body.getStyleClass().add("settings-card");
    body.setPadding(new Insets(16));body.setMinWidth(0);body.setMaxWidth(840);
    StackPane centered=new StackPane(body);StackPane.setAlignment(body,javafx.geometry.Pos.TOP_LEFT);
    page=new ScrollPane(centered);page.setFitToWidth(true);page.setId("vzor-page");
    browser.listener(snapshot->Platform.runLater(()->{if(!closed&&!busy)status.setText(snapshot.status());}));
    operation(()->{browser.initialize();return browser.snapshot();},snapshot->{status.setText(snapshot.status());});
  }
  Node node(){return page;}
  void address(String url){address.setText(url);}
  private static Label wrapped(String text){Label l=new Label(text);l.setWrapText(true);l.setMinWidth(0);return l;}
  private boolean confirmRestart(){
    if(!browser.running())return true;
    InWindowAlert ask=new InWindowAlert(Alert.AlertType.CONFIRMATION,
        "Закрыть вкладки Взора и начать выбранную сессию? Несохранённые данные вкладок и загрузки временной сессии будут потеряны.",ButtonType.OK,ButtonType.CANCEL);
    ask.initOwner(owner);ask.setHeaderText("Новая сессия Взора");themes.apply(ask.getDialogPane());
    return ask.showAndWait().orElse(ButtonType.CANCEL)==ButtonType.OK;
  }
  private void launch(boolean newSession){
    if(busy||closed)return;
    final String url=address.getText();try{SafeWebUrl.parse(url);}catch(IllegalArgumentException invalid){notice.accept(invalid.getMessage());return;}
    if(!confirmRestart())return;
    final List<Path> guarded=List.copyOf(privatePaths.get());final SafeWebSessions.Mode selected=mode.getValue();
    var token=new TorBrowserDownloadService.Cancellation();cancellation=token;
    operation(()->{
      SandboxPreparation.Result system=SandboxPreparation.prepare(p->{update(p.message(),-1);Platform.runLater(()->{if(!closed&&busy)cancel.setDisable(!p.cancellable());});},token::cancelled);
      if(!system.ready())throw new RebootRequiredException();
      SandboxPrerequisites.check();browser.initialize();browser.privatePaths(guarded);if(browser.running())browser.close();
      if(!browser.authenticatedPreflight()){
        if(!torReady.getAsBoolean())Platform.runLater(()->{if(!closed&&!token.cancelled())connect.run();});
        update("Ожидание защищённого подключения Tor…",-1);
        long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.MINUTES.toNanos(8);
        while(!torReady.getAsBoolean()){
          if(token.cancelled())throw new InterruptedIOException("Подготовка Взора отменена");
          if(System.nanoTime()>=deadline)throw new IOException("Tor пока недоступен. Повторите открытие после подключения.");
          try{Thread.sleep(200);}catch(InterruptedException stopped){Thread.currentThread().interrupt();throw new InterruptedIOException("Подготовка Взора остановлена");}
        }
        var installer=new TorBrowserDownloadService(config,torReady);
        try(var verified=installer.downloadLatest(AppPaths.root().resolve("browser-install"),p->{
          double amount=p.total()>0?Math.min(1,p.downloaded()/(double)p.total()):-1;update(p.message(),amount);
        },token)){
          if(token.cancelled())throw new InterruptedIOException("Подготовка Взора отменена");
          update("Установка проверенного Tor Browser…",-1);
          browser.install(verified.archive(),verified.signature(),token::cancelled);
        }
      }
      if(token.cancelled())throw new InterruptedIOException("Подготовка Взора отменена");
      update("Подготовка изолированной сессии…",-1);
      if(newSession)browser.newSession(selected,url);else browser.open(selected,url);
      if(closed||token.cancelled()){browser.close();throw new InterruptedIOException("Подготовка Взора отменена");}
      return browser.snapshot();
    },snapshot->{status.setText(snapshot.status());});
  }
  private void manualInstall(){
    if(busy||closed||browser.running()){notice.accept("Сначала завершите подготовку и закройте Взор");return;}
    InWindowFileChooser packages=new InWindowFileChooser();packages.setTitle("Официальный пакет Tor Browser");
    packages.getExtensionFilters().add(new FileChooser.ExtensionFilter("Tor Browser","*.tar.xz","*.exe"));File archive=packages.showOpenDialog(owner);if(archive==null)return;
    InWindowFileChooser signatures=new InWindowFileChooser();signatures.setTitle("Подпись того же пакета Tor Browser");
    signatures.getExtensionFilters().add(new FileChooser.ExtensionFilter("Подпись OpenPGP","*.asc"));File signature=signatures.showOpenDialog(owner);if(signature==null)return;
    var token=new TorBrowserDownloadService.Cancellation();cancellation=token;
    operation(()->browser.install(archive.toPath(),signature.toPath(),token::cancelled),label->status.setText("Официальный пакет проверен. Взор готов к открытию."));
  }
  @FunctionalInterface private interface Work<T>{T run()throws Exception;}
  private <T> void operation(Work<T> action,Consumer<T> done){
    if(busy||closed)return;operationGeneration++;latestProgress.set(null);busy=true;setBusy(true);
    worker.execute(()->{try{T result=action.run();Platform.runLater(()->{if(!closed)done.accept(result);});}
      catch(Exception|LinkageError failure){Platform.runLater(()->{if(!closed)status.setText(browser.snapshot().running()?"Взор ещё работает. Повторите закрытие браузера.":failure instanceof InterruptedIOException?"Подготовка Взора отменена":safeError(failure));});}
      finally{Platform.runLater(()->{busy=false;cancellation=null;if(!closed)setBusy(false);});}});
  }
  private static final class RebootRequiredException extends IOException {}
  private static String safeError(Throwable error){
    if(error instanceof RebootRequiredException)return "Компоненты установлены. Перезагрузите Windows и повторите открытие Взора.";
    if(error instanceof SandboxPrerequisites.Failure prerequisite)return prerequisite.getMessage();
    if(error instanceof LinkageError)return "Системный компонент изоляции недоступен или несовместим. Проверьте установку компонентов Взора.";
    if(error instanceof TorBrowserDownloadService.TorRequiredException)return "Для подготовки Взора требуется подключение Tor";
    // Exception text can contain an attacker-controlled HTTP status/header/path. Do not render it.
    return "Не удалось подготовить Взор. Предыдущая установка сохранена. Проверьте Tor и доступность изоляции, затем повторите.";
  }
  private void setBusy(boolean value){
    open.setDisable(value);fresh.setDisable(value);stop.setDisable(value);mode.setDisable(value);if(!value)cancel.setDisable(false);
    progress.setManaged(value);progress.setVisible(value);cancel.setManaged(value&&cancellation!=null);cancel.setVisible(value&&cancellation!=null);
    if(!value)progress.setProgress(-1);
  }
  private void update(String text,double amount){latestProgress.set(new UiProgress(operationGeneration,text,amount));queueProgress();}
  private void queueProgress(){if(!progressQueued.compareAndSet(false,true))return;Platform.runLater(()->{var value=latestProgress.getAndSet(null);progressQueued.set(false);if(!closed&&busy&&value!=null&&value.generation()==operationGeneration){status.setText(value.message());progress.setProgress(value.amount());}if(latestProgress.get()!=null)queueProgress();});}
  @Override public void close(){closed=true;var active=cancellation;if(active!=null)active.cancel();}
}
