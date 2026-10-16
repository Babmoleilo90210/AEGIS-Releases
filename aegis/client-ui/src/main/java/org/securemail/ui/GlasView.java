package org.securemail.ui;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.*;
import javafx.animation.*;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.util.Duration;
import org.securemail.client.ClientSession;
import org.securemail.client.voice.*;
import org.securemail.protocol.UserInfo;

/** Contact-bound calls inside the existing window; no audio I/O on the FX thread. */
final class GlasView implements AutoCloseable {
  private final ClientSession session; private final VoiceCallService calls;
  private final ThemeManager themes;private final ExecutorService worker;
  private final Function<String,Node> avatar; private final Consumer<String> notice;
  private final VBox body=new VBox(12),activeAvatar=new VBox();private final ScrollPane page;
  private final Label status=new Label(),peer=new Label(),identity=new Label(),duration=new Label();
  private final ListView<UserInfo> contacts=new ListView<>();
  private final Button call=new Button("Позвонить"),accept=new Button("Принять"),decline=new Button("Отклонить"),hangup=new Button("Завершить"),microphone=new Button("Включить микрофон");
  private Boolean pendingMicrophone;private final java.util.concurrent.atomic.AtomicBoolean preparingCall=new java.util.concurrent.atomic.AtomicBoolean();
  private final ListView<String> history=new ListView<>();
  private final AutoCloseable listener;private volatile boolean closed;private final java.util.concurrent.atomic.AtomicBoolean refreshQueued=new java.util.concurrent.atomic.AtomicBoolean();private final Set<AudioControls> audioControls=Collections.newSetFromMap(new WeakHashMap<>());
  private final java.util.concurrent.ThreadPoolExecutor audioWorker=new java.util.concurrent.ThreadPoolExecutor(2,2,30,java.util.concurrent.TimeUnit.SECONDS,new java.util.concurrent.ArrayBlockingQueue<>(8),task->{Thread t=new Thread(task,"glas-audio-controls");t.setDaemon(true);return t;},new java.util.concurrent.ThreadPoolExecutor.AbortPolicy());
  private final GlasTestOwnership<GlasAudioSession.MicrophoneTest> microphoneTests=new GlasTestOwnership<>();
  // A slot is retained across pending open, ownership and confirmed cleanup. Therefore
  // at most one cleanup can be outstanding, independently of the device-work queue.
  private final java.util.concurrent.atomic.AtomicBoolean microphoneSlot=new java.util.concurrent.atomic.AtomicBoolean();
  private final java.util.concurrent.ThreadPoolExecutor microphoneCleanup=new java.util.concurrent.ThreadPoolExecutor(1,1,0,java.util.concurrent.TimeUnit.SECONDS,new java.util.concurrent.ArrayBlockingQueue<>(1),task->{Thread t=new Thread(task,"glas-microphone-cleanup");t.setDaemon(true);return t;},new java.util.concurrent.ThreadPoolExecutor.AbortPolicy());

  GlasView(ClientSession session,ThemeManager themes,ExecutorService worker,Function<String,Node> avatar,Consumer<String> notice){
    this.session=session;this.calls=session.calls();this.themes=themes;this.worker=worker;this.avatar=avatar;this.notice=notice;
    Label heading=new Label("Глас");heading.getStyleClass().add("heading");
    status.setWrapText(true);status.setId("glas-status");identity.setWrapText(true);identity.setMinWidth(0);identity.getStyleClass().add("muted");
    peer.getStyleClass().add("heading");HBox participant=new HBox(12,activeAvatar,new VBox(4,peer,duration));participant.setAlignment(Pos.CENTER_LEFT);
    call.getStyleClass().add("primary");call.setOnAction(e->{UserInfo selected=contacts.getSelectionModel().getSelectedItem();if(selected==null||!preparingCall.compareAndSet(false,true))return;stopMicrophoneTests();call.setDisable(true);worker.execute(()->{try{session.prepareVoiceCall(selected,VoiceCallService.Direction.OUTGOING);calls.start(selected);}catch(Exception failure){Platform.runLater(()->notice.accept("Собеседник недоступен или звонок не разрешён. Проверьте Tor, разрешения и ключ контакта."));}finally{preparingCall.set(false);Platform.runLater(()->{if(!closed)refresh();});}});});
    accept.getStyleClass().add("primary");accept.setOnAction(e->{stopMicrophoneTests();calls.accept(calls.snapshot().callId());});decline.setOnAction(e->calls.decline(calls.snapshot().callId()));
    hangup.setOnAction(e->calls.hangup());microphone.setOnAction(e->{if(pendingMicrophone!=null)return;pendingMicrophone=!calls.snapshot().microphoneEnabled();microphone.setDisable(true);microphone.setText(pendingMicrophone?"Включение микрофона…":"Выключение микрофона…");calls.setMicrophoneEnabled(pendingMicrophone);});
    FlowPane actions=new FlowPane(8,8,accept,decline,microphone,hangup);actions.setId("glas-call-actions");
    TextField search=new TextField();search.setPromptText("Найти контакт");search.setAccessibleText("Поиск контакта для звонка");
    search.textProperty().addListener((o,a,b)->filter(b));
    contacts.setId("glas-contacts");contacts.setPrefHeight(180);contacts.setMinHeight(80);
    contacts.setCellFactory(v->new ListCell<>(){protected void updateItem(UserInfo user,boolean empty){super.updateItem(user,empty);if(empty||user==null){setText(null);setGraphic(null);}else{setText(null);HBox row=new HBox(10,avatar.apply(user.nickname()),new Label(user.nickname()));row.setAlignment(Pos.CENTER_LEFT);setGraphic(row);}}});
    contacts.getSelectionModel().selectedItemProperty().addListener((o,a,b)->call.setDisable(b==null||calls.snapshot().busy()));filter("");
    TitledPane protection=new TitledPane("Проверка соединения",identity);protection.setExpanded(false);
    history.setPrefHeight(120);TitledPane recent=new TitledPane("История звонков",history);recent.setExpanded(false);
    TitledPane audio=new TitledPane("Звук и входящие вызовы",settingsNode());audio.setExpanded(false);
    for(TitledPane section:List.of(audio,protection,recent)){section.setMinWidth(0);section.setWrapText(true);}
    body.getChildren().addAll(heading,status,participant,actions,search,contacts,call,audio,protection,recent);
    body.getStyleClass().add("settings-card");body.setPadding(new Insets(16));body.setMaxWidth(840);body.setMinWidth(0);body.setId("glas-content");
    StackPane parent=new StackPane(body);StackPane.setAlignment(body,Pos.TOP_LEFT);page=new ScrollPane(parent);page.setFitToWidth(true);page.setId("glas-page");listener=calls.listen(()->{if(calls.snapshot().busy())closeTest(microphoneTests.stop());if(refreshQueued.compareAndSet(false,true))Platform.runLater(()->{refreshQueued.set(false);refresh();});});refresh();
  }
  Node node(){return page;}
  private void filter(String text){String q=text.toLowerCase(Locale.ROOT).trim();contacts.getItems().setAll(session.local().contacts().stream().filter(u->u.nickname().toLowerCase(Locale.ROOT).contains(q)).toList());if(!contacts.getItems().isEmpty())contacts.getSelectionModel().selectFirst();}
  private void refresh(){
    if(closed)return;var snapshot=calls.snapshot();if(snapshot.busy())stopMicrophoneTests();else for(var controls:new ArrayList<>(audioControls))if(controls.testToken>=0&&!microphoneTests.current(controls.testToken))controls.resetStoppedAttempt(controls.testToken);status.setText(snapshot.status());
    boolean incoming=snapshot.state()==VoiceCallService.State.INCOMING,secure=snapshot.state()==VoiceCallService.State.SECURE;
    visible(accept,incoming);visible(decline,incoming);visible(microphone,secure);visible(hangup,snapshot.busy()&&!incoming);
    if(!secure||pendingMicrophone!=null&&snapshot.microphoneEnabled()==pendingMicrophone)pendingMicrophone=null;
    microphone.setDisable(pendingMicrophone!=null);microphone.setText(pendingMicrophone!=null?(pendingMicrophone?"Включение микрофона…":"Выключение микрофона…"):snapshot.microphoneEnabled()?"Выключить микрофон":"Включить микрофон");microphone.setAccessibleText(microphone.getText());
    call.setDisable(preparingCall.get()||snapshot.busy()||contacts.getSelectionModel().getSelectedItem()==null);
    peer.setText(snapshot.contact()==null?"Выберите контакт":snapshot.contact().nickname());
    String id=snapshot.contact()==null?"":snapshot.contact().userId();
    if(!Objects.equals(activeAvatar.getUserData(),id)){activeAvatar.setUserData(id);activeAvatar.getChildren().clear();if(snapshot.contact()!=null)activeAvatar.getChildren().add(avatar.apply(snapshot.contact().nickname()));}
    long seconds=snapshot.durationMillis()/1000;duration.setText(secure||seconds>0?String.format(Locale.ROOT,"%02d:%02d",seconds/60,seconds%60):"");
    identity.setText(snapshot.fingerprint().isEmpty()?"Личность проверяется по сохранённому ключу контакта. Ник не является доказательством личности.":
        "Отпечаток контакта:\n"+snapshot.fingerprint()+"\n\nКод текущего соединения: "+(snapshot.safetyCode().isEmpty()?"ещё не установлен":snapshot.safetyCode())+
        "\nСверьте код или полный отпечаток с собеседником. "+(secure?"Канал аутентифицирован: TLS 1.3 через Tor.":"Аудио включится только после принятия и проверки канала."));
    List<String> entries=new ArrayList<>();if(!snapshot.historyEnabled())entries.add("История отключена");else for(var entry:calls.history()){
      UserInfo contact=session.local().contacts().stream().filter(u->u.userId().equals(entry.peerId())).findFirst().orElse(null);
      String result=switch(entry.outcome()){case "declined"->"отклонён";case "missed"->"пропущен";case "unavailable"->"недоступен";default->"завершён";};
      String time=DateTimeFormatter.ofPattern("dd.MM HH:mm").withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(entry.startedMinute()));
      entries.add(time+" · "+(contact==null?"Удалённый контакт":contact.nickname())+" · "+result);
    }history.getItems().setAll(entries);
  }
  static void visible(Node node,boolean value){node.setVisible(value);node.setManaged(value);}
  Node settingsNode(){var controls=new AudioControls();audioControls.add(controls);return new VBox(10,controls.content,callPermissions());}
  private Node callPermissions(){VoiceCallPolicy original=calls.callPolicy();VBox form=new VBox(10);List<Selector<VoiceCallPolicy.Mode>> modes=new ArrayList<>();List<Map<String,CheckBox>> selected=new ArrayList<>(),denied=new ArrayList<>();List<CheckBox> organization=new ArrayList<>();
    for(boolean inbound:List.of(true,false)){VoiceCallPolicy.Rule rule=inbound?original.incoming():original.outgoing();Selector<VoiceCallPolicy.Mode> mode=new Selector<>(themes,List.of(VoiceCallPolicy.Mode.values()),rule.mode());modes.add(mode);CheckBox grant=new CheckBox("Учитывать действующие организационные полномочия");grant.setWrapText(true);grant.setSelected(rule.organizationGrantsAllowed());organization.add(grant);VBox choices=new VBox(6);Map<String,CheckBox> allowedMap=new LinkedHashMap<>(),deniedMap=new LinkedHashMap<>();for(UserInfo contact:session.local().contacts()){CheckBox allow=new CheckBox("Разрешить: "+contact.nickname()),block=new CheckBox("Запретить: "+contact.nickname());allow.setWrapText(true);block.setWrapText(true);allow.setMaxWidth(300);block.setMaxWidth(300);allow.setSelected(rule.selectedContactIds().contains(contact.userId()));block.setSelected(rule.deniedContactIds().contains(contact.userId()));allowedMap.put(contact.userId(),allow);deniedMap.put(contact.userId(),block);choices.getChildren().add(new FlowPane(8,6,allow,block));}selected.add(allowedMap);denied.add(deniedMap);form.getChildren().add(CommunityUi.fold(inbound?"Входящие вызовы":"Исходящие вызовы",new VBox(8,mode,grant,choices)));}
    form.getChildren().addAll(CommunityUi.label("Неизвестные пользователи запрещены. Явный запрет контакта имеет приоритет. Организационное разрешение проверяет сервер до подключения."),CommunityUi.button("Сохранить разрешения",()->{List<VoiceCallPolicy.Rule> rules=new ArrayList<>();for(int i=0;i<2;i++){Set<String> allow=new HashSet<>(),block=new HashSet<>();for(var entry:selected.get(i).entrySet())if(entry.getValue().isSelected())allow.add(entry.getKey());for(var entry:denied.get(i).entrySet())if(entry.getValue().isSelected())block.add(entry.getKey());rules.add(new VoiceCallPolicy.Rule(modes.get(i).getValue(),allow,block,organization.get(i).isSelected()));}worker.execute(()->{try{calls.setCallPolicy(new VoiceCallPolicy(rules.get(0),rules.get(1)));Platform.runLater(()->notice.accept("Разрешения звонков сохранены"));}catch(Exception failure){Platform.runLater(()->notice.accept("Не удалось сохранить разрешения звонков"));}});}));return CommunityUi.fold("Разрешения звонков",form);}
  private final class AudioControls {
    final VBox content=new VBox(10);final Selector<Choice> inputs=new Selector<>(themes),outputs=new Selector<>(themes);
    final Slider gain=new Slider(0,2,1),volume=new Slider(0,1,1);final ProgressBar meter=new ProgressBar(0);
    final CheckBox echo=new CheckBox("Подавление эха"),noise=new CheckBox("Подавление фонового шума"),historyEnabled=new CheckBox("Сохранять локальную зашифрованную историю"),incoming=new CheckBox("Разрешить входящие звонки"),notifications=new CheckBox("Показывать уведомления о звонках");
    final Button test=new Button("Проверить микрофон"),save=new Button("Применить настройки");
    volatile boolean disposed;long testToken=-1;final AtomicLong lastLevel=new AtomicLong();
    final Timeline levels=new Timeline(new KeyFrame(Duration.millis(150),e->{var stats=calls.audioStats();if(stats!=null)meter.setProgress(stats.inputLevel());var owned=microphoneTests.resource();if(testToken>=0&&microphoneTests.owns(testToken,owned)&&owned!=null&&!owned.running())stopTest();}));
    AudioControls(){
      var config=calls.audioConfig();reload(config.inputDeviceId(),config.outputDeviceId());gain.setValue(config.inputGain());volume.setValue(config.speakerVolume());echo.setSelected(config.echoCancellation());noise.setSelected(config.noiseSuppression());historyEnabled.setSelected(calls.snapshot().historyEnabled());incoming.setSelected(calls.incomingEnabled());notifications.setSelected(calls.notificationsEnabled());
      Button refresh=new Button("Обновить устройства");refresh.setOnAction(e->reload(selected(inputs),selected(outputs)));
      meter.setMaxWidth(Double.MAX_VALUE);meter.setAccessibleText("Уровень микрофона");
      test.setOnAction(e->{if(testToken>=0&&microphoneTests.current(testToken)){stopTest();return;}if(closed||calls.snapshot().busy()){notice.accept("Проверка микрофона доступна после завершения звонка");return;}
        if(!microphoneSlot.compareAndSet(false,true)){notice.accept("Дождитесь закрытия предыдущей проверки микрофона");return;}
        disposed=false;long token=microphoneTests.begin();testToken=token;test.setDisable(true);String device=selected(inputs);
        if(!audioExecute(()->{
          if(closed||disposed||!microphoneTests.current(token)||calls.snapshot().busy()){microphoneTests.stop(token);releaseTestSlot();Platform.runLater(()->resetStoppedAttempt(token));return;}
          GlasAudioSession.MicrophoneTest owned;
          try{owned=GlasAudioSession.testMicrophone(device,value->{long now=System.nanoTime(),previous=lastLevel.get();if(now-previous>100_000_000L&&lastLevel.compareAndSet(previous,now))Platform.runLater(()->{if(!disposed&&!closed&&microphoneTests.current(token))meter.setProgress(value);});});}
          catch(Exception|LinkageError error){releaseTestSlot();Platform.runLater(()->{if(!disposed&&!closed&&microphoneTests.current(token)){microphoneTests.stop(token);testToken=-1;test.setDisable(false);notice.accept("Микрофон недоступен. Проверьте устройство и разрешения ОС.");}});return;}
          if(!microphoneTests.claim(token,owned)){closeTest(owned);return;}
          if(closed||disposed||calls.snapshot().busy())closeTest(microphoneTests.stop(token));
          Platform.runLater(()->{if(!closed&&!disposed&&microphoneTests.owns(token,owned)){if(calls.snapshot().busy())stopTest();else{test.setDisable(false);test.setText("Остановить проверку");}}else if(!microphoneTests.current(token))resetStoppedAttempt(token);});
        })){microphoneTests.stop(token);testToken=-1;test.setDisable(false);releaseTestSlot();}
      });
      save.setOnAction(e->{stopTest();calls.configureAudio(new GlasAudioSession.Config(selected(inputs),selected(outputs),gain.getValue(),volume.getValue(),echo.isSelected(),noise.isSelected()));
        boolean keep=historyEnabled.isSelected(),allow=incoming.isSelected(),notify=notifications.isSelected();worker.execute(()->{try{calls.setHistoryEnabled(keep);calls.setIncomingEnabled(allow);calls.setNotificationsEnabled(notify);}catch(Exception failure){Platform.runLater(()->notice.accept("Не удалось сохранить параметры звонков"));}});
      });
      Button clear=new Button("Очистить историю");clear.setOnAction(e->worker.execute(()->{try{calls.clearHistory();}catch(Exception failure){Platform.runLater(()->notice.accept("Не удалось очистить историю"));}}));
      Label trusted=new Label("Звонки принимаются только от контактов с сохранённым ключом. Заблокированные пользователи не допускаются.");trusted.setWrapText(true);
      for(CheckBox box:List.of(echo,noise,historyEnabled,incoming,notifications)){box.setWrapText(true);box.setMinHeight(Region.USE_PREF_SIZE);}
      content.getChildren().addAll(new Label("Микрофон"),inputs,new Label("Устройство воспроизведения"),outputs,refresh,new Label("Усиление микрофона"),gain,new Label("Громкость собеседника"),volume,meter,test,echo,noise,processingNote(),incoming,notifications,trusted,historyEnabled,new FlowPane(8,8,save,clear));content.setMinWidth(0);for(Node child:content.getChildren())if(child instanceof Label label){label.setMinWidth(0);label.setMaxWidth(Double.MAX_VALUE);label.setMinHeight(Region.USE_PREF_SIZE);label.setWrapText(true);}
      levels.setCycleCount(Animation.INDEFINITE);content.sceneProperty().addListener((o,a,b)->{if(b==null){levels.stop();stopTest();}else{disposed=false;levels.play();}});
    }
    void reload(String mic,String speaker){audioExecute(()->{var a=GlasAudioSession.inputDevices();var b=GlasAudioSession.outputDevices();Platform.runLater(()->{if(!disposed&&!closed){fill(inputs,a,mic);fill(outputs,b,speaker);}});});}
    void stopTest(){disposed=true;long token=testToken;testToken=-1;if(token>=0)closeTest(microphoneTests.stop(token));meter.setProgress(0);test.setDisable(false);test.setText("Проверить микрофон");}
    void resetStoppedAttempt(long token){if(!closed&&testToken==token){testToken=-1;meter.setProgress(0);test.setDisable(false);test.setText("Проверить микрофон");}}
  }
  private void stopMicrophoneTests(){for(var controls:new ArrayList<>(audioControls))if(controls.testToken>=0)controls.stopTest();}
  private boolean audioExecute(Runnable task){try{audioWorker.execute(task);return true;}catch(java.util.concurrent.RejectedExecutionException stopped){if(!closed)notice.accept("Дождитесь завершения операции со звуком");return false;}}
  private void closeTest(GlasAudioSession.MicrophoneTest owned){
    if(owned==null)return;
    // The global slot cannot be reused until this task completes; queue saturation
    // by enumeration/open jobs cannot reject this independent cleanup submission.
    microphoneCleanup.execute(()->{try{owned.close();}finally{releaseTestSlot();}});
  }
  private void releaseTestSlot(){microphoneSlot.set(false);if(closed)microphoneCleanup.shutdown();}
  private static Label processingNote(){Label label=new Label("Параметры звука применяются кнопкой ниже. Проверка микрофона автоматически завершается через 15 секунд.");label.setWrapText(true);return label;}
  private record Choice(String id,String name){@Override public String toString(){return name;}}
  private void fill(Selector<Choice> selector,List<GlasAudioSession.Device> devices,String selected){
    List<Choice> choices=new ArrayList<>();choices.add(new Choice("","По умолчанию"));for(var device:devices)choices.add(new Choice(device.id(),device.name()));
    if(!selected.isEmpty()&&choices.stream().noneMatch(c->c.id().equals(selected)))choices.add(new Choice(selected,"Выбранное устройство отключено"));
    selector.getItems().setAll(choices);selector.setValue(choices.stream().filter(c->c.id().equals(selected)).findFirst().orElse(choices.getFirst()));selector.setMaxWidth(Double.MAX_VALUE);
  }
  private static String selected(Selector<Choice> selector){return selector.getValue()==null?"":selector.getValue().id();}
  @Override public void close(){closed=true;closeTest(microphoneTests.retire());for(var controls:audioControls){controls.levels.stop();controls.stopTest();}audioControls.clear();audioWorker.shutdown();if(!microphoneSlot.get())microphoneCleanup.shutdown();try{listener.close();}catch(Exception ignored){};}
}
