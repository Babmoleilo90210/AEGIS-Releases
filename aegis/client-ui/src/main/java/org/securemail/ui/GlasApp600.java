package org.securemail.ui;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import javafx.application.*;
import javafx.geometry.Insets;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import org.securemail.client.AppPaths;
import org.securemail.client.ecosystem.*;
import org.securemail.client.ecosystemauth.CorePublicConfig600;
import org.securemail.client.net.TorTransport;
import org.securemail.client.security.SystemSecrets;
import org.securemail.client.voice.*;
import org.securemail.client.voice600.*;

/** Actual standalone voice UI using the existing Opus/audio/TLS service. Mail state is never opened here. */
public final class GlasApp600 extends Application {
  private record Launch(ComponentLease lease,CorePublicConfig600 config,LocalIpc.Channel channel,Consumer<GlasApp600> started){}
  private static Launch launch;static void prepare(ComponentLease lease,CorePublicConfig600 config,LocalIpc.Channel channel,Consumer<GlasApp600> started){launch=new Launch(lease,config,channel,started);}
  private final ThreadPoolExecutor worker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(8),r->{Thread t=new Thread(r,"glas-application-work");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final CompletableFuture<Void> locked=new CompletableFuture<>(),stopped=new CompletableFuture<>();private final ThemeManager themes=new ThemeManager();private volatile boolean isLocked,closing;private Stage stage;private BorderPane root;private Label status;private GlasView view;private volatile GlasState600 state;private volatile VoiceCallService calls;private volatile GlasOnionTransport600 transport;private AutoCloseable changes;private long lastActivity;
  @Override public void start(Stage stage)throws Exception{
    if(launch==null)throw new IOException("Откройте Глас через главное АЕГИС");this.stage=stage;themes.initialize();root=new BorderPane();root.getStyleClass().add("in-window-page");root.setPadding(new Insets(12));status=new Label("Подготовка защищённой голосовой связи…");status.setWrapText(true);root.setCenter(status);themes.apply(root);Scene scene=new Scene(root,900,760);stage.setScene(scene);stage.setTitle("Глас — АЕГИС");stage.setMinWidth(640);stage.setMinHeight(480);InWindowDialog.bind(stage,root);stage.setOnCloseRequest(e->{e.consume();shutdown();});scene.addEventFilter(javafx.scene.input.InputEvent.ANY,event->{long now=System.nanoTime();if(!isLocked&&now-lastActivity>1_000_000_000L){lastActivity=now;send(LocalIpc.Packet.command(LocalIpc.Type.USER_ACTIVITY));}});stage.show();launch.started().accept(this);worker.execute(this::initialize);
  }
  private void initialize(){
    GlasState600 opened=null;GlasOnionTransport600 route=null;VoiceCallService service=null;
    try{if(isLocked||closing)throw new IOException("Глас заблокирован");var grant=GlasGrant600.decode(launch.lease().auxiliaryPublic());byte[] secret=launch.lease().proofPrivatePkcs8();PrivateKey appKey;try{appKey=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(secret));}finally{Arrays.fill(secret,(byte)0);}
      Path directory=AppPaths.root().resolve("glas600").resolve(grant.delegation().accountId());opened=new GlasState600(directory,grant,appKey,SystemSecrets.current(directory));TorTransport tor=new TorTransport("127.0.0.1",launch.config().socksPort());var signaling=new GlasSignalingClient600(GlasSignalingClient600.Config.load(),launch.config(),new String(launch.lease().capability(),java.nio.charset.StandardCharsets.US_ASCII),appKey,tor);route=new GlasOnionTransport600(opened,grant,appKey,signaling,tor);service=new VoiceCallService(opened,route);
      if(isLocked||closing)throw new IOException("Глас заблокирован");state=opened;transport=route;calls=service;VoiceCallService active=service;GlasState600 contacts=opened;changes=active.listen(()->{send(LocalIpc.Packet.count(active.snapshot().state()==VoiceCallService.State.INCOMING?1:0));if(isLocked)Platform.runLater(this::renderLocked);});
      route.status(ok->Platform.runLater(()->{if(!isLocked&&!closing)status.setText(ok?"Tor подключён":"Защищённый маршрут недоступен. Звонок остановлен.");}));route.start(service,launch.config().socksPort()+1,AppPaths.root().resolve("core600/tor/control_auth_cookie"));
      Platform.runLater(()->{if(isLocked||closing)return;view=new GlasView(active,contacts::contacts,peer->{},themes,worker,nickname->{Label avatar=new Label(nickname.substring(0,1).toUpperCase(Locale.ROOT));avatar.getStyleClass().add("avatar-placeholder");avatar.setMinSize(32,32);return avatar;},message->{var dialog=new InWindowDialog<ButtonType>();dialog.initOwner(stage);dialog.setTitle("Глас");dialog.setContentText(message);dialog.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);dialog.show();});root.setTop(status);root.setCenter(view.node());});
    }catch(Exception|LinkageError failure){if(route!=null)route.close();if(service!=null)service.close();if(opened!=null)opened.close();state=null;calls=null;transport=null;Platform.runLater(()->{if(!isLocked&&!closing){status.setText("Не удалось подготовить Глас. Проверьте Tor, доверенный сервер сигнализации и разблокировку KWallet / хранилища ОС.");root.setCenter(status);}});}
  }
  private void send(LocalIpc.Packet packet){try{if(launch!=null)launch.channel().send(packet);}catch(IOException ignored){lock();}}
  public CompletableFuture<Void> lock(){if(isLocked)return locked;isLocked=true;Platform.runLater(()->{if(view!=null){view.close();view=null;}InWindowDialog.closeAll(stage);renderLocked();worker.getQueue().clear();try{worker.execute(()->{try{VoiceCallService service=calls;if(service!=null)service.lockRestricted();GlasState600 opened=state;if(opened!=null)opened.lockHistory();locked.complete(null);}catch(Exception failed){locked.completeExceptionally(failed);}});}catch(RejectedExecutionException e){locked.completeExceptionally(e);}});return locked;}
  private void renderLocked(){if(!isLocked||closing)return;root.getChildren().clear();Label title=new Label("Глас заблокирован");title.getStyleClass().add("heading");VBox limited=new VBox(12,title);limited.setPadding(new Insets(18));VoiceCallService service=calls;var snapshot=service==null?null:service.snapshot();
    if(snapshot!=null&&snapshot.direction()==VoiceCallService.Direction.INCOMING&&snapshot.busy()){
      Label peer=new Label(snapshot.contact().nickname()),callStatus=new Label(snapshot.status());peer.getStyleClass().add("heading");callStatus.setWrapText(true);limited.getChildren().addAll(peer,callStatus);
      if(snapshot.state()==VoiceCallService.State.INCOMING){Button accept=new Button("Принять"),decline=new Button("Отклонить");accept.getStyleClass().add("primary");accept.setOnAction(e->{accept.setDisable(true);lockedIncoming(true);});decline.setOnAction(e->lockedIncoming(false));limited.getChildren().add(new HBox(8,accept,decline));}
      else {Button end=new Button("Завершить");end.setOnAction(e->service.hangup());limited.getChildren().add(end);if(snapshot.state()==VoiceCallService.State.SECURE){Button mic=new Button(snapshot.microphoneEnabled()?"Выключить микрофон":"Включить микрофон");mic.setOnAction(e->service.setMicrophoneEnabled(!service.snapshot().microphoneEnabled()));limited.getChildren().add(mic);}}
    }else{Label message=new Label("Доступен только входящий вызов. Для истории, контактов и исходящих звонков подтвердите вход в главном АЕГИС.");message.setWrapText(true);limited.getChildren().add(message);}root.setCenter(limited);
  }
  public void lockedIncoming(boolean accept){VoiceCallService active=calls;if(!isLocked||active==null)return;var snapshot=active.snapshot();if(snapshot.state()!=VoiceCallService.State.INCOMING||snapshot.direction()!=VoiceCallService.Direction.INCOMING)return;if(!accept){active.decline(snapshot.callId());return;}try{worker.execute(()->{try{GlasOnionTransport600 route=transport;if(route==null)throw new IOException("Маршрут недоступен");route.verifyCurrentPeer(snapshot.contact(),true);if(isLocked&&!closing)active.accept(snapshot.callId());}catch(Exception denied){active.decline(snapshot.callId());}});}catch(RejectedExecutionException busy){active.decline(snapshot.callId());}}
  private void closeResources()throws Exception{if(changes!=null){changes.close();changes=null;}GlasOnionTransport600 route=transport;transport=null;if(route!=null)route.close();VoiceCallService active=calls;calls=null;if(active!=null)active.close();GlasState600 opened=state;state=null;if(opened!=null)opened.close();send(LocalIpc.Packet.count(0));}
  public CompletableFuture<Void> shutdown(){if(closing)return stopped;closing=true;Platform.runLater(()->{if(view!=null){view.close();view=null;}root.getChildren().clear();stage.hide();try{worker.execute(()->{try{closeResources();stopped.complete(null);}catch(Exception failed){stopped.completeExceptionally(failed);}finally{worker.shutdown();Platform.runLater(()->{themes.close();Platform.exit();});}});}catch(RejectedExecutionException failed){stopped.completeExceptionally(failed);}});return stopped;}
  @Override public void stop(){shutdown();}
}
