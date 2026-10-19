package org.securemail.ui;

import java.io.*;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.*;
import javafx.application.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import org.securemail.client.net.EmbeddedTor;
import org.securemail.client.safeweb600.*;
import org.securemail.client.maintenance600.RuntimeLease600;

/** Standalone Взор manager: no ClientSession, LocalStore, account capability, or Core death subscription. */
public final class VzorApp600 {
  private static final AtomicReference<VzorBootstrap600> BOOT=new AtomicReference<>();
  // Held until kernel process exit, including cleanup after JavaFX returns.
  private static RuntimeLease600.Lease runtimeLease;
  private VzorApp600(){}
  public static void main(String[] args){
    if(args.length!=0)return;
    RuntimeLease600.Lease startup=null;
    try{
      startup=RuntimeLease600.running();
      VzorBootstrap600 bootstrap=VzorBootstrap600.read(System.in,Duration.ofSeconds(5));BOOT.set(bootstrap);runtimeLease=startup;startup=null;
      try{Application.launch(Window.class);}
      catch(RuntimeException|LinkageError unavailable){VzorBootstrap600 pending=BOOT.getAndSet(null);if(pending!=null)try{pending.acknowledge(System.out,VzorBootstrap600.Reply.UI_UNAVAILABLE);}catch(IOException ignored){} }
      finally{VzorBootstrap600 pending=BOOT.getAndSet(null);if(pending!=null)pending.close();}
    }catch(IOException invalid){/* Direct/unauthorized entry does not create any browser state or UI. */}
    finally{if(startup!=null)try{startup.close();}catch(IOException ignored){/* Kernel releases the rejected startup lease on exit. */}}
  }
  public static final class Window extends Application {
    private VzorManager600 manager;private VzorView view;private ThemeManager themes;
    private Thread hook;private final AtomicBoolean shutdown=new AtomicBoolean();
    @Override public void start(Stage stage){
      VzorBootstrap600 bootstrap=BOOT.getAndSet(null);if(bootstrap==null){Platform.exit();return;}
      VzorState600 state=null;
      try{
        state=VzorState600.openProcessState();manager=new VzorManager600(state);state=null;
        Platform.setImplicitExit(false);themes=new ThemeManager();themes.initialize();
        Label network=new Label("Отдельный Tor подготовки Взора: не подключён");network.setWrapText(true);network.getStyleClass().add("muted");
        ToggleGroup route=new ToggleGroup();RadioButton direct=new RadioButton("Tor"),snowflake=new RadioButton("Snowflake");direct.setToggleGroup(route);snowflake.setToggleGroup(route);direct.setSelected(true);
        Runnable connect=()->manager.connect(snowflake.isSelected()?EmbeddedTor.Mode.SNOWFLAKE:EmbeddedTor.Mode.DIRECT,p->Platform.runLater(()->network.setText("Отдельный Tor подготовки Взора: "+p+"%")),s->Platform.runLater(()->network.setText(s)));
        view=new VzorView(stage,themes,manager.config(),manager.browser(),manager.operations(),manager::downloadTorReady,connect,List::of,
          ignored->network.setText("Загрузки Взора остаются отдельными. Импорт выполняется вручную в открытом приложении «Письма»."),network::setText);
        view.address(bootstrap.address());hideArchiveImport(view.node());
        VBox body=new VBox(8,new FlowPane(8,8,new Label("Подготовка официального пакета"),direct,snowflake),network,view.node());body.setPadding(new javafx.geometry.Insets(12));VBox.setVgrow(view.node(),Priority.ALWAYS);themes.apply(body);
        stage.setScene(new Scene(body,900,720));stage.setMinWidth(640);stage.setMinHeight(480);stage.setTitle("АЕГИС — Взор");stage.setOnCloseRequest(event->{event.consume();requestClose(stage,network);});
        hook=new Thread(()->{try{if(manager!=null)manager.close();}catch(IOException ignored){}},"aegis-vzor-own-shutdown");Runtime.getRuntime().addShutdownHook(hook);
        stage.show();bootstrap.acknowledge(System.out,VzorBootstrap600.Reply.READY);
        // The original Core button is the explicit user action. Initial manager setup is asynchronous.
        Node launch=view.node().lookup("#vzor-open");if(launch instanceof Button open){
          AtomicBoolean first=new AtomicBoolean();Runnable initial=()->{if(!open.isDisabled()&&first.compareAndSet(false,true))open.fire();};
          open.disabledProperty().addListener((o,a,b)->{if(!b)Platform.runLater(initial);});Platform.runLater(initial);
        }
      }catch(Exception|LinkageError error){
        VzorBootstrap600.Reply reply=error instanceof VzorFailure600 known&&known.code()==VzorFailure600.Code.ALREADY_RUNNING?VzorBootstrap600.Reply.ALREADY_RUNNING:VzorBootstrap600.Reply.STATE_UNAVAILABLE;
        try{bootstrap.acknowledge(System.out,reply);}catch(IOException ignored){}bootstrap.close();
        VzorState600 unused=state;Thread.startVirtualThread(()->{try{if(manager!=null)manager.close();else if(unused!=null)unused.close();}catch(IOException ignored){}Platform.exit();});
      }
    }
    private static void hideArchiveImport(Node node){
      if(node instanceof Button button&&button.getText().equals("Импортировать в архив")){button.setVisible(false);button.setManaged(false);}
      if(node instanceof Parent parent)for(Node child:parent.getChildrenUnmodifiable())hideArchiveImport(child);
      if(node instanceof TitledPane titled&&titled.getContent()!=null)hideArchiveImport(titled.getContent());
      if(node instanceof ScrollPane scroll&&scroll.getContent()!=null)hideArchiveImport(scroll.getContent());
    }
    private void requestClose(Stage stage,Label status){
      if(!shutdown.compareAndSet(false,true))return;if(view!=null)view.close();status.setText("Завершение собственных процессов Взора…");stage.getScene().getRoot().setDisable(true);
      Thread.startVirtualThread(()->{
        try{manager.close();Platform.runLater(Platform::exit);}
        catch(IOException error){shutdown.set(false);Platform.runLater(()->{stage.getScene().getRoot().setDisable(false);status.setText(VzorFailure600.safeMessage(error));});}
      });
    }
    @Override public void stop(){
      if(view!=null)view.close();
      // stop() can also follow Platform.exit outside the normal Close button path.
      // Never drop the runtime lease or hook while an owned browser may still use JARs.
      if(manager!=null){Thread cleanup=new Thread(()->{
        try{manager.close();if(hook!=null)try{Runtime.getRuntime().removeShutdownHook(hook);}catch(IllegalStateException ending){/* JVM hook already owns final cleanup. */}}
        catch(IOException incomplete){System.err.println("АЕГИС: завершение собственных процессов Взора не подтверждено.");}
      },"aegis-vzor-final-cleanup");cleanup.setDaemon(false);cleanup.start();}
      if(themes!=null)themes.close();
    }
  }
}
