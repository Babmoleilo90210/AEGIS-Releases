package org.securemail.ui.ecosystem;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import org.securemail.client.ecosystem.*;

/** Real process controls; uses the existing Appearance Engine CSS tokens, never a replacement theme. */
public final class CoreLauncherView extends VBox implements AutoCloseable {
  public enum IndependentApplication { VZOR, PERSONAL_OBSIDIAN }
  @FunctionalInterface public interface BeforeLaunch{void prepare(ComponentId component)throws Exception;}
  private final BeforeLaunch beforeLaunch;
  private final DesktopProcessBroker broker;
  private final Consumer<IndependentApplication> independent;
  private final EnumMap<ComponentId,Label> status=new EnumMap<>(ComponentId.class),badges=new EnumMap<>(ComponentId.class);
  private final ThreadPoolExecutor worker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(4),r->{Thread t=new Thread(r,"aegis-launcher-work");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final Label notice=new Label("Почта и Глас открываются отдельными защищёнными процессами.");
  public CoreLauncherView(DesktopProcessBroker broker,Consumer<IndependentApplication> independent) {
    this(broker,independent,component->{});
  }
  public CoreLauncherView(DesktopProcessBroker broker,Consumer<IndependentApplication> independent,BeforeLaunch beforeLaunch){
    this.broker=Objects.requireNonNull(broker);this.independent=Objects.requireNonNull(independent);this.beforeLaunch=Objects.requireNonNull(beforeLaunch);
    setSpacing(12);setPadding(new Insets(16));setFillWidth(true);setMaxWidth(960);
    Label title=new Label("Приложения АЕГИС");title.getStyleClass().add("section-title");notice.setWrapText(true);notice.getStyleClass().add("muted");
    TilePane cards=new TilePane();cards.setHgap(12);cards.setVgap(12);cards.setPrefColumns(2);cards.setMinWidth(0);cards.setMaxWidth(Double.MAX_VALUE);cards.prefTileWidthProperty().bind(javafx.beans.binding.Bindings.createDoubleBinding(()->Math.max(80,(getWidth()-getPadding().getLeft()-getPadding().getRight()-12*(getWidth()<600?0:1))/(getWidth()<600?1:2)),widthProperty(),paddingProperty()));
    cards.getChildren().addAll(ownedCard(ComponentId.MAIL),ownedCard(ComponentId.GLAS),independentCard(IndependentApplication.VZOR,"Взор","Официальный Tor Browser"),independentCard(IndependentApplication.PERSONAL_OBSIDIAN,"Личная библиотека","Официальный Obsidian"));
    cards.prefColumnsProperty().bind(javafx.beans.binding.Bindings.when(widthProperty().lessThan(600)).then(1).otherwise(2));
    getChildren().addAll(title,notice,cards);
    for(var value:broker.statuses())accept(value);
  }
  private VBox ownedCard(ComponentId component) {
    Label name=new Label(component.label()),badge=new Label();name.setWrapText(true);name.setMinWidth(0);name.getStyleClass().add("section-title");badge.getStyleClass().add("notification-badge");badge.setVisible(false);badge.setManaged(false);badges.put(component,badge);
    // Badge occupies a separate top-left layout cell rather than overlapping a click target.
    HBox heading=new HBox(8,badge,name);Label state=new Label("Не запущено");state.setWrapText(true);state.getStyleClass().add("muted");status.put(component,state);
    Button open=new Button("Открыть"),close=new Button("Закрыть");open.setMinHeight(36);close.setMinHeight(36);open.setMinWidth(0);close.setMinWidth(0);open.setMaxWidth(Double.MAX_VALUE);close.setMaxWidth(Double.MAX_VALUE);HBox.setHgrow(open,Priority.ALWAYS);HBox.setHgrow(close,Priority.ALWAYS);
    open.setOnAction(e->work(()->{beforeLaunch.prepare(component);return broker.launch(component);}));close.setOnAction(e->work(()->{broker.stop(component);return null;}));
    VBox box=new VBox(10,heading,state,new HBox(8,open,close));box.getStyleClass().add("card");box.setPadding(new Insets(14));box.setMinWidth(0);box.setMaxWidth(Double.MAX_VALUE);return box;
  }
  private VBox independentCard(IndependentApplication app,String name,String subtitle) {
    Label title=new Label(name),description=new Label(subtitle);title.setWrapText(true);title.setMinWidth(0);title.getStyleClass().add("section-title");description.setWrapText(true);description.getStyleClass().add("muted");Button button=new Button("Открыть");button.setMinHeight(36);
    button.setOnAction(e->work(()->{independent.accept(app);return null;}));VBox card=new VBox(10,title,description,button);card.getStyleClass().add("card");card.setPadding(new Insets(14));card.setMinWidth(0);return card;
  }
  /** Safe to call from the broker reader; history and notification bodies are never passed to the launcher. */
  public void accept(DesktopProcessBroker.Status value) {
    if(!Platform.isFxApplicationThread()){Platform.runLater(()->accept(value));return;}
    Label label=status.get(value.component()),badge=badges.get(value.component());if(label==null)return;
    label.setText(value.reason());int count=value.notifications();badge.setText(count>99?"99+":Integer.toString(count));badge.setVisible(count>0);badge.setManaged(count>0);
  }
  public void locked(){notice.setText("АЕГИС заблокирован. Для открытия приложений подтвердите вход.");}
  private void work(Callable<?> task) {
    try{worker.execute(()->{try{task.call();}catch(Exception failure){Platform.runLater(()->notice.setText("Не удалось открыть приложение. Проверьте вход и установленный комплект."));}});}
    catch(RejectedExecutionException busy){notice.setText("Дождитесь завершения текущего действия.");}
  }
  /** View disposal does not close official detached third-party applications. Core owns broker shutdown separately. */
  @Override public void close(){worker.shutdownNow();}
}
