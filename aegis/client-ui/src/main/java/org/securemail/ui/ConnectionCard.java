package org.securemail.ui;

import javafx.scene.control.*;
import javafx.scene.layout.*;
import org.securemail.client.net.ConnectionStatus;
import org.securemail.client.net.EmbeddedTor;

/** One in-window card, displaying real bootstrap instead of a guessed countdown. */
final class ConnectionCard extends VBox {
  private final Label title=new Label(),mode=new Label(),percent=new Label(),details=new Label();
  private final ProgressBar progress=new ProgressBar(0);
  private final Button retry=new Button("Повторить подключение");
  ConnectionCard(Runnable reconnect){
    super(10);getStyleClass().add("connection-card");title.setWrapText(true);mode.getStyleClass().add("muted");
    progress.setMaxWidth(Double.MAX_VALUE);details.setWrapText(true);
    TitledPane more=new TitledPane("Подробности",details);more.setExpanded(false);
    HBox line=new HBox(10,mode,percent);retry.setOnAction(e->reconnect.run());
    getChildren().addAll(title,line,progress,more,retry);
  }
  void update(ConnectionStatus.Snapshot s){
    title.setText(s.label());mode.setText(s.mode()==EmbeddedTor.Mode.DIRECT?"Direct":"Snowflake");percent.setText(s.progress()+"%");
    progress.setProgress(s.state()==ConnectionStatus.State.RELAY_CONNECTING?ProgressBar.INDETERMINATE_PROGRESS:s.progress()/100.0);
    details.setText("Состояние: "+s.state()+"\nПрямое подключение вне Tor отключено."+(s.failure()==ConnectionStatus.Failure.NONE?"":"\nДиагностический код: "+s.failure()));
    boolean canRetry=s.state()==ConnectionStatus.State.FAILED||s.state()==ConnectionStatus.State.OFFLINE||s.state()==ConnectionStatus.State.IDLE;
    retry.setVisible(canRetry);retry.setManaged(canRetry);retry.setDisable(s.busy());
  }
}
