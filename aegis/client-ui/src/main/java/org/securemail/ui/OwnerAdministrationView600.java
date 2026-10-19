package org.securemail.ui;

import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.function.Consumer;
import javafx.scene.control.*;
import javafx.application.Platform;
import javafx.scene.layout.*;
import org.securemail.client.ecosystemauth.OwnerTransferFlow600;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import static org.securemail.ui.CommunityUi.*;

/** In-window public challenge exchange. Passwords and all root signing remain in independent Mail. */
public final class OwnerAdministrationView600 extends VBox implements AutoCloseable {
  public interface Operations {
    OwnerTransferFlow600.Request prepare(String target)throws Exception;
    OwnerTransferFlow600.Consent consent(OwnerTransferFlow600.Request request)throws Exception;
    void approve(OwnerTransferFlow600.Request request)throws Exception;
    void complete(OwnerTransferFlow600.Consent owner,OwnerTransferFlow600.Consent successor)throws Exception;
  }
  @FunctionalInterface public interface Tasks {void execute(Callable<Object> task,Consumer<Object> done);}
  private record Reply(Object value,Exception failure){}
  private final Operations operations;private final Tasks tasks;private final Consumer<Boolean> complete;
  private final Label status=label(""),detail=label("");private final TextField target=field("Постоянный account ID нового владельца");
  private final TextArea request=area("Публичный запрос передачи владельца",8192),own=area("Ваше публичное подтверждение",16384),incoming=area("Публичное подтверждение будущего владельца",16384);
  private final CheckBox compared=new CheckBox("Идентификаторы участников и намерение передать статус владельца проверены");
  private final Button sign,approve,finish,prepare;private boolean busy;private volatile boolean closed;private long generation;
  public OwnerAdministrationView600(Operations operations,Tasks tasks,Consumer<Boolean> complete){
    this.operations=Objects.requireNonNull(operations);this.tasks=Objects.requireNonNull(tasks);this.complete=Objects.requireNonNull(complete);setId("core600-owner-authority");setSpacing(12);setMaxWidth(960);own.setEditable(false);compared.setWrapText(true);
    prepare=button("Подготовить передачу",()->{String recipient=target.getText().strip();task(()->operations.prepare(recipient),value->{request.setText(value.encode());showRequest(value);});});
    Button inspect=button("Показать участников",()->{try{showRequest(OwnerTransferFlow600.Request.parse(request.getText()));}catch(Exception invalid){detail.setText("");status.setText("Публичный запрос повреждён или содержит лишние поля.");}});
    sign=button("Подтвердить в Почте",()->{try{var parsed=OwnerTransferFlow600.Request.parse(request.getText());task(()->operations.consent(parsed),value->{own.setText(value.encode());status.setText("Почта и ключ устройства подтвердили ваше участие. Передайте этот публичный код инициатору.");});}catch(Exception invalid){status.setText("Сначала проверьте публичный запрос.");}});
    approve=button("Второе административное подтверждение",()->{try{var parsed=OwnerTransferFlow600.Request.parse(request.getText());task(()->{operations.approve(parsed);return true;},value->status.setText("Сервер принял независимое административное подтверждение."));}catch(Exception invalid){status.setText("Сначала проверьте публичный запрос.");}});
    finish=button("Завершить передачу владельца",()->{try{var first=OwnerTransferFlow600.Consent.parse(own.getText());var second=OwnerTransferFlow600.Consent.parse(incoming.getText());task(()->{operations.complete(first,second);return true;},value->{status.setText("Владелец изменён. Прежние сессии обоих участников отозваны.");complete.accept(true);});}catch(Exception invalid){status.setText("Необходимы действующие подтверждения владельца и получателя для одного запроса.");}});
    request.textProperty().addListener((o,a,b)->{compared.setSelected(false);detail.setText("");own.clear();});compared.selectedProperty().addListener((o,a,b)->enable());
    getChildren().setAll(heading("Подтверждения полномочий"),label("Передачу начинает текущий Владелец АЕГИС. Оба участника подтверждают точные идентификаторы в Почте; второй действующий администратор отдельно одобряет ту же операцию. Запрос действует две минуты. Приватные ключи не экспортируются."),card(target,prepare),card(request,inspect,detail,compared,actions(sign,approve)),fold("Ваше публичное подтверждение",own),fold("Завершение владельцем",card(incoming,finish)),status);enable();
  }
  public javafx.scene.Node node(){return this;}
  private void showRequest(OwnerTransferFlow600.Request value){var t=value.transfer();detail.setText("Владелец: "+t.ownerAccountId+"\nНовый владелец: "+t.targetAccountId+"\nСервер Identity: "+t.audience+"\nДействует до: "+java.time.Instant.ofEpochMilli(t.expiresAt)+"\nПубличные поля будут проверены сервером при подтверждении. Сверьте полный account ID независимо от nickname.");compared.setSelected(false);status.setText("Проверьте участников перед подтверждением.");}
  private <T>void task(Callable<T> operation,Consumer<T> done){if(closed||busy)return;busy=true;enable();long epoch=generation;tasks.execute(()->{try{return new Reply(operation.call(),null);}catch(Exception failure){return new Reply(null,failure);}},reply->{if(closed||epoch!=generation)return;busy=false;enable();Reply result=(Reply)reply;if(result.failure!=null){status.setText("Подтверждение не выполнено. Проверьте Tor, действующие полномочия, срок запроса и повторную аутентификацию.");return;}@SuppressWarnings("unchecked")T value=(T)result.value;done.accept(value);});}
  private void enable(){prepare.setDisable(busy||closed);boolean disabled=busy||closed||!compared.isSelected();sign.setDisable(disabled);approve.setDisable(disabled);finish.setDisable(disabled);}
  private static TextArea area(String prompt,int maximum){TextArea field=new TextArea();field.setPromptText(prompt);field.setWrapText(true);field.setPrefRowCount(4);field.setTextFormatter(new TextFormatter<String>(change->change.getControlNewText().length()<=maximum?change:null));return field;}
  @Override public void close(){if(closed)return;closed=true;Runnable clear=()->{generation++;request.clear();own.clear();incoming.clear();target.clear();detail.setText("");status.setText("Подтверждения заблокированы.");enable();};if(Platform.isFxApplicationThread())clear.run();else Platform.runLater(clear);}
}
