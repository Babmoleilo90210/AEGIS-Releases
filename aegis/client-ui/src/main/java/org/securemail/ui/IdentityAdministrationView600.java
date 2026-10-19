package org.securemail.ui;

import java.util.Objects;
import java.util.concurrent.*;
import java.util.function.Consumer;
import javafx.application.Platform;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import org.securemail.client.ecosystemauth.IdentityAdministrationFlow600;
import org.securemail.ecosystem.protocol.IdentityAdministrationProtocol600.Operation;
import static org.securemail.ui.CommunityUi.*;

/** Fixed administrative actions inside the main window; every RPC sequence gets fresh Mail reauthentication. */
public final class IdentityAdministrationView600 extends VBox implements AutoCloseable {
  @FunctionalInterface public interface StepUp {void authenticate()throws Exception;}
  private record Reply(Object value,Exception failure){}
  private final IdentityAdministrationFlow600 flow;private final StepUp stepUp;private final OwnerAdministrationView600.Tasks tasks;private final ExecutorService owned;
  private final TextField target=field("Постоянный account ID пользователя"),role=field("Название делегируемой должности");
  private final ComboBox<Operation> operation=new ComboBox<>();private final Label status=label(""),details=label("");
  private final TextArea code=new TextArea();private final CheckBox compared=new CheckBox("Я проверил полные идентификаторы, операцию и срок запроса");
  private final Button prepare,inspect,approve,execute;private boolean busy;private volatile boolean closed;private long epoch;
  public IdentityAdministrationView600(IdentityAdministrationFlow600 flow,StepUp stepUp,OwnerAdministrationView600.Tasks tasks){this(flow,stepUp,tasks,null);}
  /** Standalone/test callers receive one bounded lane, never an unbounded background pool. */
  public IdentityAdministrationView600(IdentityAdministrationFlow600 flow,StepUp stepUp){this(flow,stepUp,null,new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(2),r->{Thread t=new Thread(r,"aegis-identity-admin-ui");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy()));}
  private IdentityAdministrationView600(IdentityAdministrationFlow600 flow,StepUp stepUp,OwnerAdministrationView600.Tasks tasks,ExecutorService owned){
    this.flow=Objects.requireNonNull(flow);this.stepUp=Objects.requireNonNull(stepUp);this.owned=owned;this.tasks=tasks!=null?tasks:(task,done)->owned.execute(()->{Object value;try{value=task.call();}catch(Exception failure){value=new Reply(null,failure);}Object result=value;Platform.runLater(()->done.accept(result));});
    setId("core600-identity-administration");setSpacing(12);setMaxWidth(960);operation.getItems().setAll(Operation.values());operation.setValue(Operation.ASSIGN);operation.setConverter(new javafx.util.StringConverter<>(){public String toString(Operation v){return v==null?"":switch(v){case ASSIGN->"Назначить администратора";case REVOKE->"Отозвать полномочия администратора";case APPROVE_RECOVERY->"Одобрить доступ после восстановления";};}public Operation fromString(String ignored){throw new UnsupportedOperationException();}});
    code.setWrapText(true);code.setPrefRowCount(5);code.setPromptText("Публичный запрос для второго администратора");code.setTextFormatter(new TextFormatter<String>(c->c.getControlNewText().length()<=4096?c:null));compared.setWrapText(true);
    prepare=button("Подготовить запрос",()->{Operation selected=operation.getValue();String account=target.getText().strip(),name=selected==Operation.ASSIGN?role.getText().strip():"";task(()->flow.prepare(selected,account,name),permit->{code.setText(permit.encode());show(permit);status.setText("Передайте публичный код независимому администратору. Затем завершите операцию здесь.");});});
    inspect=button("Проверить запрос на сервере",()->withPermit(p->task(()->{flow.inspect(p);return p;},this::show)));
    approve=button("Подтвердить вторым администратором",()->withPermit(p->task(()->{flow.approve(p);return p;},v->status.setText("Независимое подтверждение принято. Операцию завершает инициатор."))));
    execute=button("Выполнить подтверждённую операцию",()->withPermit(p->task(()->{flow.execute(p);return p;},v->{status.setText("Сервер выполнил операцию. Старые разрешения пользователя отозваны.");code.clear();details.setText("");})));
    code.textProperty().addListener((o,a,b)->{compared.setSelected(false);details.setText("");});compared.selectedProperty().addListener((o,a,b)->enable());operation.valueProperty().addListener((o,a,b)->enable());
    getChildren().setAll(heading("Управление полномочиями АЕГИС"),label("Назначение, отзыв и восстановление чувствительного доступа требуют двух независимых действующих администраторов. При отзыве оба подтверждающих администратора должны отличаться от целевого пользователя. Каждый шаг подтверждается в Почте. Приватные ключи остаются в Почте."),card(operation,target,role,prepare),card(code,inspect,details,compared,actions(approve,execute)),status);enable();
  }
  public Node node(){return this;}
  private void withPermit(Consumer<IdentityAdministrationFlow600.Permit> action){try{action.accept(IdentityAdministrationFlow600.Permit.parse(code.getText()));}catch(Exception invalid){status.setText("Публичный код повреждён, содержит лишние поля или не соответствует операции.");}}
  private void show(IdentityAdministrationFlow600.Permit p){details.setText("Инициатор: "+p.initiatorAccountId()+"\nПользователь: "+p.targetAccountId()+"\nОперация: "+operation.getConverter().toString(p.operation())+(p.roleName().isEmpty()?"":"\nДолжность: "+p.roleName())+"\nIdentity: "+p.audience()+"\nЗапрос: "+p.requestId()+"\nSHA-256 операции: "+p.payloadSha256()+"\nСрок: "+java.time.Instant.ofEpochMilli(p.expiresAt()));compared.setSelected(false);status.setText("Сервер подтвердил точное содержимое запроса. Проверьте идентификаторы перед действием.");}
  private <T>void task(Callable<T> action,Consumer<T> done){if(closed||busy)return;busy=true;enable();long captured=epoch;try{tasks.execute(()->{try{if(closed||captured!=epoch)throw new CancellationException();stepUp.authenticate();if(closed||captured!=epoch)throw new CancellationException();return new Reply(action.call(),null);}catch(Exception failure){return new Reply(null,failure);}},reply->{if(closed||captured!=epoch)return;busy=false;enable();Reply r=(Reply)reply;if(r.failure!=null){status.setText("Операция не выполнена. Проверьте соединение, полномочия, срок запроса и подтверждение в Почте.");return;}@SuppressWarnings("unchecked")T value=(T)r.value;done.accept(value);});}catch(RejectedExecutionException rejected){busy=false;enable();status.setText("Предыдущая операция ещё завершается. Повторите позже.");}}
  private void enable(){boolean disabled=busy||closed;operation.setDisable(disabled);target.setDisable(disabled);role.setDisable(disabled||operation.getValue()!=Operation.ASSIGN);code.setDisable(disabled);compared.setDisable(disabled);prepare.setDisable(disabled);inspect.setDisable(disabled);approve.setDisable(disabled||!compared.isSelected());execute.setDisable(disabled||!compared.isSelected());}
  @Override public void close(){closed=true;if(owned!=null)owned.shutdownNow();Runnable clear=()->{epoch++;target.clear();role.clear();code.clear();details.setText("");status.setText("Управление полномочиями заблокировано.");enable();};if(Platform.isFxApplicationThread())clear.run();else Platform.runLater(clear);}
}
