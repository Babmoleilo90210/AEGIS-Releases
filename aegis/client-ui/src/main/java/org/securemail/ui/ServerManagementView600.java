package org.securemail.ui;

import javafx.application.Platform;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.management600.ManagementClient600;
import static org.securemail.ui.CommunityUi.*;

/** Embedded compact server controls. Core supplies a fresh, reauthenticated ADMIN grant per action. */
public final class ServerManagementView600 extends BorderPane implements AutoCloseable {
  private final ManagementClient600 client;private final ManagementClient600.GrantProvider grants;
  private final ThreadPoolExecutor work=new ThreadPoolExecutor(1,1,30,TimeUnit.SECONDS,new ArrayBlockingQueue<>(2),r->{Thread t=new Thread(r,"aegis-server-management-ui");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private final ComboBox<ManagementClient600.Service> service=new ComboBox<>();
  private final Label status=label("Действия проверяются сервером. Для каждой операции требуется действующее подтверждение личности.");
  private final Label result=label("");private final VBox confirmation=card();private final FlowPane controls=new FlowPane(8,8);private volatile boolean closed;private boolean busy;
  public ServerManagementView600(ManagementClient600 client,ManagementClient600.GrantProvider provider){
    this.client=Objects.requireNonNull(client);grants=Objects.requireNonNull(provider);service.getItems().setAll(ManagementClient600.Service.values());service.setValue(ManagementClient600.Service.IDENTITY);service.setMinWidth(0);service.setMaxWidth(320);service.setAccessibleText("Серверная служба");
    Button check=button("Проверить состояние",()->submit(ManagementClient600.Request.status(service.getValue())));
    Button restart=button("Перезапустить",()->confirm(ManagementClient600.Request.restart(service.getValue()),"Перезапустить службу «"+service.getValue()+"»? Текущие операции этой службы могут прерваться."));
    Button backup=button("Создать резервную копию",()->confirm(ManagementClient600.Request.backup(),"Создать зашифрованную серверную копию? Новые службы АЕГИС будут кратко остановлены. Задание выполняется асинхронно; результат нужно проверить отдельно."));
    controls.getChildren().setAll(service,check,restart,backup);confirmation.setVisible(false);confirmation.setManaged(false);
    VBox body=card(heading("Управление сервером"),label("Доступны только разрешённые службы АЕГИС. Произвольные команды и управление прежним Relay отсутствуют."),controls,status,confirmation,result,fold("Резервные копии и восстановление",label("Восстановление разрешается только по точному идентификатору копии после независимых подтверждений двух действующих администраторов. Оно создаёт отдельный проверяемый каталог и не заменяет рабочие данные автоматически. Сведения о готовности внешнего хранилища и результат задания проверяются серверным оператором.")));
    body.setMaxWidth(900);setCenter(scroll(body));
  }
  private void confirm(ManagementClient600.Request request,String question){if(busy||closed)return;confirmation.getChildren().setAll(label(question),actions(button("Подтвердить",()->{hideConfirmation();submit(request);}),button("Отмена",this::hideConfirmation)));confirmation.setManaged(true);confirmation.setVisible(true);}
  private void hideConfirmation(){confirmation.setVisible(false);confirmation.setManaged(false);confirmation.getChildren().clear();}
  private void submit(ManagementClient600.Request request){
    if(busy||closed)return;hideConfirmation();busy=true;controls.setDisable(true);status.setText("Подтверждение личности и проверка серверных полномочий…");result.setText("");
    try{work.execute(()->{try{var grant=grants.acquire(request);if(closed)throw new java.io.IOException("Раздел закрыт");var response=client.execute(request,grant);Platform.runLater(()->{if(closed)return;finish();if(response.exitCode()!=0){status.setText("Системная операция завершилась с ошибкой. Проверьте состояние службы.");return;}status.setText(request.action()==ManagementClient600.Action.BACKUP_CREATE?"Задание резервного копирования принято. Это ещё не подтверждение готовности копии.":"Сервер подтвердил результат операции.");result.setText(request.action()==ManagementClient600.Action.STATUS?readableStatus(response.output()):response.output());});}
      catch(Exception denied){Platform.runLater(()->{if(closed)return;finish();status.setText(denied instanceof ManagementClient600.Rejected||denied instanceof ManagementClient600.Busy?denied.getMessage():"Результат операции не подтверждён. Проверьте Tor, повторную аутентификацию и состояние службы перед новым действием.");});}});}catch(RejectedExecutionException full){finish();status.setText("Дождитесь завершения текущей операции.");}
  }
  private void finish(){busy=false;controls.setDisable(false);}
  static String readableStatus(String raw){
    Map<String,String> labels=Map.of("ActiveState","Состояние","SubState","Подсостояние","MainPID","Процесс","MemoryCurrent","Память, байт","TasksCurrent","Задачи");Map<String,String> states=Map.of("active","Работает","inactive","Остановлена","failed","Ошибка","activating","Запускается","deactivating","Завершается","running","Выполняется","dead","Не запущена","exited","Завершена","[not set]","Не определено");StringBuilder text=new StringBuilder();
    for(String line:raw.split("\n")){int index=line.indexOf('=');if(index<1)continue;String key=line.substring(0,index),value=line.substring(index+1);if(labels.containsKey(key)&&value.matches("[A-Za-z0-9 \\[\\]-]{0,40}"))text.append(labels.get(key)).append(": ").append((key.equals("ActiveState")||key.equals("SubState"))?states.getOrDefault(value,"Переходное состояние"):states.getOrDefault(value,value)).append('\n');}
    return text.isEmpty()?"Служба пока не предоставила показатели.":text.toString().strip();
  }
  @Override public void close(){closed=true;work.shutdownNow();client.close();if(Platform.isFxApplicationThread()){result.setText("");hideConfirmation();}else Platform.runLater(()->{result.setText("");hideConfirmation();});}
}
