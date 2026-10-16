package org.securemail.ui;

import com.google.gson.*;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import static org.securemail.ui.CommunityUi.*;

/** Explicit permissions and clearance are independent; server rejects escalation and inheritance cycles. */
final class RoleBuilder {
  private final VBox body=new VBox(10);
  RoleBuilder(CommunityUi api,String scope,Label status){
    ListView<JsonObject> roles=list("Нет созданных ролей");TextField name=field("Название роли"),parents=field("Родительские роли: идентификаторы через запятую"),permissions=field("Полномочия через запятую"),clearance=field("Уровень допуска (число)");clearance.setText("0");final JsonObject[] selected={null};String[] after={""};
    java.util.function.Consumer<Boolean> load=more->api.call("org.roles.list",obj("scope",scope,"after",more?after[0]:"","limit",30),status,response->{if(!more)roles.getItems().clear();roles.getItems().addAll(items(response,response.has("roles")?"roles":"items"));after[0]=str(response,"nextAfter");});
    roles.getSelectionModel().selectedItemProperty().addListener((o,a,b)->{selected[0]=b;if(b!=null){name.setText(str(b,"name"));parents.setText(join(array(b,"parents")));permissions.setText(join(array(b,"permissions")));clearance.setText(str(b,"clearance"));}});
    Button save=button("Сохранить роль",()->{int level;try{level=Integer.parseInt(clearance.getText().trim());}catch(NumberFormatException invalid){status.setText("Укажите числовой уровень допуска.");return;}JsonObject args=obj("scope",scope,"name",name.getText(),"parents",strings(parents.getText()),"permissions",strings(permissions.getText()),"clearance",level);String action="admin.roles.create",kind="ROLE_CREATE";if(selected[0]!=null){args.addProperty("id",str(selected[0],"id"));args.addProperty("revision",number(selected[0],"revision"));action="admin.roles.update";kind="ROLE_UPDATE";}execute(api,scope,action,kind,args,status,()->load.accept(false));});
    Button delete=button("Удалить выбранную роль",()->{JsonObject chosen=selected[0];if(chosen==null)return;InWindowAlert confirm=new InWindowAlert(Alert.AlertType.CONFIRMATION,"Удалить роль и связанные назначения? Сервер повторно проверит полномочия.",ButtonType.OK,ButtonType.CANCEL);api.themes.apply(confirm.getDialogPane());if(confirm.showAndWait().orElse(ButtonType.CANCEL)!=ButtonType.OK)return;execute(api,scope,"admin.roles.delete","ROLE_DELETE",obj("id",str(chosen,"id"),"revision",number(chosen,"revision")),status,()->load.accept(false));});
    body.getChildren().addAll(heading("Конструктор ролей"),label("Уровень допуска сам по себе не предоставляет права публикации или администрирования."),roles,actions(button("Обновить роли",()->load.accept(false)),button("Ещё роли",()->{if(!after[0].isEmpty())load.accept(true);}),button("Новая роль",()->{selected[0]=null;roles.getSelectionModel().clearSelection();name.clear();parents.clear();permissions.clear();clearance.setText("0");})),name,parents,permissions,clearance,actions(save,delete));load.accept(false);
  }
  private void execute(CommunityUi api,String scope,String action,String kind,JsonObject payload,Label status,Runnable refresh){if(!scope.equals("GLOBAL")){api.privileged(action,payload,status,result->refresh.run());return;}api.privileged("admin.critical.request",obj("kind",kind,"payload",payload),status,request->{TextField requestId=field("Одобренный запрос второго администратора");requestId.setText(str(request,"id"));body.getChildren().add(card(label("Другой администратор должен проверить и подтвердить запрос."),label("Отпечаток: "+str(request,"digest")),requestId,button("Выполнить одобренное изменение",()->{JsonObject args=payload.deepCopy();args.addProperty("requestId",requestId.getText());api.privileged(action,args,status,result->refresh.run());})));});}
  Node node(){return body;}
  static String join(JsonArray values){java.util.List<String> result=new java.util.ArrayList<>();for(JsonElement value:values)if(value.isJsonPrimitive())result.add(value.getAsString());return String.join(", ",result);}
}
