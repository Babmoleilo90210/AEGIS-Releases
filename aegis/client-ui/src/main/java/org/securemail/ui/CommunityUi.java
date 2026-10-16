package org.securemail.ui;

import com.google.gson.*;
import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

/** One bounded asynchronous RPC lane. Server responses, never UI role flags, authorize operations. */
final class CommunityUi implements AutoCloseable {
  @FunctionalInterface interface Rpc { JsonObject call(String action,JsonObject data)throws Exception; }
  @FunctionalInterface interface StepUp { String authenticate(char[] password,String otp)throws Exception; }
  final ThemeManager themes;final Rpc rpc;final Consumer<String> openLink;final StepUp stepUp;
  private final ThreadPoolExecutor work=new ThreadPoolExecutor(1,1,30,TimeUnit.SECONDS,new ArrayBlockingQueue<>(16),r->{Thread t=new Thread(r,"aegis-community-ui");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
  private volatile boolean closed;
  CommunityUi(ThemeManager themes,Rpc rpc,StepUp stepUp,Consumer<String> openLink){this.themes=themes;this.rpc=rpc;this.stepUp=stepUp;this.openLink=openLink;}
  void call(String action,JsonObject args,Label status,Consumer<JsonObject> done){
    if(closed)return;if(status!=null)status.setText("Выполняется…");
    try{work.execute(()->{try{JsonObject result=rpc.call(action,args.deepCopy());Platform.runLater(()->{if(!closed){if(status!=null)status.setText("");done.accept(result);}});}catch(Exception failure){Platform.runLater(()->{if(!closed&&status!=null)status.setText(message(failure));});}});}catch(RejectedExecutionException full){if(status!=null)status.setText("Очередь заполнена. Дождитесь завершения операции.");}
  }
  void prepared(String action,Callable<JsonObject> prepare,Label status,Consumer<JsonObject> done){task(()->rpc.call(action,prepare.call()),status,done);}
  <T> void task(Callable<T> action,Label status,Consumer<T> done){if(closed)return;if(status!=null)status.setText("Выполняется…");try{work.execute(()->{try{T result=action.call();Platform.runLater(()->{if(!closed){if(status!=null)status.setText("");done.accept(result);}});}catch(Exception failed){Platform.runLater(()->{if(!closed&&status!=null)status.setText(message(failed));});}});}catch(RejectedExecutionException full){if(status!=null)status.setText("Очередь заполнена. Дождитесь завершения операции.");}}
  void privileged(String action,JsonObject args,Label status,Consumer<JsonObject> done){
    PasswordField password=new PasswordField();password.setPromptText("Пароль аккаунта");password.setMaxWidth(340);Label hint=label("Повторно подтвердите вход для административного действия. Пароль не передаётся общему серверу.");TextField otp=field("Одноразовый код администратора (8 цифр)");VBox form=new VBox(8,hint,password,otp);InWindowDialog<String> dialog=new InWindowDialog<>();dialog.setTitle("Подтверждение личности");dialog.getDialogPane().setContent(form);ButtonType confirm=new ButtonType("Подтвердить",ButtonBar.ButtonData.OK_DONE);dialog.getDialogPane().getButtonTypes().setAll(confirm,ButtonType.CANCEL);dialog.setResultConverter(b->b==confirm?password.getText():null);themes.apply(dialog.getDialogPane());Optional<String> result=dialog.showAndWait();password.clear();if(result.isEmpty())return;char[] secret=result.get().toCharArray();String oneTime=otp.getText().trim();otp.clear();if(status!=null)status.setText("Проверка личности…");
    try{work.execute(()->{try{String token=stepUp.authenticate(secret,oneTime);JsonObject data=args.deepCopy();data.addProperty("stepUp",token);JsonObject response=rpc.call(action,data);Platform.runLater(()->{if(!closed){if(status!=null)status.setText("");done.accept(response);}});}catch(Exception failed){Platform.runLater(()->{if(!closed&&status!=null)status.setText(message(failed));});}finally{Arrays.fill(secret,'\0');}});}catch(RejectedExecutionException busy){Arrays.fill(secret,'\0');if(status!=null)status.setText("Дождитесь завершения предыдущей операции.");}
  }
  static String message(Exception error){String value=(error instanceof org.securemail.client.community.CommunityClient.Rejected rejected?rejected.code():Objects.toString(error.getMessage(),"")).toUpperCase(Locale.ROOT);if(value.contains("FACTOR_UNCONFIGURED"))return "Для управления настройте одноразовые коды администратора через защищённую процедуру регистрации.";if(value.contains("FACTOR")||value.contains("OTP"))return "Проверьте одноразовый код. Уже использованный код повторно не принимается.";if(value.contains("DENIED")||value.contains("FORBIDDEN")||value.contains("PERMISSION"))return "Недостаточно действующих полномочий. Обновите разрешения или обратитесь к администрации.";if(value.contains("CONFLICT")||value.contains("REVISION"))return "Материал уже изменён. Обновите страницу перед повторным сохранением.";if(value.contains("NOT_FOUND"))return "Материал недоступен.";if(value.contains("STEP")||value.contains("AUTH"))return "Подтвердите личность повторно.";if(value.contains("CONFIG")||value.contains("ДОВЕРЕННЫЙ ONION-СЕРВЕР")||value.contains("ОБЩЕЙ СИСТЕМЫ ПОВРЕЖДЕНЫ"))return "Общий сервер не настроен. Откройте «Настройки → Сеть, Tor и обновления».";return "Общий сервер недоступен или отклонил запрос. Проверьте Tor, адрес сервера и введённые данные.";}
  static boolean administrative(JsonObject me){if(str(me,"isAdmin").equals("true"))return true;Set<String> privileged=Set.of("ORG_APPROVE","GLOBAL_ROLES_MANAGE","GLOBAL_ADMIN_MANAGE","VERIFICATION_MANAGE","LEVELS_MANAGE","AGENT_MANAGE","SOURCE_MANAGE","WORKER_MANAGE","ADMIN_AUDIT","ADMIN_CONTENT");for(JsonElement permission:array(me,"permissions"))if(privileged.contains(permission.getAsString()))return true;return false;}
  static JsonObject obj(Object... pairs){JsonObject value=new JsonObject();for(int i=0;i<pairs.length;i+=2){Object item=pairs[i+1];String key=pairs[i].toString();if(item instanceof JsonElement json)value.add(key,json);else if(item instanceof Number n)value.addProperty(key,n);else if(item instanceof Boolean b)value.addProperty(key,b);else if(item!=null)value.addProperty(key,item.toString());}return value;}
  static String str(JsonObject obj,String key){JsonElement value=obj.get(key);return value==null||value.isJsonNull()?"":value.isJsonPrimitive()?value.getAsString():value.toString();}
  static long number(JsonObject obj,String key){try{return obj.get(key).getAsLong();}catch(Exception invalid){return 0;}}
  static JsonArray array(JsonObject obj,String key){JsonElement value=obj.get(key);return value!=null&&value.isJsonArray()?value.getAsJsonArray():new JsonArray();}
  static List<JsonObject> items(JsonObject obj,String key){List<JsonObject> values=new ArrayList<>();for(JsonElement item:array(obj,key))if(item.isJsonObject())values.add(item.getAsJsonObject());return values;}
  static JsonArray strings(String value){JsonArray result=new JsonArray();for(String item:value.split("[,\\n]"))if(!item.isBlank())result.add(item.trim());return result;}
  static Label label(String text){Label value=new Label(text);value.setWrapText(true);value.setMinWidth(0);value.setMaxWidth(Double.MAX_VALUE);value.setMinHeight(Region.USE_PREF_SIZE);return value;}
  static Label heading(String text){Label value=label(text);value.getStyleClass().add("heading");return value;}
  static TextField field(String prompt){TextField value=new TextField();value.setPromptText(prompt);value.setAccessibleText(prompt);value.setMinWidth(0);return value;}
  static Button button(String title,Runnable action){Button value=new Button(title);value.getStyleClass().add("wrapped-action");value.setWrapText(true);value.setMinHeight(36);value.setMinWidth(0);value.setOnAction(e->action.run());value.parentProperty().addListener((o,a,b)->{value.maxWidthProperty().unbind();if(b instanceof Region region)value.maxWidthProperty().bind(region.widthProperty());});return value;}
  static FlowPane actions(Node... values){FlowPane row=new FlowPane(8,8,values);row.setMinWidth(0);return row;}
  static VBox card(Node... values){VBox box=new VBox(10,values);box.setMinWidth(0);box.setPadding(new Insets(14));box.getStyleClass().add("settings-card");return box;}
  static ScrollPane scroll(Node body){ScrollPane page=new ScrollPane(body);page.setFitToWidth(true);page.setMinWidth(0);return page;}
  static ComboBox<JsonObject> choice(String prompt){ComboBox<JsonObject> box=new ComboBox<>();box.setPromptText(prompt);box.setAccessibleText(prompt);box.setMinWidth(0);box.setMaxWidth(Double.MAX_VALUE);box.setConverter(new javafx.util.StringConverter<>(){public String toString(JsonObject item){return item==null?"":title(item);}public JsonObject fromString(String ignored){return null;}});return box;}
  static ListView<JsonObject> list(String empty){ListView<JsonObject> result=new ListView<>();result.setMinSize(100,100);result.setPrefHeight(220);result.setPlaceholder(label(empty));result.setCellFactory(v->new ListCell<>(){protected void updateItem(JsonObject item,boolean blank){super.updateItem(item,blank);setText(null);setGraphic(blank||item==null?null:label(title(item)));}});return result;}
  static String title(JsonObject item){for(String name:List.of("title","name","nickname","question","kind","id")){String text=str(item,name);if(!text.isBlank())return text;}return "Материал";}
  static void fill(ListView<JsonObject> list,JsonObject data,String... keys){for(String key:keys)if(data.has(key)){list.getItems().setAll(items(data,key));return;}list.getItems().clear();}
  static TitledPane fold(String title,Node content){TitledPane result=new TitledPane(title,content);result.setExpanded(false);result.setMinWidth(0);result.setWrapText(true);return result;}
  @Override public void close(){closed=true;work.shutdownNow();}
}
