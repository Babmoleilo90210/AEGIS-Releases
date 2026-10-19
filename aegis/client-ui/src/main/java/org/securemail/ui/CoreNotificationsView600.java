package org.securemail.ui;

import com.google.gson.*;
import javafx.application.Platform;
import javafx.animation.PauseTransition;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.nio.file.Path;
import org.securemail.client.ecosystemauth.CoreNotificationPreferences600;
import org.securemail.client.ecosystemauth.CoreNotificationArrivals600;
import static org.securemail.ui.CommunityUi.*;

/** Core notifications contain only server-ACL-filtered shared-system events.
 * Private Mail/Glas content stays inside those independent applications. */
public final class CoreNotificationsView600 extends BorderPane implements AutoCloseable {
    private static final int PAGE=50,MAX_ITEMS=500;
    private static final Map<String,String>CATEGORIES=new LinkedHashMap<>();
    static {CATEGORIES.put("ORGANIZATION","Организации");CATEGORIES.put("ROLE","Роли и полномочия");CATEGORIES.put("VERIFICATION","Подтверждения статуса");CATEGORIES.put("NEWS","Новости");CATEGORIES.put("MODERATION","Модерация");CATEGORIES.put("EVENT_CHANGED","Изменения мероприятий");CATEGORIES.put("EVENT_REGISTERED","Регистрация на мероприятия");CATEGORIES.put("LIBRARY","Библиотека");CATEGORIES.put("AGENT","ИИ-редактор");CATEGORIES.put("SECURITY","Безопасность");}
    private record Reply(JsonObject data,String error){}
    private record LocalReply(CoreNotificationPreferences600.Settings settings,boolean success){}
    private final CommunityUi api;private final Label status=label("");private final VBox entries=new VBox(8),preferences=new VBox(8);
    private final LinkedHashMap<String,JsonObject>items=new LinkedHashMap<>();private final ComboBox<String>filter=new ComboBox<>();
    private final Button more=button("Загрузить ещё",()->load(true));private final AtomicLong lifecycle=new AtomicLong(),listing=new AtomicLong();
    private final ScheduledExecutorService refresh=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-core-notification-refresh");t.setDaemon(true);return t;});
    private final CoreNotificationPreferences600 localStore;private CoreNotificationPreferences600.Settings local=CoreNotificationPreferences600.Settings.defaults();
    private final CoreNotificationArrivals600 arrivals=new CoreNotificationArrivals600();private final Object presentationGate=new Object();private final Runnable sound;
    private final Consumer<CoreNotificationArrivals600.Presentation> presentationObserver;
    private final CheckBox localSound=new CheckBox("Звуковой сигнал"),localBanner=new CheckBox("Сообщение внутри окна"),localPrivacy=new CheckBox("Скрывать заголовки во всплывающем сообщении");
    private final Label localStatus=label(""),bannerText=label("");private final FlowPane banner=actions(bannerText,button("Скрыть",this::hideBanner));
    private final PauseTransition bannerTimeout=new PauseTransition(javafx.util.Duration.seconds(8));private boolean localReady;
    private String cursor="";private boolean busy;private volatile boolean closed;
    public CoreNotificationsView600(CommunityUi api,Runnable openApplications,Runnable openUpdates){
        this(api,openApplications,openUpdates,CoreNotificationPreferences600.defaultFile(),()->java.awt.Toolkit.getDefaultToolkit().beep(),ignored->{});
    }
    /** Presentation backend seam: production uses the OS default beep; tests observe requests without claiming audible native output. */
    public CoreNotificationsView600(CommunityUi api,Runnable openApplications,Runnable openUpdates,Path preferencesFile,Runnable sound,Consumer<CoreNotificationArrivals600.Presentation> observer){
        this.localStore=new CoreNotificationPreferences600(preferencesFile);this.sound=Objects.requireNonNull(sound);this.presentationObserver=Objects.requireNonNull(observer);
        this.api=Objects.requireNonNull(api);Objects.requireNonNull(openApplications);Objects.requireNonNull(openUpdates);setId("core600-notifications");
        filter.getItems().add("Все события");filter.getItems().addAll(CATEGORIES.values());filter.setValue("Все события");filter.setMinWidth(0);filter.setMaxWidth(Double.MAX_VALUE);filter.setOnAction(e->render());
        Button reload=button("Обновить",()->load(false));reload.setId("core600-notifications-refresh");more.setId("core600-notifications-more");
        banner.setId("notification600-banner");banner.getStyleClass().add("settings-card");banner.setPadding(new javafx.geometry.Insets(10));bannerText.setId("notification600-banner-text");bannerText.prefWidthProperty().bind(javafx.beans.binding.Bindings.max(120,widthProperty().subtract(150)));banner.setVisible(false);banner.setManaged(false);bannerTimeout.setOnFinished(e->hideBanner());
        setTop(new VBox(8,card(heading("Центр уведомлений"),actions(filter,reload),status),banner));TitledPane settings=fold("Категории уведомлений",preferences);settings.setId("core600-notification-preferences");
        localSound.setId("notification600-local-sound");localBanner.setId("notification600-local-banner");localPrivacy.setId("notification600-local-privacy");for(CheckBox option:List.of(localSound,localBanner,localPrivacy)){option.setWrapText(true);option.setDisable(true);option.setOnAction(e->saveLocalSettings());}
        TitledPane presentation=fold("Показ и звук",new VBox(8,localSound,localBanner,localPrivacy,label("Звук зависит от системных настроек. Сообщения отображаются только в открытом разблокированном АЕГИС."),localStatus));presentation.setId("notification600-local-preferences");
        setCenter(scroll(new VBox(12,card(label("Личные письма и звонки доступны в отдельных приложениях. Их содержание не передаётся в этот центр."),actions(button("Письма и Глас",openApplications),button("Проверенные обновления",openUpdates))),presentation,settings,entries,more)));
        loadLocalSettings();load(false);loadSettings();refresh.scheduleWithFixedDelay(()->Platform.runLater(()->{if(!closed)load(false);}),15,15,TimeUnit.SECONDS);
    }
    public Node node(){return this;}
    private void request(String action,JsonObject args,Consumer<JsonObject>done,Consumer<String>failure){
        long epoch=lifecycle.get();api.task(()->{try{return new Reply(api.rpc.call(action,args.deepCopy()),"");}catch(Exception error){return new Reply(null,CommunityUi.message(error));}},null,result->{if(closed||epoch!=lifecycle.get())return;if(result.data()!=null)done.accept(result.data());else failure.accept(result.error());});
    }
    private void load(boolean append){
        if(closed||busy||append&&(cursor.isEmpty()||items.size()>=MAX_ITEMS))return;busy=true;long version=listing.incrementAndGet();String start=append?cursor:"";status.setText("Проверка доступных уведомлений…");more.setDisable(true);
        request("content.notifications.list",obj("limit",PAGE,"cursor",start),page->{if(version!=listing.get())return;busy=false;if(!append)items.clear();List<JsonObject>received=items(page,"items");
            List<CoreNotificationArrivals600.Notice> observed=new ArrayList<>();for(JsonObject event:received){String id=str(event,"id");if(items.size()>=MAX_ITEMS)break;if(!id.matches("[a-f0-9-]{36}")||!CATEGORIES.containsKey(str(event,"category")))continue;items.put(id,event.deepCopy());notice(event).ifPresent(observed::add);}
            cursor=str(page,"nextCursor");if(cursor.isEmpty()&&received.size()==PAGE)cursor=str(received.getLast(),"id");render();status.setText(items.size()>=MAX_ITEMS?"Показаны первые 500 событий. Уточните категорию или обновите список.":"Доступных событий: "+items.size());
            arrivals.observe(observed,append,local).ifPresent(event->{if(localReady)present(event);});
        },error->{if(version!=listing.get())return;busy=false;cursor="";items.clear();hideBanner();render();status.setText(error+" Содержимое списка скрыто до новой проверки.");});
    }
    private void render(){
        if(closed)return;entries.getChildren().clear();for(JsonObject event:items.values()){String category=CATEGORIES.get(str(event,"category"));if(!filter.getValue().equals("Все события")&&!filter.getValue().equals(category))continue;
            boolean read=event.has("read")&&event.get("read").isJsonPrimitive()&&event.get("read").getAsBoolean();Label title=label(str(event,"title"));title.setId("notification600-title-"+str(event,"id"));VBox row=card(label(category+(read?" · Прочитано":" · Новое")),title);row.setId("notification600-"+str(event,"id"));
            if(!read){Button mark=button("Отметить прочитанным",()->markRead(event));mark.setId("notification600-read-"+str(event,"id"));row.getChildren().add(mark);}entries.getChildren().add(row);
        }
        if(entries.getChildren().isEmpty())entries.getChildren().add(label("Нет доступных событий в выбранной категории."));more.setDisable(busy||cursor.isEmpty()||items.size()>=MAX_ITEMS);more.setManaged(!cursor.isEmpty()&&items.size()<MAX_ITEMS);more.setVisible(more.isManaged());
    }
    private void markRead(JsonObject event){request("content.notifications.read",obj("id",str(event,"id")),answer->{if(answer.has("read")&&answer.get("read").getAsBoolean()){JsonObject current=items.get(str(event,"id"));if(current!=null)current.addProperty("read",true);render();status.setText("Событие отмечено прочитанным.");}},error->{items.remove(str(event,"id"));hideBanner();render();status.setText(error);});}
    private void loadSettings(){request("content.notifications.settings",obj(),this::settings,error->status.setText(error));}
    private void settings(JsonObject values){preferences.getChildren().clear();Map<String,Boolean>enabled=new HashMap<>();for(JsonObject item:items(values,"items"))if(CATEGORIES.containsKey(str(item,"category")))enabled.put(str(item,"category"),item.has("enabled")&&item.get("enabled").getAsBoolean());
        for(var category:CATEGORIES.entrySet()){CheckBox setting=new CheckBox(category.getValue());setting.setId("notification600-preference-"+category.getKey());setting.setWrapText(true);setting.setSelected(enabled.getOrDefault(category.getKey(),true));setting.setOnAction(e->{boolean selected=setting.isSelected();setting.setDisable(true);request("content.notifications.settings",obj("category",category.getKey(),"enabled",selected),answer->{settings(answer);status.setText("Настройки уведомлений сохранены сервером.");},error->{setting.setSelected(!selected);setting.setDisable(false);status.setText(error);});});preferences.getChildren().add(setting);}
    }
    private static Optional<CoreNotificationArrivals600.Notice> notice(JsonObject event){try{
        JsonElement read=event.get("read"),created=event.get("createdAt");if(read==null||!read.isJsonPrimitive()||!read.getAsJsonPrimitive().isBoolean()||created==null||!created.isJsonPrimitive()||!created.getAsJsonPrimitive().isNumber())return Optional.empty();
        return Optional.of(new CoreNotificationArrivals600.Notice(str(event,"id"),read.getAsBoolean(),created.getAsBigDecimal().longValueExact(),str(event,"title")));
    }catch(IllegalArgumentException|ArithmeticException|IllegalStateException invalid){return Optional.empty();}}
    private void loadLocalSettings(){long epoch=lifecycle.get();api.task(()->{try{return new LocalReply(localStore.load(),true);}catch(Exception failed){return new LocalReply(CoreNotificationPreferences600.Settings.defaults(),false);}},null,result->{if(closed||epoch!=lifecycle.get())return;local=result.settings();localReady=true;showLocalSettings();localStatus.setText(result.success()?"Параметры показа хранятся только на этом устройстве.":"Файл параметров не прочитан. Действуют безопасные настройки; исходный файл сохранён.");});}
    private void showLocalSettings(){localSound.setSelected(local.sound());localBanner.setSelected(local.banner());localPrivacy.setSelected(local.hideDetails());for(CheckBox option:List.of(localSound,localBanner,localPrivacy))option.setDisable(false);}
    private void saveLocalSettings(){if(closed||!localReady)return;var requested=new CoreNotificationPreferences600.Settings(localSound.isSelected(),localBanner.isSelected(),localPrivacy.isSelected());local=local.restrictWith(requested);hideBanner();for(CheckBox option:List.of(localSound,localBanner,localPrivacy))option.setDisable(true);long epoch=lifecycle.get();
        api.task(()->{try{localStore.save(requested);return new LocalReply(requested,true);}catch(Exception failure){return new LocalReply(requested,false);}},null,result->{if(closed||epoch!=lifecycle.get())return;if(result.success())local=result.settings();showLocalSettings();localStatus.setText(result.success()?"Параметры показа сохранены на устройстве.":"Не удалось сохранить параметры. Более строгие ограничения действуют до выхода.");});
    }
    private void present(CoreNotificationArrivals600.Presentation event){synchronized(presentationGate){if(closed||!localReady)return;
        if(event.banner()){bannerText.setText(event.text());banner.setManaged(true);banner.setVisible(true);bannerTimeout.playFromStart();}
        if(event.sound())try{sound.run();}catch(RuntimeException|LinkageError unavailable){localStatus.setText("Системный звуковой сигнал недоступен.");}
        try{presentationObserver.accept(event);}catch(RuntimeException ignored){localStatus.setText("Дополнительный обработчик уведомления недоступен.");}
    }}
    private void hideBanner(){bannerTimeout.stop();bannerText.setText("");banner.setManaged(false);banner.setVisible(false);}
    /** Shared CommunityUi is owned by Core. This page only invalidates its own callbacks and visible data. */
    public void lock(){close();}
    @Override public void close(){synchronized(presentationGate){if(closed)return;closed=true;arrivals.close();lifecycle.incrementAndGet();listing.incrementAndGet();refresh.shutdownNow();}Runnable clear=()->{hideBanner();items.clear();entries.getChildren().clear();preferences.getChildren().clear();for(CheckBox option:List.of(localSound,localBanner,localPrivacy))option.setDisable(true);localReady=false;cursor="";more.setDisable(true);status.setText("Центр уведомлений заблокирован.");};if(Platform.isFxApplicationThread())clear.run();else Platform.runLater(clear);}
}
