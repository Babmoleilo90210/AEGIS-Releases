package org.securemail.ui;

import com.google.gson.*;
import javafx.application.Platform;
import javafx.geometry.Orientation;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import org.securemail.client.library600.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import static org.securemail.ui.CommunityUi.*;

/** Actual Library HTTP view. Core injects freshly acquired LIBRARY capability/proof connection.
 * Plaintext stays in this inert JavaFX viewer unless the server explicitly authorizes offline export.
 * Protected Obsidian cannot be launched without an installed OS-boundary implementation. */
public final class LibraryLauncherView600 extends BorderPane implements AutoCloseable {
    @FunctionalInterface public interface Provider { Connection acquire() throws Exception; }
    @FunctionalInterface public interface LiveGuard { boolean active() throws Exception; }
    public record Connection(HttpLibraryTransport600 transport,LibraryConnector600 connector,LiveGuard guard) {
        public Connection {Objects.requireNonNull(transport);Objects.requireNonNull(connector);Objects.requireNonNull(guard);}
    }
    public interface ProtectedLauncher extends AutoCloseable {
        /** Installed implementation must verify process/profile/OS isolation and fail closed. */
        void open(Path authorizedProjection) throws Exception;
        @Override void close() throws Exception;
    }
    private record Snapshot(Map<String,Object>material,LibraryReadPermit600 permit,Map<String,Object>rights){}
    private final Button create=button("Создать",()->compose(null,"NOTE"));
    private final List<JsonObject>createOrganizations=new ArrayList<>();private boolean canCreateGlobal;
    private final Provider provider;
    private final ProtectedLauncher launcher;
    private final Consumer<String> openSafeLink;
    private final ThreadPoolExecutor worker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(8),r->{Thread t=new Thread(r,"aegis-library-view-work");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    private final ScheduledThreadPoolExecutor poll=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"aegis-library-view-lease");t.setDaemon(true);return t;});
    private final ScheduledExecutorService expiry=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-library-local-expiry");t.setDaemon(true);return t;});
    private final ThreadPoolExecutor materialCleanup=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(8),r->{Thread t=new Thread(r,"aegis-library-material-cleanup");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    private final Label status=label("Получение разрешения Библиотеки…"),limitNotice=label("");
    private final TreeView<JsonObject> tree=new TreeView<>();
    private final TextField query=field("Поиск материалов");
    private final VBox preview=new VBox(10);
    private final KnowledgeGraph graph=new KnowledgeGraph(this::open);
    private final List<JsonObject> nodes=new ArrayList<>(),edges=new ArrayList<>();
    private final java.util.concurrent.atomic.AtomicReference<LibraryReadPermit600> readPermit=new java.util.concurrent.atomic.AtomicReference<>();
    private final AtomicInteger selection=new AtomicInteger();
    private final AtomicBoolean disposing=new AtomicBoolean();
    private final CompletableFuture<Void> cleanup=new CompletableFuture<>();
    private final SplitPane panes=new SplitPane();
    private final StackPane narrow=new StackPane();
    private final ScrollPane right=scroll(preview);
    private String narrowMode="catalog";
    private volatile Connection connection;
    private volatile boolean closed,locked;
    private String graphCursor="",lockedCursor="";
    private boolean first=true;
    public LibraryLauncherView600(Provider provider,ProtectedLauncher launcher,Consumer<String> openSafeLink) {
        this.provider=Objects.requireNonNull(provider);this.launcher=launcher;Objects.requireNonNull(openSafeLink);this.openSafeLink=url->{if(url.startsWith("aegis-library:")){try{String id=url.substring("aegis-library:".length());if(!UUID.fromString(id).toString().equals(id))throw new IllegalArgumentException();open(obj("id",id,"title","Материал"));}catch(IllegalArgumentException invalid){status.setText("Некорректная внутренняя ссылка.");}}else openSafeLink.accept(url);};poll.setRemoveOnCancelPolicy(true);
        setId("library600-page");preview.setPadding(new javafx.geometry.Insets(12));tree.setShowRoot(false);tree.setMinWidth(100);tree.setPrefWidth(200);
        tree.setCellFactory(v->new TreeCell<>(){protected void updateItem(JsonObject item,boolean empty){super.updateItem(item,empty);setText(empty||item==null?null:title(item));setGraphic(empty||item==null||!item.has("locked")?null:lockGlyph());setAccessibleText(empty||item==null?"":(item.has("locked")?"Закрыто: ":"")+title(item));setWrapText(true);setMinWidth(0);setPrefWidth(Math.max(80,tree.getWidth()-26));}
            @Override public void updateSelected(boolean selected){super.updateSelected(selected);setStyle("-fx-text-fill:-aegis-text;-fx-background-color:"+(selected?"-aegis-control":"transparent")+";");}
        });
        tree.getSelectionModel().selectedItemProperty().addListener((o,a,b)->{if(b!=null&&b.getValue()!=null)open(b.getValue());});
        MenuButton more=new MenuButton("Ещё");more.setMinHeight(36);more.getStyleClass().add("wrapped-action");
        for(var item:List.<Map.Entry<String,Runnable>>of(Map.entry("Загрузить ещё",()->load(true)),Map.entry("Сбросить вид",graph::reset),Map.entry("Показать каталог",()->mode("catalog")),Map.entry("Показать граф",()->mode("graph")),Map.entry("Показать материал",()->mode("preview")),Map.entry("Заблокировать",this::lock))){MenuItem action=new MenuItem(item.getKey());action.setOnAction(e->item.getValue().run());more.getItems().add(action);}
        create.setDisable(true);create.setId("library600-create");query.setPrefColumnCount(10);
        status.managedProperty().bind(status.textProperty().isNotEmpty());status.visibleProperty().bind(status.managedProperty());limitNotice.managedProperty().bind(limitNotice.textProperty().isNotEmpty());limitNotice.visibleProperty().bind(limitNotice.managedProperty());
        tree.setStyle("-fx-background-color:-aegis-panel;-fx-border-width:0;");
        setTop(card(heading("Библиотека"),actions(query,button("Найти",()->load(false)),create,more),status,limitNotice));
        right.setPrefWidth(340);right.setMinWidth(160);panes.setOrientation(Orientation.HORIZONTAL);panes.getItems().setAll(tree,graph,right);panes.setDividerPositions(.2,.7);setCenter(panes);
        widthProperty().addListener((o,a,b)->responsive(b.doubleValue()));
        if(launcher==null)preview.getChildren().setAll(label("Закрытые материалы открываются внутри АЕГИС. Защищённый Obsidian требует проверенной изоляции ОС."));
        execute(()->{Connection value=provider.acquire();synchronized(this){if(closed||locked){value.transport().close();if(locked)value.connector().revoke();else value.connector().close();throw new java.io.IOException("View closed");}connection=value;}return value;},value->{status.setText("Разрешение приложения подтверждено сервером.");load(false);startPolling();});
    }
    public Node node(){return this;}
    private void startPolling(){
        expiry.scheduleWithFixedDelay(()->{Connection c=connection;if(c==null||closed||locked)return;LibraryReadPermit600 permit=readPermit.get();try{c.connector().maintain();if(permit!=null)permit.requireCurrent();}catch(Exception expired){invalidateRead(permit,"Срок доступа к материалу истёк. Требуется новая проверка.");}},1,1,TimeUnit.SECONDS);
        poll.scheduleWithFixedDelay(()->{
        Connection c=connection;if(c==null||closed||locked)return;LibraryReadPermit600 current=readPermit.get();
        try{if(!c.guard().active()){Platform.runLater(this::lock);return;}
            if(current!=null){Map<String,Object>fresh=c.transport().verifiedRequest("library600.read.authorize",Map.of("id",current.materialId()));LibraryReadPermit600 renewed=current.renewVerified(fresh,java.time.Clock.systemUTC(),System::nanoTime);if(readPermit.compareAndSet(current,renewed))current.revoke();}
        }catch(LibraryReadPermit600.SnapshotChanged changed){invalidateRead(current,"Материал или полномочия изменены. Откройте документ заново.");}
         catch(HttpLibraryTransport600.Rejected denied){invalidateRead(current,"Доступ к материалу изменён. Откройте разрешённый материал заново.");}
         catch(Exception unavailable){if(current==null){Platform.runLater(this::lock);return;}try{current.requireOffline();Platform.runLater(()->{if(!closed&&!locked)status.setText("Проверка сервера недоступна. Действует только ранее разрешённая копия.");});}catch(Exception expired){invalidateRead(current,"Срок доступа к материалу истёк. Требуется новая серверная проверка.");}}
    },2,5,TimeUnit.SECONDS);}
    private void invalidateRead(LibraryReadPermit600 expected,String reason){
        if(expected!=null&&!readPermit.compareAndSet(expected,null)||expected==null&&readPermit.get()!=null)return;if(expected!=null)expected.revoke();selection.incrementAndGet();
        Platform.runLater(()->{if(!closed&&!locked){nodes.clear();edges.clear();graph.data(List.of(),List.of());tree.setRoot(null);preview.getChildren().setAll(label(reason));status.setText(reason);}});
        try{Connection c=connection;if(c!=null)c.connector().revokeProjections();}catch(Exception failed){Platform.runLater(()->{if(!closed&&!locked)status.setText("Содержимое скрыто; очистка локальной копии ещё не подтверждена.");});}
        try{materialCleanup.execute(()->{try{if(launcher!=null)launcher.close();}catch(Exception failed){Platform.runLater(()->{if(!closed&&!locked)status.setText("Содержимое скрыто; остановка защищённого процесса ещё не подтверждена.");});}});}catch(RejectedExecutionException busy){Platform.runLater(()->{if(!closed&&!locked)status.setText("Содержимое скрыто; дождитесь подтверждения остановки защищённого процесса.");});}
    }
    /** Switching a document revokes its native view too. Cleanup runs independently of a stalled RPC/open. */
    private CompletableFuture<Void> clearSelection(){
        LibraryReadPermit600 previous=readPermit.getAndSet(null);if(previous!=null)previous.revoke();selection.incrementAndGet();preview.getChildren().clear();
        CompletableFuture<Void> finished=new CompletableFuture<>();
        try{materialCleanup.execute(()->{try{if(launcher!=null)launcher.close();Connection c=connection;if(c!=null)c.connector().clearPlaintextProjections();finished.complete(null);}catch(Exception error){finished.completeExceptionally(error);}});}catch(RejectedExecutionException stopped){finished.completeExceptionally(stopped);}return finished;
    }
    @SuppressWarnings("unchecked") private Map<String,Object>rpc(String operation,Map<String,Object>args)throws Exception {
        Connection c=connection;if(c==null||locked||closed)throw new IllegalStateException("Библиотека заблокирована");
        Map<String,Object>envelope=c.transport().verifiedRequest("library600."+operation,args);
        if(!(envelope.get("data")instanceof Map<?,?>result))throw new IllegalStateException("Некорректный ответ");return (Map<String,Object>)result;
    }
    private void mode(String selected){narrowMode=selected;responsive(getWidth());}
    private void responsive(double width){
        if(width<750){panes.getItems().clear();Node shown=switch(narrowMode){case "graph"->graph;case "preview"->right;default->tree;};narrow.getChildren().setAll(shown);setCenter(narrow);}
        else{narrow.getChildren().clear();panes.getItems().setAll(tree,graph,right);panes.setDividerPositions(.22,.67);setCenter(panes);}
    }
    private void load(boolean more){
        if(connection==null||locked||closed)return;
        if(more&&!first&&graphCursor.isEmpty()&&lockedCursor.isEmpty()){status.setText("Все доступные страницы получены.");return;}
        if(nodes.size()>=500&&more){limitNotice.setText("Показана часть библиотеки: предел 500 узлов. Уточните поиск.");return;}
        if(!more){graphCursor="";lockedCursor="";nodes.clear();edges.clear();first=true;clearSelection();}
        String gc=graphCursor,lc=lockedCursor,text=query.getText();boolean getGraph=first||!gc.isEmpty(),getLocked=first||!lc.isEmpty();first=false;
        execute(()->{
            Map<String,Object>g=getGraph?rpc("graph",Map.of("cursor",gc,"limit",50,"query",text)):Map.of("nodes",List.of(),"edges",List.of(),"nextCursor","");
            Map<String,Object>c=getLocked?rpc("catalog",Map.of("lockedCursor",lc,"limit",50)):Map.of("locked",List.of(),"nextLockedCursor","");return List.of(g,c,rpc("capabilities",Map.of()));
        },pages->{
            JsonObject capabilities=json(pages.get(2));canCreateGlobal=capabilities.get("canCreateGlobal").getAsBoolean();createOrganizations.clear();createOrganizations.addAll(items(capabilities,"organizations"));create.setDisable(!canCreateGlobal&&createOrganizations.isEmpty());JsonObject g=json(pages.get(0)),catalog=json(pages.get(1));graphCursor=str(g,"nextCursor");lockedCursor=str(catalog,"nextLockedCursor");
            Map<String,JsonObject>known=new LinkedHashMap<>();for(JsonObject n:nodes)known.put(str(n,"id"),n);
            for(JsonObject n:items(g,"nodes"))if(known.size()<500)known.put(str(n,"id"),n);
            for(JsonObject n:items(catalog,"locked")){String name=str(n,"displayTitle");if(!text.isBlank()&&!name.toLowerCase(Locale.ROOT).contains(text.toLowerCase(Locale.ROOT)))continue;JsonObject locked=n.deepCopy();locked.addProperty("id",str(n,"opaqueId"));locked.addProperty("title",name);locked.addProperty("type","LOCKED");if(known.size()<500)known.put(str(locked,"id"),locked);}
            nodes.clear();nodes.addAll(known.values());Set<String>edgeIds=new HashSet<>();for(JsonObject e:edges)edgeIds.add(str(e,"id"));for(JsonObject e:items(g,"edges"))if(edges.size()<2000&&edgeIds.add(str(e,"id"))&&known.containsKey(str(e,"from"))&&known.containsKey(str(e,"to")))edges.add(e);
            graph.data(nodes,edges);TreeItem<JsonObject>root=new TreeItem<>(obj("title","Материалы"));for(JsonObject n:nodes)root.getChildren().add(new TreeItem<>(n));tree.setRoot(root);
            limitNotice.setText(nodes.size()>=500||edges.size()>=2000?"Показана часть графа. Уточните поиск.":"");status.setText("Доступных узлов: "+nodes.size());
        });
    }
    private void open(JsonObject item){
        mode("preview");CompletableFuture<Void> cleared=clearSelection();
        if(item.has("locked")){TextArea reason=new TextArea();reason.setPromptText("Зачем вам нужен доступ");reason.setPrefRowCount(3);preview.getChildren().setAll(heading(title(item)),label("Содержание закрыто. Доступно только разрешённое название."),reason,button("Запросить доступ",()->{String message=reason.getText();execute(()->rpc("access.request",Map.of("opaqueId",str(item,"opaqueId"),"reason",message)),r->status.setText("Заявка сохранена сервером. Права выдаются отдельным решением администрации."));}));return;}
        int version=selection.get();execute(()->{cleared.get(30,TimeUnit.SECONDS);if(version!=selection.get())throw new CancellationException();String id=str(item,"id");Map<String,Object>body=rpc("read",Map.of("id",id));Connection c=connection;if(c==null)throw new IllegalStateException();Map<String,Object>authorization=c.transport().verifiedRequest("library600.read.authorize",Map.of("id",id));LibraryReadPermit600 permit=LibraryReadPermit600.acceptVerified(id,((Number)body.get("revision")).longValue(),(String)body.get("body"),authorization,java.time.Clock.systemUTC(),System::nanoTime);@SuppressWarnings("unchecked")Map<String,Object>rights=(Map<String,Object>)rpc("permissions",Map.of("id",id)).get("rights");return new Snapshot(body,permit,rights);},value->{if(version!=selection.get()){value.permit().revoke();return;}LibraryReadPermit600 old=readPermit.getAndSet(value.permit());if(old!=null)old.revoke();JsonObject material=json(value.material());material.add("clientRights",new Gson().toJsonTree(value.rights()));
            Button obsidian=button("Открыть в защищённом Obsidian",()->project(str(material,"id")));obsidian.setDisable(launcher==null);
            preview.getChildren().setAll(heading(title(material)),label(typeName(str(material,"type"))+" · "+state(str(material,"state"))+" · версия "+str(material,"revision")),DocumentEditor.render(str(material,"body"),openSafeLink),actions(button("Предложить изменение",()->edit(material)),button("Предложения",()->proposals(material)),button("История",()->history(material)),button("Связи",()->links(material)),management(material)),obsidian);
            if(launcher==null)preview.getChildren().add(label("Запуск защищённого Obsidian заблокирован до проверки изоляции ОС. Личный Obsidian остаётся независимым."));
        });
    }
    private void project(String id){int version=selection.get();execute(()->{Connection c=connection;if(c==null||launcher==null)throw new IllegalStateException();Path file=c.connector().project(id);if(version!=selection.get()){c.connector().clearPlaintextProjections();throw new CancellationException();}launcher.open(file);if(version!=selection.get()){launcher.close();c.connector().clearPlaintextProjections();throw new CancellationException();}return true;},done->status.setText("Передана только разрешённая сервером локальная проекция."));}
    private void projectOffline(String id){int version=selection.get();execute(()->{LibraryReadPermit600 permit=readPermit.get();if(permit==null||!permit.materialId().equals(id))throw new java.io.IOException("Нет действующего допуска");permit.requireOffline();Connection c=connection;if(c==null||launcher==null)throw new IllegalStateException();Path file=c.connector().projectOffline(id);permit.requireOffline();if(version!=selection.get()){c.connector().clearPlaintextProjections();throw new CancellationException();}launcher.open(file);if(version!=selection.get()){launcher.close();c.connector().clearPlaintextProjections();throw new CancellationException();}return true;},done->status.setText("Открыта ранее разрешённая копия в пределах текущего допуска."));}
    private void discovery(JsonObject material){TextField account=field("Account ID получателя"),display=field("Разрешённое название без закрытых сведений");display.setText(title(material));preview.getChildren().setAll(heading("Доступ по названию"),label("Название выдаётся отдельно и не открывает текст. Одобрение заявки само по себе не выдаёт READ."),account,display,actions(button("Разрешить название",()->{Map<String,Object>args=Map.of("materialId",str(material,"id"),"subject",account.getText().strip(),"displayTitle",display.getText());execute(()->rpc("discovery.grant",args),result->status.setText("Разрешено только название. Содержание остаётся под ACL."));}),button("Отозвать название",()->{Map<String,Object>args=Map.of("materialId",str(material,"id"),"subject",account.getText().strip());execute(()->rpc("discovery.revoke",args),result->status.setText("Разрешение названия отозвано."));}),button("Заявки",()->accessRequests(material,"",false)),button("К материалу",()->open(material))));}
    private void accessRequests(JsonObject material,String cursor,boolean more){execute(()->rpc("access.list",Map.of("materialId",str(material,"id"),"cursor",cursor,"limit",25)),result->{if(!more)preview.getChildren().setAll(heading("Заявки доступа"),button("Назад",()->discovery(material)));for(JsonObject request:items(json(result),"items")){VBox row=card(label(str(request,"subject")),label(str(request,"reason")),label(state(str(request,"state"))));if(str(request,"state").equals("REQUESTED"))row.getChildren().add(actions(button("Одобрить заявку",()->accessDecision(material,str(request,"id"),"APPROVE")),button("Отклонить",()->accessDecision(material,str(request,"id"),"REJECT"))));preview.getChildren().add(row);}String next=str(json(result),"nextCursor");if(!next.isEmpty())preview.getChildren().add(button("Следующие заявки",()->accessRequests(material,next,true)));});}
    private void accessDecision(JsonObject material,String id,String decision){execute(()->rpc("access.decide",Map.of("requestId",id,"decision",decision)),result->{accessRequests(material,"",false);status.setText("Решение сохранено. Правила доступа изменяются отдельным уполномоченным действием.");});}
    private void compose(JsonObject material,String initialType){
        mode("preview");if(material==null)clearSelection();TextField name=field("Название материала");name.setId("library600-edit-title");if(material!=null)name.setText(title(material));
        DocumentEditor editor=new DocumentEditor(openSafeLink);if(material!=null)editor.text(str(material,"body"));ComboBox<JsonObject>kind=choice("Тип материала");kind.setId("library600-edit-type");
        for(String type:List.of("NOTE","ARTICLE","DOCUMENT","PDF","IMAGE","VIDEO","PERSON","ORGANIZATION","TOPIC"))kind.getItems().add(obj("id",type,"title",typeName(type)));for(JsonObject item:kind.getItems())if(str(item,"id").equals(initialType))kind.setValue(item);
        ComboBox<JsonObject>organization=choice("Область публикации");if(canCreateGlobal)organization.getItems().add(obj("id","","title","Общая библиотека"));organization.getItems().addAll(createOrganizations);if(!organization.getItems().isEmpty())organization.setValue(organization.getItems().getFirst());
        TextField level=field("Минимальный уровень допуска"),rights=field("Необходимые разрешения через запятую"),users=field("Разрешённые account ID через запятую"),orgs=field("Разрешённые организации через запятую");level.setText("0");CheckBox offline=new CheckBox("Разрешить локальную копию при наличии права экспорта");
        if(material!=null&&material.has("policy")){JsonObject policy=material.getAsJsonObject("policy");level.setText(str(policy,"minimumLevel"));rights.setText(join(policy,"permissions"));users.setText(join(policy,"users"));orgs.setText(join(policy,"organizations"));offline.setSelected(policy.has("offlineAllowed")&&policy.get("offlineAllowed").getAsBoolean());}
        TitledPane policy=new TitledPane("Доступ и локальные копии",new VBox(8,level,rights,users,orgs,offline));policy.setExpanded(false);policy.setAnimated(false);policy.setVisible(material==null||right(material,"ACCESS_MANAGE"));policy.setManaged(policy.isVisible());
        Button save=button(material==null?"Создать черновик":"Сохранить новую версию",()->{
            String body=editor.text(),title=name.getText();Map<String,Object>args=new LinkedHashMap<>();args.put("title",title);args.put("body",body);
            if(material==null){if(kind.getValue()==null||organization.getValue()==null){status.setText("Выберите тип и область публикации.");return;}args.put("type",str(kind.getValue(),"id"));args.put("organization",str(organization.getValue(),"id"));}
            else{args.put("id",str(material,"id"));args.put("revision",number(material,"revision"));}
            try{if(policy.isVisible())args.put("policy",Map.of("minimumLevel",Integer.parseInt(level.getText().strip()),"permissions",split(rights.getText()),"users",split(users.getText()),"organizations",split(orgs.getText()),"offlineAllowed",offline.isSelected()));}catch(RuntimeException invalid){status.setText("Проверьте уровень допуска и правила доступа.");return;}
            execute(()->rpc(material==null?"create":"update",args),result->{JsonObject changed=json(result);status.setText("Черновик сохранён на сервере. Публикация — отдельное действие.");open(changed);});
        });save.setId("library600-save-draft");preview.getChildren().setAll(heading(material==null?"Новый материал":"Редактирование материала"),name);
        if(material==null)preview.getChildren().addAll(actions(kind,organization));preview.getChildren().addAll(editor.node(),policy,actions(save,button("Отмена",()->{if(material!=null)open(material);else load(false);})));
    }
    private static List<String>split(String value){if(value.isBlank())return List.of();return Arrays.stream(value.split(",")).map(String::strip).filter(s->!s.isEmpty()).distinct().toList();}
    private static String join(JsonObject value,String key){if(!value.has(key)||!value.get(key).isJsonArray())return "";List<String>out=new ArrayList<>();for(JsonElement item:value.getAsJsonArray(key))out.add(item.getAsString());return String.join(", ",out);}
    private static boolean right(JsonObject material,String permission){return material.has("clientRights")&&material.getAsJsonObject("clientRights").has(permission)&&material.getAsJsonObject("clientRights").get(permission).getAsBoolean();}
    private static String typeName(String type){return switch(type){case "NOTE"->"Заметка";case "ARTICLE"->"Статья";case "DOCUMENT"->"Документ";case "PDF"->"PDF-документ";case "IMAGE"->"Изображение";case "VIDEO"->"Видео";case "PERSON"->"Пользователь";case "ORGANIZATION"->"Организация";case "TOPIC"->"Раздел / тема";default->type;};}
    private MenuButton management(JsonObject material){MenuButton menu=new MenuButton("Материал");menu.setMinHeight(36);menu.getStyleClass().add("wrapped-action");
        if(right(material,"EDIT"))menuItem(menu,"Редактировать",()->compose(material,str(material,"type")));
        if(right(material,"ACCESS_MANAGE"))menuItem(menu,"Доступ по названию и заявки",()->discovery(material));
        if(launcher!=null)menuItem(menu,"Открыть ранее разрешённую копию",()->projectOffline(str(material,"id")));
        String state=str(material,"state");if(right(material,"CREATE")&&Set.of("DRAFT","REJECTED").contains(state))menuItem(menu,"Отправить на проверку",()->transition(material,"submit",""));
        if(right(material,"MODERATE")&&state.equals("SUBMITTED")){menuItem(menu,"Одобрить публикацию",()->transition(material,"moderate","APPROVE"));menuItem(menu,"Отклонить публикацию",()->transition(material,"moderate","REJECT"));}
        if(right(material,"PUBLISH")&&Set.of("DRAFT","APPROVED").contains(state))menuItem(menu,"Опубликовать",()->transition(material,"publish",""));
        if(right(material,"PUBLISH")&&Set.of("PUBLISHED","CORRECTED").contains(state))menuItem(menu,"Отозвать публикацию",()->confirmTransition(material,"retract","Отозвать публикацию?"));
        if(right(material,"DELETE"))menuItem(menu,"Удалить материал",()->confirmTransition(material,"delete","Удалить материал из опубликованного каталога? История сохраняется."));
        menu.setVisible(!menu.getItems().isEmpty());menu.setManaged(menu.isVisible());return menu;
    }
    private static void menuItem(MenuButton menu,String text,Runnable action){MenuItem item=new MenuItem(text);item.setOnAction(e->action.run());menu.getItems().add(item);}
    private void transition(JsonObject material,String operation,String decision){Map<String,Object>args=new LinkedHashMap<>(Map.of("id",str(material,"id"),"revision",number(material,"revision")));if(!decision.isEmpty())args.put("decision",decision);execute(()->rpc(operation,args),result->open(json(result)));}
    private void confirmTransition(JsonObject material,String operation,String question){preview.getChildren().setAll(heading(question),label(title(material)),actions(button("Подтвердить",()->transition(material,operation,"")),button("Отмена",()->open(material))));}
    private void links(JsonObject material){execute(()->rpc("link.list",Map.of("id",str(material,"id"),"limit",100)),result->{
        preview.getChildren().setAll(heading("Связи материала"),button("К материалу",()->open(material)));
        for(JsonObject link:items(json(result),"items")){String other=str(link,"from").equals(str(material,"id"))?str(link,"to"):str(link,"from");String label=nodes.stream().filter(n->str(n,"id").equals(other)).findFirst().map(CommunityUi::title).orElse("Связанный доступный материал");VBox entry=card(label(label),label(str(link,"explanation")),label(state(str(link,"state"))));if(str(link,"state").equals("PROPOSED")&&right(material,"EDIT"))entry.getChildren().add(actions(button("Подтвердить связь",()->decideLink(material,str(link,"id"),"APPROVE")),button("Отклонить связь",()->decideLink(material,str(link,"id"),"REJECT"))));preview.getChildren().add(entry);}
        if(right(material,"LINK")){ComboBox<JsonObject>target=choice("Связать с материалом");for(JsonObject node:nodes)if(!node.has("locked")&&!str(node,"id").equals(str(material,"id")))target.getItems().add(node);TextField explanation=field("Основание связи");preview.getChildren().add(card(target,explanation,button("Предложить связь",()->{if(target.getValue()==null)return;Map<String,Object>args=Map.of("from",str(material,"id"),"to",str(target.getValue(),"id"),"explanation",explanation.getText());execute(()->rpc("link.propose",args),ignored->links(material));})));}
    });}
    private void decideLink(JsonObject material,String id,String decision){execute(()->rpc("link.decide",Map.of("id",id,"decision",decision)),ignored->links(material));}
    private void edit(JsonObject material){TextField title=field("Название");title.setText(CommunityUi.title(material));DocumentEditor editor=new DocumentEditor(openSafeLink);editor.text(str(material,"body"));String changeId=UUID.randomUUID().toString();preview.getChildren().setAll(heading("Предложение изменения"),title,editor.node(),button("Отправить редактору",()->{String proposedTitle=title.getText(),proposedBody=editor.text();execute(()->rpc("proposal.create",Map.of("materialId",str(material,"id"),"baseRevision",number(material,"revision"),"changeId",changeId,"title",proposedTitle,"body",proposedBody)),result->{status.setText("Предложение сохранено. Исходный материал не изменён.");open(material);});}));}
    private void proposals(JsonObject material){proposalsPage(material,"",false);}
    private void proposalsPage(JsonObject material,String cursor,boolean more){execute(()->rpc("proposal.list",Map.of("materialId",str(material,"id"),"limit",25,"cursor",cursor)),result->{
        if(!more)preview.getChildren().setAll(heading("Предложения"),button("К материалу",()->open(material)));
        for(JsonObject proposal:items(json(result),"items"))preview.getChildren().add(button(title(proposal)+" · "+state(str(proposal,"state")),()->showProposal(material,str(proposal,"id"))));
        String next=str(json(result),"nextCursor");if(!next.isEmpty()){Button nextButton=new Button("Следующие предложения");nextButton.setMinHeight(36);nextButton.setOnAction(e->{nextButton.setDisable(true);proposalsPage(material,next,true);});preview.getChildren().add(nextButton);}
    });}
    private void showProposal(JsonObject material,String id){execute(()->rpc("proposal.get",Map.of("proposalId",id)),result->{JsonObject p=json(result);preview.getChildren().setAll(heading(title(p)),DocumentEditor.render(str(p,"body"),openSafeLink),label(state(str(p,"state"))));if(str(p,"state").equals("PENDING"))preview.getChildren().add(actions(button("Утвердить",()->decide(material,id,"APPROVE")),button("Отклонить",()->decide(material,id,"REJECT"))));preview.getChildren().add(button("К материалу",()->open(material)));});}
    private void decide(JsonObject material,String id,String decision){execute(()->rpc("proposal.decide",Map.of("proposalId",id,"decision",decision)),r->{status.setText("Решение подтверждено сервером.");open(material);});}
    private void history(JsonObject material){historyPage(material,0,false);}
    private void historyPage(JsonObject material,long cursor,boolean more){Map<String,Object>args=new LinkedHashMap<>(Map.of("id",str(material,"id"),"limit",5));if(cursor>0)args.put("cursor",cursor);execute(()->rpc("revisions",args),result->{
        if(!more)preview.getChildren().setAll(heading("История версий"),button("К материалу",()->open(material)));
        JsonObject page=json(result);for(JsonObject revision:items(page,"items")){VBox row=card(label("Версия "+str(revision,"revision")),DocumentEditor.render(str(revision,"body"),openSafeLink));if(right(material,"EDIT"))row.getChildren().add(button("Восстановить как новый черновик",()->execute(()->rpc("revert",Map.of("id",str(material,"id"),"revision",number(material,"revision"),"targetRevision",number(revision,"revision"))),restored->open(json(restored)))));preview.getChildren().add(row);}
        long next=number(page,"nextCursor");if(next>0){Button nextButton=new Button("Более ранние версии");nextButton.setMinHeight(36);nextButton.setOnAction(e->{nextButton.setDisable(true);historyPage(material,next,true);});preview.getChildren().add(nextButton);}
    });}
    private static Node lockGlyph(){var shape=new javafx.scene.shape.SVGPath();shape.setContent("M4 9 H16 V20 H4 Z M7 9 V6 A3 3 0 0 1 13 6 V9 M10 13 V16");shape.setStyle("-fx-fill:transparent;-fx-stroke:-aegis-text;-fx-stroke-width:1.6;");var box=new StackPane(shape);box.setMinSize(18,22);box.setPrefSize(18,22);box.setMaxSize(18,22);return box;}
    private static String state(String s){return switch(s){case "PENDING"->"Ожидает решения";case "APPROVED"->"Утверждено";case "REJECTED"->"Отклонено";case "DRAFT"->"Черновик";case "SUBMITTED"->"На проверке";case "PUBLISHED"->"Опубликовано";case "CORRECTED"->"Исправлено";case "RETRACTED"->"Отозвано";case "PROPOSED"->"Предложено";case "REQUESTED"->"Заявка подана";case "APPROVED_PENDING_GRANT"->"Одобрено, ожидается выдача прав";default->s;};}
    private static JsonObject json(Map<String,Object>map){return new Gson().toJsonTree(map).getAsJsonObject();}
    private <T>void execute(Callable<T>action,Consumer<T>done){if(closed||locked)return;int requestSelection=selection.get();status.setText("Выполняется…");try{worker.execute(()->{try{T result=action.call();Platform.runLater(()->{if(!closed&&!locked&&requestSelection==selection.get()){status.setText("");done.accept(result);}else if(result instanceof Snapshot snapshot)snapshot.permit().revoke();});}catch(Exception error){if(error instanceof LibraryReadPermit600.SnapshotChanged&&requestSelection==selection.get())invalidateRead(readPermit.get(),"Материал изменился при получении. Откройте его заново.");Platform.runLater(()->{if(!closed&&!locked&&requestSelection==selection.get())status.setText(error instanceof HttpLibraryTransport600.Rejected rejected?switch(rejected.code()){case "NOT_FOUND"->"Материал недоступен.";case "CONFLICT"->"Материал изменён. Обновите его перед сохранением.";default->"Недостаточно действующих полномочий.";}:"Не удалось проверить ответ Библиотеки. Проверьте Tor и действующую сессию.");});}});}catch(RejectedExecutionException busy){status.setText("Дождитесь завершения текущего действия.");}}
    public void lock(){if(!Platform.isFxApplicationThread()){Platform.runLater(this::lock);return;}if(locked||closed)return;locked=true;LibraryReadPermit600 permit=readPermit.getAndSet(null);if(permit!=null)permit.revoke();nodes.clear();edges.clear();graph.data(List.of(),List.of());tree.setRoot(null);preview.getChildren().setAll(label("Библиотека заблокирована. Для продолжения подтвердите вход в АЕГИС."));status.setText("Доступ заблокирован");disposeConnection();}
    /** Completes only after owned protected-process stop and plaintext-projection cleanup, or exceptionally on failure. */
    public CompletionStage<Void> closedFuture(){return cleanup.minimalCompletionStage();}
    private void disposeConnection(){
        if(!disposing.compareAndSet(false,true))return;
        poll.shutdownNow();expiry.shutdownNow();materialCleanup.shutdownNow();Connection old;synchronized(this){old=connection;connection=null;}if(old!=null)old.transport().close();worker.getQueue().clear();
        worker.shutdownNow();
        ExecutorService cleanupWorker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(1),r->{Thread thread=new Thread(r,"aegis-library-owned-cleanup");thread.setDaemon(false);return thread;},new ThreadPoolExecutor.AbortPolicy());
        try{cleanupWorker.execute(()->{
            Exception failure=null;
            try{if(launcher!=null)launcher.close();}catch(Exception e){failure=e;}
            try{if(old!=null){if(locked)old.connector().revoke();else old.connector().close();}}catch(Exception e){if(failure==null)failure=e;else failure.addSuppressed(e);}
            if(failure==null)cleanup.complete(null);else cleanup.completeExceptionally(failure);
        });}catch(RejectedExecutionException rejected){cleanup.completeExceptionally(rejected);}finally{cleanupWorker.shutdown();}
    }
    @Override public void close(){if(closed)return;closed=true;LibraryReadPermit600 permit=readPermit.getAndSet(null);if(permit!=null)permit.revoke();selection.incrementAndGet();disposeConnection();}
}
