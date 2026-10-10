package org.securemail.ui;

import javafx.application.Platform;
import javafx.geometry.*;
import javafx.scene.*;
import javafx.scene.canvas.Canvas;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.stage.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import org.securemail.client.appearance.*;
import org.securemail.client.storage.*;
import static org.securemail.client.appearance.Appearance.*;

/** Gallery, editor and layout controls are pages in the existing window. */
final class AppearanceView {
  private final Stage owner;private final ThemeManager themes;private final AppearanceStore store;private final ExecutorService worker;
  private final InWindowDialog<Void> page=new InWindowDialog<>();private final Label message=new Label(),selection=new Label();
  private final TilePane gallery=new TilePane(10,10);
  private final TextField search=new TextField(),themeName=new TextField(),layoutName=new TextField(),lightAt=new TextField(),darkAt=new TextField(),backgroundColor=new TextField(),gradientColor=new TextField();
  private final Selector<String> category;private final CheckBox onlyFavorites=new CheckBox("Избранные");
  private final Map<String,TextField> colors=new LinkedHashMap<>();
  private final Slider scale=new Slider(80,200,100),spacing=new Slider(4,24,10),iconSize=new Slider(16,32,20),avatarSize=new Slider(24,64,32),radius=new Slider(0,24,8),alpha=new Slider(75,100,100),navigationWidth=new Slider(120,240,174),foldersWidth=new Slider(12,30,18),listWidth=new Slider(25,55,38),textWidth=new Slider(360,1200,720),viewPadding=new Slider(8,40,20);
  private final Selector<Mode> mode;private final Selector<Theme> dayTheme,nightTheme;
  private final Selector<UiPreferences.Density> density;
  private final Selector<Shape> avatarShape,buttonShape,iconShape;
  private final Selector<Zone> zone;private final Selector<Labels> labels;private final Selector<MailLayout> mailLayout;private final Selector<Rows> rows;private final Selector<Composer> composer;private final Selector<Appearance.Background> background;
  private final CheckBox collapsed=new CheckBox("Свернуть навигацию"),highContrast=new CheckBox("Повышенный контраст"),animations=new CheckBox("Короткие анимации"),opaque=new CheckBox("Непрозрачные панели"),shadows=new CheckBox("Мягкие тени"),viewCard=new CheckBox("Карточка письма"),metadataTop=new CheckBox("Сведения сверху");
  private final Map<String,CheckBox> fields=new LinkedHashMap<>();
  private final Map<String,Selector<String>> fontFamily=new LinkedHashMap<>();private final Map<String,Slider> fontSize=new LinkedHashMap<>();private final Map<String,Selector<Weight>> fontWeight=new LinkedHashMap<>();
  private final ListView<String> order=new ListView<>(),actions=new ListView<>();
  private final Selector<String> savedLayouts;private Theme selected;private String image="";private boolean loading,applied;

  AppearanceView(Stage owner,ThemeManager themes,ExecutorService worker)throws java.io.IOException{
    this.owner=owner;this.themes=themes;this.worker=worker;store=themes.store();selected=themes.visualTheme();
    category=new Selector<>(themes,List.of("Все","Минимализм","Объёмный","Прозрачный","Классический","Прежние темы","Мои темы"),"Все");
    mode=selector(Mode.values(),Mode.MANUAL);dayTheme=new Selector<>(themes,store.themes().values(),store.theme("minimal-light"));nightTheme=new Selector<>(themes,store.themes().values(),store.theme("minimal-dark"));
    density=selector(UiPreferences.Density.values(),UiPreferences.Density.NORMAL);avatarShape=selector(Shape.values(),Shape.CIRCLE);buttonShape=selector(Shape.values(),Shape.ROUNDED);iconShape=selector(Shape.values(),Shape.ROUNDED);
    zone=selector(Zone.values(),Zone.LEFT);labels=selector(Labels.values(),Labels.BOTH);mailLayout=selector(MailLayout.values(),MailLayout.THREE);rows=selector(Rows.values(),Rows.CARDS);composer=selector(Composer.values(),Composer.PAGE);background=selector(Appearance.Background.values(),Appearance.Background.SOLID);
    savedLayouts=new Selector<>(themes,store.layouts().keySet(),null);
    search.setPromptText("Найти оформление");themeName.setPromptText("Название темы");layoutName.setPromptText("Название макета");
    for(String name:List.of("Фон","Панели","Элементы","Текст","Подписи","Акцент","Входящие","Отправленные"))colors.put(name,new TextField());
    for(String name:List.of("Аватар","Ник","Тема","Дата","Статус","Вложения","Фрагмент"))fields.put(name,new CheckBox(name));
    List<String> fonts=new ArrayList<>();fonts.add("System");Font.getFamilies().stream().filter(s->s.matches("[\\p{L}\\p{N} _.-]{1,64}")).sorted().forEach(fonts::add);
    for(String name:List.of("Навигация","Заголовки","Письма")){fontFamily.put(name,new Selector<>(themes,fonts,"System"));fontSize.put(name,new Slider(11,26,14));fontWeight.put(name,selector(Weight.values(),Weight.NORMAL));}
    search.textProperty().addListener((o,a,b)->fillGallery());category.setOnAction(e->fillGallery());onlyFavorites.setOnAction(e->fillGallery());
    page.initOwner(owner);page.setTitle("Оформление");page.onClose(()->{if(!applied)themes.cancelPreview();});
    message.setWrapText(true);message.getStyleClass().add("security-warning");selection.getStyleClass().add("brand");
    HBox filter=new HBox(8,search,category,onlyFavorites);HBox.setHgrow(search,Priority.ALWAYS);gallery.setPrefTileWidth(230);gallery.setPrefColumns(3);
    VBox presets=new VBox(10,filter,gallery);presets.setPadding(new Insets(8));
    GridPane palette=new GridPane();palette.setHgap(12);palette.setVgap(8);int row=0;for(var e:colors.entrySet())entry(palette,row++,e.getKey(),e.getValue());
    entry(palette,row++,"Скругление",slider(radius));entry(palette,row++,"Прозрачность, %",slider(alpha));
    palette.add(shadows,0,row++,2,1);entry(palette,row++,"Название",themeName);
    FlowPane themeActions=new FlowPane(8,8,button("Сохранить тему",this::saveTheme),button("Переименовать",this::renameTheme),button("Удалить мою тему",this::deleteTheme),button("Экспорт",this::exportTheme),button("Импорт",this::importTheme));palette.add(themeActions,0,row,2,1);
    GridPane typography=new GridPane();typography.setHgap(12);typography.setVgap(10);row=0;
    for(String name:fontFamily.keySet()){entry(typography,row++,name,fontFamily.get(name));entry(typography,row++,"Размер",slider(fontSize.get(name)));entry(typography,row++,"Насыщенность",fontWeight.get(name));}
    GridPane components=new GridPane();components.setHgap(12);components.setVgap(8);row=0;
    entry(components,row++,"Аватары",avatarShape);entry(components,row++,"Размер аватаров",slider(avatarSize));entry(components,row++,"Кнопки",buttonShape);entry(components,row++,"Значки",iconShape);entry(components,row++,"Размер значков",slider(iconSize));entry(components,row++,"Плотность",density);entry(components,row++,"Интервалы",slider(spacing));entry(components,row++,"Масштаб, %",slider(scale));components.add(new VBox(8,highContrast,animations,opaque),0,row,2,1);
    GridPane navigation=new GridPane();navigation.setHgap(12);navigation.setVgap(8);row=0;entry(navigation,row++,"Расположение",zone);entry(navigation,row++,"Подписи",labels);entry(navigation,row++,"Ширина",slider(navigationWidth));navigation.add(collapsed,0,row++,2,1);entry(navigation,row++,"Порядок разделов",reorder(order));entry(navigation,row++,"Действия в письме",reorder(actions));
    GridPane mail=new GridPane();mail.setHgap(12);mail.setVgap(8);row=0;entry(mail,row++,"Почтовый центр",mailLayout);entry(mail,row++,"Ширина папок, %",slider(foldersWidth));entry(mail,row++,"Ширина списка, %",slider(listWidth));entry(mail,row++,"Список писем",rows);FlowPane flags=new FlowPane(10,8);flags.getChildren().addAll(fields.values());mail.add(flags,0,row++,2,1);entry(mail,row++,"Редактор",composer);entry(mail,row++,"Ширина текста",slider(textWidth));entry(mail,row++,"Отступы просмотра",slider(viewPadding));mail.add(new HBox(12,viewCard,metadataTop),0,row++,2,1);entry(mail,row++,"Сохранённый макет",savedLayouts);entry(mail,row++,"Название макета",layoutName);
    mail.add(new FlowPane(8,8,button("Сохранить макет",this::saveLayout),button("Переименовать",this::renameLayout),button("Удалить",this::deleteLayout),button("Экспорт",this::exportLayout),button("Импорт",this::importLayout),button("Стандартный макет",()->{try{Settings s=gather();populate(s.layout(defaults().layout()),selected);preview();}catch(Exception e){failure(e);}})),0,row,2,1);
    savedLayouts.setOnAction(e->{if(loading)return;Layout l=store.layouts().get(savedLayouts.getValue());if(l!=null)try{populate(gather().layout(l),selected);preview();}catch(Exception ex){failure(ex);}});
    GridPane automatic=new GridPane();automatic.setHgap(12);automatic.setVgap(8);row=0;entry(automatic,row++,"Режим темы",mode);entry(automatic,row++,"Светлая тема",dayTheme);entry(automatic,row++,"Тёмная тема",nightTheme);entry(automatic,row++,"Светлая с HH:MM",lightAt);entry(automatic,row++,"Тёмная с HH:MM",darkAt);
    GridPane backgrounds=new GridPane();backgrounds.setHgap(12);backgrounds.setVgap(8);row=0;entry(backgrounds,row++,"Фон",background);entry(backgrounds,row++,"Первый цвет",backgroundColor);entry(backgrounds,row++,"Второй цвет",gradientColor);backgrounds.add(button("Выбрать JPG / PNG / WebP",this::chooseBackground),0,row++,2,1);Label local=new Label("До 5 МБ. Фоновое изображение не переносится в JSON-экспорте.");local.setWrapText(true);local.getStyleClass().add("muted");backgrounds.add(local,0,row,2,1);
    VBox all=new VBox(10,message,selection,presets,fold("Цвета и моя тема",palette),fold("Шрифты",typography),fold("Размеры и доступность",components),fold("Навигация",navigation),fold("Почта и макеты",mail),fold("Фон",backgrounds),fold("Система и расписание",automatic),new FlowPane(8,8,button("Безопасное оформление",()->{try{themes.reset();applied=true;page.close();}catch(Exception e){failure(e);}}),button("Восстановить резервную копию",()->{try{themes.restore();applied=true;page.close();}catch(Exception e){failure(e);}})));
    all.setPadding(new Insets(12));ScrollPane scroll=new ScrollPane(all);scroll.setFitToWidth(true);
    Button apply=button("Применить",this::apply);apply.getStyleClass().add("primary");Button preview=button("Предпросмотр",this::preview),cancel=button("Отмена",page::close);
    BorderPane body=new BorderPane(scroll);FlowPane footer=new FlowPane(8,8,preview,cancel,apply);footer.setPadding(new Insets(12));body.setBottom(footer);body.setMinSize(0,0);body.setPrefWidth(790);body.prefHeightProperty().bind(javafx.beans.binding.Bindings.createDoubleBinding(()->Math.max(250,owner.getScene().getHeight()*100/scale.getValue()-150),owner.getScene().heightProperty(),scale.valueProperty()));page.getDialogPane().setContent(body);themes.apply(page.getDialogPane());
    populate(themes.settings(),selected);message.setText(themes.recovery());fillGallery();
    scale.valueProperty().addListener((o,a,b)->{if(!loading)preview();});
  }
  private <T> Selector<T> selector(T[] values,T value){return new Selector<>(themes,List.of(values),value);}
  private static TitledPane fold(String name,Node body){TitledPane pane=new TitledPane(name,body);pane.setExpanded(false);pane.setAnimated(false);return pane;}
  private static void entry(GridPane grid,int row,String label,Node node){Label title=new Label(label);title.setWrapText(true);title.setMaxWidth(185);grid.add(title,0,row);grid.add(node,1,row);GridPane.setHgrow(node,Priority.ALWAYS);if(node instanceof Region region)region.setMinWidth(0);}
  private static Node slider(Slider slider){slider.setBlockIncrement(1);slider.setMajorTickUnit(20);Label value=new Label();value.textProperty().bind(slider.valueProperty().asString("%.0f"));HBox row=new HBox(8,slider,value);HBox.setHgrow(slider,Priority.ALWAYS);return row;}
  private Button button(String text,Runnable action){Button button=new Button(text);button.setOnAction(e->action.run());return button;}
  private void populate(Settings s,Theme theme){
    loading=true;try{selected=theme;selection.setText(theme.name()+" · предпросмотр");themeName.setText(theme.name());Palette p=theme.palette();List<String> v=List.of(p.background(),p.panel(),p.control(),p.text(),p.muted(),p.accent(),p.incoming(),p.outgoing());int i=0;for(TextField field:colors.values())field.setText(v.get(i++));radius.setValue(theme.radius());alpha.setValue(theme.alpha());shadows.setSelected(theme.shadow());
      scale.setValue(s.scale());density.setValue(s.density());Components c=s.components();avatarShape.setValue(c.avatars());buttonShape.setValue(c.buttons());iconShape.setValue(c.icons());avatarSize.setValue(c.avatarSize());iconSize.setValue(c.iconSize());spacing.setValue(c.spacing());highContrast.setSelected(c.highContrast());animations.setSelected(c.animations());opaque.setSelected(c.opaque());
      List<Type> t=List.of(s.typography().navigation(),s.typography().heading(),s.typography().mail());i=0;for(String name:fontFamily.keySet()){Type type=t.get(i++);fontFamily.get(name).setValue(type.family());fontSize.get(name).setValue(type.size());fontWeight.get(name).setValue(type.weight());}
      Layout l=s.layout();zone.setValue(l.zone());labels.setValue(l.labels());collapsed.setSelected(l.collapsed());navigationWidth.setValue(l.navigationWidth());order.getItems().setAll(l.order());actions.getItems().setAll(l.actions());mailLayout.setValue(l.mail());rows.setValue(l.rows());foldersWidth.setValue(l.foldersPercent());listWidth.setValue(l.listPercent());composer.setValue(l.composer());textWidth.setValue(l.textWidth());viewPadding.setValue(l.viewPadding());viewCard.setSelected(l.viewCard());metadataTop.setSelected(l.metadataTop());Fields f=l.fields();List<Boolean> b=List.of(f.avatar(),f.nickname(),f.subject(),f.date(),f.status(),f.attachments(),f.snippet());i=0;for(CheckBox box:fields.values())box.setSelected(b.get(i++));
      mode.setValue(s.mode());dayTheme.getItems().setAll(store.themes().values());nightTheme.getItems().setAll(store.themes().values());dayTheme.setValue(store.theme(s.lightTheme()));nightTheme.setValue(store.theme(s.darkTheme()));lightAt.setText(s.lightAt());darkAt.setText(s.darkAt());background.setValue(s.backdrop().mode());backgroundColor.setText(s.backdrop().color());gradientColor.setText(s.backdrop().gradient());image=s.backdrop().image();
    }finally{loading=false;}
  }
  private int value(Slider slider){return (int)Math.round(slider.getValue());}
  private Type type(String name){return new Type(fontFamily.get(name).getValue(),value(fontSize.get(name)),fontWeight.get(name).getValue());}
  private boolean flag(String name){return fields.get(name).isSelected();}
  private Theme edited(){List<String> p=colors.values().stream().map(f->f.getText().trim()).toList();return new Theme(selected.id(),selected.name(),selected.category(),new Palette(p.get(0),p.get(1),p.get(2),p.get(3),p.get(4),p.get(5),p.get(6),p.get(7)),value(radius),shadows.isSelected(),value(alpha));}
  private Settings gather(){return new Settings(selected.id(),mode.getValue(),dayTheme.getValue().id(),nightTheme.getValue().id(),lightAt.getText().trim(),darkAt.getText().trim(),value(scale),density.getValue(),new Typography(type("Навигация"),type("Заголовки"),type("Письма")),new Components(avatarShape.getValue(),buttonShape.getValue(),iconShape.getValue(),value(iconSize),value(avatarSize),value(spacing),highContrast.isSelected(),animations.isSelected(),opaque.isSelected()),new Layout(zone.getValue(),labels.getValue(),order.getItems(),collapsed.isSelected(),value(navigationWidth),mailLayout.getValue(),rows.getValue(),value(foldersWidth),value(listWidth),composer.getValue(),value(textWidth),value(viewPadding),viewCard.isSelected(),metadataTop.isSelected(),actions.getItems(),new Fields(flag("Аватар"),flag("Ник"),flag("Тема"),flag("Дата"),flag("Статус"),flag("Вложения"),flag("Фрагмент")),themes.settings().layout().previewBelow()),new Backdrop(background.getValue(),backgroundColor.getText().trim(),gradientColor.getText().trim(),image));}
  private void preview(){try{themes.preview(gather(),edited());message.setText(themes.recovery());}catch(Exception e){failure(e);}}
  private Settings saveEdited(Settings settings)throws Exception{
    Theme value=edited();if(!value.equals(store.theme(selected.id()))){String name=themeName.getText().trim();if(value.category()!=Category.CUSTOM){if(name.equals(value.name()))name=value.name().substring(0,Math.min(42,value.name().length()))+" — моя";value=value.copy(name);store.addTheme(value,settings.manual(value.id()));}else{value=value.rename(name);store.updateTheme(value,settings);}selected=value;settings=settings.manual(value.id());}
    return settings;
  }
  private void apply(){try{Settings value=saveEdited(gather());themes.commit(value);applied=true;page.close();}catch(Exception e){failure(e);}}
  private void saveTheme(){try{Theme value=edited();String name=themeName.getText().trim();if(value.category()==Category.CUSTOM){value=value.rename(name);store.updateTheme(value,gather());}else{if(name.equals(value.name()))name=value.name().substring(0,Math.min(42,value.name().length()))+" — моя";value=value.copy(name);store.addTheme(value,gather().manual(value.id()));}Settings s=gather().manual(value.id());populate(s,value);fillGallery();preview();message.setText("Тема сохранена. Нажмите «Применить» для выбора.");}catch(Exception e){failure(e);}}
  private void renameTheme(){try{store.renameTheme(selected.id(),themeName.getText());selected=store.theme(selected.id());fillGallery();selection.setText(selected.name());}catch(Exception e){failure(e);}}
  private void deleteTheme(){try{store.removeTheme(selected.id());selected=store.theme("minimal-dark");populate(defaults(),selected);fillGallery();preview();}catch(Exception e){failure(e);}}
  private void fillGallery(){
    gallery.getChildren().clear();String query=search.getText().trim().toLowerCase(Locale.ROOT);for(Theme theme:store.themes().values()){
      if(!theme.name().toLowerCase(Locale.ROOT).contains(query)||!category.getValue().equals("Все")&&!theme.category().toString().equals(category.getValue())||onlyFavorites.isSelected()&&!store.favorites().contains(theme.id()))continue;
      Canvas preview=new Canvas(186,78);var g=preview.getGraphicsContext2D();Palette p=theme.palette();g.setFill(Color.web(p.background()));g.fillRoundRect(0,0,186,78,10,10);g.setFill(Color.web(p.panel()));g.fillRoundRect(6,7,29,64,6,6);g.setFill(Color.web(p.control()));for(int y:List.of(10,32,54))g.fillRoundRect(42,y,135,17,theme.radius(),theme.radius());g.setFill(Color.web(p.accent()));g.fillOval(13,15,14,14);g.setFill(Color.web(p.text()));g.fillRoundRect(49,15,68,3,2,2);g.fillRoundRect(49,37,94,3,2,2);g.setFill(Color.web(p.muted()));g.fillRoundRect(49,59,57,3,2,2);
      Button choose=button(theme.name(),()->{try{Settings s=store.template(theme.id(),gather()).manual(theme.id());if(s.backdrop().mode()!=Appearance.Background.IMAGE)s=s.backdrop(new Backdrop(Appearance.Background.SOLID,theme.palette().background(),theme.palette().panel(),""));populate(s,theme);preview();}catch(Exception e){failure(e);}});choose.setGraphic(preview);choose.setContentDisplay(ContentDisplay.TOP);choose.setMaxWidth(Double.MAX_VALUE);choose.setAccessibleText("Предпросмотр "+theme.name());
      Button pin=button(store.favorites().contains(theme.id())?"★":"☆",()->{try{store.favorite(theme.id(),!store.favorites().contains(theme.id()));fillGallery();}catch(Exception e){failure(e);}});pin.setTooltip(new Tooltip("Избранное оформление"));pin.setAccessibleText("Избранное "+theme.name());Label type=new Label(theme.category().toString());type.getStyleClass().add("muted");HBox metadata=new HBox(8,type,pin);VBox tile=new VBox(7,choose,metadata);tile.getStyleClass().add("preset-tile");gallery.getChildren().add(tile);
    }
  }
  private Node reorder(ListView<String> list){list.setPrefHeight(150);list.setCellFactory(v->new ListCell<>(){protected void updateItem(String id,boolean empty){super.updateItem(id,empty);setText(empty||id==null?null:display(id));}});return new VBox(6,list,new HBox(8,button("↑",()->move(list,-1)),button("↓",()->move(list,1))));}
  private static String display(String id){return switch(id){case "letters"->"Письма";case "contacts"->"Контакты";case "friends"->"Друзья";case "search"->"Поиск";case "profile"->"Профиль";case "settings"->"Настройки";case "reply"->"Ответить";case "forward"->"Переслать";case "copy"->"Копировать";default->id;};}
  private static void move(ListView<String> list,int shift){int i=list.getSelectionModel().getSelectedIndex(),next=i+shift;if(i<0||next<0||next>=list.getItems().size())return;Collections.swap(list.getItems(),i,next);list.getSelectionModel().select(next);}
  private void saveLayout(){try{store.saveLayout(layoutName.getText(),gather().layout());refreshLayouts();message.setText("Макет сохранён.");}catch(Exception e){failure(e);}}
  private void renameLayout(){try{store.renameLayout(savedLayouts.getValue(),layoutName.getText());refreshLayouts();}catch(Exception e){failure(e);}}
  private void deleteLayout(){try{store.removeLayout(savedLayouts.getValue());refreshLayouts();}catch(Exception e){failure(e);}}
  private void refreshLayouts(){savedLayouts.getItems().setAll(store.layouts().keySet());}
  private Path pick(String name,boolean save){InWindowFileChooser picker=new InWindowFileChooser();picker.setTitle(name);picker.getExtensionFilters().add(new FileChooser.ExtensionFilter("AEGIS JSON","*.json"));if(save)picker.setInitialFileName(name+".json");var file=save?picker.showSaveDialog(owner):picker.showOpenDialog(owner);return file==null?null:file.toPath();}
  private void exportTheme(){Path path=pick("AEGIS-theme",true);if(path!=null)runIO(()->{store.exportTheme(selected.id(),path);return true;},"Тема экспортирована.");}
  private void importTheme(){Path path=pick("Тема",false);if(path!=null)runIO(()->{store.importTheme(path);return true;},"Тема добавлена в библиотеку.");}
  private void exportLayout(){Path path=pick("AEGIS-layout",true);String name=savedLayouts.getValue();if(path!=null)runIO(()->{store.exportLayout(name,path);return true;},"Макет экспортирован.");}
  private void importLayout(){Path path=pick("Макет",false);if(path!=null)runIO(()->{store.importLayout(path);return true;},"Макет добавлен.");}
  private void chooseBackground(){InWindowFileChooser picker=new InWindowFileChooser();picker.setTitle("Фон");picker.getExtensionFilters().add(new FileChooser.ExtensionFilter("JPG, PNG, WebP · до 5 МБ","*.jpg","*.jpeg","*.png","*.webp"));var file=picker.showOpenDialog(owner);if(file==null)return;message.setText("Подготовка фона…");worker.execute(()->{try{byte[] clean=BackgroundCodec.load(file.toPath());String id;try{id=store.image(clean);}finally{Arrays.fill(clean,(byte)0);}Platform.runLater(()->{if(!page.isShowing())return;image=id;background.setValue(Appearance.Background.IMAGE);preview();});}catch(Exception e){Platform.runLater(()->failure(e));}});}
  @FunctionalInterface private interface IO{boolean run()throws Exception;}
  private void runIO(IO operation,String success){worker.execute(()->{try{operation.run();Platform.runLater(()->{if(page.isShowing()){fillGallery();refreshLayouts();message.setText(success);}});}catch(Exception e){Platform.runLater(()->failure(e));}});}
  private void failure(Exception error){String text=error.getMessage();message.setText(text!=null&&text.length()<160?text:"Не удалось изменить оформление. Проверьте выбранные значения.");}
  void show(){page.show();}
}
