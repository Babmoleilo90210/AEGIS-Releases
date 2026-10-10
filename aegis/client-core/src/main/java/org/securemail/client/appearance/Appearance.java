package org.securemail.client.appearance;

import com.google.gson.*;
import java.io.IOException;
import java.time.LocalTime;
import java.util.*;
import org.securemail.client.storage.UiPreferences;
import org.securemail.client.update.JsonData;

/** Appearance data only. No CSS, file paths, URLs, accounts or cryptographic material. */
public final class Appearance {
  public static final int SCHEMA=1,MAX_JSON=65536;
  private Appearance(){}
  public enum Category {MINIMAL,DEPTH,TRANSPARENT,CLASSIC,LEGACY,CUSTOM;
    public String toString(){return switch(this){case MINIMAL->"Минимализм";case DEPTH->"Объёмный";case TRANSPARENT->"Прозрачный";case CLASSIC->"Классический";case LEGACY->"Прежние темы";case CUSTOM->"Мои темы";};}}
  public enum Shape {SQUARE,ROUNDED,CIRCLE;public String toString(){return switch(this){case SQUARE->"Квадрат";case ROUNDED->"Скруглённый";case CIRCLE->"Круг";};}}
  public enum Zone {LEFT,TOP,BOTTOM;public String toString(){return switch(this){case LEFT->"Слева";case TOP->"Сверху";case BOTTOM->"Снизу";};}}
  public enum Labels {ICONS,TEXT,BOTH;public String toString(){return switch(this){case ICONS->"Значки";case TEXT->"Текст";case BOTH->"Значки и текст";};}}
  public enum MailLayout {TWO,THREE,COMPACT,CUSTOM;public String toString(){return switch(this){case TWO->"Две колонки";case THREE->"Три колонки";case COMPACT->"Компактный";case CUSTOM->"Свои пропорции";};}}
  public enum Rows {COMPACT,EXPANDED,CARDS,PREVIEW;public String toString(){return switch(this){case COMPACT->"Компактные строки";case EXPANDED->"Расширенные строки";case CARDS->"Карточки";case PREVIEW->"Карточки с фрагментом";};}}
  public enum Composer {PAGE,DRAWER;public String toString(){return this==PAGE?"Страница":"Выдвижная панель";}}
  public enum Mode {MANUAL,SYSTEM,SCHEDULE;public String toString(){return switch(this){case MANUAL->"Вручную";case SYSTEM->"Как в системе";case SCHEDULE->"По расписанию";};}}
  public enum Background {SOLID,GRADIENT,IMAGE;public String toString(){return switch(this){case SOLID->"Цвет";case GRADIENT->"Градиент";case IMAGE->"Локальное изображение";};}}
  public enum Weight {NORMAL,MEDIUM,BOLD;public String toString(){return switch(this){case NORMAL->"Обычный";case MEDIUM->"Средний";case BOLD->"Жирный";};}}
  public static final List<String> SECTIONS=List.of("letters","contacts","friends","search","profile","settings");
  public static final List<String> ACTIONS=List.of("reply","forward","copy");

  public record Palette(String background,String panel,String control,String text,String muted,String accent,String incoming,String outgoing){
    public Palette {for(String s:List.of(background,panel,control,text,muted,accent,incoming,outgoing))color(s);
      for(String surface:List.of(background,panel,control,incoming,outgoing))if(contrast(text,surface)<4.5)throw new IllegalArgumentException("Недостаточный контраст текста (нужно 4,5:1)");
      if(contrast(muted,panel)<3)throw new IllegalArgumentException("Недостаточный контраст подписей (нужно 3:1)");}
    public JsonObject json(){JsonObject o=new JsonObject();o.addProperty("background",background);o.addProperty("panel",panel);o.addProperty("control",control);o.addProperty("text",text);o.addProperty("muted",muted);o.addProperty("accent",accent);o.addProperty("incoming",incoming);o.addProperty("outgoing",outgoing);return o;}
    public static Palette parse(JsonObject o)throws IOException{JsonData.fields(o,"background","panel","control","text","muted","accent","incoming","outgoing");return checked(()->new Palette(Appearance.text(o,"background",7),Appearance.text(o,"panel",7),Appearance.text(o,"control",7),Appearance.text(o,"text",7),Appearance.text(o,"muted",7),Appearance.text(o,"accent",7),Appearance.text(o,"incoming",7),Appearance.text(o,"outgoing",7)));}
  }
  public record Theme(String id,String name,Category category,Palette palette,int radius,boolean shadow,int alpha){
    public Theme {identifier(id);name=label(name);Objects.requireNonNull(category);Objects.requireNonNull(palette);range(radius,0,24);range(alpha,75,100);}
    public Theme copy(String name){return new Theme("user-"+UUID.randomUUID(),name,Category.CUSTOM,palette,radius,shadow,alpha);}
    public Theme rename(String name){return new Theme(id,name,category,palette,radius,shadow,alpha);}
    public JsonObject json(){JsonObject o=new JsonObject();o.addProperty("id",id);o.addProperty("name",name);o.addProperty("category",category.name());o.add("palette",palette.json());o.addProperty("radius",radius);o.addProperty("shadow",shadow);o.addProperty("alpha",alpha);return o;}
    public static Theme parse(JsonObject o)throws IOException{JsonData.fields(o,"id","name","category","palette","radius","shadow","alpha");return checked(()->new Theme(Appearance.text(o,"id",50),Appearance.text(o,"name",48),value(Category.class,o,"category"),Palette.parse(object(o,"palette")),integer(o,"radius"),JsonData.bool(o,"shadow"),integer(o,"alpha")));}
    public String toString(){return name;}
  }
  public record Type(String family,int size,Weight weight){
    public Type {Objects.requireNonNull(family);if(!family.matches("[\\p{L}\\p{N} _.-]{1,64}"))throw new IllegalArgumentException("Недопустимое имя шрифта");range(size,11,26);Objects.requireNonNull(weight);}
    public JsonObject json(){JsonObject o=new JsonObject();o.addProperty("family",family);o.addProperty("size",size);o.addProperty("weight",weight.name());return o;}
    public static Type parse(JsonObject o)throws IOException{JsonData.fields(o,"family","size","weight");return checked(()->new Type(Appearance.text(o,"family",64),integer(o,"size"),value(Weight.class,o,"weight")));}
  }
  public record Typography(Type navigation,Type heading,Type mail){
    public Typography {Objects.requireNonNull(navigation);Objects.requireNonNull(heading);Objects.requireNonNull(mail);}
    public JsonObject json(){JsonObject o=new JsonObject();o.add("navigation",navigation.json());o.add("heading",heading.json());o.add("mail",mail.json());return o;}
    public static Typography parse(JsonObject o)throws IOException{JsonData.fields(o,"navigation","heading","mail");return new Typography(Type.parse(object(o,"navigation")),Type.parse(object(o,"heading")),Type.parse(object(o,"mail")));}
  }
  public record Components(Shape avatars,Shape buttons,Shape icons,int iconSize,int avatarSize,int spacing,boolean highContrast,boolean animations,boolean opaque){
    public Components {Objects.requireNonNull(avatars);Objects.requireNonNull(buttons);Objects.requireNonNull(icons);range(iconSize,16,32);range(avatarSize,24,64);range(spacing,4,24);}
    public JsonObject json(){JsonObject o=new JsonObject();o.addProperty("avatars",avatars.name());o.addProperty("buttons",buttons.name());o.addProperty("icons",icons.name());o.addProperty("iconSize",iconSize);o.addProperty("avatarSize",avatarSize);o.addProperty("spacing",spacing);o.addProperty("highContrast",highContrast);o.addProperty("animations",animations);o.addProperty("opaque",opaque);return o;}
    public static Components parse(JsonObject o)throws IOException{JsonData.fields(o,"avatars","buttons","icons","iconSize","avatarSize","spacing","highContrast","animations","opaque");return checked(()->new Components(value(Shape.class,o,"avatars"),value(Shape.class,o,"buttons"),value(Shape.class,o,"icons"),integer(o,"iconSize"),integer(o,"avatarSize"),integer(o,"spacing"),JsonData.bool(o,"highContrast"),JsonData.bool(o,"animations"),JsonData.bool(o,"opaque")));}
  }
  public record Fields(boolean avatar,boolean nickname,boolean subject,boolean date,boolean status,boolean attachments,boolean snippet){
    public JsonObject json(){JsonObject o=new JsonObject();o.addProperty("avatar",avatar);o.addProperty("nickname",nickname);o.addProperty("subject",subject);o.addProperty("date",date);o.addProperty("status",status);o.addProperty("attachments",attachments);o.addProperty("snippet",snippet);return o;}
    public static Fields parse(JsonObject o)throws IOException{JsonData.fields(o,"avatar","nickname","subject","date","status","attachments","snippet");return new Fields(JsonData.bool(o,"avatar"),JsonData.bool(o,"nickname"),JsonData.bool(o,"subject"),JsonData.bool(o,"date"),JsonData.bool(o,"status"),JsonData.bool(o,"attachments"),JsonData.bool(o,"snippet"));}
  }
  public record Layout(Zone zone,Labels labels,List<String> order,boolean collapsed,int navigationWidth,MailLayout mail,Rows rows,int foldersPercent,int listPercent,Composer composer,int textWidth,int viewPadding,boolean viewCard,boolean metadataTop,List<String> actions,Fields fields,boolean previewBelow){
    public Layout(Zone zone,Labels labels,List<String> order,boolean collapsed,int navigationWidth,MailLayout mail,Rows rows,int foldersPercent,int listPercent,Composer composer,int textWidth,int viewPadding,boolean viewCard,boolean metadataTop,List<String> actions,Fields fields){this(zone,labels,order,collapsed,navigationWidth,mail,rows,foldersPercent,listPercent,composer,textWidth,viewPadding,viewCard,metadataTop,actions,fields,false);}
    public Layout {Objects.requireNonNull(zone);Objects.requireNonNull(labels);Objects.requireNonNull(mail);Objects.requireNonNull(rows);Objects.requireNonNull(composer);Objects.requireNonNull(fields);order=permutation(order,SECTIONS);actions=permutation(actions,ACTIONS);range(navigationWidth,120,240);range(foldersPercent,12,30);range(listPercent,25,55);if(foldersPercent+listPercent>75)throw new IllegalArgumentException("Слишком узкая область просмотра");range(textWidth,360,1200);range(viewPadding,8,40);}
    public Layout panels(int folders,int list){return new Layout(zone,labels,order,collapsed,navigationWidth,mail,rows,folders,list,composer,textWidth,viewPadding,viewCard,metadataTop,actions,fields,previewBelow);}
    public Layout below(boolean value){return new Layout(zone,labels,order,collapsed,navigationWidth,mail,rows,foldersPercent,listPercent,composer,textWidth,viewPadding,viewCard,metadataTop,actions,fields,value);}
    public JsonObject json(){JsonObject o=new JsonObject();o.addProperty("zone",zone.name());o.addProperty("labels",labels.name());o.add("order",strings(order));o.addProperty("collapsed",collapsed);o.addProperty("navigationWidth",navigationWidth);o.addProperty("mail",mail.name());o.addProperty("rows",rows.name());o.addProperty("foldersPercent",foldersPercent);o.addProperty("listPercent",listPercent);o.addProperty("composer",composer.name());o.addProperty("textWidth",textWidth);o.addProperty("viewPadding",viewPadding);o.addProperty("viewCard",viewCard);o.addProperty("metadataTop",metadataTop);o.add("actions",strings(actions));o.add("fields",fields.json());o.addProperty("previewBelow",previewBelow);return o;}
    public static Layout parse(JsonObject o)throws IOException{JsonData.fields(o,"zone","labels","order","collapsed","navigationWidth","mail","rows","foldersPercent","listPercent","composer","textWidth","viewPadding","viewCard","metadataTop","actions","fields","previewBelow");return checked(()->new Layout(value(Zone.class,o,"zone"),value(Labels.class,o,"labels"),list(o,"order",6),JsonData.bool(o,"collapsed"),integer(o,"navigationWidth"),value(MailLayout.class,o,"mail"),value(Rows.class,o,"rows"),integer(o,"foldersPercent"),integer(o,"listPercent"),value(Composer.class,o,"composer"),integer(o,"textWidth"),integer(o,"viewPadding"),JsonData.bool(o,"viewCard"),JsonData.bool(o,"metadataTop"),list(o,"actions",3),Fields.parse(object(o,"fields")),JsonData.bool(o,"previewBelow")));}
  }
  public record Backdrop(Background mode,String color,String gradient,String image){
    public Backdrop {Objects.requireNonNull(mode);Appearance.color(color);Appearance.color(gradient);Objects.requireNonNull(image);if(!image.isEmpty()&&!image.matches("[a-f0-9]{64}"))throw new IllegalArgumentException("Недопустимое изображение");if(mode==Background.IMAGE&&image.isEmpty())throw new IllegalArgumentException("Выберите фоновое изображение");}
    public JsonObject json(){JsonObject o=new JsonObject();o.addProperty("mode",mode.name());o.addProperty("color",color);o.addProperty("gradient",gradient);o.addProperty("image",image);return o;}
    public static Backdrop parse(JsonObject o)throws IOException{JsonData.fields(o,"mode","color","gradient","image");return checked(()->new Backdrop(value(Background.class,o,"mode"),Appearance.text(o,"color",7),Appearance.text(o,"gradient",7),Appearance.text(o,"image",64)));}
  }
  public record Settings(String theme,Mode mode,String lightTheme,String darkTheme,String lightAt,String darkAt,int scale,UiPreferences.Density density,Typography typography,Components components,Layout layout,Backdrop backdrop){
    public Settings {identifier(theme);identifier(lightTheme);identifier(darkTheme);Objects.requireNonNull(mode);LocalTime.parse(lightAt);LocalTime.parse(darkAt);if(!lightAt.matches("\\d{2}:\\d{2}")||!darkAt.matches("\\d{2}:\\d{2}")||lightAt.equals(darkAt))throw new IllegalArgumentException("Проверьте расписание");range(scale,80,200);Objects.requireNonNull(density);Objects.requireNonNull(typography);Objects.requireNonNull(components);Objects.requireNonNull(layout);Objects.requireNonNull(backdrop);}
    public Settings theme(String id){return new Settings(id,mode,lightTheme,darkTheme,lightAt,darkAt,scale,density,typography,components,layout,backdrop);}
    public Settings layout(Layout next){return new Settings(theme,mode,lightTheme,darkTheme,lightAt,darkAt,scale,density,typography,components,next,backdrop);}
    public Settings backdrop(Backdrop next){return new Settings(theme,mode,lightTheme,darkTheme,lightAt,darkAt,scale,density,typography,components,layout,next);}
    public Settings manual(String id){Theme next=PresetLibrary.get(id);Backdrop bg=next!=null&&!theme.equals(id)&&backdrop.mode()==Background.SOLID?new Backdrop(Background.SOLID,next.palette().background(),next.palette().panel(),""):backdrop;return new Settings(id,Mode.MANUAL,lightTheme,darkTheme,lightAt,darkAt,scale,density,typography,components,layout,bg);}
    public UiPreferences legacy(){return new UiPreferences(scale,density,!layout.collapsed(),layout.fields().avatar()?UiPreferences.Avatars.SMALL:UiPreferences.Avatars.OFF,layout.mail()==MailLayout.COMPACT?UiPreferences.Preview.OFF:(layout.previewBelow()?UiPreferences.Preview.BOTTOM:UiPreferences.Preview.RIGHT),layout.fields().subject(),layout.fields().date());}
    public JsonObject json(){JsonObject o=new JsonObject();o.addProperty("theme",theme);o.addProperty("mode",mode.name());o.addProperty("lightTheme",lightTheme);o.addProperty("darkTheme",darkTheme);o.addProperty("lightAt",lightAt);o.addProperty("darkAt",darkAt);o.addProperty("scale",scale);o.addProperty("density",density.name());o.add("typography",typography.json());o.add("components",components.json());o.add("layout",layout.json());o.add("backdrop",backdrop.json());return o;}
    public static Settings parse(JsonObject o)throws IOException{JsonData.fields(o,"theme","mode","lightTheme","darkTheme","lightAt","darkAt","scale","density","typography","components","layout","backdrop");return checked(()->new Settings(Appearance.text(o,"theme",50),value(Mode.class,o,"mode"),Appearance.text(o,"lightTheme",50),Appearance.text(o,"darkTheme",50),Appearance.text(o,"lightAt",5),Appearance.text(o,"darkAt",5),integer(o,"scale"),value(UiPreferences.Density.class,o,"density"),Typography.parse(object(o,"typography")),Components.parse(object(o,"components")),Layout.parse(object(o,"layout")),Backdrop.parse(object(o,"backdrop"))));}
  }
  public static Settings defaults(){return new Settings("minimal-dark",Mode.MANUAL,"minimal-light","minimal-dark","07:00","20:00",100,UiPreferences.Density.NORMAL,new Typography(new Type("System",13,Weight.NORMAL),new Type("System",17,Weight.MEDIUM),new Type("System",14,Weight.NORMAL)),new Components(Shape.CIRCLE,Shape.ROUNDED,Shape.ROUNDED,20,32,10,false,true,false),new Layout(Zone.LEFT,Labels.BOTH,SECTIONS,false,174,MailLayout.THREE,Rows.CARDS,18,38,Composer.PAGE,720,20,true,true,ACTIONS,new Fields(true,true,true,true,true,true,false)),new Backdrop(Background.SOLID,"#15191f","#20262e",""));}
  public static Settings legacy(UiPreferences old,String theme){Settings d=defaults();String selected=switch(theme){case "SYSTEM"->"minimal-dark";case "BLACK","DARK","DARK_GREEN","GREY","LIGHT","WHITE"->"legacy-"+theme.toLowerCase(Locale.ROOT).replace('_','-');default->"minimal-dark";};Layout l=d.layout();l=new Layout(l.zone(),l.labels(),l.order(),!old.sidebar(),l.navigationWidth(),old.preview()==UiPreferences.Preview.OFF?MailLayout.COMPACT:MailLayout.THREE,Rows.COMPACT,l.foldersPercent(),l.listPercent(),l.composer(),l.textWidth(),l.viewPadding(),l.viewCard(),l.metadataTop(),l.actions(),new Fields(old.avatars()!=UiPreferences.Avatars.OFF,true,old.subject(),old.date(),true,true,false));if(old.preview()==UiPreferences.Preview.BOTTOM)l=new Layout(l.zone(),l.labels(),l.order(),l.collapsed(),l.navigationWidth(),MailLayout.TWO,l.rows(),l.foldersPercent(),l.listPercent(),l.composer(),l.textWidth(),l.viewPadding(),l.viewCard(),l.metadataTop(),l.actions(),l.fields(),true);Theme chosen=PresetLibrary.get(selected);Backdrop bg=new Backdrop(Background.SOLID,chosen.palette().background(),chosen.palette().panel(),"");return new Settings(selected,theme.equals("SYSTEM")?Mode.SYSTEM:Mode.MANUAL,d.lightTheme(),d.darkTheme(),d.lightAt(),d.darkAt(),old.scale(),old.density(),d.typography(),d.components(),l,bg);}
  public static String effectiveTheme(Settings s,boolean light,LocalTime now){if(s.mode()==Mode.MANUAL)return s.theme();if(s.mode()==Mode.SYSTEM)return light?s.lightTheme():s.darkTheme();LocalTime a=LocalTime.parse(s.lightAt()),b=LocalTime.parse(s.darkAt());boolean day=a.isBefore(b)?!now.isBefore(a)&&now.isBefore(b):!now.isBefore(a)||now.isBefore(b);return day?s.lightTheme():s.darkTheme();}
  public static double contrast(String a,String b){double x=luminance(a),y=luminance(b);return (Math.max(x,y)+.05)/(Math.min(x,y)+.05);}
  private static double luminance(String color){color(color);int n=Integer.parseInt(color.substring(1),16);double[] c={((n>>16)&255)/255.,((n>>8)&255)/255.,(n&255)/255.};for(int i=0;i<3;i++)c[i]=c[i]<=.04045?c[i]/12.92:Math.pow((c[i]+.055)/1.055,2.4);return .2126*c[0]+.7152*c[1]+.0722*c[2];}
  public static String color(String s){if(s==null||!s.matches("#[a-fA-F0-9]{6}"))throw new IllegalArgumentException("Цвет должен иметь формат #RRGGBB");return s;}
  public static String label(String s){s=Objects.requireNonNull(s).trim();if(s.isBlank()||s.length()>48||s.chars().anyMatch(Character::isISOControl))throw new IllegalArgumentException("Недопустимое название");return s;}
  private static void identifier(String s){if(s==null||!s.matches("[a-z0-9-]{1,50}"))throw new IllegalArgumentException("Недопустимый идентификатор оформления");}
  private static void range(int n,int a,int b){if(n<a||n>b)throw new IllegalArgumentException("Значение вне допустимого диапазона");}
  private static List<String> permutation(List<String> a,List<String> b){if(a==null||a.size()!=b.size()||!new HashSet<>(a).equals(new HashSet<>(b)))throw new IllegalArgumentException("Некорректный порядок элементов");return List.copyOf(a);}
  private static JsonArray strings(List<String> a){JsonArray out=new JsonArray();a.forEach(out::add);return out;}
  private static List<String> list(JsonObject o,String key,int max)throws IOException{JsonElement v=o.get(key);if(v==null||!v.isJsonArray()||v.getAsJsonArray().size()>max)throw new IOException("Invalid appearance list");List<String> result=new ArrayList<>();for(JsonElement e:v.getAsJsonArray()){if(!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isString()||e.getAsString().length()>24)throw new IOException("Invalid appearance entry");result.add(e.getAsString());}return result;}
  public static JsonObject object(JsonObject o,String key)throws IOException{JsonElement v=o.get(key);if(v==null||!v.isJsonObject())throw new IOException("Expected appearance object");return v.getAsJsonObject();}
  private static String text(JsonObject o,String key,int max)throws IOException{return JsonData.text(o,key,max);}
  private static int integer(JsonObject o,String key)throws IOException{return Math.toIntExact(JsonData.number(o,key));}
  private static <T extends Enum<T>> T value(Class<T> type,JsonObject o,String key)throws IOException{return Enum.valueOf(type,Appearance.text(o,key,24));}
  @FunctionalInterface private interface Read<T>{T read()throws IOException;}
  private static <T> T checked(Read<T> read)throws IOException{try{return read.read();}catch(RuntimeException e){throw new IOException("Некорректное оформление",e);}}
}
