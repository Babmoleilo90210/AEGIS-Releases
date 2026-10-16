package org.securemail.ui;
import com.google.gson.*;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import java.util.*;
import static org.securemail.ui.CommunityUi.*;
/** Human labels, normalized server identifiers. Never infer a city from the network address. */
final class CityPicker {
 private record City(String id,String name){public String toString(){return name;}}
 private final CommunityUi api;private final String initial;private final ComboBox<City> choice=new ComboBox<>();private final Label status=label("");private final VBox node;private long generation;
 CityPicker(CommunityUi api,String selected){this.api=api;initial=selected;choice.setPromptText("Выберите город (необязательно)");choice.setMinWidth(0);choice.setMaxWidth(Double.MAX_VALUE);node=new VBox(6,choice,button("Обновить города",this::reload),status);reload();}
 private void reload(){String selected=id().isEmpty()?initial:id();long version=++generation;choice.getItems().setAll(new City("","Город не выбран"));choice.getSelectionModel().selectFirst();load("",selected,version,new HashSet<>());}
 private void load(String cursor,String selected,long version,Set<String> seen){if(version!=generation)return;if(!seen.add(cursor)||seen.size()>1000){status.setText("Каталог изменился во время загрузки. Обновите список городов.");return;}api.call("agent.cities.list",obj("limit",100,"cursor",cursor),status,result->{if(version!=generation)return;Set<String> known=new HashSet<>();for(City city:choice.getItems())known.add(city.id);for(JsonObject city:items(result,"cities")){String name=str(city,"name"),id=str(city,"id");if(choice.getItems().size()<1001&&known.add(id))choice.getItems().add(new City(id,name.isBlank()?id:name));}if(id().isEmpty())choice.getItems().stream().filter(city->city.id.equals(selected)).findFirst().ifPresent(choice::setValue);String next=str(result,"nextCursor");if(!next.isEmpty()){if(choice.getItems().size()>=1001){status.setText("Показаны первые 1000 городов. Для обновления каталога нажмите «Обновить города».");return;}load(next,selected,version,seen);}});}
 Node node(){return node;}
 String id(){City value=choice.getValue();return value==null?"":value.id;}
}
