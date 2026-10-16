package org.securemail.ui;

import com.google.gson.JsonObject;
import javafx.geometry.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.function.Consumer;
import static org.securemail.ui.CommunityUi.*;

/** A real month calendar of already-authorized server events; a day click does not bypass a fresh get. */
final class EventsCalendar extends VBox {
 private YearMonth month=YearMonth.now();private final Label heading=label("");private final GridPane days=new GridPane();private final VBox selected=new VBox(8);private final TitledPane dayDetails;private List<JsonObject> events=List.of();private final Consumer<JsonObject> open;private final Consumer<YearMonth> changed;
 EventsCalendar(Consumer<JsonObject> open,Consumer<YearMonth> changed){super(10);this.open=open;this.changed=changed;setId("events-month-calendar");setMinWidth(0);Button back=button("Предыдущий месяц",()->navigate(month.minusMonths(1))),next=button("Следующий месяц",()->navigate(month.plusMonths(1))),today=button("Сегодня",()->navigate(YearMonth.now()));dayDetails=fold("Мероприятия выбранного дня",selected);dayDetails.setId("events-selected-day");getChildren().addAll(actions(back,heading,next,today),days,dayDetails,label("Календарь показывает полученные разрешённые мероприятия. Кнопка «Загрузить ещё» получает следующую страницу с сервера."));days.setHgap(3);days.setVgap(3);days.setMinWidth(0);for(int n=0;n<7;n++){ColumnConstraints column=new ColumnConstraints();column.setPercentWidth(100./7);column.setMinWidth(0);days.getColumnConstraints().add(column);}show(month);}
 void data(List<JsonObject> values){events=List.copyOf(values.stream().limit(500).toList());show(month);}
 YearMonth month(){return month;}
 private void navigate(YearMonth value){selected.getChildren().clear();dayDetails.setExpanded(false);show(value);changed.accept(month);}
 void show(YearMonth value){month=value;heading.setText(month.format(DateTimeFormatter.ofPattern("LLLL yyyy",Locale.forLanguageTag("ru-RU"))));days.getChildren().clear();for(int col=0;col<7;col++){Label name=label(DayOfWeek.of(col+1).getDisplayName(TextStyle.SHORT_STANDALONE,Locale.forLanguageTag("ru-RU")));name.setAlignment(Pos.CENTER);days.add(name,col,0);}int offset=month.atDay(1).getDayOfWeek().getValue()-1;for(int day=1;day<=month.lengthOfMonth();day++){LocalDate date=month.atDay(day);List<JsonObject> daily=events.stream().filter(event->date.equals(eventDate(event))).sorted(Comparator.comparingLong(event->number(event,"startsAt"))).toList();Button choose=button(Integer.toString(day)+(daily.isEmpty()?"":" ·"),()->select(date,daily));choose.setWrapText(false);choose.setTooltip(new Tooltip("Мероприятий: "+daily.size()));choose.setId("event-day-"+date);choose.setAccessibleText(date.format(DateTimeFormatter.ofPattern("d MMMM yyyy",Locale.forLanguageTag("ru-RU")))+", мероприятий: "+daily.size());choose.setMinSize(0,42);choose.setMaxWidth(Double.MAX_VALUE);if(date.equals(LocalDate.now()))choose.getStyleClass().add("calendar-today");VBox cell=new VBox(3,choose);cell.setMinWidth(0);cell.getStyleClass().add("calendar-day");cell.setPadding(new Insets(2));int index=offset+day-1;days.add(cell,index%7,index/7+1);}}
 private static LocalDate eventDate(JsonObject event){long time=number(event,"startsAt");return time<=0?null:Instant.ofEpochMilli(time).atZone(ZoneId.systemDefault()).toLocalDate();}
 private void select(LocalDate date,List<JsonObject> values){selected.getChildren().setAll(label(date.format(DateTimeFormatter.ofPattern("d MMMM yyyy",Locale.forLanguageTag("ru-RU")))));if(values.isEmpty())selected.getChildren().add(label("Среди полученных мероприятий на этот день записей нет."));else for(JsonObject event:values)selected.getChildren().add(button(title(event),()->open.accept(event)));dayDetails.setExpanded(true);}
}
