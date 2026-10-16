package org.securemail.ui;

import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.*;
import java.net.URI;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.*;

/** Markdown is the canonical document: changing editing modes never rewrites its contents. No HTML engine. */
final class DocumentEditor {
  private String canonical="";private boolean synchronizing;private TextArea activeEditor;private final TextArea source=new TextArea();private final VBox visual=new VBox(8);private final TabPane tabs=new TabPane();private final Consumer<String> link;
  DocumentEditor(Consumer<String> link){this.link=link;source.setTextFormatter(new TextFormatter<String>(change->change.getControlNewText().length()<=250000?change:null));activeEditor=source;source.focusedProperty().addListener((o,a,b)->{if(b)activeEditor=source;});source.textProperty().addListener((o,a,b)->{if(!synchronizing)canonical=b;});source.setWrapText(true);source.setPromptText("Текст материала в Markdown");source.setPrefRowCount(12);source.setId("document-markdown-source");Tab formatted=new Tab("Визуальный",CommunityUi.scroll(visual)),markdown=new Tab("Markdown",source);formatted.setClosable(false);markdown.setClosable(false);tabs.getTabs().setAll(formatted,markdown);tabs.setMinSize(0,180);tabs.setPrefHeight(360);tabs.getSelectionModel().selectedItemProperty().addListener((o,a,b)->{if(b==formatted)renderBlocks();});renderBlocks();}
  Node node(){return tabs;}
  String text(){return canonical;}
  void text(String value){canonical=value==null?"":value;synchronizing=true;try{source.setText(canonical);}finally{synchronizing=false;}renderBlocks();}
  void append(String value){text(canonical+value);}
  private void decorate(String left,String right){TextArea editing=activeEditor==null?source:activeEditor;String selection=editing.getSelectedText();editing.replaceSelection(left+(selection.isEmpty()?"Текст":selection)+right);if(editing==source)renderBlocks();}
  private void renderBlocks(){
    visual.getChildren().clear();visual.getChildren().add(CommunityUi.actions(CommunityUi.button("Абзац",()->append("\n\nНовый абзац")),CommunityUi.button("Жирный",()->decorate("**","**")),CommunityUi.button("Курсив",()->decorate("_","_")),CommunityUi.button("Код",()->decorate("`","`")),CommunityUi.button("Заголовок",()->append("\n\n## Заголовок")),CommunityUi.button("Список",()->append("\n\n- Первый пункт\n- Второй пункт")),CommunityUi.button("Таблица",()->append("\n\n| Столбец | Значение |\n| --- | --- |\n| Текст | Текст |")),CommunityUi.button("Цитата",()->append("\n\n> Цитата")),CommunityUi.button("Ссылка",()->append("\n\n[Название](https://example.org)")),CommunityUi.button("Внутренняя ссылка",()->append("\n\n[[идентификатор материала]]"))));
    String original=canonical;Matcher separator=Pattern.compile("(?:\\r?\\n){2,}").matcher(original);List<String> blocks=new ArrayList<>(),gaps=new ArrayList<>();int previous=0;while(separator.find()){blocks.add(original.substring(previous,separator.start()));gaps.add(separator.group());previous=separator.end();}blocks.add(original.substring(previous));
    if(blocks.size()>100)visual.getChildren().add(CommunityUi.label("Показаны первые 100 блоков. Полный документ доступен в режиме Markdown и сохраняется без удаления остальных блоков."));for(int i=0;i<Math.min(100,blocks.size());i++){int at=i;String block=blocks.get(i);VBox preview=new VBox(4);preview.getChildren().setAll(render(block,link));TextArea edit=new TextArea(block);edit.setTextFormatter(new TextFormatter<String>(change->canonical.length()-blocks.get(at).length()+change.getControlNewText().length()<=250000?change:null));edit.focusedProperty().addListener((o,a,b)->{if(b)activeEditor=edit;});edit.setWrapText(true);edit.setPrefRowCount(Math.min(12,Math.max(2,block.split("\n",-1).length)));edit.setVisible(false);edit.setManaged(false);Button change=CommunityUi.button("Изменить блок",()->{edit.setVisible(!edit.isVisible());edit.setManaged(edit.isVisible());});edit.textProperty().addListener((o,a,b)->{blocks.set(at,b);StringBuilder full=new StringBuilder();for(int j=0;j<blocks.size();j++){full.append(blocks.get(j));if(j<gaps.size())full.append(gaps.get(j));}canonical=full.toString();synchronizing=true;try{source.setText(canonical);}finally{synchronizing=false;}preview.getChildren().setAll(render(b,link));});VBox row=CommunityUi.card(preview,change,edit);visual.getChildren().add(row);}
  }
  static Node render(String markdown,Consumer<String> open){
    VBox result=new VBox(5);result.setMinWidth(0);String text=markdown==null?"":markdown;boolean truncated=text.length()>100000;if(truncated)text=text.substring(0,100000);
    String[] lines=text.split("\\R",-1);for(int index=0;index<Math.min(lines.length,500);index++){
      String value=lines[index];
      if(value.strip().startsWith("|")&&index+1<lines.length&&lines[index+1].matches("\\s*\\|?[-: |]+\\|?\\s*")){
        List<String> headings=tableCells(value);TableView<List<String>> table=new TableView<>();table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);table.setMinWidth(0);
        for(int column=0;column<Math.min(16,headings.size());column++){int at=column;TableColumn<List<String>,String> item=new TableColumn<>(headings.get(column));item.setCellValueFactory(row->new javafx.beans.property.SimpleStringProperty(at<row.getValue().size()?row.getValue().get(at):""));table.getColumns().add(item);}
        index++;while(index+1<lines.length&&lines[index+1].strip().startsWith("|")&&table.getItems().size()<500)table.getItems().add(tableCells(lines[++index]));table.setPrefHeight(Math.min(360,50+table.getItems().size()*28));result.getChildren().add(table);continue;
      }
      String css="";if(value.startsWith("#")){int count=0;while(count<value.length()&&value.charAt(count)=='#')count++;if(count<=6){value=value.substring(count).stripLeading();css="heading";}}else if(value.startsWith("> "))value="│ "+value.substring(2);else if(value.startsWith("- "))value="• "+value.substring(2);
      TextFlow paragraph=new TextFlow();paragraph.setMinWidth(0);if(!css.isEmpty())paragraph.getStyleClass().add(css);
      Matcher links=Pattern.compile("(!?)\\[([^]\\r\\n]{0,200})]\\(([^)\\s]{1,2048})\\)").matcher(value);int start=0;
      while(links.find()){inline(paragraph,value.substring(start,links.start()),open);String href=links.group(3),caption=links.group(2);if(safe(href)){Hyperlink item=new Hyperlink((links.group(1).isEmpty()?"":"Изображение: ")+(caption.isBlank()?href:caption));item.setOnAction(e->open.accept(href));paragraph.getChildren().add(item);}else paragraph.getChildren().add(documentText((links.group(1).isEmpty()?"Ссылка: ":"Изображение: ")+caption));start=links.end();}
      inline(paragraph,value.substring(start),open);result.getChildren().add(paragraph);
    }if(truncated||lines.length>500)result.getChildren().add(CommunityUi.label("Показан фрагмент большого документа. Полное содержимое доступно в Markdown или экспорте."));return result;
  }
  private static List<String> tableCells(String row){String value=row.strip();if(value.startsWith("|"))value=value.substring(1);if(value.endsWith("|"))value=value.substring(0,value.length()-1);return Arrays.stream(value.split("\\|",-1)).map(String::strip).toList();}
  private static void inline(TextFlow target,String value,Consumer<String> open){Matcher format=Pattern.compile("\\*\\*([^*\\r\\n]+)\\*\\*|_([^_\\r\\n]+)_|`([^`\\r\\n]+)`|\\[\\[([a-zA-Z0-9_-]{1,80})]]").matcher(value);int previous=0;while(format.find()){target.getChildren().add(documentText(value.substring(previous,format.start())));if(format.group(4)!=null){String id=format.group(4);Hyperlink internal=new Hyperlink(id);internal.setOnAction(e->open.accept("aegis-library:"+id));target.getChildren().add(internal);}else{Text styled=documentText(format.group(1)!=null?format.group(1):format.group(2)!=null?format.group(2):format.group(3));styled.setStyle("-fx-fill:-aegis-text;"+(format.group(1)!=null?"-fx-font-weight:bold;":format.group(2)!=null?"-fx-font-style:italic;":"-fx-font-family:monospace;"));target.getChildren().add(styled);}previous=format.end();}target.getChildren().add(documentText(value.substring(previous)));}
  private static Text documentText(String value){Text text=new Text(value);text.setStyle("-fx-fill:-aegis-text;");return text;}
  static boolean safe(String url){try{org.securemail.client.safeweb.SafeWebUrl.parse(url);return true;}catch(IllegalArgumentException invalid){return false;}}
}
