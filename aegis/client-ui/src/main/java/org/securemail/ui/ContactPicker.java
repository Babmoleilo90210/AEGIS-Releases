package org.securemail.ui;
import java.util.*;
import javafx.collections.*;
import javafx.collections.transformation.FilteredList;
import javafx.scene.control.*;

/** Native popup; guarded refilter prevents ComboBox value/editor recursion. */
final class ContactPicker extends Selector<String> {
  private final List<String> contacts;private final FilteredList<String> filtered;private boolean changing;
  ContactPicker(List<String> names,ThemeManager themes){
    super(themes);
    contacts=names.stream().sorted(String.CASE_INSENSITIVE_ORDER).toList();filtered=new FilteredList<>(FXCollections.observableArrayList(contacts));setItems(filtered);setEditable(true);setMaxWidth(Double.MAX_VALUE);setVisibleRowCount(8);setPromptText("Найти контакт…");getEditor().setPromptText("Найти контакт…");themes.stylePopup(this);
    getSelectionModel().selectedItemProperty().addListener((o,a,b)->{if(changing||b==null)return;changing=true;try{getEditor().setText(b);}finally{changing=false;}});
    getEditor().textProperty().addListener((o,a,b)->{if(changing)return;filter(b);if(getEditor().isFocused()&&!b.isBlank()&&!isShowing())show();});
    setOnShowing(e->{String text=getEditor().getText();refilter(text,contacts.contains(text));});
  }
  void filter(String value){refilter(value,false);}
  private void refilter(String value,boolean all){
    if(changing)return;changing=true;int caret=getEditor().getCaretPosition();
    try{
      String query=value.toLowerCase(Locale.ROOT);filtered.setPredicate(name->all||name.toLowerCase(Locale.ROOT).contains(query));
      if(getValue()!=null&&!getValue().equals(value)){getSelectionModel().clearSelection();setValue(null);}
      getEditor().setText(value);getEditor().positionCaret(Math.min(value.length(),caret));
    }finally{changing=false;}
  }
}
