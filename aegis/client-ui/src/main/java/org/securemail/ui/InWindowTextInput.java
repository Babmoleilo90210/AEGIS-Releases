package org.securemail.ui;
import javafx.scene.control.*;
final class InWindowTextInput extends InWindowDialog<String>{
  InWindowTextInput(){this("");}
  InWindowTextInput(String value){TextField text=new TextField(value);text.setPromptText("Введите значение");setTitle("Название");getDialogPane().setContent(text);getDialogPane().getButtonTypes().addAll(ButtonType.OK,ButtonType.CANCEL);setResultConverter(b->b==ButtonType.OK?text.getText():null);}
}
