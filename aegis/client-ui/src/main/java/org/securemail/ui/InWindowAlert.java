package org.securemail.ui;
import javafx.scene.control.*;
final class InWindowAlert extends InWindowDialog<ButtonType>{
  InWindowAlert(Alert.AlertType type,String text,ButtonType...buttons){setContentText(text);getDialogPane().getButtonTypes().addAll(buttons);setResultConverter(b->b);}
}
