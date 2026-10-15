package org.securemail.ui;
import javafx.scene.control.*;
import javafx.scene.layout.*;
final class SecretField extends HBox {
  final PasswordField hidden=new PasswordField();
  private final TextField visible=new TextField();
  SecretField(String prompt){
    super(8);hidden.setPromptText(prompt);visible.setPromptText(prompt);
    visible.textProperty().bindBidirectional(hidden.textProperty());visible.setVisible(false);visible.setManaged(false);
    hidden.setTextFormatter(new TextFormatter<String>(change->change.getControlNewText().length()<=1024?change:null));
    visible.setTextFormatter(new TextFormatter<String>(change->change.getControlNewText().length()<=1024?change:null));
    Button eye=new Button("◉");eye.setTooltip(new Tooltip("Показать / скрыть"));
    eye.setOnAction(e->{boolean show=!visible.isVisible();visible.setVisible(show);visible.setManaged(show);hidden.setVisible(!show);hidden.setManaged(!show);});
    HBox.setHgrow(hidden,Priority.ALWAYS);HBox.setHgrow(visible,Priority.ALWAYS);getChildren().addAll(hidden,visible,eye);
  }
  char[] value(){return hidden.getText().toCharArray();}
  void clear(){hidden.clear();visible.clear();}
}

