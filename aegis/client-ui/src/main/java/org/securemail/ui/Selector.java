package org.securemail.ui;

import javafx.scene.control.ComboBox;
import java.util.*;

/** Every selector uses JavaFX's separate PopupControl window, never an in-layout overlay. */
class Selector<T> extends ComboBox<T> {
  Selector(ThemeManager themes){setVisibleRowCount(8);setMinWidth(0);setMaxWidth(Double.MAX_VALUE);themes.stylePopup(this);}
  Selector(ThemeManager themes,Collection<T> values,T selected){this(themes);getItems().setAll(values);setValue(selected);}
}
