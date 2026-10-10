package org.securemail.ui;

import javafx.scene.Node;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.SVGPath;

/** Small locally defined geometric symbols, with no font or external-resource dependency. */
final class NavigationGlyph {
  static Node create(String name,int size){SVGPath path=new SVGPath();path.setContent(switch(name){
    case "letters"->"M3 5 H21 V19 H3 Z M3 5 L12 12 L21 5";
    case "contacts"->"M4 3 H20 V21 H4 Z M9 8 A3 3 0 1 0 15 8 A3 3 0 1 0 9 8 M7 18 Q7 13 12 13 Q17 13 17 18";
    case "friends"->"M4 9 A3 3 0 1 0 10 9 A3 3 0 1 0 4 9 M14 9 A3 3 0 1 0 20 9 A3 3 0 1 0 14 9 M2 21 Q2 14 7 14 Q12 14 12 21 M12 21 Q12 14 17 14 Q22 14 22 21";
    case "search"->"M3 10 A7 7 0 1 0 17 10 A7 7 0 1 0 3 10 M15 15 L22 22";
    case "profile"->"M9 7 A3 3 0 1 0 15 7 A3 3 0 1 0 9 7 M4 22 Q4 13 12 13 Q20 13 20 22";
    case "settings"->"M3 6 H21 M3 12 H21 M3 18 H21 M7 3 V9 M17 9 V15 M10 15 V21";
    default->"M4 4 H20 V20 H4 Z";});path.setFill(Color.TRANSPARENT);path.setStroke(Color.GRAY);path.setStrokeWidth(1.7);path.getStyleClass().add("glyph");path.setScaleX(size/24.0);path.setScaleY(size/24.0);StackPane icon=new StackPane(path);icon.setMinSize(size+10,size+10);icon.setMaxSize(size+10,size+10);icon.getStyleClass().add("nav-icon");return icon;}
}
