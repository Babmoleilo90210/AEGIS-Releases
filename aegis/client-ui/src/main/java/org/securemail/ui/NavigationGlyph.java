package org.securemail.ui;

import javafx.scene.Node;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.SVGPath;
import javafx.scene.shape.StrokeLineCap;
import javafx.scene.shape.StrokeLineJoin;

/** Small locally defined geometric symbols, with no font or external-resource dependency. */
final class NavigationGlyph {
  static Node create(String name,int size){SVGPath path=new SVGPath();path.setContent(switch(name){
    case "letters"->"M3 5 H21 V19 H3 Z M3 5 L12 12 L21 5";
    case "safeweb"->"M12 2 A10 10 0 1 0 12 22 A10 10 0 1 0 12 2 M16 8 L14 14 L8 16 L10 10 Z";
    case "glas"->"M5 3 L9 3 L11 8 L8 10 Q10 14 14 16 L16 13 L21 15 L21 19 Q21 22 18 21 Q6 19 3 7 Q2 4 5 3 Z";
    case "archive"->"M3 4 H21 V8 H3 Z M5 8 V21 H19 V8 M9 12 H15";
    case "contacts"->"M4 3 H20 V21 H4 Z M9 8 A3 3 0 1 0 15 8 A3 3 0 1 0 9 8 M7 18 Q7 13 12 13 Q17 13 17 18";
    case "organizations"->"M3 8 A3 3 0 1 0 9 8 A3 3 0 1 0 3 8 M15 8 A3 3 0 1 0 21 8 A3 3 0 1 0 15 8 M1 21 Q1 14 6 14 Q11 14 11 21 M13 21 Q13 14 18 14 Q23 14 23 21";
    case "news"->"M4 3 H20 V21 H4 Z M7 7 H17 M7 11 H12 M7 15 H12 M15 11 H17 V16 H15 Z M7 18 H17";
    case "library"->"M10 10 L5 5 M14 10 L19 5 M10 14 L5 19 M14 14 L19 19 M9 12 A3 3 0 1 0 15 12 A3 3 0 1 0 9 12 M2 4 A2 2 0 1 0 6 4 A2 2 0 1 0 2 4 M18 4 A2 2 0 1 0 22 4 A2 2 0 1 0 18 4 M2 20 A2 2 0 1 0 6 20 A2 2 0 1 0 2 20 M18 20 A2 2 0 1 0 22 20 A2 2 0 1 0 18 20";
    case "friends"->"M4 9 A3 3 0 1 0 10 9 A3 3 0 1 0 4 9 M14 9 A3 3 0 1 0 20 9 A3 3 0 1 0 14 9 M2 21 Q2 14 7 14 Q12 14 12 21 M12 21 Q12 14 17 14 Q22 14 22 21";
    case "search"->"M3 10 A7 7 0 1 0 17 10 A7 7 0 1 0 3 10 M15 15 L22 22";
    case "profile"->"M9 7 A3 3 0 1 0 15 7 A3 3 0 1 0 9 7 M4 22 Q4 13 12 13 Q20 13 20 22";
    case "settings"->"M3 6 H21 M3 12 H21 M3 18 H21 M7 3 V9 M17 9 V15 M10 15 V21";
    default->"M4 4 H20 V20 H4 Z";});path.setFill(Color.TRANSPARENT);path.setStroke(Color.GRAY);path.setStrokeWidth(1.7);path.setStrokeLineCap(StrokeLineCap.ROUND);path.setStrokeLineJoin(StrokeLineJoin.ROUND);path.getStyleClass().add("glyph");path.setScaleX(size/24.0);path.setScaleY(size/24.0);StackPane icon=new StackPane(path);icon.setMinSize(size+10,size+10);icon.setPrefSize(size+10,size+10);icon.setMaxSize(size+10,size+10);icon.getStyleClass().add("nav-icon");return icon;}
}
