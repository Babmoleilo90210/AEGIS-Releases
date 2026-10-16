package org.securemail.ui;

import com.google.gson.*;
import javafx.scene.canvas.*;
import javafx.scene.control.Label;
import javafx.scene.input.*;
import javafx.scene.layout.*;
import javafx.scene.paint.*;
import java.util.*;
import java.util.function.Consumer;
import static org.securemail.ui.CommunityUi.*;

/** Bounded canvas graph. Only server-filtered nodes and edges enter the view. No hidden-node counts. */
final class KnowledgeGraph extends Pane {
  private final Canvas canvas=new Canvas();private final Label textToken=new Label(),accentToken=new Label();private final Map<String,Point> positions=new LinkedHashMap<>();private List<JsonObject> nodes=List.of(),edges=List.of();private final Consumer<JsonObject> selected;private double zoom=1,panX,panY,lastX,lastY;private String dragged="",current="";private final java.util.prefs.Preferences preferences=java.util.prefs.Preferences.userRoot().node("org/aegis/library-viewport");
  private record Point(double x,double y){}
  KnowledgeGraph(Consumer<JsonObject> selected){this.selected=selected;setId("library-knowledge-graph");setMinSize(120,160);setPrefSize(600,460);textToken.setStyle("-fx-text-fill:-aegis-text;");accentToken.setStyle("-fx-text-fill:-aegis-accent;");textToken.setVisible(false);accentToken.setVisible(false);textToken.setManaged(false);accentToken.setManaged(false);getChildren().addAll(canvas,textToken,accentToken);zoom=Math.max(.25,Math.min(3,preferences.getDouble("zoom",1)));panX=preferences.getDouble("x",0);panY=preferences.getDouble("y",0);widthProperty().addListener((o,a,b)->draw());heightProperty().addListener((o,a,b)->draw());setOnScroll(e->{double old=zoom;zoom=Math.max(.25,Math.min(3,zoom*Math.exp(e.getDeltaY()*.0015)));panX=e.getX()-(e.getX()-panX)*zoom/old;panY=e.getY()-(e.getY()-panY)*zoom/old;save();draw();e.consume();});setOnMousePressed(e->{lastX=e.getX();lastY=e.getY();dragged=hit(e.getX(),e.getY());});setOnMouseDragged(e->{double dx=e.getX()-lastX,dy=e.getY()-lastY;if(!dragged.isEmpty()){Point p=positions.get(dragged);positions.put(dragged,new Point(p.x+dx/zoom,p.y+dy/zoom));}else{panX+=dx;panY+=dy;}lastX=e.getX();lastY=e.getY();draw();});setOnMouseReleased(e->{save();dragged="";});setOnMouseClicked(e->{if(e.isStillSincePress()){current=hit(e.getX(),e.getY());nodes.stream().filter(n->str(n,"id").equals(current)).findFirst().ifPresent(selected);draw();}});}
  void data(List<JsonObject> loaded,List<JsonObject> links){nodes=List.copyOf(loaded.stream().limit(500).toList());Set<String> ids=new HashSet<>();for(JsonObject n:nodes)ids.add(str(n,"id"));edges=links.stream().filter(e->ids.contains(str(e,"from"))&&ids.contains(str(e,"to"))).limit(2000).toList();positions.keySet().retainAll(ids);for(int i=0;i<nodes.size();i++){String id=str(nodes.get(i),"id");double angle=i*2.399963229728653,radius=35*Math.sqrt(i);positions.putIfAbsent(id,new Point(240+Math.cos(angle)*radius,220+Math.sin(angle)*radius));}draw();}
  void reset(){zoom=1;panX=panY=0;save();draw();}
  private String hit(double x,double y){for(JsonObject n:nodes){String id=str(n,"id");Point point=positions.get(id);if(Math.hypot(x-(point.x*zoom+panX),y-(point.y*zoom+panY))<14*zoom+5)return id;}return "";}
  private void save(){preferences.putDouble("zoom",zoom);preferences.putDouble("x",panX);preferences.putDouble("y",panY);}
  private void draw(){canvas.setWidth(getWidth());canvas.setHeight(getHeight());GraphicsContext g=canvas.getGraphicsContext2D();g.clearRect(0,0,canvas.getWidth(),canvas.getHeight());Paint text=textToken.getTextFill(),accent=accentToken.getTextFill();Set<String> neighbors=new HashSet<>();for(JsonObject e:edges){String from=str(e,"from"),to=str(e,"to");if(from.equals(current))neighbors.add(to);if(to.equals(current))neighbors.add(from);Point a=positions.get(from),b=positions.get(to);g.setStroke(from.equals(current)||to.equals(current)?accent:text);g.setGlobalAlpha(from.equals(current)||to.equals(current)?.8:.2);g.setLineWidth(1);g.strokeLine(a.x*zoom+panX,a.y*zoom+panY,b.x*zoom+panX,b.y*zoom+panY);}g.setGlobalAlpha(1);for(JsonObject node:nodes){String id=str(node,"id");Point p=positions.get(id);double x=p.x*zoom+panX,y=p.y*zoom+panY,r=(id.equals(current)?10:7)*zoom;g.setFill(id.equals(current)||neighbors.contains(id)?accent:text);g.fillOval(x-r,y-r,r*2,r*2);String title=title(node);if(title.length()>38)title=title.substring(0,36)+"…";g.fillText(title,x+11*zoom,y+4,220);}}
}
