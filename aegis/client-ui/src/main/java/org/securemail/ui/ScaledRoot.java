package org.securemail.ui;

import javafx.scene.Parent;
import javafx.scene.layout.Region;
import javafx.scene.transform.Scale;

/** Scales layout and painting together in JavaFX logical pixels, independently of OS DPI. */
final class ScaledRoot extends Region {
  private final Parent content;
  private final Scale transform=new Scale(1,1,0,0);
  private double factor=1;
  ScaledRoot(Parent content){
    this.content=content;getChildren().add(content);content.getTransforms().add(transform);
    getStyleClass().add("scaled-root");
  }
  void scale(int percent){factor=percent/100.0;transform.setX(factor);transform.setY(factor);requestLayout();}
  Parent content(){return content;}
  @Override protected void layoutChildren(){
    content.resizeRelocate(0,0,getWidth()/factor,getHeight()/factor);
  }
  @Override protected double computePrefWidth(double height){return content.prefWidth(height<0?-1:height/factor)*factor;}
  @Override protected double computePrefHeight(double width){return content.prefHeight(width<0?-1:width/factor)*factor;}
  @Override protected double computeMinWidth(double height){return 0;}
  @Override protected double computeMinHeight(double width){return 0;}
}
