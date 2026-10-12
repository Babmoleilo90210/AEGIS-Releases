package org.securemail.ui;

/** Uses logical pixels after user scale. Does not modify fonts, saved layouts or DPI. */
final class ResponsiveGeometry {
  private ResponsiveGeometry(){}
  static double inset(double width){return Math.max(8,Math.min(24,8+Math.max(0,width-700)/80));}
  static double spacing(double width,int configured){return configured+Math.min(4,Math.max(0,width-1100)/250);}
  static double avatar(double width,int configured){return configured+Math.min(8,Math.max(0,width-1100)/100);}
}
