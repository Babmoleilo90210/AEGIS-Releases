package org.securemail.ui;

import java.io.*;
import java.util.*;
import javafx.scene.text.Font;

/** Licensed local TTF resources. Loading never opens a URL or downloads anything. */
final class BundledFonts {
  static final List<String> REQUIRED=List.of("Noto Sans","Inter","Roboto","PT Sans","DejaVu Sans");
  private static final String CYRILLIC="АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюяABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  private static final Map<String,Boolean> loaded=new LinkedHashMap<>();
  private static boolean initialized;
  private BundledFonts(){}
  static synchronized void load(){
    if(initialized)return;initialized=true;
    String[] stems={"NotoSans","Inter","Roboto","PTSans","DejaVuSans"};
    for(int i=0;i<stems.length;i++){
      String family=REQUIRED.get(i);boolean complete=true;
      for(String weight:List.of("Regular","Bold")){
        try(InputStream in=BundledFonts.class.getResourceAsStream("fonts/"+stems[i]+"-"+weight+".ttf")){
          if(in==null)throw new IOException("Missing bundled font");byte[] bytes=in.readNBytes(2*1024*1024+1);
          if(bytes.length>2*1024*1024)throw new IOException("Font size limit");
          try{
            java.awt.Font checked=java.awt.Font.createFont(java.awt.Font.TRUETYPE_FONT,new ByteArrayInputStream(bytes));
            if(checked.canDisplayUpTo(CYRILLIC)!=-1)throw new IOException("Cyrillic glyphs missing");
            Font font=Font.loadFont(new ByteArrayInputStream(bytes),14);
            if(font==null||!font.getFamily().equals(family))throw new IOException("JavaFX family mismatch");
          }finally{Arrays.fill(bytes,(byte)0);}
        }catch(IOException|java.awt.FontFormatException|RuntimeException invalid){complete=false;}
      }
      loaded.put(family,complete);
    }
  }
  static List<String> families(){load();return Font.getFamilies().stream().filter(s->s.matches("[\\p{L}\\p{N} _.-]{1,64}")).filter(BundledFonts::cyrillic).sorted().toList();}
  static boolean cyrillic(String family){load();if(family.equals("System"))return true;if(loaded.containsKey(family))return loaded.get(family);return new java.awt.Font(family,java.awt.Font.PLAIN,14).canDisplayUpTo(CYRILLIC)==-1;}
  static boolean available(String family){load();return family.equals("System")||Font.getFamilies().contains(family)&&cyrillic(family);}
  static Map<String,Boolean> verified(){load();return Map.copyOf(loaded);}
}
