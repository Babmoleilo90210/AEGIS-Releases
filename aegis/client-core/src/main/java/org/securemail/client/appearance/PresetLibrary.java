package org.securemail.client.appearance;

import java.util.*;
import static org.securemail.client.appearance.Appearance.*;

/** Immutable local reference palettes. Exactly four new presets per visual category. */
public final class PresetLibrary {
  private static final Map<String,Theme> THEMES=create();
  private PresetLibrary(){}
  public static Map<String,Theme> builtins(){return THEMES;}
  public static Theme get(String id){return THEMES.get(id);}
  private static Map<String,Theme> create(){
    LinkedHashMap<String,Theme> m=new LinkedHashMap<>();
    add(m,"minimal-dark","Minimal Dark",Category.MINIMAL,dark("#15191f","#20262e","#303842","#82cbb7"),6,false,100);
    add(m,"minimal-light","Minimal Light",Category.MINIMAL,light("#f2f4f7","#ffffff","#e4e9ef","#24665a"),6,false,100);
    add(m,"minimal-graphite","Minimal Graphite",Category.MINIMAL,dark("#17191d","#24272d","#343941","#a8b8ca"),4,false,100);
    add(m,"minimal-pastel","Minimal Pastel",Category.MINIMAL,light("#f2eff8","#fcfbff","#e7e1f1","#66539a"),8,false,100);
    add(m,"deep-blue","Deep Blue",Category.DEPTH,dark("#101827","#1b283e","#2b3c58","#89b3ec"),14,true,100);
    add(m,"soft-violet","Soft Violet",Category.DEPTH,dark("#1b1727","#2a223b","#403350","#c0a1e4"),14,true,100);
    add(m,"forest-green","Forest Green",Category.DEPTH,dark("#0f1c18","#192e26","#294338","#8dc8a7"),14,true,100);
    add(m,"warm-sand","Warm Sand",Category.DEPTH,light("#efe6d9","#fbf5eb","#e3d5c3","#86552e"),14,true,100);
    add(m,"frost-blue","Frost Blue",Category.TRANSPARENT,light("#e7eef7","#f5f9ff","#dbe6f4","#355e93"),12,false,88);
    add(m,"glass-graphite","Glass Graphite",Category.TRANSPARENT,dark("#121820","#24303d","#344351","#a4c0dc"),12,false,88);
    add(m,"mist-green","Mist Green",Category.TRANSPARENT,light("#e7f0e9","#f4fbf6","#d9e8de","#366b51"),12,false,90);
    add(m,"soft-lavender","Soft Lavender",Category.TRANSPARENT,light("#edeaf7","#f8f6ff","#e0daf0","#635588"),12,false,90);
    add(m,"classic-light","Classic Light",Category.CLASSIC,light("#f0f1f3","#ffffff","#dfe3e8","#365882"),3,false,100);
    add(m,"classic-dark","Classic Dark",Category.CLASSIC,dark("#191d23","#252b34","#363e49","#97b6de"),3,false,100);
    add(m,"classic-blue","Classic Blue",Category.CLASSIC,light("#e4eaf2","#f7faff","#d4dfee","#315d92"),3,false,100);
    add(m,"classic-sepia","Classic Sepia",Category.CLASSIC,light("#eee5d4","#fbf3e4","#ded0b7","#79582b"),3,false,100);
    add(m,"legacy-black","Чёрная",Category.LEGACY,new Palette("#090b0e","#111419","#20252d","#e5e8ee","#89949f","#82cbb7","#232a34","#23423c"),6,false,100);
    add(m,"legacy-dark","Тёмно-серая",Category.LEGACY,new Palette("#15191f","#20262e","#303842","#e5e9ef","#a1acb8","#82cbb7","#232a34","#23423c"),6,false,100);
    add(m,"legacy-dark-green","Тёмно-зелёная",Category.LEGACY,new Palette("#0c1812","#14271d","#263e30","#edf4ee","#a7bdae","#85c89a","#1b3024","#284a35"),6,false,100);
    add(m,"legacy-grey","Серая",Category.LEGACY,new Palette("#353a41","#424951","#535d66","#f2f4f6","#c0c8cf","#82cbb7","#424951","#535d66"),6,false,100);
    add(m,"legacy-light","Светло-серая",Category.LEGACY,new Palette("#d7dce1","#e4e8ec","#c5cdd4","#1a2630","#536371","#205947","#e4e8ec","#c5cdd4"),6,false,100);
    add(m,"legacy-white","Белая",Category.LEGACY,new Palette("#f6f8fa","#ffffff","#e0e6eb","#19232c","#64717c","#205947","#ffffff","#e0e6eb"),6,false,100);
    return Collections.unmodifiableMap(m);
  }
  private static void add(Map<String,Theme> m,String id,String name,Category category,Palette palette,int radius,boolean shadow,int alpha){m.put(id,new Theme(id,name,category,palette,radius,shadow,alpha));}
  private static Palette dark(String bg,String panel,String control,String accent){return new Palette(bg,panel,control,"#eef2f6","#b5bfcb",accent,panel,control);}
  private static Palette light(String bg,String panel,String control,String accent){return new Palette(bg,panel,control,"#1a2630","#53616e",accent,panel,control);}
}
