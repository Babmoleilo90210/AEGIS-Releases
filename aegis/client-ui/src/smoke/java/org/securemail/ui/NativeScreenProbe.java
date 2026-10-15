package org.securemail.ui;

import javafx.application.Platform;
import javafx.stage.Screen;
import java.util.concurrent.*;

/** Reports the actual native screen. Never forces Monocle or modifies OS DPI settings. */
public final class NativeScreenProbe {
  public static void main(String[] args)throws Exception {
    var done=new CompletableFuture<Void>();
    Platform.startup(()->Platform.runLater(()->{
      try {
        Screen screen=Screen.getPrimary();
        boolean nativeToolkit=!"Monocle".equalsIgnoreCase(System.getProperty("glass.platform",""));
        System.out.println("AEGIS_SCREEN {\"outputScaleX\":"+screen.getOutputScaleX()+",\"outputScaleY\":"+screen.getOutputScaleY()+",\"dpi\":"+screen.getDpi()+",\"nativeToolkit\":"+nativeToolkit+"}");
        done.complete(null);
      } catch(Throwable error){done.completeExceptionally(error);}
    }));
    try {done.get(20,TimeUnit.SECONDS);} finally {Platform.exit();}
  }
}
