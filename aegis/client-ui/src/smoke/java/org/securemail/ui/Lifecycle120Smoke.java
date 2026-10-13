package org.securemail.ui;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.*;

/** Actual JavaFX display and guarded manual reveal. No production accounts/network or keys. */
public final class Lifecycle120Smoke {
  public static void main(String[] args)throws Exception {
    Path profile=Files.createTempDirectory("aegis120-lifecycle-ui-");System.setProperty("aegis.profile",profile.toString());Platform.startup(()->Platform.setImplicitExit(false));
    var worker=Executors.newSingleThreadExecutor();AtomicInteger displayed=new AtomicInteger();long now=System.currentTimeMillis();var sender=Identity.create();var recipient=Identity.create();var crypto=new AutomaticEncryption(java.time.Clock.systemUTC());
    PlainMessage plain=PlainMessage.letter("Защищённое письмо",LetterEnvelope.seal("DISPLAY EVENT FIXTURE","letter-password-123".toCharArray(),"manual-FF1".toCharArray()),null,100000);
    var packet=crypto.encrypt(plain,86400,86400000,sender,"raven",new UserInfo(recipient.userId(),"blackfox",recipient.publicKey(),null));
    var item=new LocalStore.HistoryItem(packet.messageId(),"raven",false,"Получено",now,now+86400000,packet);VBox host=new VBox();
    Stage stage=MessengerSmoke.fx(()->{var window=new Stage();window.setScene(new Scene(new BorderPane(host),1000,800));window.show();return window;});
    MailViewer viewer=MessengerSmoke.fx(()->{
      var themes=new ThemeManager();var actions=new MailViewer.Actions(){public void reply(LocalStore.HistoryItem i,PlainMessage p){}public void forward(LocalStore.HistoryItem i,PlainMessage p,String s,PlainMessage.FileBundle b){}public void original(MailContext c){}public boolean unknown(){return false;}public void displayed(){displayed.incrementAndGet();}};
      return new MailViewer(stage,themes,plain,item,worker,System::currentTimeMillis,host,actions);
    });
    try{
      MessengerSmoke.fx(()->{var password=(PasswordField)MessengerSmoke.get(viewer,"password");password.setText("letter-password-123");host.lookupAll(".button").stream().filter(n->n instanceof Button b&&b.getText().equals("Открыть")).map(n->(Button)n).findFirst().orElseThrow().fire();return null;});
      MessengerSmoke.until(()->MessengerSmoke.get(viewer,"opened")!=null);
      MessengerSmoke.fx(()->{MessengerSmoke.check(displayed.get()==0,"Entering letter password falsely acknowledged read");((SecretField)MessengerSmoke.get(viewer,"code")).hidden.setText("manual-FF1");MessengerSmoke.check(displayed.get()==0,"Typing FF1 falsely acknowledged read");host.lookupAll(".button").stream().filter(n->n instanceof Button b&&b.getText().equals("Показать результат")).map(n->(Button)n).findFirst().orElseThrow().fire();return null;});
      MessengerSmoke.until(()->displayed.get()==1);
      MessengerSmoke.fx(()->{MessengerSmoke.check(!((TextArea)MessengerSmoke.get(viewer,"text")).getText().isEmpty(),"No body displayed");MessengerSmoke.check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Lifecycle opened another window");return null;});
      System.out.println("Lifecycle120Smoke PASS: actual body display event, no read on password/FF1 entry, explicit final reveal, one Stage; native Windows11/KDE NOT_RUN");
    }finally{MessengerSmoke.fx(()->{viewer.close();stage.close();Platform.exit();return null;});worker.shutdownNow();}
  }
}
