package org.securemail.ui;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.*;
import org.securemail.client.*;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;
import org.securemail.client.update.*;

public final class MessengerSmoke {
 static Object get(Object object,String field)throws Exception{var f=object.getClass().getDeclaredField(field);f.setAccessible(true);return f.get(object);}
 static void set(Object app,String field,Object value)throws Exception{var f=MessengerApp.class.getDeclaredField(field);f.setAccessible(true);f.set(app,value);}
 static <T> T fx(Callable<T> action)throws Exception{
   var result=new CompletableFuture<T>();Platform.runLater(()->{try{result.complete(action.call());}catch(Throwable e){result.completeExceptionally(e);}});return result.get(30,TimeUnit.SECONDS);
 }
 static void check(boolean condition,String reason){if(!condition)throw new AssertionError(reason);}
 static void until(Callable<Boolean> condition)throws Exception{
   long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);
   while(System.nanoTime()<end){if(fx(condition))return;Thread.sleep(100);}throw new AssertionError("Timed out waiting for UI");
 }
 static void snapshot(Stage stage,Path path)throws Exception{
   stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();
   var image=stage.getScene().snapshot(null);var pixels=image.getPixelReader();
   var bitmap=new java.awt.image.BufferedImage((int)image.getWidth(),(int)image.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);
   for(int y=0;y<bitmap.getHeight();y++)for(int x=0;x<bitmap.getWidth();x++)bitmap.setRGB(x,y,pixels.getArgb(x,y));
   javax.imageio.ImageIO.write(bitmap,"png",path.toFile());
 }
 public static void main(String[] args)throws Exception{
   Path temp=Files.createTempDirectory("aegis-03-ui-test");System.setProperty("aegis.profile",temp.toString());
   Path out=Path.of("build/ui-smoke").toAbsolutePath();Files.createDirectories(out);
   ClientConfig config=ClientConfig.load(temp.resolve("none.properties"));
   var session=new ClientSession(config,"smoke vault password 42".toCharArray());session.local().bindNickname("blackfox");
   var sender=Identity.create();var raven=new UserInfo(sender.userId(),"raven",sender.publicKey(),null);session.local().trust(raven);
   String original="Письмо АЕГИС 🦊\nТекст меняется сразу при вводе кода.";
   var crypto=new AutomaticEncryption(Clock.systemUTC());EncryptedPacket packet;
   try(var p=PlainMessage.letter("Проверка письма",LetterEnvelope.seal(original,"Frost-8134".toCharArray(),"Raven-821".toCharArray()),null,10000)){
     packet=crypto.encrypt(p,1800,86400000,sender,"raven",new UserInfo(session.local().identity().userId(),"blackfox",session.local().identity().publicKey(),null));
   }
   session.local().accept(packet);var item=session.local().loadHistory(packet.messageId(),false);
   ExecutorService worker=Executors.newSingleThreadExecutor();MessengerApp app=new MessengerApp();
   CompletableFuture<Void> startup=new CompletableFuture<>();Platform.startup(()->{Platform.setImplicitExit(false);startup.complete(null);});startup.get();
   Stage owner=fx(()->{
     Stage stage=new Stage();BorderPane root=new BorderPane();var scene=new Scene(root,1020,730);scene.getStylesheets().add(MessengerApp.class.getResource("messenger.css").toExternalForm());stage.setScene(scene);stage.show();
     set(app,"stage",stage);set(app,"root",root);set(app,"config",config);
     set(app,"presets",new UiPresetStore(temp));set(app,"updates",new UpdateService(temp,19050));set(app,"updatePreferences",UpdatePreferences.load(temp));
     var themes=(ThemeManager)get(app,"themes");themes.apply(root);
     app.serverPage();snapshot(stage,out.resolve("server.png"));app.loginPage();snapshot(stage,out.resolve("login.png"));app.registerPage();snapshot(stage,out.resolve("registration.png"));
     set(app,"session",session);app.mainPage();return stage;
   });
   try{
     until(()->((ListView<?>)get(app,"letters")).getItems().size()==1);
     fx(()->{var change=MessengerApp.class.getDeclaredMethod("updateChanged",UpdateService.Snapshot.class);change.setAccessible(true);SignedManifest release=new SignedManifest("1.1.1","stable","1.0.0","optional",new SignedManifest.Announcement("Update","UI-only fixture",true),new SignedManifest.Notes("2026-10-08T00:00:00Z","Fix","UI-only fixture"),java.util.List.of(),null,null);change.invoke(app,new UpdateService.Snapshot(UpdateService.State.AVAILABLE,0,72,release,false,"Доступно обновление"));check(((Button)get(app,"updateBadge")).isVisible(),"Update badge absent");change.invoke(app,new UpdateService.Snapshot(UpdateService.State.FAILED,0,0,null,false,"Подпись отклонена"));check(!((Button)get(app,"updateBadge")).isVisible(),"Invalid update displayed trusted badge");return null;});
     fx(()->{snapshot(owner,out.resolve("inbox.png"));app.composePage();snapshot(owner,out.resolve("compose.png"));return null;});
     var themes=(ThemeManager)fx(()->get(app,"themes"));
     for(var theme:ThemeManager.Theme.values())fx(()->{themes.select(theme);snapshot(owner,out.resolve("theme-"+theme.name()+".png"));return null;});
     fx(()->{themes.select(ThemeManager.Theme.DARK);return null;});
     AtomicLong now=new AtomicLong(System.currentTimeMillis());
     MailViewer viewer=fx(()->new MailViewer(owner,themes,crypto.decrypt(packet,session.local().identity(),10000),item,worker,now::get));
     PasswordField password=(PasswordField)fx(()->get(viewer,"password"));TextArea text=(TextArea)fx(()->get(viewer,"text"));
     Label error=(Label)fx(()->get(viewer,"error"));
     Button unlock=fx(()->((HBox)((VBox)get(viewer,"content")).getChildren().get(3)).getChildren().stream().filter(n->n instanceof Button).map(n->(Button)n).findFirst().orElseThrow());
     fx(()->{password.setText("wrong-password");unlock.fire();return null;});
     until(()->error.getText().equals("Неверный пароль письма."));
     check(fx(()->text.getText().isEmpty()),"Unauthenticated output was displayed");
     fx(()->{password.setText("Frost-8134");unlock.fire();return null;});
     until(()->get(viewer,"opened")!=null);
     SecretField code=(SecretField)fx(()->get(viewer,"code"));
     fx(()->{snapshot((Stage)get(viewer,"stage"),out.resolve("letter-ff1.png"));code.hidden.setText("wrong");return null;});
     until(()->!text.getText().isEmpty());
     check(!fx(()->text.getText()).equals(original),"Wrong code decrypted text");
     fx(()->{for(String input:new String[]{"R","Ra","Rav","Rave","Raven-821"})code.hidden.setText(input);return null;});
     until(()->text.getText().equals(original));
     fx(()->{snapshot((Stage)get(viewer,"stage"),out.resolve("letter-open.png"));viewer.close();return null;});
     check(fx(()->text.getText().isEmpty()&&code.hidden.getText().isEmpty()),"View retained secrets after close");
     var reopened=fx(()->new MailViewer(owner,themes,crypto.decrypt(packet,session.local().identity(),10000),item,worker,now::get));
     check(fx(()->get(reopened,"opened")==null),"Reopen bypassed password");
     now.set(item.expiresAt()+1);until(()->!reopened.showing());
     System.out.println("Mail GUI passed: inbox, compose, five themes, wrong password, FF1 live typing, stale-result prevention, close/reopen, TTL view close");
   }finally{worker.shutdownNow();fx(()->{app.stop();return null;});}
 }
}

