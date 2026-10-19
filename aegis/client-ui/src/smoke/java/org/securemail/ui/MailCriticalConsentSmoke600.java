package org.securemail.ui;

import java.lang.reflect.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import org.securemail.client.ecosystem.*;
import org.securemail.client.ecosystemauth.CorePublicConfig600;
import org.securemail.client.storage.LocalStore;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Actual consent rendering with a real Mail vault, explicitly bypassing only the unavailable live setup in this test harness. */
public final class MailCriticalConsentSmoke600 {
  private static <T>T fx(Callable<T> task)throws Exception{var result=new CompletableFuture<T>();Platform.runLater(()->{try{result.complete(task.call());}catch(Throwable failure){result.completeExceptionally(failure);}});return result.get(20,TimeUnit.SECONDS);}
  private static Object field(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
  private static void set(Object object,String name,Object value)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);f.set(object,value);}
  private static List<Node> nodes(Node root){List<Node> result=new ArrayList<>();result.add(root);if(root instanceof Parent parent)for(Node node:parent.getChildrenUnmodifiable())result.addAll(nodes(node));return result;}
  private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
  private static void screenshot(Stage stage,Path path)throws Exception{Parent root=stage.getScene().getRoot();root.applyCss();root.layout();var image=stage.getScene().snapshot(null);var output=new java.awt.image.BufferedImage((int)image.getWidth(),(int)image.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);for(int y=0;y<output.getHeight();y++)for(int x=0;x<output.getWidth();x++)output.setRGB(x,y,image.getPixelReader().getArgb(x,y));javax.imageio.ImageIO.write(output,"png",path.toFile());}
  public static void main(String[] args)throws Exception {
    Path output=Path.of(args[0]),profile=Files.createTempDirectory("aegis-critical-mail6-");Files.createDirectories(output);System.setProperty("aegis.profile",profile.toString());var ready=new CompletableFuture<Void>();Platform.startup(()->{Platform.setImplicitExit(false);ready.complete(null);});ready.get();
    try(var mail=new LocalStore(profile.resolve("mail"),"critical consent synthetic Mail password".toCharArray(),Clock.systemUTC(),200000,4000000)){
      mail.bindNickname("raven");var keys=KeyPairGenerator.getInstance("Ed25519");KeyPair service=keys.generateKeyPair(),target=keys.generateKeyPair(),app=keys.generateKeyPair();var config=new CorePublicConfig600("a".repeat(56)+".onion",80,service.getPublic().getEncoded(),19350);var account=new KeyPair(KeyFactory.getInstance("Ed25519").generatePublic(new java.security.spec.X509EncodedKeySpec(mail.identity().publicKey())),null);var cap=MailOwnerTransferAuthorizationSmoke600.cap(service,account,app,"ab".repeat(32));long expires=System.currentTimeMillis()+100000;
      var transfer=new IdentityProtocol.OwnerTransfer(cap.audience,IdentityProtocol.nonce(),cap.accountId,cap.deviceId,3,IdentityProtocol.id(target.getPublic().getEncoded()),"cd".repeat(32),3,7,expires);var delegation=new IdentityProtocol.FirstDelegation(cap.audience,cap.accountId,cap.deviceId,3,transfer.targetAccountId,transfer.targetDeviceId,3,"Уполномоченный администратор",IdentityProtocol.nonce(),expires);
      List<MailPairing600.Request> requests=List.of(MailOwnerTransferAuthorizationSmoke600.request(cap,app,transfer,IdentityProtocol.OwnerTransferRole.OWNER_APPROVE),MailFirstDelegateAuthorizationSmoke600.request(cap,app,delegation,IdentityProtocol.FirstDelegateRole.OWNER_APPROVE),MailOwnerBootstrapAuthorizationSmoke600.request(cap,app,new IdentityProtocol.OwnerBootstrap(cap.audience,cap.accountId,IdentityProtocol.nonce(),System.currentTimeMillis()+240000)));int frame=0;
      for(var request:requests){String name=switch(frame++){case 0->"owner-transfer-consent";case 1->"first-delegate-consent";default->"owner-bootstrap-consent";};fx(()->{var window=new MailPairingEntrypoint600.PairingWindow();ThemeManager themes=(ThemeManager)field(window,"themes");themes.initialize();Stage stage=new Stage();VBox content=new VBox(12);content.setPadding(new javafx.geometry.Insets(20));content.setMaxWidth(700);ScrollPane scroll=new ScrollPane(content);scroll.setFitToWidth(true);BorderPane shell=new BorderPane(scroll);stage.setScene(new Scene(shell,800,600));themes.apply(shell);stage.show();Class<?> prepared=Class.forName("org.securemail.ui.MailPairingEntrypoint600$Prepared");Constructor<?> ctor=prepared.getDeclaredConstructors()[0];ctor.setAccessible(true);Object context=ctor.newInstance(null,request,config,null);set(window,"stage",stage);set(window,"content",content);set(window,"context",context);set(window,"state",new Label());set(window,"mail",mail);Method consent=window.getClass().getDeclaredMethod("consent");consent.setAccessible(true);consent.invoke(window);CheckBox checkbox=nodes(content).stream().filter(n->n instanceof CheckBox).map(n->(CheckBox)n).findFirst().orElseThrow();Button confirm=nodes(content).stream().filter(n->n instanceof Button b&&b.getText().equals("Подтвердить")).map(n->(Button)n).findFirst().orElseThrow();check(!checkbox.isSelected()&&confirm.isDisabled(),"Critical consent was automatic");String labels=nodes(content).stream().filter(n->n instanceof Labeled).map(n->((Labeled)n).getText()).reduce("",(a,b)->a+"\n"+b);check(labels.contains(request instanceof MailPairing600.OwnerBootstrapRequest?cap.accountId:transfer.targetAccountId),"Target account missing from actual consent UI");if(request instanceof MailPairing600.OwnerBootstrapRequest)check(labels.contains(cap.audience)&&labels.contains("CLI"),"Bootstrap omitted operator trust fingerprint/CLI boundary");checkbox.setSelected(true);check(!confirm.isDisabled(),"Explicit consent did not enable confirmation");checkbox.setSelected(false);check(confirm.isDisabled(),"Withdrawn consent remained active");screenshot(stage,output.resolve(name+".png"));((ExecutorService)field(window,"worker")).shutdownNow();themes.close();stage.hide();return null;});}
      System.out.println("PASS: actual Mail OwnerTransfer/FirstDelegate/OwnerBootstrap consent UI, full target fingerprint/role text and unchecked-required reversible consent. 3 real Monocle PNGs. Scope=real vault+local typed fixtures; live server, proof emission and native acceptance NOT_RUN here.");
    }finally{Platform.exit();}
  }
}
