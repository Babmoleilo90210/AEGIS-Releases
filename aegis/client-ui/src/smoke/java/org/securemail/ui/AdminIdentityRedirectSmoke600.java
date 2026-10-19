package org.securemail.ui;

import com.google.gson.JsonObject;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javafx.application.Platform;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;

/** UI-only fixture verifies the Core 6 route; Identity authorization is tested through real HTTP/SQL separately. */
public final class AdminIdentityRedirectSmoke600 {
  private static <T>T fx(Callable<T> action)throws Exception{var f=new CompletableFuture<T>();Platform.runLater(()->{try{f.complete(action.call());}catch(Throwable error){f.completeExceptionally(error);}});return f.get(20,TimeUnit.SECONDS);}
  private static void check(boolean test,String message){if(!test)throw new AssertionError(message);}
  private static Button button(Parent root,String text){return root.lookupAll(".button").stream().filter(n->n instanceof Button b&&b.getText().equals(text)).map(n->(Button)n).findFirst().orElseThrow();}
  private static void await(Callable<Boolean> ready)throws Exception{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(System.nanoTime()<until){if(fx(ready))return;Thread.sleep(30);}throw new AssertionError("JavaFX page did not settle");}
  public static void main(String[]args)throws Exception {
    Platform.startup(()->Platform.setImplicitExit(false));ThemeManager theme=fx(ThemeManager::new);AtomicInteger callback=new AtomicInteger();List<String> calls=new CopyOnWriteArrayList<>();CommunityUi api=fx(()->new CommunityUi(theme,(action,data)->{calls.add(action);return action.equals("community.me")?CommunityUi.obj("isAdmin",true,"permissions",new com.google.gson.JsonArray()):new JsonObject();},(CommunityUi.DelegatedStepUp)()->"synthetic step up",url->{}));BorderPane root=fx(BorderPane::new);Stage stage=fx(()->{Stage s=new Stage();s.setScene(new Scene(root,1024,768));s.getScene().getStylesheets().add(Objects.requireNonNull(AdminView.class.getResource("messenger.css")).toExternalForm());theme.initialize();theme.apply(root);s.show();return s;});
    try {
      fx(()->{root.setCenter(new AdminView(api,callback::incrementAndGet).node());return null;});await(()->!root.lookupAll(".button").isEmpty());fx(()->{root.applyCss();root.layout();button(root,"Роли и уровни").fire();return null;});await(()->!root.lookupAll(".titled-pane").isEmpty());fx(()->{for(Node node:root.lookupAll(".titled-pane"))if(node instanceof TitledPane pane&&pane.getText().equals("Глобальная администрация"))pane.setExpanded(true);root.applyCss();root.layout();return null;});
      fx(()->{check(root.lookupAll(".button").stream().noneMatch(n->n instanceof Button b&&Set.of("Запросить выдачу полномочий","Запросить отзыв полномочий").contains(b.getText())),"Core 6 exposes legacy ineffective administrator writes");button(root,"Администраторы и восстановление").fire();return null;});check(callback.get()==1,"Core 6 Identity route not invoked exactly once");check(calls.stream().noneMatch(s->s.startsWith("admin.administrators.")),"Core 6 submitted a legacy administrator RPC");
      System.out.println("PASS_HEADLESS: Core 6 administrator controls route to typed Identity callback; legacy administrator grant/revoke controls and RPC absent. Scope=actual JavaFX with UI data fixture, not authorization/native acceptance.");
    }finally{fx(()->{api.close();theme.close();stage.close();Platform.exit();return null;});}
  }
}
