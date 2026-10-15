package org.securemail.ui;

import java.nio.file.*;
import java.util.concurrent.*;
import javafx.animation.PauseTransition;
import javafx.application.Platform;
import javafx.stage.Stage;
import javafx.util.Duration;
import org.securemail.client.*;
import org.securemail.client.crypto.*;
import org.securemail.protocol.*;

/** Development-only visual smoke test. No Tor and no external network. */
public final class UiSmoke {
  private UiSmoke() {}

  public static void main(String[] args) throws Exception {
    Path temp = Files.createTempDirectory("aegis-ui-smoke-");
    System.setProperty("user.home", temp.toString());
    Path output = Path.of("build/ui-smoke").toAbsolutePath();
    Files.createDirectories(output);
    CompletableFuture<Void> done = new CompletableFuture<>();
    Platform.startup(
        () -> {
          AegisApp app = new AegisApp();
          Stage stage = new Stage();
          try {
            app.start(stage);
            snapshot(stage, output.resolve("login.png"));
            invoke(app, "settingsPage");
            snapshot(stage, output.resolve("settings.png"));
            ClientSession session =
                new ClientSession(
                    ClientConfig.load(temp.resolve("missing.properties")),
                    "smoke test vault password".toCharArray());
            session.local().bindNickname("blackfox");
            Identity raven = Identity.create();
            session.local().trust(new UserInfo(raven.userId(), "raven", raven.publicKey(), null));
            try (var text = PlainMessage.text("A visual test letter")) {
              session
                  .local()
                  .accept(
                      session
                          .crypto()
                          .encrypt(
                              text,
                              "smoke test message password".toCharArray(),
                              Algorithm.AES_256_GCM,
                              1800,
                              86400_000,
                              raven,
                              "raven",
                              session.local().identity().userId()));
            }
            var field = AegisApp.class.getDeclaredField("session");
            field.setAccessible(true);
            field.set(app, session);
            invoke(app, "composePage");
            snapshot(stage, output.resolve("compose.png"));
            invoke(app, "contactsPage");
            snapshot(stage, output.resolve("contacts.png"));
            invoke(app, "inboxPage");
            PauseTransition pause = new PauseTransition(Duration.seconds(2));
            pause.setOnFinished(
                e -> {
                  try {
                    snapshot(stage, output.resolve("inbox.png"));
                    app.stop();
                    stage.close();
                    done.complete(null);
                  } catch (Exception ex) {
                    done.completeExceptionally(ex);
                  } finally {
                    Platform.exit();
                  }
                });
            pause.play();
          } catch (Exception e) {
            app.stop();
            stage.close();
            done.completeExceptionally(e);
            Platform.exit();
          }
        });
    done.get(30, TimeUnit.SECONDS);
    System.out.println("UI smoke passed: login, settings, compose, contacts, inbox");
  }

  private static void invoke(AegisApp a, String name) throws Exception {
    var m = AegisApp.class.getDeclaredMethod(name);
    m.setAccessible(true);
    m.invoke(a);
  }

  private static void snapshot(Stage stage, Path path) throws Exception {
    var root = stage.getScene().getRoot();
    root.applyCss();
    root.layout();
    var image = stage.getScene().snapshot(null);
    var reader = image.getPixelReader();
    var b =
        new java.awt.image.BufferedImage(
            (int) image.getWidth(),
            (int) image.getHeight(),
            java.awt.image.BufferedImage.TYPE_INT_ARGB);
    for (int y = 0; y < b.getHeight(); y++)
      for (int x = 0; x < b.getWidth(); x++) b.setRGB(x, y, reader.getArgb(x, y));
    javax.imageio.ImageIO.write(b, "png", path.toFile());
  }
}
