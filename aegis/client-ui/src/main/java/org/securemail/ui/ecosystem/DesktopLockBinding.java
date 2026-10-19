package org.securemail.ui.ecosystem;

import java.util.Objects;
import javafx.animation.*;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.input.InputEvent;
import javafx.util.Duration;
import org.securemail.client.ecosystem.IdleLockGuard;

/** Attach to Core and every owned scene. OS native session-lock adapters must call operatingSystemLocked(). */
public final class DesktopLockBinding implements AutoCloseable {
  private final Scene scene;private final IdleLockGuard guard;
  private final EventHandler<InputEvent> activity=event->recordActivity();
  private final Timeline timer;
  public DesktopLockBinding(Scene scene,IdleLockGuard guard) {
    this.scene=Objects.requireNonNull(scene);this.guard=Objects.requireNonNull(guard);
    scene.addEventFilter(InputEvent.ANY,activity);timer=new Timeline(new KeyFrame(Duration.seconds(1),event->guard.check()));timer.setCycleCount(Animation.INDEFINITE);timer.play();
  }
  private void recordActivity(){guard.userActivity();}
  /** An OS unlock notification must never call authenticatedUnlock; a new user authentication is required. */
  public void operatingSystemLocked(){guard.operatingSystemLocked();}
  @Override public void close(){timer.stop();scene.removeEventFilter(InputEvent.ANY,activity);}
}
