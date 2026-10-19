package org.securemail.client.ecosystem;

import java.time.Duration;
import java.util.Objects;
import java.util.function.LongSupplier;

/** Monotonic 10 minute idle lock; an OS lock signal always locks immediately. It never authenticates an unlock. */
public final class IdleLockGuard {
  public enum Reason { INACTIVITY, OPERATING_SYSTEM, SESSION_REVOKED }
  @FunctionalInterface public interface LockAction { void lock(Reason reason); }
  public static final Duration MAX_IDLE=Duration.ofMinutes(10);
  private final LongSupplier nanoTime;private final LockAction action;private final long timeout;
  private long lastActivity;private boolean locked;
  public IdleLockGuard(LockAction action) {this(System::nanoTime,MAX_IDLE,action);}
  public IdleLockGuard(LongSupplier nanoTime,Duration idle,LockAction action) {
    this.nanoTime=Objects.requireNonNull(nanoTime);this.action=Objects.requireNonNull(action);
    if(idle.isNegative()||idle.isZero()||idle.compareTo(MAX_IDLE)>0)throw new IllegalArgumentException("Автоблокировка не может превышать 10 минут");
    timeout=idle.toNanos();lastActivity=nanoTime.getAsLong();
  }
  /** Only actual trusted input events count; network notifications and repaint timers must not call this. */
  public synchronized void userActivity(){if(!locked)lastActivity=nanoTime.getAsLong();}
  public synchronized void check(){if(!locked && nanoTime.getAsLong()-lastActivity>=timeout)lock(Reason.INACTIVITY);}
  public synchronized void operatingSystemLocked(){lock(Reason.OPERATING_SYSTEM);}
  public synchronized void sessionRevoked(){lock(Reason.SESSION_REVOKED);}
  public synchronized void authenticatedUnlock(){locked=false;lastActivity=nanoTime.getAsLong();}
  public synchronized boolean locked(){return locked;}
  private void lock(Reason reason){if(locked)return;locked=true;action.lock(reason);}
}
