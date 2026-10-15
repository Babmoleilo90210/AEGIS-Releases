package org.securemail.client.net;
import java.time.Duration;
/** Uses monotonic progress time, independently from the overall attempt deadline. */
public final class BootstrapWatch {
  private final long stallNanos;private long changedAt;private int highest=-1;
  public BootstrapWatch(Duration stall,long now){if(stall.isNegative()||stall.isZero())throw new IllegalArgumentException("stall");stallNanos=stall.toNanos();changedAt=now;}
  public void progress(int value,long now){if(value>highest){highest=value;changedAt=now;}}
  public boolean stalled(long now){return highest<100&&now-changedAt>=stallNanos;}
}
