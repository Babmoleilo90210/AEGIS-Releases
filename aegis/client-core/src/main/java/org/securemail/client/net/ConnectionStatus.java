package org.securemail.client.net;

import java.util.Objects;
import java.util.function.Consumer;

/** Transport status only; CONNECTED does not mean an authenticated account session. */
public final class ConnectionStatus {
  public enum State { IDLE, BOOTSTRAPPING_DIRECT, BOOTSTRAPPING_SNOWFLAKE, TOR_CONNECTED, RELAY_CONNECTING, CONNECTED, OFFLINE, FAILED }
  public enum Failure { NONE, TOR_UNAVAILABLE, RELAY_UNAVAILABLE }
  public record Snapshot(State state, EmbeddedTor.Mode mode, int progress, Failure failure) {
    public boolean busy(){return state==State.BOOTSTRAPPING_DIRECT||state==State.BOOTSTRAPPING_SNOWFLAKE||state==State.RELAY_CONNECTING;}
    public String label(){return switch(state){
      case IDLE -> "Соединение не запущено";
      case BOOTSTRAPPING_DIRECT, BOOTSTRAPPING_SNOWFLAKE -> "Подключение через Tor";
      case TOR_CONNECTED -> "Tor подключён";
      case RELAY_CONNECTING -> "Подключение к серверу";
      case CONNECTED -> "Соединение защищено";
      case OFFLINE -> "Нет соединения";
      case FAILED -> failure==Failure.RELAY_UNAVAILABLE?"Нет соединения с сервером":"Не удалось подключиться через Tor";
    };}
  }
  private volatile Snapshot value=new Snapshot(State.IDLE,EmbeddedTor.Mode.DIRECT,0,Failure.NONE);
  private volatile Consumer<Snapshot> changed=s->{};
  public Snapshot snapshot(){return value;}
  public void listener(Consumer<Snapshot> listener){changed=Objects.requireNonNull(listener);changed.accept(value);}
  private void set(Snapshot next){value=next;changed.accept(next);}
  public synchronized void bootstrap(EmbeddedTor.Mode mode,int percent){
    if(percent<0||percent>100)throw new IllegalArgumentException("Bootstrap range");
    set(new Snapshot(mode==EmbeddedTor.Mode.DIRECT?State.BOOTSTRAPPING_DIRECT:State.BOOTSTRAPPING_SNOWFLAKE,mode,percent,Failure.NONE));
  }
  public synchronized void torConnected(){set(new Snapshot(State.TOR_CONNECTED,value.mode(),100,Failure.NONE));}
  public synchronized void relayConnecting(){if(value.progress()!=100)throw new IllegalStateException("Tor not ready");set(new Snapshot(State.RELAY_CONNECTING,value.mode(),100,Failure.NONE));}
  public synchronized void connected(){if(value.state()!=State.RELAY_CONNECTING)throw new IllegalStateException("Relay not checked");set(new Snapshot(State.CONNECTED,value.mode(),100,Failure.NONE));}
  public synchronized void failed(Failure failure){if(failure==Failure.NONE)throw new IllegalArgumentException("Failure required");set(new Snapshot(State.FAILED,value.mode(),value.progress(),failure));}
  public synchronized void offline(){if(!value.busy())set(new Snapshot(State.OFFLINE,value.mode(),0,Failure.NONE));}
}
