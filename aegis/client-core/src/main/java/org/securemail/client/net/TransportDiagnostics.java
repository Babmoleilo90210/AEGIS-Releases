package org.securemail.client.net;
import java.util.Locale;
/** Classifies actual PT messages; never logs arbitrary text or substitutions of secrets. */
public final class TransportDiagnostics {
  private TransportDiagnostics() {}
  public static void accept(String line){TechnicalLog.Event event=classify(line);if(event!=null)TechnicalLog.record(event,0);}
  public static TechnicalLog.Event classify(String line){
    if(line==null||line.length()>8192)return null;String text=line.toLowerCase(Locale.ROOT);
    if(text.contains("broker")&&(text.contains("error")||text.contains("failed")||text.contains("timeout")||text.contains("unreachable")))return TechnicalLog.Event.SNOWFLAKE_BROKER_ERROR;
    if(text.contains("snowflake")&&(text.contains("connected")||text.contains("connection established")))return TechnicalLog.Event.SNOWFLAKE_CONNECTED;
    if(text.startsWith("status ")||text.startsWith("log "))return TechnicalLog.Event.LYREBIRD_STATUS;
    if(text.contains("no such host")||text.contains("connection refused")||text.contains("no route to host"))return TechnicalLog.Event.NETWORK_ERROR;
    return null;
  }
}
