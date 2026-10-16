package org.securemail.ui;
/** Owner-only current UI classes. The five-category Interface200/250 assertions are not used. */
public final class AppearanceNativeLauncher500 {
 public static void main(String[]args)throws Exception {
  if(args.length!=2)throw new IllegalArgumentException("APP_DIRECTORY interface|archive|vzor-glas|community-flow");
  System.setProperty("aegis.home",java.nio.file.Path.of(args[0]).toAbsolutePath().toString());
  org.securemail.client.net.TorTransport.requireAvailability(()->false);
  switch(args[1]){
   case "interface"->Interface500Smoke.main(new String[0]);
   case "archive"->ArchiveMenu500Smoke.main(new String[0]);
   case "vzor-glas"->VzorGlas250Smoke.main(new String[0]);
   case "community-flow"->Community500FlowSmoke.main(new String[0]);
   default->throw new IllegalArgumentException("Unknown 5.0 UI fixture");
  }
 }
}
