package org.securemail.ui;

/** Owner-only current-candidate synthetic fixtures; never installed in app/*.jar. */
public final class AppearanceNativeLauncher {
  public static void main(String[] args)throws Exception {
    if(args.length!=2)throw new IllegalArgumentException("APP_DIRECTORY refinement|responsive|vzor-glas");
    System.setProperty("aegis.home",java.nio.file.Path.of(args[0]).toAbsolutePath().toString());
    org.securemail.client.net.TorTransport.requireAvailability(()->false);
    switch(args[1]) {
      case "refinement" -> Interface250RefinementSmoke.main(new String[0]);
      case "responsive" -> SettingsResponsive200Smoke.main(new String[0]);
      case "vzor-glas" -> VzorGlas250Smoke.main(new String[0]);
      default -> throw new IllegalArgumentException("Unknown current-candidate UI fixture");
    }
  }
}
