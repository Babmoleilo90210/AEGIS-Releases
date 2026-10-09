package org.securemail.ui;

import org.securemail.client.net.TorTransport;

/** Synthetic native GUI scenes only; never starts Tor or connects to relay/updates. */
public final class NativeGuiSmokeLauncher {
  public static void main(String[] args)throws Exception {
    TorTransport.requireAvailability(()->false);
    switch(args[0]) {
      case "picker" -> PickerSmoke.main(new String[0]);
      case "selectors" -> ClientUiRegressionSmoke.main(new String[0]);
      case "messenger" -> MessengerSmoke.main(new String[0]);
      case "aegis11" -> Aegis11UiSmoke.main(new String[0]);
      case "single-window" -> SingleWindowSmoke.main(new String[0]);
      default -> throw new IllegalArgumentException("Unknown native GUI test");
    }
  }
}
