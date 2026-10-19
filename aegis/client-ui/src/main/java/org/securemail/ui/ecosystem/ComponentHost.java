package org.securemail.ui.ecosystem;

import java.io.IOException;
import org.securemail.client.ecosystem.*;

/** Installed application adapter. The installer pins its JAR; direct startup is denied before run(). */
public interface ComponentHost extends ComponentRuntime.Callbacks {
  default boolean supports(ComponentId component){return component==ComponentId.MAIL;}
  /** Verify the pinned Identity signature and this app's proof-of-possession credential before reading a vault. */
  void verifyAuthorization(ComponentLease lease) throws IOException;
  default void connected(LocalIpc.Channel channel)throws IOException{}
  /** Perform live generation and proof-of-possession checks after the pipe handshake, before READY or any account UI. */
  default void verifyStartupAuthorization(ComponentLease lease)throws IOException{verifyAuthorization(lease);}
  /** Open the actual Mail/Glas UI. Must not duplicate or migrate the legacy root identity into Core. */
  void run(ComponentLease lease) throws Exception;
}
