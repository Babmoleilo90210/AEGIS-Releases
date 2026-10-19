package org.securemail.client.ecosystem;

import java.io.IOException;

/** Implement with the pinned Identity service and component proof-of-possession credentials. */
public interface SessionAuthority {
  ComponentLease authorize(ComponentId component) throws IOException;
  /** Must reject expired, revoked, changed-generation, wrong-component and locked grants. */
  void validate(ComponentLease lease) throws IOException;
}
