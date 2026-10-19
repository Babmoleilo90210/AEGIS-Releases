package org.securemail.client.ecosystem;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import org.securemail.client.storage.LocalStore;

/** Mail-only account binding, checked after local unlock and before Relay authentication, delivery or rendering. */
public final class MailComponentGate600 {
  private volatile org.securemail.client.ecosystemauth.IdentityRelayCredentials600 networkCredentials;
  private final ComponentLease lease;private final LocalIpc.CapabilityVerifier verifier;private final AtomicBoolean locked=new AtomicBoolean();
  public MailComponentGate600(ComponentLease lease,LocalIpc.CapabilityVerifier verifier)throws IOException {
    this.lease=Objects.requireNonNull(lease);this.verifier=Objects.requireNonNull(verifier);if(lease.component()!=ComponentId.MAIL)throw LocalIpc.rejected();verify();
  }
  public void networkCredentials(org.securemail.client.ecosystemauth.IdentityRelayCredentials600 value){networkCredentials=Objects.requireNonNull(value);}
  public void prepareNetwork(org.securemail.client.net.NetworkService network)throws IOException {if(network!=null&&!network.loggedIn()){verify();var credentials=networkCredentials;if(credentials!=null)network.identitySession6(credentials);}}
  public ComponentLease lease(){return lease;}
  public void verify()throws IOException {if(locked.get())throw new IOException("Почта заблокирована главным приложением");verifier.verify(lease);if(locked.get())throw new IOException("Почта заблокирована главным приложением");}
  public void verifyUnlockedVault(LocalStore store)throws IOException {verify();if(!lease.accountId().equals(store.identity().userId()))throw new IOException("Хранилище принадлежит другой учётной записи АЕГИС");}
  public void lock(){locked.set(true);}
  public boolean locked(){return locked.get();}
}
