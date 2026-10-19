package org.securemail.client.ecosystem;

/** Fixed application identifiers. Detached third-party applications never receive an AEGIS lease. */
public enum ComponentId {
  MAIL("Почта"), GLAS("Глас"), USER_DAEMON("Фоновая служба");
  private final String label;
  ComponentId(String label) { this.label = label; }
  public String label() { return label; }
}
