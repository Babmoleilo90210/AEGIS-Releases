package org.securemail.management;

import java.io.*;
import java.util.*;

/** Compile-time action/unit allowlist; no client paths, shell command, URL, env or unit name. */
public final class ManagementPolicy {
  private ManagementPolicy() {}
  public enum Service {
    MAIL_RELAY("mail-relay"), IDENTITY("identity"), ATTACHMENTS("attachments"), GLAS_SIGNALING("glas-signaling"), COMMUNITY("community"), NEWS_WORKER("news-worker"), LIBRARY("library"), MONITORING("monitoring");
    private final String unit; Service(String unit) { this.unit = unit; } public String stagingUnit() { return "aegis600-staging-" + unit + ".service"; }
  }
  public enum Action {
    STATUS("management.status", false), RESTART("management.service.restart", false), BACKUP_CREATE("management.backup.create", false), BACKUP_RESTORE("management.backup.restore", true);
    private final String permission; private final boolean critical;
    Action(String permission, boolean critical) { this.permission = permission; this.critical = critical; }
    public String permission() { return permission; } public boolean critical() { return critical; }
  }
  public record Request(String id, Action action, Service service, String snapshot) {
    public Request {
      if (id == null || !UUID.fromString(id).toString().equals(id)) throw new IllegalArgumentException("Идентификатор операции"); Objects.requireNonNull(action);
      snapshot = snapshot == null ? "" : snapshot;
      if (action == Action.STATUS || action == Action.RESTART) { Objects.requireNonNull(service); if (!snapshot.isEmpty()) throw new IllegalArgumentException("Аргументы операции"); }
      else { if (service != null || (action == Action.BACKUP_RESTORE ? !snapshot.matches("[a-f0-9]{64}") : !snapshot.isEmpty())) throw new IllegalArgumentException("Аргументы резервной копии"); }
    }
    public byte[] encode() {
      try { var bytes = new ByteArrayOutputStream(); try (var out = new DataOutputStream(bytes)) { out.writeUTF("AEGIS-MANAGEMENT-REQUEST/v1"); out.writeUTF(id); out.writeUTF(action.name()); out.writeUTF(service == null ? "" : service.name()); out.writeUTF(snapshot); } return bytes.toByteArray(); }
      catch (IOException impossible) { throw new IllegalStateException(impossible); }
    }
  }
  public static Request decode(byte[] bytes) throws IOException {
    if (bytes.length > 1024) throw new IOException("Размер операции");
    try (var in = new DataInputStream(new ByteArrayInputStream(bytes))) {
      if (!in.readUTF().equals("AEGIS-MANAGEMENT-REQUEST/v1")) throw new IOException("Протокол управления"); String id = in.readUTF(); Action action = Action.valueOf(in.readUTF()); String s = in.readUTF(); var request = new Request(id, action, s.isEmpty() ? null : Service.valueOf(s), in.readUTF());
      if (in.read() != -1 || !java.security.MessageDigest.isEqual(bytes, request.encode())) throw new IOException("Неканоническая операция"); return request;
    } catch (IllegalArgumentException failure) { throw new IOException("Операция не разрешена", failure); }
  }
  public static List<String> command(Request request) {
    return switch (request.action()) {
      case STATUS -> List.of("/usr/bin/systemctl", "show", "--no-pager", "--property=ActiveState,SubState,MainPID,MemoryCurrent,TasksCurrent", "--", request.service().stagingUnit());
      case RESTART -> List.of("/usr/bin/systemctl", "try-restart", "--", request.service().stagingUnit());
      case BACKUP_CREATE -> List.of("/usr/bin/systemctl", "--no-block", "start", "--", "aegis600-staging-backup.service");
      case BACKUP_RESTORE -> List.of("/usr/bin/systemctl", "--no-block", "start", "--", "aegis600-staging-restore@" + request.snapshot() + ".service");
    };
  }
  /** Defense in depth at the process boundary; even an internal caller cannot add systemctl verbs/options. */
  public static boolean allowsCommand(List<String> arguments) {
    if (arguments == null) return false;
    for (Service service : Service.values()) {
      for (Action action : List.of(Action.STATUS, Action.RESTART)) {
        if (command(new Request("00000000-0000-0000-0000-000000000000", action, service, "")).equals(arguments)) return true;
      }
    }
    if (command(new Request("00000000-0000-0000-0000-000000000000", Action.BACKUP_CREATE, null, "")).equals(arguments)) return true;
    if (arguments.size() != 5 || !arguments.subList(0, 4).equals(List.of("/usr/bin/systemctl", "--no-block", "start", "--"))) return false;
    String unit = arguments.get(4);
    return unit != null && unit.matches("aegis600-staging-restore@[a-f0-9]{64}\\.service");
  }
}
