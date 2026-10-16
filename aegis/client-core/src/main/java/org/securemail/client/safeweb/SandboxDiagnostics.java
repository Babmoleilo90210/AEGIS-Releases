package org.securemail.client.safeweb;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

/** Only fixed reason codes leave this boundary. Never render native stderr,
 * which can contain the user's home, X cookie path, browser URL or other data.
 */
final class SandboxDiagnostics {
    private SandboxDiagnostics() {}
    enum Component { NAMESPACE, DISPLAY, NETWORK, BROWSER }
    static SandboxPrerequisites.Code classify(Component component, String text) {
        String value = text == null ? "" : text.toLowerCase(Locale.ROOT);
        if (value.contains("authorization required") || value.contains("no protocol specified")
                || value.contains("invalid mit-magic-cookie") || value.contains("cannot open display")
                || value.contains("can't open display")) return SandboxPrerequisites.Code.LINUX_DISPLAY_AUTH_FAILED;
        if (value.contains("namespace") || value.contains("netlink_route") || value.contains("loopback:")
                || value.contains("unshare") || value.contains("userns")) return SandboxPrerequisites.Code.LINUX_NAMESPACE_UNAVAILABLE;
        if (value.contains("permission denied") || value.contains("operation not permitted"))
            return SandboxPrerequisites.Code.LINUX_PERMISSION_DENIED;
        if (value.contains("libgtk-3") || value.contains("libdbus-glib")) return SandboxPrerequisites.Code.LINUX_BROWSER_LIBRARY_MISSING;
        return switch (component) {
            case NAMESPACE -> SandboxPrerequisites.Code.LINUX_NAMESPACE_UNAVAILABLE;
            case DISPLAY -> SandboxPrerequisites.Code.LINUX_DISPLAY_START_FAILED;
            case NETWORK -> SandboxPrerequisites.Code.LINUX_NETWORK_START_FAILED;
            case BROWSER -> SandboxPrerequisites.Code.LINUX_BROWSER_START_FAILED;
        };
    }
    /** Drain to prevent pipe deadlock, retain at most 8 KiB only in memory,
     * reduce it immediately to a fixed code, and zero the byte buffer on EOF.
     * One virtual thread per own bounded startup process; no file or log output.
     */
    static final class Capture {
        private final Component component;
        private volatile SandboxPrerequisites.Code reason;
        private final Thread reader;
        Capture(Process process, Component component) {
            this.component = component; this.reason = classify(component, "");
            reader = Thread.startVirtualThread(() -> {
                byte[] retained = new byte[8192], chunk = new byte[1024]; int used = 0;
                try (InputStream input = process.getErrorStream()) {
                    int read;
                    while ((read = input.read(chunk)) >= 0) {
                        int count = Math.min(read, retained.length - used);
                        if (count > 0) { System.arraycopy(chunk, 0, retained, used, count); used += count;
                            reason = classify(component, new String(retained, 0, used, StandardCharsets.UTF_8)); }
                        Arrays.fill(chunk, (byte) 0);
                    }
                } catch (IOException ignored) { /* Process teardown closes the pipe. */ }
                finally { Arrays.fill(retained, (byte) 0); Arrays.fill(chunk, (byte) 0); }
            });
        }
        SandboxPrerequisites.Code reason() { return reason; }
        SandboxPrerequisites.Failure failure() {
            try { reader.join(100); } catch (InterruptedException error) { Thread.currentThread().interrupt(); }
            return new SandboxPrerequisites.Failure(reason);
        }
    }
}
