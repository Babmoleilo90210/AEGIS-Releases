package org.securemail.client.safeweb;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.*;
import java.util.List;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class SandboxDiagnosticsTest {
    @TempDir Path temporary;
    @Test void namespaceAndDisplayFailuresHaveActionableFixedReasonsWithoutHostText() {
        assertEquals(SandboxPrerequisites.Code.LINUX_NAMESPACE_UNAVAILABLE,
                SandboxDiagnostics.classify(SandboxDiagnostics.Component.NAMESPACE, "bwrap: loopback: Failed to create NETLINK_ROUTE socket: Operation not permitted /home/private-user/key"));
        assertEquals(SandboxPrerequisites.Code.LINUX_DISPLAY_AUTH_FAILED,
                SandboxDiagnostics.classify(SandboxDiagnostics.Component.DISPLAY, "Authorization required /run/user/1000/private-xauth"));
        assertEquals(SandboxPrerequisites.Code.LINUX_PERMISSION_DENIED,
                SandboxDiagnostics.classify(SandboxDiagnostics.Component.NAMESPACE, "permission denied /home/private-user"));
        assertEquals(SandboxPrerequisites.Code.LINUX_BROWSER_LIBRARY_MISSING,
                SandboxDiagnostics.classify(SandboxDiagnostics.Component.BROWSER, "libdbus-glib-1.so.2: cannot open shared object file"));
        for (var component : SandboxDiagnostics.Component.values()) {
            var reason = SandboxDiagnostics.classify(component, "untrusted private-user token=private-secret https://private.example");
            assertFalse(reason.message().contains("private")); assertFalse(reason.message().contains("token="));
        }
    }
    @Test @EnabledOnOs(OS.LINUX) void realStderrPipeIsDrainedAndReducedToFixedCode() throws Exception {
        Process process = new ProcessBuilder("/bin/sh", "-c", "printf 'bwrap: creating new namespace: Operation not permitted /home/private-user'; printf 'bwrap: creating new namespace: Operation not permitted /home/private-user' >&2; exit 1")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        var capture = new SandboxDiagnostics.Capture(process, SandboxDiagnostics.Component.NAMESPACE);
        assertTrue(process.waitFor(3, TimeUnit.SECONDS));
        var failure = capture.failure(); assertEquals(SandboxPrerequisites.Code.LINUX_NAMESPACE_UNAVAILABLE, failure.code());
        assertFalse(failure.getMessage().contains("private-user")); assertNull(failure.getCause());
    }
    @Test void socketPolicyRequiresSocketTypeAndExactUserOwnership() {
        assertTrue(LinuxSafeWebSandbox.displaySocketPolicy(0140755,1000,1000));
        assertFalse(LinuxSafeWebSandbox.displaySocketPolicy(0100755,1000,1000));
        assertFalse(LinuxSafeWebSandbox.displaySocketPolicy(0140755,1001,1000));
        assertFalse(LinuxSafeWebSandbox.displaySocketPolicy(0120755,1000,1000));
    }
    @Test @EnabledOnOs(OS.LINUX) void displayReadinessRejectsARegularFileOrLink() throws Exception {
        Path run = Files.createDirectory(temporary.resolve("run")), socket = temporary.resolve("socket");
        assertFalse(LinuxSafeWebSandbox.ownDisplaySocket(socket, run));
        Files.writeString(socket, "fake readiness"); assertFalse(LinuxSafeWebSandbox.ownDisplaySocket(socket, run));
        Path alias = temporary.resolve("alias"); Files.createSymbolicLink(alias, socket);
        assertFalse(LinuxSafeWebSandbox.ownDisplaySocket(alias, run));
    }
    @Test @EnabledOnOs(OS.LINUX) void actualOwnedUnixSocketIsAcceptedWhenOsPermitsSockets() throws Exception {
        Path run = Files.createDirectory(temporary.resolve("run")), socket = temporary.resolve("socket");
        ServerSocketChannel opened;
        try { opened = ServerSocketChannel.open(StandardProtocolFamily.UNIX); }
        catch (java.net.SocketException denied) { org.junit.jupiter.api.Assumptions.abort("Host sandbox forbids AF_UNIX: actual socket acceptance NOT_RUN"); return; }
        try (ServerSocketChannel server = opened) {
            server.bind(UnixDomainSocketAddress.of(socket)); assertTrue(LinuxSafeWebSandbox.ownDisplaySocket(socket, run));
            Path alias = temporary.resolve("alias"); Files.createSymbolicLink(alias, socket);
            assertFalse(LinuxSafeWebSandbox.ownDisplaySocket(alias, run));
        }
    }
    @Test @EnabledOnOs(OS.LINUX) void namespaceProbeHasNoHomeDisplayNetworkSharingOrUserCommand() {
        List<String> command = LinuxSafeWebSandbox.namespaceProbeCommand();
        assertEquals("/usr/bin/bwrap", command.getFirst()); assertEquals("/usr/bin/true", command.getLast());
        assertTrue(command.containsAll(List.of("--unshare-all", "--cap-drop", "ALL", "--clearenv")));
        for (String forbidden : List.of("--share-net", "--dev-bind", "DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "-c", System.getProperty("user.home")))
            assertFalse(command.contains(forbidden), forbidden);
    }
}
