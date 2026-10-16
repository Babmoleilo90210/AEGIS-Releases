package org.securemail.client.safeweb;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** Pure policy + real harmless process fixtures; never installs host packages. */
class SandboxPreparationTest {
    @Test void onlyCachyAndArchReceiveAnImmutableFixedAllowlist() throws Exception {
        List<String> expected = List.of("/usr/bin/pkexec", "--disable-internal-agent", "--user", "root", "/usr/bin/pacman",
                "-S", "--needed", "--noconfirm", "--", "bubblewrap", "slirp4netns", "xorg-server-xephyr", "xorg-xwayland", "gtk3", "dbus-glib");
        for (String release : List.of("ID=arch\n", "NAME=\"CachyOS\"\nID=cachyos\nID_LIKE=arch\n", "ID=\"cachyos\"", "ID='arch'")) {
            List<String> command = SandboxPreparation.linuxCommand(release); assertEquals(expected, command);
            assertThrows(UnsupportedOperationException.class, () -> command.add("--noconfirm"));
            assertFalse(command.contains("-Sy")); assertFalse(command.contains("-Syu")); assertFalse(command.contains("sh"));
        }
        var failure = assertThrows(SandboxPrerequisites.Failure.class,
                () -> SandboxPreparation.linuxCommand("ID=ubuntu\nID_LIKE=arch\n"));
        assertEquals(SandboxPrerequisites.Code.LINUX_AUTOMATIC_INSTALL_UNSUPPORTED, failure.code());
    }
    @Test void distroMetadataCannotInjectOptionsShellCodeOrContradictoryIds() {
        for (String text : List.of("ID=arch;id", "ID=arch\nID=cachyos", "ID=$(id)", "ID=arch --config=/tmp/evil",
                "ID=\"arch\"x", "ID=ARCH", "ID=../arch", "ID=arch\0", "ID_LIKE=arch", "ID="))
            assertThrows(IOException.class, () -> SandboxPreparation.linuxCommand(text), text);
        assertThrows(IOException.class, () -> SandboxPreparation.linuxCommand("x".repeat(16385)));
    }
    @Test void onlyMissingSupportedComponentsMayRequestElevation() {
        assertTrue(SandboxPreparation.installable(SandboxPrerequisites.Code.LINUX_BWRAP_MISSING));
        assertTrue(SandboxPreparation.installable(SandboxPrerequisites.Code.LINUX_BROWSER_LIBRARY_MISSING));
        assertTrue(SandboxPreparation.installable(SandboxPrerequisites.Code.WINDOWS_COMPONENT_MISSING));
        for (var code : List.of(SandboxPrerequisites.Code.WINDOWS_HOME_UNSUPPORTED, SandboxPrerequisites.Code.WINDOWS_VERSION_REQUIRED,
                SandboxPrerequisites.Code.WINDOWS_CLI_UNAVAILABLE, SandboxPrerequisites.Code.LINUX_UNSAFE_DEPENDENCY,
                SandboxPrerequisites.Code.LINUX_NAMESPACE_UNAVAILABLE, SandboxPrerequisites.Code.LINUX_DISPLAY_REQUIRED))
            assertFalse(SandboxPreparation.installable(code), code.toString());
    }
    @Test void windowsOnlyEnablesTheOfficialFeatureWithoutRestartOrScript() {
        assertEquals(List.of("/Online", "/Enable-Feature", "/FeatureName:Containers-DisposableClientVM", "/All", "/NoRestart", "/Quiet"),
                WindowsFeatureInstaller.dismArguments());
        assertFalse(WindowsFeatureInstaller.dismArguments().stream().anyMatch(a -> a.contains("PowerShell") || a.contains("-File") || a.contains("http")));
    }
    @Test void preCancelledPreparationNeverInspectsOrMutatesOs() {
        assertThrows(IOException.class, () -> SandboxPreparation.prepare(p -> fail("No progress expected"), () -> true));
        assertFalse(SandboxPreparation.busy());
    }
    @Test @EnabledOnOs(OS.LINUX) void actualHarmlessTransactionCompletesWithoutInheritedShellArguments() throws Exception {
        Process process = new ProcessBuilder("/bin/sh", "-c", "exit 7").start();
        assertEquals(7, SandboxPreparation.awaitTransaction(process, Duration.ofSeconds(3))); assertFalse(process.isAlive());
    }
    @Test @EnabledOnOs(OS.LINUX) void interruptDoesNotKillAnAlreadyAuthorizedSystemTransaction() throws Exception {
        Process process = new ProcessBuilder("/bin/sh", "-c", "sleep 0.1; exit 0").start();
        try {
            Thread.currentThread().interrupt(); assertEquals(0, SandboxPreparation.awaitTransaction(process, Duration.ofSeconds(3)));
            assertTrue(Thread.currentThread().isInterrupted()); assertFalse(process.isAlive());
        } finally { Thread.interrupted(); if (process.isAlive()) process.destroyForcibly(); }
    }
    @Test @EnabledOnOs(OS.LINUX) void timeoutReportsStillRunningWithoutKillingTheTransaction() throws Exception {
        Process process = new ProcessBuilder("/bin/sleep", "5").start();
        try {
            var failure = assertThrows(SandboxPrerequisites.Failure.class,
                    () -> SandboxPreparation.awaitTransaction(process, Duration.ofMillis(20)));
            assertEquals(SandboxPrerequisites.Code.INSTALLATION_CONTINUES, failure.code()); assertTrue(process.isAlive());
        } finally { process.destroyForcibly(); assertTrue(process.waitFor(3, TimeUnit.SECONDS)); }
    }
}
