package org.securemail.client.safeweb;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class SandboxPrerequisitesTest {
    @Test void platformPolicyRejectsMacAndUnsupportedArchitectures() {
        for (String os : new String[]{"Mac OS X", "Darwin", "FreeBSD", "", "Windows-like\nsecret"}) {
            if (os.startsWith("Windows")) continue;
            assertEquals(SandboxPrerequisites.Code.UNSUPPORTED_OS,
                    assertThrows(SandboxPrerequisites.Failure.class, () -> SandboxPrerequisites.requirePlatform(os, "amd64")).code());
        }
        assertDoesNotThrow(() -> SandboxPrerequisites.requirePlatform("Linux", "x86_64"));
        assertDoesNotThrow(() -> SandboxPrerequisites.requirePlatform("Windows 11", "amd64"));
        for (String arch : new String[]{"aarch64", "x86", "", "amd64\nsecret"})
            assertEquals(SandboxPrerequisites.Code.UNSUPPORTED_ARCHITECTURE,
                    assertThrows(SandboxPrerequisites.Failure.class, () -> SandboxPrerequisites.requirePlatform("Windows 11", arch)).code());
    }
    @Test void windowsBuildAndEditionAreExplicit() {
        for (String build : new String[]{"26100", "26200", "28000"}) assertDoesNotThrow(() -> SandboxPrerequisites.requireWindowsVersion(build));
        for (String build : new String[]{"26099", "22631", "17763", "2147483647", "26100\nsecret", ""})
            assertEquals(SandboxPrerequisites.Code.WINDOWS_VERSION_REQUIRED,
                    assertThrows(SandboxPrerequisites.Failure.class, () -> SandboxPrerequisites.requireWindowsVersion(build)).code());
        for (String edition : new String[]{"Core", "CoreN", "CoreSingleLanguage", "CoreCountrySpecific"}) {
            var failure = assertThrows(SandboxPrerequisites.Failure.class, () -> SandboxPrerequisites.requireWindowsEdition(edition));
            assertEquals(SandboxPrerequisites.Code.WINDOWS_HOME_UNSUPPORTED, failure.code()); assertTrue(failure.getMessage().contains("Windows Home"));
        }
        for (String edition : new String[]{"Professional", "ProfessionalN", "ProfessionalEducation", "ProfessionalWorkstation", "Enterprise", "EnterpriseS", "Education"})
            assertDoesNotThrow(() -> SandboxPrerequisites.requireWindowsEdition(edition));
        assertEquals(SandboxPrerequisites.Code.WINDOWS_EDITION_UNSUPPORTED,
                assertThrows(SandboxPrerequisites.Failure.class, () -> SandboxPrerequisites.requireWindowsEdition("ServerStandard")).code());
    }
    @Test void displayMustBeLocalWithoutShellOrNetworkSyntax() {
        for (String display : new String[]{":0", ":12.0", ":12345.99"}) assertEquals(display, assertDoesNotThrow(() -> SandboxPrerequisites.requireLocalDisplay(display)));
        for (String display : new String[]{"localhost:0", "127.0.0.1:0", "host.example:1", "unix:0", ":0;touch secret", ":0\nsecret", "", ":123456"})
            assertEquals(SandboxPrerequisites.Code.LINUX_DISPLAY_REQUIRED,
                    assertThrows(SandboxPrerequisites.Failure.class, () -> SandboxPrerequisites.requireLocalDisplay(display)).code());
        assertFalse(SandboxPrerequisites.localDisplay(null));
    }
    @Test void dependencyOwnershipAndWritableBitsFailClosed() {
        Set<PosixFilePermission> safe = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE,
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_EXECUTE);
        assertDoesNotThrow(() -> SandboxPrerequisites.executablePolicy(0, safe));
        assertEquals(SandboxPrerequisites.Code.LINUX_UNSAFE_DEPENDENCY,
                assertThrows(SandboxPrerequisites.Failure.class, () -> SandboxPrerequisites.executablePolicy(1000, safe)).code());
        for (var writable : new PosixFilePermission[]{PosixFilePermission.GROUP_WRITE, PosixFilePermission.OTHERS_WRITE}) {
            var permissions = new java.util.HashSet<>(safe); permissions.add(writable);
            assertThrows(SandboxPrerequisites.Failure.class, () -> SandboxPrerequisites.executablePolicy(0, permissions));
        }
    }
    @Test void missingDependencyIsTypedAndDoesNotExposeUntrustedPath(@TempDir Path directory) {
        Path missing = directory.resolve("missing\nprivate-account-id");
        for (var code : new SandboxPrerequisites.Code[]{SandboxPrerequisites.Code.LINUX_BWRAP_MISSING, SandboxPrerequisites.Code.LINUX_SLIRP_MISSING, SandboxPrerequisites.Code.LINUX_XEPHYR_MISSING}) {
            var failure = assertThrows(SandboxPrerequisites.Failure.class, () -> SandboxPrerequisites.requireSystemExecutable(missing, code));
            assertEquals(code, failure.code()); assertFalse(failure.getMessage().contains("private-account-id"));
            assertFalse(failure.getMessage().contains(directory.toString()));
        }
    }
}
