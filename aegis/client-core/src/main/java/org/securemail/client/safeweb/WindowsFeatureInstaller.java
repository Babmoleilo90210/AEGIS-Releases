package org.securemail.client.safeweb;

import com.sun.jna.*;
import com.sun.jna.platform.win32.*;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import java.io.IOException;
import java.nio.file.*;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/** UAC enables exactly one Windows optional feature, using the protected and
 * Authenticode-verified OS DISM binary. No script, executable path, command text,
 * feature name, download or user argument crosses the elevation boundary.
 * Windows servicing owns its transaction; we never kill it to cancel a browser.
 */
final class WindowsFeatureInstaller {
    private WindowsFeatureInstaller() {}
    private static final AtomicBoolean ACTIVE = new AtomicBoolean();
    static boolean busy() { return ACTIVE.get(); }
    private interface Trust extends StdCallLibrary {
        int WinVerifyTrust(WinDef.HWND window, Pointer action, Pointer data);
    }
    static List<String> dismArguments() {
        return List.of("/Online", "/Enable-Feature", "/FeatureName:Containers-DisposableClientVM", "/All", "/NoRestart", "/Quiet");
    }
    static int enable(BooleanSupplier cancelled, Runnable authorized) throws IOException {
        try { return enableNative(cancelled, authorized); }
        catch (SandboxPrerequisites.Failure failure) { throw failure; }
        catch (IOException | RuntimeException | LinkageError failure) {
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.WINDOWS_CHECK_FAILED, failure);
        }
    }
    private static int enableNative(BooleanSupplier cancelled, Runnable authorized) throws IOException {
        if (!System.getProperty("os.name", "").startsWith("Windows") || Native.POINTER_SIZE != 8)
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.UNSUPPORTED_OS);
        // Re-check immediately before elevation; Home and old Windows are never
        // offered registry tricks or unofficial feature/component installers.
        String key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        SandboxPrerequisites.requireWindowsEdition(Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE, key, "EditionID"));
        SandboxPrerequisites.requireWindowsVersion(Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE, key, "CurrentBuildNumber"));
        Path windows = WindowsSafeWebSandbox.windowsDirectory();
        Path executable = windows.resolve("System32/Dism.exe");
        if (!Files.isRegularFile(executable, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(executable)
                || !executable.toRealPath().equals(executable.toAbsolutePath().normalize()))
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.WINDOWS_CHECK_FAILED);
        verifyAuthenticode(executable);
        if (cancelled.getAsBoolean() || Thread.currentThread().isInterrupted()) throw new IOException("Подготовка Взора отменена");
        ShellAPI.SHELLEXECUTEINFO info = new ShellAPI.SHELLEXECUTEINFO();
        info.fMask = 0x00000040 | 0x00000100 | 0x00000400; // NOCLOSEPROCESS, NOASYNC, FLAG_NO_UI; UAC still shown.
        info.lpVerb = "runas"; info.lpFile = executable.toString(); info.lpParameters = String.join(" ", dismArguments());
        info.lpDirectory = windows.resolve("System32").toString(); info.nShow = 0;
        if (!Shell32.INSTANCE.ShellExecuteEx(info)) {
            int error = Kernel32.INSTANCE.GetLastError();
            throw new SandboxPrerequisites.Failure(error == 1223 ? SandboxPrerequisites.Code.INSTALL_AUTHORIZATION_CANCELLED
                    : SandboxPrerequisites.Code.WINDOWS_CHECK_FAILED);
        }
        if (info.hProcess == null || WinBase.INVALID_HANDLE_VALUE.equals(info.hProcess))
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.WINDOWS_CHECK_FAILED);
        ACTIVE.set(true);
        boolean interrupted = false, completed = false;
        try {
            authorized.run(); long until = System.nanoTime() + Duration.ofMinutes(30).toNanos();
            while (System.nanoTime() < until) {
                int state = Kernel32.INSTANCE.WaitForSingleObject(info.hProcess, 250);
                if (state == 0) {
                    completed = true;
                    IntByReference exit = new IntByReference();
                    if (!Kernel32.INSTANCE.GetExitCodeProcess(info.hProcess, exit))
                        throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.WINDOWS_CHECK_FAILED);
                    if (exit.getValue() != 0 && exit.getValue() != 3010)
                        throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.INSTALLATION_FAILED);
                    return exit.getValue();
                }
                if (state != 258) throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.WINDOWS_CHECK_FAILED);
                if (Thread.interrupted()) interrupted = true;
            }
            // Keep a single bounded monitor/handle if OS servicing outlives the
            // UI timeout. A repeated click cannot spawn more privileged jobs.
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.INSTALLATION_CONTINUES);
        } finally {
            if (completed) { Kernel32.INSTANCE.CloseHandle(info.hProcess); ACTIVE.set(false); }
            else Thread.startVirtualThread(() -> {
                boolean stopped = false;
                try {
                    for (;;) {
                        int status = Kernel32.INSTANCE.WaitForSingleObject(info.hProcess, 1000);
                        if (status == 0) { stopped = true; break; }
                        if (status != 258) break; // Unknown OS state remains busy until application restart.
                    }
                } finally { Kernel32.INSTANCE.CloseHandle(info.hProcess); if (stopped) ACTIVE.set(false); }
            });
            if (interrupted) Thread.currentThread().interrupt();
        }
    }
    /** WinVerifyTrust WINTRUST_ACTION_GENERIC_VERIFY_V2, x64 structure layout
     * from Microsoft wintrust.h. Cache-only avoids an unexpected direct network
     * request from the client. Windows services perform actual feature downloads.
     */
    static void verifyAuthenticode(Path executable) throws IOException {
        if (Native.POINTER_SIZE != 8) throw new IOException("Требуется 64-разрядная Windows");
        Path systemTrust = WindowsSafeWebSandbox.windowsDirectory().resolve("System32/wintrust.dll");
        if (!Files.isRegularFile(systemTrust, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(systemTrust)
                || !systemTrust.toRealPath().equals(systemTrust.toAbsolutePath().normalize()))
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.WINDOWS_CHECK_FAILED);
        try (Memory file = new Memory(32); Memory data = new Memory(88); Memory guid = new Memory(16);
                Memory wide = new Memory((long) (executable.toString().length() + 1) * Native.WCHAR_SIZE)) {
            // No current-directory/PATH lookup for the signature verification DLL.
            Trust trust = Native.load(systemTrust.toString(), Trust.class);
            file.clear(); data.clear(); guid.clear();
            wide.setWideString(0, executable.toString()); file.setInt(0, 32); file.setPointer(8, wide);
            guid.setInt(0, 0x00aac56b); guid.setShort(4, (short) 0xcd44); guid.setShort(6, (short) 0x11d0);
            guid.write(8, new byte[]{(byte) 0x8c, (byte) 0xc2, 0, (byte) 0xc0, 0x4f, (byte) 0xc2, (byte) 0x95, (byte) 0xee}, 0, 8);
            data.setInt(0, 88); data.setInt(24, 2); data.setInt(32, 1); data.setPointer(40, file);
            data.setInt(48, 1); data.setInt(72, 0x1010);
            int result;
            try { result = trust.WinVerifyTrust(null, guid, data); }
            finally { data.setInt(48, 2); trust.WinVerifyTrust(null, guid, data); }
            if (result != 0) throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.WINDOWS_CHECK_FAILED);
        } catch (RuntimeException | LinkageError error) {
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.WINDOWS_CHECK_FAILED, error);
        }
    }
}
