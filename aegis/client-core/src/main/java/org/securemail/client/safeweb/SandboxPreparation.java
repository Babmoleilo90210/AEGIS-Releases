package org.securemail.client.safeweb;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Narrow OS component preparation. Call only on a worker, never the JavaFX thread.
 * No owner credentials, browser URL, arbitrary command, package name or directory
 * is accepted. The only elevated operations are fixed official OS transactions.
 * Cancellation is honoured before elevation and after an active package transaction;
 * killing a privileged package manager mid-transaction could damage the host OS.
 */
public final class SandboxPreparation {
    private SandboxPreparation() {}
    public enum Stage { CHECKING, AUTHORIZATION, INSTALLING, VERIFYING, READY, REBOOT_REQUIRED }
    public record Progress(Stage stage, String message, boolean cancellable) {}
    public record Result(boolean ready, boolean rebootRequired, String message) {}
    private static final AtomicBoolean ACTIVE = new AtomicBoolean();
    private static final AtomicBoolean LINUX_TRANSACTION = new AtomicBoolean();
    private static final List<String> ARCH_PACKAGES = List.of("bubblewrap", "slirp4netns", "xorg-server-xephyr",
            "xorg-xwayland", "gtk3", "dbus-glib");
    private static final Path PKEXEC = Path.of("/usr/bin/pkexec"), PACMAN = Path.of("/usr/bin/pacman");
    private static final Duration INSTALL_LIMIT = Duration.ofMinutes(30);

    public static boolean busy() { return ACTIVE.get() || LINUX_TRANSACTION.get() || WindowsFeatureInstaller.busy(); }

    /** UI must display the fixed package/feature purpose before calling this.
     * Polkit/UAC provides the actual OS authorization, not an AEGIS password form.
     * Successful installation does not constitute a sandbox/network acceptance.
     */
    public static Result prepare(Consumer<Progress> progress, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(progress); Objects.requireNonNull(cancelled);
        if (LINUX_TRANSACTION.get() || WindowsFeatureInstaller.busy() || !ACTIVE.compareAndSet(false, true))
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.INSTALLATION_BUSY);
        try {
            checkCancelled(cancelled); emit(progress, Stage.CHECKING, "Проверка системных компонентов Взора…", true);
            String os = System.getProperty("os.name", "");
            SandboxPrerequisites.requirePlatform(os, System.getProperty("os.arch", ""));
            try {
                SandboxPrerequisites.check();
                if (os.equals("Linux")) LinuxSafeWebSandbox.probeNamespaces();
                emit(progress, Stage.READY, "Системные компоненты готовы; подлинность браузера и изоляция проверяются отдельно", true);
                return new Result(true, false, "Системные компоненты Взора готовы");
            } catch (SandboxPrerequisites.Failure missing) {
                if (!installable(missing.code())) throw missing;
                checkCancelled(cancelled);
                if (os.equals("Linux")) installLinux(progress, cancelled);
                else {
                    // Windows edition/build checks already precede COMPONENT_MISSING.
                    emit(progress, Stage.AUTHORIZATION, "Подтвердите UAC: включение только компонента Windows Sandbox. Отмена доступна в системном запросе", false);
                    int result = WindowsFeatureInstaller.enable(cancelled, () -> emit(progress, Stage.INSTALLING,
                            "Windows включает Sandbox. Системную операцию нельзя безопасно прервать", false));
                    if (result == 3010) {
                        emit(progress, Stage.REBOOT_REQUIRED, SandboxPrerequisites.Code.WINDOWS_REBOOT_REQUIRED.message(), false);
                        return new Result(false, true, SandboxPrerequisites.Code.WINDOWS_REBOOT_REQUIRED.message());
                    }
                }
                checkCancelled(cancelled); emit(progress, Stage.VERIFYING, "Повторная проверка установленных компонентов…", true);
                SandboxPrerequisites.check();
                if (os.equals("Linux")) LinuxSafeWebSandbox.probeNamespaces();
                emit(progress, Stage.READY, "Системные компоненты Взора готовы", true);
                return new Result(true, false, "Системные компоненты Взора готовы");
            }
        } finally { ACTIVE.set(false); }
    }
    static boolean installable(SandboxPrerequisites.Code code) {
        return switch (code) {
            case LINUX_BWRAP_MISSING, LINUX_SLIRP_MISSING, LINUX_XEPHYR_MISSING, LINUX_XWAYLAND_MISSING, LINUX_BROWSER_LIBRARY_MISSING,
                    WINDOWS_COMPONENT_MISSING -> true;
            default -> false;
        };
    }
    /** Exact allowlist, no -Sy partial upgrade, no AUR, shell, downloaded helper,
     * arbitrary options, alternate config/root/hooks, or user PATH resolution.
     * Repository signatures and system administrator policy remain pacman's job.
     */
    static List<String> linuxCommand(String osRelease) throws IOException {
        String id = distroId(osRelease);
        if (!id.equals("arch") && !id.equals("cachyos"))
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.LINUX_AUTOMATIC_INSTALL_UNSUPPORTED);
        List<String> command = new ArrayList<>(List.of(PKEXEC.toString(), "--disable-internal-agent", "--user", "root",
                PACMAN.toString(), "-S", "--needed", "--noconfirm", "--"));
        command.addAll(ARCH_PACKAGES); return List.copyOf(command);
    }
    static String distroId(String text) throws IOException {
        if (text == null || text.length() > 16384 || text.indexOf('\0') >= 0) throw new IOException("Некорректные сведения о Linux");
        String id = null;
        for (String line : text.split("\\R", -1)) {
            if (!line.startsWith("ID=")) continue;
            if (id != null) throw new IOException("Неоднозначные сведения о Linux");
            String value = line.substring(3);
            if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) value = value.substring(1, value.length() - 1);
            else if (value.length() >= 2 && value.startsWith("'") && value.endsWith("'")) value = value.substring(1, value.length() - 1);
            if (!value.matches("[a-z0-9_-]{1,64}")) throw new IOException("Некорректный идентификатор Linux");
            id = value;
        }
        if (id == null) throw new IOException("Не определён дистрибутив Linux"); return id;
    }
    private static void installLinux(Consumer<Progress> progress, BooleanSupplier cancelled) throws IOException {
        // /etc/os-release is normally an administrator-owned link to /usr/lib/os-release.
        Path release = Path.of("/etc/os-release").toRealPath();
        requireRootFile(release);
        byte[] bytes;
        try (var input = Files.newInputStream(release, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(16385); if (bytes.length > 16384) throw new IOException("Слишком большой файл сведений о Linux");
        }
        List<String> command = linuxCommand(new String(bytes, StandardCharsets.UTF_8));
        SandboxPrerequisites.requireSystemExecutable(PKEXEC, SandboxPrerequisites.Code.LINUX_AUTHORIZATION_UNAVAILABLE);
        SandboxPrerequisites.requireSystemExecutable(PACMAN, SandboxPrerequisites.Code.LINUX_AUTHORIZATION_UNAVAILABLE);
        checkCancelled(cancelled);
        emit(progress, Stage.AUTHORIZATION, "Подтвердите Polkit: пакеты bubblewrap, slirp4netns, Xephyr, Xwayland, GTK 3 и dbus-glib из репозиториев ОС. Отмена — в системном запросе", false);
        ProcessBuilder builder = new ProcessBuilder(command).directory(Path.of("/").toFile());
        builder.environment().clear(); builder.environment().put("PATH", "/usr/bin:/bin"); builder.environment().put("LANG", "C.UTF-8");
        // Polkit finds the graphical session agent via the process/session, not
        // user-controlled D-Bus, PYTHONPATH, LD_*, pacman config or shell variables.
        builder.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);
        Process process = builder.start();
        LINUX_TRANSACTION.set(true);
        process.onExit().whenComplete((ignored, failure) -> {
            if (failure == null && !process.isAlive()) LINUX_TRANSACTION.set(false);
            // Unknown servicing state stays busy; never dispatch another root
            // transaction merely because monitoring failed.
        });
        try { process.getOutputStream().close(); } catch (IOException ignored) { /* Noninteractive manager may already have exited. */ }
        emit(progress, Stage.INSTALLING, "Системный менеджер подготавливает компоненты. Подтверждённую транзакцию нельзя безопасно прервать", false);
        int exit = awaitTransaction(process, INSTALL_LIMIT);
        if (exit == 126) throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.INSTALL_AUTHORIZATION_CANCELLED);
        if (exit == 127) throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.LINUX_AUTHORIZATION_UNAVAILABLE);
        if (exit != 0) throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.INSTALLATION_FAILED);
        checkCancelled(cancelled);
    }
    static int awaitTransaction(Process process, Duration maximum) throws IOException {
        long deadline = System.nanoTime() + maximum.toNanos(); boolean interrupted = false;
        try {
            while (process.isAlive() && System.nanoTime() < deadline) {
                try { process.waitFor(250, TimeUnit.MILLISECONDS); }
                catch (InterruptedException ignored) { interrupted = true; }
            }
            if (process.isAlive()) throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.INSTALLATION_CONTINUES);
            return process.exitValue();
        } finally { if (interrupted) Thread.currentThread().interrupt(); }
    }
    private static void requireRootFile(Path file) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(file))
            throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.LINUX_UNSAFE_DEPENDENCY);
        Path cursor = file;
        while (cursor != null) {
            if (Files.isSymbolicLink(cursor)) throw new SandboxPrerequisites.Failure(SandboxPrerequisites.Code.LINUX_UNSAFE_DEPENDENCY);
            SandboxPrerequisites.executablePolicy((Integer) Files.getAttribute(cursor, "unix:uid", LinkOption.NOFOLLOW_LINKS),
                    Files.getPosixFilePermissions(cursor, LinkOption.NOFOLLOW_LINKS));
            cursor = cursor.getParent();
        }
    }
    private static void checkCancelled(BooleanSupplier cancelled) throws IOException {
        if (cancelled.getAsBoolean() || Thread.currentThread().isInterrupted()) throw new IOException("Подготовка Взора отменена");
    }
    private static void emit(Consumer<Progress> consumer, Stage stage, String message, boolean cancellable) {
        try { consumer.accept(new Progress(stage, message, cancellable)); }
        catch (RuntimeException ignored) { /* A disposed UI cannot abort OS servicing. */ }
    }
}
