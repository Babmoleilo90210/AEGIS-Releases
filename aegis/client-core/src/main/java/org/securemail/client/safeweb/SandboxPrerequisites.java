package org.securemail.client.safeweb;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/** Read-only availability preflight. It neither starts a VM/browser nor enables OS features.
 * A successful return means prerequisites were found, not that isolation/network tests passed. */
public final class SandboxPrerequisites {
    private SandboxPrerequisites() {}
    public enum Code {
        UNSUPPORTED_OS("Взор доступен только на Windows 11 x64 и Linux x86_64; эта операционная система не поддерживается"),
        UNSUPPORTED_ARCHITECTURE("Взор требует систему и Java x86_64 (amd64)"),
        LINUX_BWRAP_MISSING("Для изоляции Взор установите системный пакет bubblewrap (bwrap) через менеджер пакетов"),
        LINUX_SLIRP_MISSING("Для изоляции Взор установите системный пакет slirp4netns через менеджер пакетов"),
        LINUX_XEPHYR_MISSING("Для изоляции Взор установите системный Xephyr (в CachyOS пакет xorg-server-xephyr) через менеджер пакетов"),
        LINUX_UNSAFE_DEPENDENCY("Небезопасные права компонентов Взор: нужны системные bwrap, slirp4netns и Xephyr с владельцем root без записи для группы и остальных"),
        LINUX_DISPLAY_REQUIRED("Взор требует локальный X11 или Xwayland. В сеансе KDE Wayland включите Xwayland; прямой доступ браузера к экрану отключён"),
        WINDOWS_VERSION_REQUIRED("Управляемый Взор требует Windows 11 24H2 или новее (сборка 26100+) x64"),
        WINDOWS_HOME_UNSUPPORTED("Windows Home не поддерживает Microsoft Windows Sandbox. Изолированный Взор недоступен; обычный запуск браузера отключён"),
        WINDOWS_EDITION_UNSUPPORTED("Для Взор требуется Windows 11 Pro, Enterprise или Education с Microsoft Windows Sandbox; эта редакция не поддерживается"),
        WINDOWS_COMPONENT_MISSING("Компонент Windows Sandbox не установлен. Нужны Windows 11 Pro, Enterprise или Education, включённая виртуализация и Windows Sandbox; АЕГИС не меняет компоненты ОС автоматически"),
        WINDOWS_CLI_UNAVAILABLE("Нужен актуальный официальный Microsoft Windows Sandbox с CLI wsb.exe. Завершите установку компонента из меню Пуск; АЕГИС не устанавливает его автоматически"),
        WINDOWS_CHECK_FAILED("Не удалось проверить редакцию или системные компоненты Windows Sandbox"),
        ENVIRONMENT_CHECK_FAILED("Не удалось безопасно проверить системные компоненты Взор");
        private final String message;
        Code(String message) { this.message = message; }
    }
    public static final class Failure extends IOException {
        private static final long serialVersionUID = 1L;
        private final Code code;
        Failure(Code code) { super(code.message); this.code = code; }
        // Preserve only the fixed reason code: native/filesystem causes can contain private host paths.
        Failure(Code code, Throwable cause) { super(code.message); this.code = code; }
        public Code code() { return code; }
    }
    public static void check() throws Failure {
        String os = System.getProperty("os.name", ""), arch = System.getProperty("os.arch", "");
        requirePlatform(os, arch);
        try {
            if (os.equals("Linux")) LinuxSafeWebSandbox.requireEnvironment();
            else WindowsSafeWebSandbox.requireEnvironment();
        } catch (Failure failure) { throw failure; }
        catch (IOException | RuntimeException | LinkageError failure) {
            throw new Failure(os.equals("Linux") ? Code.ENVIRONMENT_CHECK_FAILED : Code.WINDOWS_CHECK_FAILED, failure);
        }
    }
    static void requirePlatform(String os, String arch) throws Failure {
        if (!"Linux".equals(os) && (os == null || !os.startsWith("Windows"))) throw new Failure(Code.UNSUPPORTED_OS);
        if (!"amd64".equalsIgnoreCase(arch) && !"x86_64".equalsIgnoreCase(arch)) throw new Failure(Code.UNSUPPORTED_ARCHITECTURE);
    }
    static void requireWindowsVersion(String build) throws Failure {
        if (build == null || !build.matches("[0-9]{4,6}") || Integer.parseInt(build) < 26100) throw new Failure(Code.WINDOWS_VERSION_REQUIRED);
    }
    static void requireWindowsEdition(String edition) throws Failure {
        if (edition != null && edition.matches("Core(?:N|SingleLanguage|CountrySpecific)?")) throw new Failure(Code.WINDOWS_HOME_UNSUPPORTED);
        if (edition == null || !edition.matches("Professional(?:N|EducationN?|WorkstationN?)?|Enterprise(?:N|S|SN)?|EducationN?"))
            throw new Failure(Code.WINDOWS_EDITION_UNSUPPORTED);
    }
    static boolean localDisplay(String display) { return display != null && display.matches(":[0-9]{1,5}(\\.[0-9]{1,2})?"); }
    static String requireLocalDisplay(String display) throws Failure {
        if (!localDisplay(display)) throw new Failure(Code.LINUX_DISPLAY_REQUIRED);
        return display;
    }
    static void requireSystemExecutable(Path path, Code missing) throws Failure {
        try {
            if (!Files.isRegularFile(path) || !Files.isExecutable(path)) throw new Failure(missing);
            // Check both the requested fixed system path and its resolved target's ancestors.
            // A root-owned executable in a user-renamable parent is not a trusted dependency.
            requireRootParents(path.toAbsolutePath().normalize().getParent());
            Path real = path.toRealPath(); requireRootParents(real.getParent());
            executablePolicy((Integer) Files.getAttribute(real, "unix:uid", LinkOption.NOFOLLOW_LINKS),
                    Files.getPosixFilePermissions(real, LinkOption.NOFOLLOW_LINKS));
        } catch (Failure failure) { throw failure; }
        catch (IOException | RuntimeException failure) { throw new Failure(Code.LINUX_UNSAFE_DEPENDENCY, failure); }
    }
    private static void requireRootParents(Path path) throws IOException {
        Path cursor = path.getRoot(); directoryPolicy(cursor);
        for (Path component : path) { cursor = cursor.resolve(component); directoryPolicy(cursor); }
    }
    private static void directoryPolicy(Path path) throws IOException {
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) throw new Failure(Code.LINUX_UNSAFE_DEPENDENCY);
        executablePolicy((Integer) Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS),
                Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS));
    }
    static void executablePolicy(int uid, Set<PosixFilePermission> permissions) throws Failure {
        if (uid != 0 || permissions.contains(PosixFilePermission.GROUP_WRITE) || permissions.contains(PosixFilePermission.OTHERS_WRITE))
            throw new Failure(Code.LINUX_UNSAFE_DEPENDENCY);
    }
}
