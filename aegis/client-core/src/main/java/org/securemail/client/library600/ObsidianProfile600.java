package org.securemail.client.library600;

import java.io.IOException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** A verified profile PLAN. This does not launch or claim to sandbox Obsidian.
 * Personal Obsidian may remain open. Protected launch MUST fail closed without an OS-boundary driver. */
public final class ObsidianProfile600 {
    public enum Mode { PERSONAL, PROTECTED }
    public record Plan(Mode mode, Path binary, Path vault, Path configuration, Map<String,String> approvedPlugins,
                       boolean requiresOsIsolation) { }
    private ObsidianProfile600() { }
    public static Plan validate(Mode mode, Path binary, String expectedSha256, Path vault, Path configuration,
                                Map<String,String> approvedPlugins) throws Exception {
        Objects.requireNonNull(mode); Objects.requireNonNull(approvedPlugins);
        Path executable = regular(binary); Path root = directory(vault); Path config = directory(configuration);
        if (!expectedSha256.matches("[a-f0-9]{64}") || !hash(executable).equals(expectedSha256)
                || root.startsWith(config) || config.startsWith(root)) throw new IOException("Профиль Obsidian не прошёл проверку");
        if (approvedPlugins.size()>16) throw new IOException("Слишком много разрешённых плагинов");
        Map<String,String> checked = new TreeMap<>();
        for (var entry : approvedPlugins.entrySet()) {
            String name = entry.getKey(), expected = entry.getValue();
            if (!name.matches("[a-z0-9][a-z0-9-]{0,79}") || !expected.matches("[a-f0-9]{64}"))
                throw new IOException("Некорректный манифест плагинов");
            Path script = regular(root.resolve(".obsidian/plugins/"+name+"/main.js"));
            if (!hash(script).equals(expected)) throw new IOException("Подмена разрешённого плагина");
            checked.put(name,expected);
        }
        if (mode==Mode.PROTECTED) {
            Path plugins = root.resolve(".obsidian/plugins");
            if (Files.exists(plugins,LinkOption.NOFOLLOW_LINKS)) {
                directory(plugins);
                try (var children=Files.list(plugins)) {
                    for(Path child:children.toList()) {
                        directory(child);
                        if(!checked.containsKey(child.getFileName().toString())) throw new IOException("Посторонний плагин в защищённом профиле");
                        // Dynamic code/style/import payloads cannot be hidden alongside the pinned script.
                        try(var files=Files.walk(child)) {
                            for(Path file:files.toList()) {
                                if(Files.isSymbolicLink(file)) throw new IOException("Ссылка в плагине");
                                if(Files.isRegularFile(file) && !file.getFileName().toString().equals("main.js")
                                        && !file.getFileName().toString().equals("manifest.json"))
                                    throw new IOException("Непроверенный дополнительный файл плагина");
                            }
                        }
                    }
                }
            }
        }
        return new Plan(mode,executable,root,config,Map.copyOf(checked),mode==Mode.PROTECTED);
    }
    private static Path directory(Path value)throws IOException {
        Path p=value.toAbsolutePath().normalize();if(!Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS)||!p.toRealPath().equals(p))throw new IOException("Небезопасный каталог профиля");return p;
    }
    private static Path regular(Path value)throws IOException {
        Path p=value.toAbsolutePath().normalize();if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||!p.toRealPath().equals(p))throw new IOException("Небезопасный файл профиля");return p;
    }
    private static String hash(Path p)throws Exception {
        MessageDigest sha=MessageDigest.getInstance("SHA-256");try(var in=Files.newInputStream(p)){byte[]buf=new byte[32768];for(int n;(n=in.read(buf))!=-1;)sha.update(buf,0,n);}return HexFormat.of().formatHex(sha.digest());
    }
}
