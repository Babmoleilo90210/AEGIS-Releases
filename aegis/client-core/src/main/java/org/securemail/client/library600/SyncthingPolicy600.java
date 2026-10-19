package org.securemail.client.library600;

import java.util.Map;

/** Exact deny-fallback policy for a separately authorised dataset, never per-note authorization. */
public final class SyncthingPolicy600 {
    private SyncthingPolicy600() { }
    public static Map<String,String> environment(int socksPort) {
        if (socksPort < 1 || socksPort > 65535) throw new IllegalArgumentException("Порт SOCKS");
        // Launcher must start with a clean environment; http_proxy/https_proxy/ALL_PROXY inherited values are forbidden.
        return Map.of("ALL_PROXY", "socks5://127.0.0.1:" + socksPort, "ALL_PROXY_NO_FALLBACK", "1");
    }
    public static void applyEnvironment(ProcessBuilder process, int socksPort) {
        var env=process.environment();
        for(String name:java.util.List.of("ALL_PROXY","all_proxy","HTTP_PROXY","http_proxy","HTTPS_PROXY","https_proxy","NO_PROXY","no_proxy"))env.remove(name);
        env.putAll(environment(socksPort));
    }
    public static String config(String deviceId, String onion, int port, String folderId, String path) {
        if (deviceId == null || !deviceId.matches("[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}")
                || onion == null || !onion.matches("[a-z2-7]{56}\\.onion") || port < 1 || port > 65535
                || folderId == null || !folderId.matches("[a-f0-9]{32,64}") || path == null || path.isBlank()
                || path.length() > 4096 || path.chars().anyMatch(c -> c < 32))
            throw new IllegalArgumentException("Некорректный разрешённый набор синхронизации");
        return "<configuration version=\"37\"><folder id=\"" + folderId + "\" path=\"" + xml(path)
                + "\" type=\"receiveonly\" rescanIntervalS=\"300\"><device id=\"" + deviceId
                + "\"/></folder><device id=\"" + deviceId + "\"><address>tcp://" + onion + ":" + port
                + "</address><autoAcceptFolders>false</autoAcceptFolders><introducer>false</introducer></device>"
                + "<gui enabled=\"false\"/><options><listenAddress></listenAddress><globalAnnounceEnabled>false</globalAnnounceEnabled>"
                + "<localAnnounceEnabled>false</localAnnounceEnabled><relaysEnabled>false</relaysEnabled>"
                + "<natEnabled>false</natEnabled><announceLANAddresses>false</announceLANAddresses>"
                + "<autoUpgradeIntervalH>0</autoUpgradeIntervalH><urAccepted>-1</urAccepted>"
                + "<crashReportingEnabled>false</crashReportingEnabled></options></configuration>\n";
    }
    private static String xml(String s) { return s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&apos;"); }
}
