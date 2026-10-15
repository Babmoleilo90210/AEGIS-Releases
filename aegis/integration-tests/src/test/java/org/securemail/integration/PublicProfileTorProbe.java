package org.securemail.integration;

import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.*;
import org.securemail.client.crypto.Secrets;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.relay.*;

/** Explicit operator probe: REAL bundled Tor, fresh onion, disposable staging Relay,
 * two synthetic accounts. No production endpoints/accounts or signing keys are used.
 * Generated avatars are synthetic PNGs. NOT_RUN remains when real Tor cannot bootstrap.
 * This is one-host transport evidence, never Windows 11/CachyOS native acceptance.
 */
public final class PublicProfileTorProbe {
    private PublicProfileTorProbe() { }
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();
    private static final List<String> CHECKS = List.of("publish", "crossAccountReceive", "changedAvatar", "privacyRestriction", "avatarRemoval", "offlineCacheAfterRestart", "relayRestartPersistence");
    public static void main(String[] arguments) throws Exception {
        if (arguments.length < 2 || arguments.length > 3 || arguments.length == 3 && !arguments[2].equals("snowflake")) throw new IllegalArgumentException("bundled-app-directory evidence-output-directory [snowflake]");
        Path app = Path.of(arguments[0]).toAbsolutePath(), output = Files.createDirectories(Path.of(arguments[1]).toAbsolutePath());
        Path staging = Files.createTempDirectory("AEGIS public-profile Tor staging ");
        String previousHome = System.getProperty("aegis.home"), previousProfile = System.getProperty("aegis.profile");
        System.setProperty("aegis.home", app.toString()); System.setProperty("aegis.profile", staging.toString());
        boolean snowflakeFirst = arguments.length == 3;
        if (snowflakeFirst) Files.writeString(staging.resolve("tor-mode.txt"), "snowflake\n");
        JsonObject report = new JsonObject(); report.addProperty("result", "INCOMPLETE"); report.addProperty("transport", "actual bundled Tor onion service, no SOCKS harness");
        report.addProperty("startedAt", Instant.now().toString()); report.addProperty("productionModified", false); report.addProperty("physicalHosts", 1);
        report.addProperty("nativeWindows11CachyOS", "NOT_RUN"); report.addProperty("torBootstrap", "NOT_RUN");
        report.addProperty("firstMode", snowflakeFirst ? "SNOWFLAKE" : "DIRECT");
        report.addProperty("bootstrapBudgetSeconds", 300);
        JsonObject checks = new JsonObject(); CHECKS.forEach(name -> checks.addProperty(name, "NOT_RUN")); report.add("checks", checks);
        write(output, report);
        Set<Integer> ports = new HashSet<>(); while (ports.size() < 4) ports.add(freePort()); var p = ports.iterator();
        ClientConfig config = new ClientConfig("127.0.0.1", p.next(), p.next(), p.next(), staging.resolve("tor/control_auth_cookie"), p.next(),
                1800, "", 80, staging.resolve("data"), 1_000_000, 8_000_000, 60_000);
        char[] password = Base64.getEncoder().encodeToString(Secrets.random(24)).toCharArray();
        var tor = new TorConnection(config); var timeout = Executors.newSingleThreadScheduledExecutor(r -> { var thread = new Thread(r, "profile-probe-budget"); thread.setDaemon(true); return thread; });
        Thread operator = Thread.currentThread(); timeout.schedule(() -> { System.out.println("Real Tor profile probe time budget exhausted; closing only its own Tor"); tor.close(); operator.interrupt(); }, 300, TimeUnit.SECONDS);
        try (tor) {
            TorTransport.requireAvailability(tor::ready);
            int[] maximum = {0};
            try {
                tor.start(Duration.ofSeconds(45), Duration.ofSeconds(240), (mode, progress) -> {
                    maximum[0] = Math.max(maximum[0], progress); report.addProperty("torMaximumBootstrapPercent", maximum[0]);
                    System.out.println("Actual staging Tor " + mode + " " + progress + "%");
                });
            } catch (Exception blocked) {
                report.addProperty("result", "BLOCKED"); report.addProperty("torBootstrap", "BLOCKED"); report.addProperty("blockedAt", "actual-tor-bootstrap");
                report.addProperty("reason", blocked.getClass().getSimpleName() + ": " + String.valueOf(blocked.getMessage()).replace('\n', ' ').replace('\r', ' '));
                System.out.println("Real profile transport NOT_RUN: actual bundled Tor did not become ready"); return;
            }
            if (!tor.ready()) throw new IOException("Tor did not confirm SOCKS/control readiness");
            report.addProperty("torBootstrap", "PASS"); report.addProperty("torMaximumBootstrapPercent", 100);
            String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8), alice = "probea" + suffix, bob = "probeb" + suffix;
            Clock clock = Clock.systemUTC();
            RelayConfig relayConfig = new RelayConfig(staging.resolve("relay/relay.db"), "127.0.0.1", 0, 604800000, 1_000_000, 8_000_000, 256, 2, true, Set.of(alice, bob));
            byte[] latest;
            try (RelayStore relay = new RelayStore(relayConfig, clock); RelayServer server = new RelayServer(relayConfig, relay, clock);
                 LocalStore a = new LocalStore(staging.resolve("a"), password, clock, 1_000_000, 8_000_000);
                 LocalStore b = new LocalStore(staging.resolve("b"), password, clock, 1_000_000, 8_000_000);
                 TorControl control = new TorControl(config.torControlPort(), config.torCookiePath())) {
                server.start(); String onion = control.publish(server.port());
                // The fresh service must genuinely be available through Tor before registration.
                RelayProbe.check(config.withRelay(onion));
                NetworkService na = new NetworkService(new TorTransport("127.0.0.1", config.torSocksPort()), onion, 80, a, 1_000_000);
                NetworkService nb = new NetworkService(new TorTransport("127.0.0.1", config.torSocksPort()), onion, 80, b, 1_000_000);
                na.authenticate(alice, password, true); nb.authenticate(bob, password, true); b.trust(nb.find(alice));
                byte[] first = avatar(0x337799); latest = avatar(0xbb4422); long revision = clock.millis();
                na.publishProfile(a.identity().profile(alice, revision, true, "Synthetic public profile", first)); pass(checks, "publish");
                b.cacheProfile(nb.profile(alice)); equal(first, b.avatar(alice)); pass(checks, "crossAccountReceive");
                na.publishProfile(a.identity().profile(alice, revision + 1, true, "Synthetic changed profile", latest));
                b.cacheProfile(nb.profile(alice)); equal(latest, b.avatar(alice)); pass(checks, "changedAvatar");
                na.publishProfile(a.identity().profile(alice, revision + 2, false, "Private synthetic fixture", latest));
                var hidden = nb.profile(alice); if (hidden.visible() || !hidden.about().isEmpty()) throw new AssertionError("Private profile disclosed its description");
                b.cacheProfile(hidden); if (b.avatar(alice) != null) throw new AssertionError("Private profile retained remote avatar"); pass(checks, "privacyRestriction");
                na.publishProfile(a.identity().profile(alice, revision + 3, true, "Avatar removed", new byte[0]));
                b.cacheProfile(nb.profile(alice)); if (b.avatar(alice) != null) throw new AssertionError("Removed avatar remains visible"); pass(checks, "avatarRemoval");
                na.publishProfile(a.identity().profile(alice, revision + 4, true, "Restored synthetic fixture", latest)); b.cacheProfile(nb.profile(alice));
            }
            // No network/service handles are used for this reopened, encrypted local cache.
            try (LocalStore offline = new LocalStore(staging.resolve("b"), password, clock, 1_000_000, 8_000_000)) { equal(latest, offline.avatar(alice)); pass(checks, "offlineCacheAfterRestart"); }
            try (RelayStore reopened = new RelayStore(relayConfig, clock)) {
                var saved = reopened.profile(alice); if (saved == null || !saved.visible()) throw new AssertionError("Staging Relay lost public profile");
                equal(latest, saved.avatar()); pass(checks, "relayRestartPersistence");
            }
            report.addProperty("result", "PASS"); System.out.println("PublicProfileTorProbe PASS: real Tor two-account staging profile/avatar/cache/privacy exchange");
        } catch (Exception | AssertionError failed) {
            report.addProperty("result", report.get("torBootstrap").getAsString().equals("PASS") ? "FAIL" : "BLOCKED");
            report.addProperty("reason", failed.getClass().getSimpleName() + ": " + String.valueOf(failed.getMessage()).replace('\n', ' ').replace('\r', ' '));
            throw failed;
        } finally {
            timeout.shutdownNow(); tor.close(); TorTransport.requireAvailability(() -> false); Arrays.fill(password, '\0');
            report.addProperty("finishedAt", Instant.now().toString()); write(output, report);
            copySafeLog(staging.resolve("logs/connection.log"), output.resolve("technical-events.log"));
            restore("aegis.home", previousHome); restore("aegis.profile", previousProfile);
            try (var paths = Files.walk(staging)) { for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path); }
        }
    }
    private static void copySafeLog(Path source, Path target) throws IOException {
        if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS) || Files.size(source) > 1_048_576) return;
        StringBuilder filtered = new StringBuilder();
        for (String line : Files.readAllLines(source))
            if (line.matches("[0-9T:.Z+\\-]+ [A-Z_]+ -?[0-9]{1,10}")) filtered.append(line).append('\n');
        Files.writeString(target, filtered.toString());
    }
    private static void pass(JsonObject checks, String check) { checks.addProperty(check, "PASS"); System.out.println("Actual Tor profile " + check + " PASS"); }
    private static void equal(byte[] expected, byte[] actual) { if (!Arrays.equals(expected, actual)) throw new AssertionError("Synthetic avatar bytes differ"); }
    private static int freePort() throws IOException { try (var socket = new ServerSocket(0, 1, InetAddress.getByAddress(new byte[]{127, 0, 0, 1}))) { return socket.getLocalPort(); } }
    private static byte[] avatar(int color) throws IOException {
        var image = new java.awt.image.BufferedImage(24, 24, java.awt.image.BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < image.getHeight(); y++) for (int x = 0; x < image.getWidth(); x++) image.setRGB(x, y, color);
        var bytes = new ByteArrayOutputStream(); javax.imageio.ImageIO.write(image, "png", bytes); return AvatarCodec.normalize(bytes.toByteArray());
    }
    private static void write(Path output, JsonObject report) throws IOException { Files.writeString(output.resolve("RESULTS.json"), JSON.toJson(report) + "\n"); }
    private static void restore(String name, String previous) { if (previous == null) System.clearProperty(name); else System.setProperty(name, previous); }
}
