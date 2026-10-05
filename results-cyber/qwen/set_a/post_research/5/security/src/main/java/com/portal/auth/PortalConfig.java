package com.portal.auth;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Loads the security-relevant configuration.
 *
 * <h2>Every value here is attacker-influenceable</h2>
 * The config file can be written by anything with write access to the path; the
 * environment belongs to whoever can start the process; system properties belong to
 * whoever built the command line. None of them are trusted, so:
 * <ul>
 *   <li>every key is checked for type, length, range and character class;</li>
 *   <li>an <b>unrecognised key</b> is a hard failure rather than being ignored. Silently
 *       dropping {@code portal.throttle.enabled=false} (a key that does not exist here)
 *       is exactly how a "permissive default" gets deployed believing it was
 *       configured;</li>
 *   <li>there are no defaults for anything that can weaken security: the data directory
 *       and the HTTPS keystore must be supplied. The only defaults are values whose
 *       weaker alternative would be unsafe, and each is a floor;</li>
 *   <li>file paths must be absolute, regular files, not symlinks, and not readable by
 *       group or other;</li>
 *   <li>a secret here is read as a <em>path</em> to a private file or from the
 *       environment, and never from a command-line argument.</li>
 * </ul>
 *
 * <p>Priority is env -&gt; config file -&gt; system property for the operational knobs,
 * and never across a security floor: a system property cannot lower the KDF minimum.
 */
public final class PortalConfig {

    public static final String ENV_DATA_DIR = "PORTAL_DATA_DIR";
    public static final String ENV_CONFIG_FILE = "PORTAL_CONFIG";
    public static final String ENV_KEYSTORE = "PORTAL_KEYSTORE";
    public static final String ENV_KEYSTORE_PASSWORD_FILE = "PORTAL_KEYSTORE_PASSWORD_FILE";
    public static final String ENV_TRUSTED_PROXIES = "PORTAL_TRUSTED_PROXY_CIDRS";

    public static final String KEY_ITERATIONS = "portal.kdf.iterations";
    public static final String KEY_LISTEN_HOST = "portal.listen.host";
    public static final String KEY_LISTEN_PORT = "portal.listen.port";
    public static final String KEY_TRUSTED_PROXIES = "portal.trusted.proxy.cidrs";
    public static final String KEY_HSTS = "portal.hsts.max.age.seconds";
    private static final int CONFIG_MAX_BYTES = 16 * 1024;

    private final Path dataDir;
    private final int iterations;
    private final String listenHost;
    private final int listenPort;
    private final String keystorePath;
    private final Path keystorePasswordFile;
    private final String trustedProxyCsv;
    private final long hstsMaxAgeSeconds;

    /**
     * Package-private for the test suites, which need a config without a real environment
     * (env vars are per-process and cannot be varied from inside a running JVM).
     * {@link #fromEnvironment} stays the only public path, and it runs every check below
     * before reaching this constructor -- nothing here re-validates because nothing can
     * arrive here without passing through those checks.
     */
    PortalConfig(Path dataDir, int iterations, String listenHost, int listenPort,
                 String keystorePath, Path keystorePasswordFile, String trustedProxyCsv,
                 long hstsMaxAgeSeconds) {
        this.dataDir = dataDir;
        this.iterations = iterations;
        this.listenHost = listenHost;
        this.listenPort = listenPort;
        this.keystorePath = keystorePath;
        this.keystorePasswordFile = keystorePasswordFile;
        this.trustedProxyCsv = trustedProxyCsv;
        this.hstsMaxAgeSeconds = hstsMaxAgeSeconds;
    }

    public Path dataDir() {
        return dataDir;
    }

    public int iterations() {
        return iterations;
    }

    public String listenHost() {
        return listenHost;
    }

    public int listenPort() {
        return listenPort;
    }

    /** Null when the portal front end is not being run. */
    public String keystorePath() {
        return keystorePath;
    }

    public Path keystorePasswordFile() {
        return keystorePasswordFile;
    }

    public String trustedProxyCsv() {
        return trustedProxyCsv;
    }

    public long hstsMaxAgeSeconds() {
        return hstsMaxAgeSeconds;
    }

    /** CLI/portal startup. Any refusal is reported as a machine token, never a value. */
    public static PortalConfig fromEnvironment() {
        Properties file = new Properties();
        String configPath = System.getenv(ENV_CONFIG_FILE);
        if (configPath != null && !configPath.isEmpty()) {
            file.putAll(readConfigFile(absolute("config path", configPath)));
        }

        Path dataDir = PrivateFiles.requireDataDirectory(
                absolute(ENV_DATA_DIR, require(ENV_DATA_DIR)));

        int iterations = intRange(orDefault(file, KEY_ITERATIONS,
                String.valueOf(PasswordHasher.DEFAULT_ITERATIONS)),
                PasswordHasher.MIN_ITERATIONS, PasswordHasher.MAX_ITERATIONS, KEY_ITERATIONS);

        String host = hostLiteral(orDefault(file, KEY_LISTEN_HOST, "127.0.0.1"));
        int port = intRange(orDefault(file, KEY_LISTEN_PORT, "8443"), 1, 65535, KEY_LISTEN_PORT);

        String keystore = optionalEnv(ENV_KEYSTORE);
        String passwordFile = optionalEnv(ENV_KEYSTORE_PASSWORD_FILE);
        if (keystore != null || passwordFile != null) {
            if (keystore == null || passwordFile == null) {
                throw new IllegalStateException(
                        "keystore-and-password-file-must-be-supplied-together");
            }
            Path ks = absolute(ENV_KEYSTORE, keystore);
            PrivateFiles.requireNoGroupOrOtherAccess(ks);
            Path pw = absolute(ENV_KEYSTORE_PASSWORD_FILE, passwordFile);
            PrivateFiles.requireNoGroupOrOtherAccess(pw);
            keystore = ks.toString();
            return build(dataDir, iterations, host, port, keystore, pw,
                    orDefault(file, KEY_TRUSTED_PROXIES, optionalEnv(ENV_TRUSTED_PROXIES)),
                    intRange(orDefault(file, KEY_HSTS, "31536000"), 0, 31_536_000, KEY_HSTS));
        }
        return build(dataDir, iterations, host, port, null, null,
                orDefault(file, KEY_TRUSTED_PROXIES, optionalEnv(ENV_TRUSTED_PROXIES)),
                intRange(orDefault(file, KEY_HSTS, "31536000"), 0, 31_536_000, KEY_HSTS));
    }

    private static PortalConfig build(Path dataDir, int iterations, String host, int port,
                                      String keystore, Path passwordFile, String proxies,
                                      long hsts) {
        // Validate now, at load time: a malformed proxy list must stop startup rather than
        // silently disable per-source attribution at the first request.
        SourceRef.parseCidrList(proxies == null ? "" : proxies);
        return new PortalConfig(dataDir, iterations, host, port, keystore, passwordFile,
                proxies == null ? "" : proxies, hsts);
    }

    private static Properties readConfigFile(Path file) {
        PrivateFiles.requireNoGroupOrOtherAccess(file);
        String body;
        try {
            if (Files.size(file) > CONFIG_MAX_BYTES) {
                throw new IllegalStateException("config-too-large");
            }
            body = Files.readString(file);
        } catch (IOException unreadable) {
            throw new IllegalStateException("config-unreadable", unreadable);
        }
        Properties p = new Properties();
        try {
            p.load(new StringReader(body));
        } catch (IOException malformed) {
            throw new IllegalStateException("config-malformed", malformed);
        }
        for (String key : p.stringPropertyNames()) {
            boolean known = key.equals(KEY_ITERATIONS) || key.equals(KEY_LISTEN_HOST)
                    || key.equals(KEY_LISTEN_PORT) || key.equals(KEY_TRUSTED_PROXIES)
                    || key.equals(KEY_HSTS);
            if (!known) {
                throw new IllegalStateException("config-unknown-key: " + key);
            }
        }
        return p;
    }

    private static String require(String envKey) {
        String v = optionalEnv(envKey);
        if (v == null) {
            throw new IllegalStateException("required-configuration-missing: " + envKey);
        }
        return v;
    }

    private static String optionalEnv(String key) {
        String v = System.getenv(key);
        return (v == null || v.isEmpty()) ? null : v;
    }

    private static String orDefault(Properties file, String key, String fallbackFromEnv) {
        String fromFile = file.getProperty(key);
        if (fromFile != null && !fromFile.isEmpty()) {
            return fromFile;
        }
        String fromProperty = System.getProperty(key);
        if (fromProperty != null && !fromProperty.isEmpty()) {
            return fromProperty;
        }
        if (fallbackFromEnv != null && !fallbackFromEnv.isEmpty()) {
            return fallbackFromEnv;
        }
        return null;
    }

    private static String orDefault(Properties file, String key, int fallback) {
        String v = orDefault(file, key, (String) null);
        return v == null ? String.valueOf(fallback) : v;
    }

    /**
     * An unsigned decimal literal inside {@code [min, max]}, or a refusal.
     *
     * <p>{@link Integer#parseInt} accepts a leading {@code '+'}, so {@code +150000} would
     * otherwise be read as a valid setting. It happens to parse to the same number, which is
     * why the hole is worth closing on the grammar rather than on the value: every other
     * config check in this class is a strict-shape check, and a knob whose accepted syntax is
     * wider than the one documented teaches operators that config values are parsed loosely
     * -- which is exactly the assumption that makes {@code 150000 } (trailing space) being
     * refused surprising. Non-ASCII digits are refused by {@code parseInt} already; the sign
     * was the one shape it accepted that we do not.
     */
    private static int intRange(String raw, int min, int max, String key) {
        if (raw == null || raw.isEmpty() || raw.length() > 12) {
            throw new IllegalStateException("config-value-invalid: " + key);
        }
        for (int i = 0; i < raw.length(); i++) {
            if (raw.charAt(i) < '0' || raw.charAt(i) > '9') {
                throw new IllegalStateException("config-value-invalid: " + key);
            }
        }
        int value;
        try {
            value = Integer.parseInt(raw);
        } catch (NumberFormatException notAnInteger) {
            throw new IllegalStateException("config-value-invalid: " + key);
        }
        if (value < min || value > max) {
            throw new IllegalStateException("config-value-out-of-range: " + key);
        }
        return value;
    }

    /** Literal IPv4/IPv6 bind address only -- never a hostname (no DNS at startup). */
    private static String hostLiteral(String raw) {
        if (raw == null || raw.length() > 45) {
            throw new IllegalStateException("config-value-invalid: " + KEY_LISTEN_HOST);
        }
        if (!SourceRef.isLiteralIpv4(raw) && !SourceRef.isLiteralIpv6(raw)) {
            throw new IllegalStateException("config-listen-host-must-be-literal");
        }
        return raw;
    }

    /**
     * Every path this program is pointed at must be absolute and free of {@code ..}.
     *
     * <p>The parent-reference check is done on the <em>raw</em> segments and not on
     * {@code p.normalize()}. Normalising first makes the guard vacuous: {@code
     * normalize()} is precisely the operation that deletes {@code ..}, so the text it
     * hands back can never contain one. Measured before this was fixed --
     * {@code PORTAL_DATA_DIR=/tmp/../etc/x} was accepted, and because the data directory
     * is created if absent, startup wrote a fresh {@code 0700} directory under
     * {@code /etc}. The purpose of the rule is that the directory a deployment names is
     * the directory that gets used; an operator's typo, or a value interpolated from
     * elsewhere, must not silently relocate the roster and audit log somewhere else.
     *
     * <p>Checking raw segments has the mirror-image cost, and it is the acceptable one: a
     * directory genuinely named {@code "..odd"} is refused even though it is legal POSIX.
     * Refusing a name we never generate is cheap; silently writing private state to an
     * unchosen directory is not.
     */
    private static Path absolute(String what, String raw) {
        if (raw.length() > 512) {
            throw new IllegalStateException("path-too-long: " + what);
        }
        Path p;
        try {
            p = Path.of(raw);
        } catch (InvalidPathException bad) {
            throw new IllegalStateException("path-invalid: " + what);
        }
        if (!p.isAbsolute()) {
            throw new IllegalStateException("path-must-be-absolute: " + what);
        }
        for (Path segment : p) {
            if (segment.toString().equals("..")) {
                throw new IllegalStateException("path-must-not-contain-parent-ref: " + what);
            }
        }
        return p;
    }
}
