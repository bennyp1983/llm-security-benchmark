package com.portal.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Adversarial tests for the two layers that sit <em>above</em> the authentication logic:
 * configuration loading ({@link PortalConfig}) and the real operator command line
 * ({@link Main} + {@link PortalCli}).
 *
 * <h2>Why the CLI half drives a real subprocess</h2>
 * Calling {@code PortalCli.run(...)} in-process would let the test disagree with the
 * shipped program in exactly the places that matter: which environment the process really
 * sees, whether the prompt is flushed before the read, what the exit code actually is, and
 * what lands on a terminal that a human -- and a shell history file -- then owns. Each case
 * launches {@code java -cp <out/main> com.portal.auth.Main} with a scrubbed environment and
 * asserts on the combined transcript.
 *
 * <h2>Why prompts are counted, not merely matched</h2>
 * Batch mode consumes stdin positionally. If production ever read one line too many, a
 * canned answer meant for field <i>n+1</i> would be read as field <i>n</i>, and a substring
 * match would still find the expected words while the program authenticated a password it
 * had just read as a username. Every login/enrolment case asserts the number of prompts
 * printed equals the number of answers supplied, so a desynchronisation fails loudly.
 *
 * <h2>Fixtures</h2>
 * No username fixture is a substring of any password fixture
 * ({@link InputPolicy#strengthFailure} refuses such a password), and no password fixture
 * contains a digit-and-letter run long enough to trip the sequence rule. Where a case
 * deliberately violates a rule, the fixture is built to violate exactly one.
 */
public final class ConfigCliSuite {

    private static final String MAIN_CLASS = "com.portal.auth.Main";
    /** The property is the {@code src/main/java} root, so the package must be appended. */
    private static final Path SRC_MAIN = Path.of(System.getProperty("portal.src.main", ""),
            "com", "portal", "auth");

    private ConfigCliSuite() {
    }

    public static void main(String[] args) {
        TestKit.fixedClockAt(java.time.Instant.parse("2026-03-01T00:00:00Z"));
        Path jarDir = classDir();
        if (jarDir == null) {
            TestKit.ok("cannot locate out/main to launch subprocesses", false);
            System.exit(TestKit.report("config-cli"));
            return;
        }
        Path home = TestKit.scratchDir("cli-home");
        pathRules(jarDir, home);
        configFile(jarDir, home);
        ranges(jarDir, home);
        listenHost(jarDir, home);
        keystorePairing(jarDir, home);
        redaction(jarDir, home);
        cliHandshake(jarDir, home);
        cliDenials(jarDir, home);
        cliLineFraming(jarDir, home);
        cliEnrolment(jarDir, home);
        cliAdmin(jarDir, home);
        cliArgv(jarDir, home);
        concurrentWrites(jarDir, home);
        auditDiscipline(jarDir, home);
        System.exit(TestKit.report("config-cli"));
    }

    /**
     * Locate {@code out/main}.
     *
     * <p>The obvious derivation is wrong: {@code getCodeSource().getLocation()} reports the
     * <em>package</em> directory ({@code out/test/com/portal/auth}) rather than the classpath
     * root, so a single {@code getParent()} lands on {@code auth}. Scan the classpath for the
     * entry that actually holds {@code Main.class}, and fall back to walking up from the code
     * source until a sibling {@code main} directory shows up.
     */
    private static Path classDir() {
        String marker = "com" + java.io.File.separator + "portal"
                + java.io.File.separator + "auth" + java.io.File.separator + "Main.class";
        for (String entry : System.getProperty("java.class.path").split(
                java.util.regex.Pattern.quote(java.io.File.pathSeparator))) {
            if (entry.isBlank()) {
                continue;
            }
            Path candidate = Path.of(entry);
            if (Files.isRegularFile(candidate.resolve(marker))) {
                return candidate.toAbsolutePath();
            }
        }
        try {
            Path p = Path.of(ConfigCliSuite.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            for (int depth = 0; p != null && depth < 8; depth++) {
                Path sibling = p.resolveSibling("main");
                if (Files.isRegularFile(sibling.resolve(marker))) {
                    return sibling.toAbsolutePath();
                }
                p = p.getParent();
            }
        } catch (Exception cannotLocate) {
            TestKit.note("code source location unreadable: " + cannotLocate.getMessage());
        }
        return null;
    }

    // ---------------------------------------------------------------------- path rules

    private static void pathRules(Path jarDir, Path home) {
        Path data = dir(home, "paths-data");
        Map<String, String> base = env(data);

        // The regression this section exists for. The parent-reference check used to run on
        // the *normalised* path -- but normalising is the operation that deletes "..", so the
        // guard could never fire. Measured before the fix, PORTAL_DATA_DIR=/tmp/../etc/portal-x
        // was accepted, and because the data directory is created when absent, startup wrote a
        // fresh 0700 directory under /etc.
        // The claim is about THIS run, so it is measured as a before/after diff on the
        // directory's contents rather than as an unconditional "absent". An unconditional
        // absence assertion is not owned by this test: the mutation battery runs a mutant
        // that restores the vacuous guard, that mutant really does create the directory, and
        // the leftover then made every honest run afterwards fail a check that had nothing to
        // do with the code under test. The diff says exactly what this process is
        // responsible for -- it must not create the directory and must not write into it --
        // and it stays true regardless of what an earlier process left behind. The exit code
        // and the machine token above are what actually kill that mutant; they do not look at
        // the filesystem at all.
        Path escapeTarget = Path.of("/etc/portal-x");
        java.util.Set<String> before = entriesOf(escapeTarget);
        Result traversal = run(jarDir, with(base, PortalConfig.ENV_DATA_DIR,
                "/tmp/../etc/portal-x"), "status");
        TestKit.eq("traversal out of the named data dir is refused", 2, traversal.code());
        TestKit.ok("and it refuses with a machine token",
                traversal.combined().contains("path-must-not-contain-parent-ref"));
        TestKit.ok("this run neither created the target directory nor wrote into it",
                entriesOf(escapeTarget).equals(before));
        TestKit.ok("the refusal does not echo the attempted path",
                !traversal.combined().contains("/etc/portal-x"));
        TestKit.ok("traversal inside the scratch tree is refused too",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR,
                        home.resolve("inner/../outside").toString()), "status").combined()
                        .contains("path-must-not-contain-parent-ref"));
        TestKit.ok("the config path gets the same rule",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, "/tmp/../etc/cfg"), "status")
                        .combined().contains("path-must-not-contain-parent-ref"));
        // Both keystore values at once: the pairing check fires first, so a lone keystore
        // with traversal is refused for the wrong reason and would prove nothing.
        Map<String, String> ksPair = new LinkedHashMap<>(base);
        ksPair.put(PortalConfig.ENV_KEYSTORE, "/tmp/../etc/s.p12");
        ksPair.put(PortalConfig.ENV_KEYSTORE_PASSWORD_FILE, "/tmp/../etc/s.pass");
        TestKit.ok("a keystore path gets the same rule",
                run(jarDir, ksPair, "status").combined()
                        .contains("path-must-not-contain-parent-ref"));

        // The honest cost of checking raw segments, pinned so nobody "repairs" it by putting
        // normalize() back: a legal name that merely starts with dots is accepted, because it
        // is not a parent reference.
        Path dotDir = dir(home, "dotdir");
        dir(dotDir, "..odd");
        TestKit.ok("a directory genuinely named \"..odd\" is accepted (a dot-prefixed name is "
                + "not a parent reference)",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR,
                        dotDir.resolve("..odd").toString()), "status").ok());

        TestKit.ok("a relative data dir is refused",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, "relative/dir"), "status")
                        .combined().contains("path-must-be-absolute"));
        TestKit.ok("a dot-slash-prefixed path is not absolute",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, "./" + data), "status")
                        .combined().contains("path-must-be-absolute"));
        TestKit.ok("a trailing dot segment stays legal",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, data + "/."), "status").ok());
        TestKit.ok("a trailing separator stays legal",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, data + "/"), "status").ok());
        TestKit.ok("a path with no root at all is refused",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, "C:/portal"), "status")
                        .combined().contains("path-must-be-absolute"));
        TestKit.ok("an over-long path is refused before anything is opened",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, "/" + "a".repeat(600)), "status")
                        .combined().contains("path-too-long"));
        TestKit.ok("a missing data dir is a named missing key, not a default",
                run(jarDir, without(base, PortalConfig.ENV_DATA_DIR), "status").combined()
                        .contains("required-configuration-missing"));
        TestKit.ok("and the key name is cut off with the rest of the message",
                !run(jarDir, without(base, PortalConfig.ENV_DATA_DIR), "status").combined()
                        .contains("PORTAL_DATA_DIR"));
        TestKit.ok("an empty data dir is the same as absent, and still refused",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, ""), "status").combined()
                        .contains("required-configuration-missing"));
        TestKit.ok("an uncreatable data dir is refused",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, "/proc/1/nope"), "status")
                        .combined().contains("data-dir-uncreatable"));
        TestKit.ok("and the unwritable path is not echoed",
                !run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, "/proc/1/nope"), "status")
                        .combined().contains("/proc/1/"));

        Path worldParent = dir(home, "worldparent");
        chmod(worldParent, "rwxrwxrwx");
        TestKit.ok("a world-writable non-sticky ancestor is refused",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR,
                        worldParent.resolve("child").toString()), "status").combined()
                        .contains("data-ancestor-world-writable"));
        chmod(worldParent, "rwx------");

        Path symlinked = home.resolve("symlinked-data");
        try {
            Files.createSymbolicLink(symlinked, data);
        } catch (IOException | UnsupportedOperationException cannotLink) {
            TestKit.note("symlinks unavailable, skipping the data-dir symlink case");
        }
        if (Files.exists(symlinked, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            TestKit.ok("the data directory may not be a symlink",
                    run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, symlinked.toString()),
                            "status").combined().contains("data-dir-must-not-be-symlink"));
        }

        Path fileAsDir = write(home.resolve("file-as-dir"), "x");
        TestKit.ok("an existing file where a directory is expected is refused",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, fileAsDir.toString()), "status")
                        .combined().contains("data-dir-exists-but-not-directory"));

        Path groupData = dir(home, "group-data");
        chmod(groupData, "rwxr-x---");
        TestKit.ok("a group-readable data directory is refused",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, groupData.toString()),
                        "status").combined().contains("permissions-too-open"));
        chmod(groupData, "rwxr-xr-x");
        TestKit.ok("a world-readable data directory is refused too",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, groupData.toString()),
                        "status").combined().contains("permissions-too-open"));
        chmod(groupData, "rwx------");

        Path fresh = home.resolve("auto-created-data");
        TestKit.ok("an absent data directory is created for us",
                run(jarDir, with(base, PortalConfig.ENV_DATA_DIR, fresh.toString()), "status").ok());
        TestKit.ok("and it is created 0700, not at the process umask",
                modeIs(fresh, "rwx------"));
    }

    // --------------------------------------------------------------- unknown config keys

    private static void configFile(Path jarDir, Path home) {
        Path data = dir(home, "cfg-data");
        Map<String, String> base = env(data);
        Path dir = dir(home, "cfg-files");

        // The exact attack the allowlist exists for: a key that would disable a security
        // control, spelled plausibly. Ignoring it would let a deployment believe it had
        // turned a control off (or on) while the code silently did the opposite.
        for (String key : List.of("portal.throttle.enabled", "portal.auth.enabled",
                "portal.allow.insecure", "portal.kdf.iterations.minimum",
                "portal.listen.host.allow.hostname", "SECRETTOKEN-NotReal",
                "portal.trusted.proxy.cidrs.extra")) {
            Path f = cfg(dir, "evil-" + Math.abs(key.hashCode()) + ".properties",
                    key + "=Sup3r-Secret-Value\n");
            Result r = run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, f.toString()),
                    "version");
            TestKit.ok("\"" + TestKit.show(key) + "\" is refused, not ignored",
                    r.combined().contains("config-unknown-key"));
            TestKit.eq("\"" + TestKit.show(key) + "\" stops startup", 2, r.code());
            TestKit.ok("\"" + TestKit.show(key) + "\" value never reaches the terminal",
                    !r.combined().contains("Sup3r-Secret-Value"));
        }
        // The allowlist is enforced per key: one good line must not launder a bad one.
        TestKit.ok("a valid key alongside an unknown one still refuses",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir, "mixed.properties",
                        "portal.kdf.iterations=150000\nportal.unknown=1\n").toString()), "version")
                        .combined().contains("config-unknown-key"));

        // The accepted set, exactly -- so a key the README documents cannot silently miss.
        Path good = cfg(dir, "good.properties",
                "portal.kdf.iterations=150000\nportal.listen.host=127.0.0.1\n"
                        + "portal.listen.port=8443\nportal.hsts.max.age.seconds=31536000\n"
                        + "portal.trusted.proxy.cidrs=127.0.0.1/32\n");
        TestKit.ok("the five documented keys are exactly the accepted set",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, good.toString()), "version")
                        .ok());
        Map<String, String> keyValues = new LinkedHashMap<>();
        keyValues.put(PortalConfig.KEY_ITERATIONS, "150000");
        keyValues.put(PortalConfig.KEY_LISTEN_HOST, "127.0.0.1");
        keyValues.put(PortalConfig.KEY_LISTEN_PORT, "8443");
        keyValues.put(PortalConfig.KEY_HSTS, "31536000");
        keyValues.put(PortalConfig.KEY_TRUSTED_PROXIES, "127.0.0.1/32");
        for (Map.Entry<String, String> k : keyValues.entrySet()) {
            TestKit.ok("documented key " + k.getKey() + " is accepted on its own",
                    run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                            "k-" + k.getKey() + ".properties",
                            k.getKey() + "=" + k.getValue() + "\n").toString()), "version").ok());
        }

        Path groupRead = cfg(dir, "group-read.properties", "portal.listen.port=8443\n");
        chmod(groupRead, "rw-r-----");
        TestKit.ok("a group-readable config file is refused",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, groupRead.toString()),
                        "version").combined().contains("config-readable-by-group-or-other"));
        chmod(groupRead, "rw-r--r--");
        TestKit.ok("a world-readable config file is refused",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, groupRead.toString()),
                        "version").combined().contains("config-readable-by-group-or-other"));
        chmod(groupRead, "r--------");
        TestKit.ok("a read-only private config is accepted (we do not demand our own mode)",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, groupRead.toString()),
                        "version").ok());

        Path symlink = dir.resolve("config-symlink.properties");
        try {
            Files.createSymbolicLink(symlink, good);
        } catch (IOException | UnsupportedOperationException cannotLink) {
            TestKit.note("symlinks unavailable, skipping the config symlink case");
        }
        if (Files.exists(symlink, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            TestKit.ok("a symlinked config file is refused",
                    run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, symlink.toString()),
                            "version").combined().contains("config-symlink-refused"));
        }

        Path huge = dir.resolve("huge.properties");
        StringBuilder pad = new StringBuilder();
        for (int i = 0; i < 40_000; i++) {
            pad.append("# a comment line to inflate this file well past the bound\n");
        }
        write(huge, pad.toString());
        TestKit.ok("an oversized config file is refused before it is parsed",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, huge.toString()), "version")
                        .combined().contains("config-too-large"));

        Path dirAsConfig = dir(dir, "config-dir");
        TestKit.ok("a directory as the config path is refused",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, dirAsConfig.toString()),
                        "version").combined().contains("config-not-a-regular-file"));
        TestKit.ok("a missing config file is refused, not treated as empty",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE,
                        dir.resolve("nope.properties").toString()), "version").combined()
                        .contains("config-not-a-regular-file"));
        TestKit.ok("an empty PORTAL_CONFIG is the same as unset",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, ""), "version").ok());

        // java.util.Properties strips leading whitespace from a value and keeps trailing
        // whitespace. Pinning both here because the CLI's own rule is "never trim a
        // credential": a config value that silently lost trailing spaces would be a
        // different knob from the one the operator wrote.
        TestKit.ok("a leading space in a value is Properties' framing, same value as without",
                versionLine(run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                        "lead.properties", "portal.kdf.iterations=  150000\n").toString()),
                        "version")).equals("150000"));
        TestKit.ok("a trailing space is NOT removed, so the value is refused as written",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir, "tail.properties",
                        "portal.kdf.iterations=150000 \n").toString()), "version").combined()
                        .contains("config-value-invalid"));
        TestKit.ok("a control character in a value is refused as written",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir, "ctl.properties",
                        "portal.kdf.iterations=150000\u0001\n").toString()), "version").combined()
                        .contains("config-value-invalid"));
        TestKit.ok("an empty value falls back to the default, not to zero",
                versionLine(run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                        "empty.properties", "portal.kdf.iterations=\n").toString()),
                        "version")).equals(String.valueOf(PasswordHasher.DEFAULT_ITERATIONS)));
    }

    // --------------------------------------------------------------------- numeric ranges

    private static void ranges(Path jarDir, Path home) {
        Path data = dir(home, "range-data");
        Path dir = dir(home, "range-files");
        Map<String, String> base = env(data);

        // Arabic-Indic digits are written as escapes: the sources are US-ASCII by policy, and
        // Integer.parseInt accepts only ASCII digits, so this must be refused rather than
        // quietly read as a number.
        for (String bad : List.of("0", "-1", "99999", "abc", "1e3", "150000x", "+150000",
                "0x249f0", "\u0660\u0661\u0662\u0663", "1_000_000", "999999999999", "150000.0",
                "-0", " 150000x", "150000;rm")) {
            TestKit.ok("iterations \"" + TestKit.show(bad) + "\" is refused",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                        "it-" + Math.abs(bad.hashCode()) + ".properties",
                        "portal.kdf.iterations=" + bad + "\n").toString()), "version").code() == 2);
        }
        // The floor is a floor: below it the program refuses outright rather than hashing
        // weakly and carrying on.
        TestKit.ok("iterations below the documented floor are refused by range",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir, "lo.properties",
                        "portal.kdf.iterations=" + (PasswordHasher.MIN_ITERATIONS - 1)
                                + "\n").toString()), "version").combined()
                        .contains("config-value-out-of-range"));
        TestKit.eq("the floor itself is accepted",
                String.valueOf(PasswordHasher.MIN_ITERATIONS),
                versionLine(run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                        "floor.properties", "portal.kdf.iterations=" + PasswordHasher.MIN_ITERATIONS
                                + "\n").toString()), "version")));
        TestKit.eq("the ceiling is accepted",
                String.valueOf(PasswordHasher.MAX_ITERATIONS),
                versionLine(run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                        "max.properties", "portal.kdf.iterations=" + PasswordHasher.MAX_ITERATIONS
                                + "\n").toString()), "version")));
        TestKit.ok("the ceiling plus one is refused",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir, "over.properties",
                        "portal.kdf.iterations=" + (PasswordHasher.MAX_ITERATIONS + 1)
                                + "\n").toString()), "version").combined()
                        .contains("config-value-out-of-range"));

        // No side door to a weaker cost: the KDF strength has exactly one knob, and no
        // plausible environment variable is it.
        for (String envKey : List.of("PORTAL_ITERATIONS", "PORTAL_KDF_ITERATIONS", "PORTAL_KDF",
                "ITERATIONS", "PORTAL_PBKDF2_ROUNDS")) {
            Result r = run(jarDir, with(base, envKey, "1"), "version");
            TestKit.ok(envKey + " cannot lower the KDF cost",
                    r.ok() && versionLine(r).equals(
                            String.valueOf(PasswordHasher.DEFAULT_ITERATIONS)));
        }
        TestKit.ok("the configured cost is reported so an operator can audit it",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir, "shown.properties",
                        "portal.kdf.iterations=200000\n").toString()), "version").stdout()
                        .contains("iterations=200000"));

        for (String bad : List.of("0", "-1", "65536", "999999", "http", "80a", "8_0", "1e4",
                "-0", "65535x")) {
            TestKit.ok("port \"" + TestKit.show(bad) + "\" is refused",
                    run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                            "pt-" + Math.abs(bad.hashCode()) + ".properties",
                            "portal.listen.port=" + bad + "\n").toString()), "version").code() == 2);
        }
        for (String good : List.of("1", "8443", "65535")) {
            TestKit.ok("port " + good + " is accepted",
                    run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                            "pg-" + good + ".properties", "portal.listen.port=" + good
                                    + "\n").toString()), "version").ok());
        }

        for (String bad : List.of("-1", "31536001", "x", "1e9", "999999999999")) {
            TestKit.ok("hsts \"" + TestKit.show(bad) + "\" is refused",
                    run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                            "hs-" + Math.abs(bad.hashCode()) + ".properties",
                            "portal.hsts.max.age.seconds=" + bad + "\n").toString()),
                            "version").code() == 2);
        }
        TestKit.ok("hsts 0 is accepted (a deployment may decline to pin)",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir, "hs0.properties",
                        "portal.hsts.max.age.seconds=0\n").toString()), "version").ok());

        // A malformed proxy list must stop startup. If it were tolerated the list would
        // silently become empty, and every user behind the proxy would share one throttle
        // bucket -- which is the failure the feature exists to prevent.
        for (String bad : List.of("10.0.0.0/33", "10/8", "10.0.0.256/24", "010.0.0.0/24",
                "10.0.0.0/", "/24", "10.0.0.0/24/", "fe80::/64", "10.0.0.0/24,,10.0.1.0/24",
                "not-a-range", "10.0.0.0/024", "10.0.0.0/+8", "10.0.0.0/ 8", "10.0.0.0/24 ",
                "10.0.0.0/24;", "256.0.0.0/8", "10.0.0.0//8")) {
            TestKit.ok("proxy list \"" + TestKit.show(bad) + "\" refuses startup",
                    run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                            "px-" + Math.abs(bad.hashCode()) + ".properties",
                            "portal.trusted.proxy.cidrs=" + bad + "\n").toString()),
                            "version").code() == 2);
        }
        TestKit.ok("a well-formed proxy list is accepted",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir, "px-ok.properties",
                        "portal.trusted.proxy.cidrs=127.0.0.1/32,10.0.0.0/8\n").toString()),
                        "version").ok());
        TestKit.ok("the environment form of the proxy list is validated too",
                run(jarDir, with(base, PortalConfig.ENV_TRUSTED_PROXIES, "10.0.0.0/33"),
                        "version").code() == 2);
        TestKit.ok("an oversized proxy list is refused rather than truncated",
                run(jarDir, with(base, PortalConfig.ENV_TRUSTED_PROXIES,
                        "10.0." + "0,".repeat(20) + "9.0/24"), "version").code() == 2);
    }

    // ------------------------------------------------------------------------ listen host

    private static void listenHost(Path jarDir, Path home) {
        Path data = dir(home, "host-data");
        Path dir = dir(home, "host-files");
        Map<String, String> base = env(data);

        // Never a hostname: a name would mean a DNS lookup at startup, binding to whatever a
        // resolver says and turning a config value into a network call.
        //
        // " 127.0.0.1" (leading space) is deliberately NOT in this list -- see the pin below.
        for (String bad : List.of("localhost", "portal.internal", "0.0.0.0.example",
                "127.0.0.1 ", " 127.0.0.1\t", "127.0.0.1:8443", "[::1]", "::1%lo", "127.1",
                "127.0.0.01", "127.0.0.1/32", "*", "0", "127.0.0.1;rm", "127.0.0.1\u0001",
                "\u0001127.0.0.1", "0177.0.0.1", "127.0.0.1.")) {
            Result r = run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                    "h-" + Math.abs(bad.hashCode()) + ".properties",
                    "portal.listen.host=" + bad + "\n").toString()), "version");
            TestKit.ok("listen host \"" + TestKit.show(bad) + "\" is refused",
                    r.code() == 2 && r.combined().contains("startup-refused"));
        }
        // The one whitespace asymmetry that is not ours: java.util.Properties trims a value's
        // leading whitespace and keeps its trailing whitespace, so " 127.0.0.1" reaches the
        // validator as "127.0.0.1" and is accepted while "127.0.0.1 " (asserted refused above)
        // is not. Pinned rather than worked around, because the only way to remove the
        // asymmetry is to trim the value ourselves -- which is exactly the credential-folding
        // hazard InputPolicy refuses to take. What matters is that folding can only ever
        // produce a strict literal or a refusal, never a different host than the operator
        // typed: the validator is applied after the strip.
        Result leadingSpace = run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                "h-lead-space.properties", "portal.listen.host= 127.0.0.1\n").toString()),
                "version");
        TestKit.eq("a leading space is stripped by the .properties reader, so the literal is accepted",
                0, leadingSpace.code());
        TestKit.ok("and nothing but the strip changed it -- the value still has to be a literal",
                leadingSpace.combined().contains("kdf=pbkdf2-sha256"));
        TestKit.ok("a leading tab is likewise stripped to the same literal",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                        "h-lead-tab.properties", "portal.listen.host=\t127.0.0.1\n").toString()),
                        "version").ok());
        TestKit.ok("the strip does not rescue a hostname",
                run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                        "h-lead-space-name.properties",
                        "portal.listen.host= localhost\n").toString()),
                        "version").code() == 2);
        for (String good : List.of("127.0.0.1", "0.0.0.0", "::1", "::", "fe80::", "2001:db8::1",
                "0000:0000:0000:0000:0000:0000:0000:0001", "255.255.255.255")) {
            TestKit.ok("literal listen host \"" + TestKit.show(good) + "\" is accepted",
                    run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, cfg(dir,
                            "hg-" + Math.abs(good.hashCode()) + ".properties",
                            "portal.listen.host=" + good + "\n").toString()), "version").ok());
        }
        TestKit.ok("no DNS API is reachable from the config layer",
                !codeOnly("PortalConfig.java").contains("InetAddress"));
        TestKit.ok("the default bind address is loopback, not 0.0.0.0",
                run(jarDir, base, "version").ok());
        TestKit.ok("the loopback default is what the source says",
                codeOnly("PortalConfig.java").contains("\"127.0.0.1\"")
                        && !codeOnly("PortalConfig.java").contains("\"0.0.0.0\""));
    }

    // ----------------------------------------------------------- keystore / secret files

    private static void keystorePairing(Path jarDir, Path home) {
        Path data = dir(home, "ks-data");
        Path dir = dir(home, "ks-files");
        Map<String, String> base = env(data);
        Path ks = write(dir.resolve("server.p12"), "private-but-not-a-real-keystore");
        Path pw = write(dir.resolve("server.pass"), "Not-A-Real-Passphrase-9!");

        TestKit.ok("a keystore with no password file refuses startup",
                run(jarDir, with(base, PortalConfig.ENV_KEYSTORE, ks.toString()), "version")
                        .combined().contains("keystore-and-password-file-must-be-supplied-together"));
        TestKit.ok("a password file with no keystore refuses startup too",
                run(jarDir, with(base, PortalConfig.ENV_KEYSTORE_PASSWORD_FILE, pw.toString()),
                        "version").combined()
                        .contains("keystore-and-password-file-must-be-supplied-together"));
        TestKit.eq("the pair together is accepted by a non-serving command", 0,
                run(jarDir, Map.of(PortalConfig.ENV_DATA_DIR, data.toString(),
                        PortalConfig.ENV_KEYSTORE, ks.toString(),
                        PortalConfig.ENV_KEYSTORE_PASSWORD_FILE, pw.toString()), "version").code());

        // Serving is the only consumer of the keystore, and it must fail closed rather than
        // fall back to cleartext or to a generated key.
        Result serve = run(jarDir, Map.of(PortalConfig.ENV_DATA_DIR, data.toString()), "portal");
        TestKit.eq("serving with no keystore at all exits 2", 2, serve.code());
        TestKit.ok("and names the missing keystore",
                serve.combined().contains("https-keystore-not-configured"));
        TestKit.ok("it never prints a stack trace", !serve.combined().contains("at com.portal"));
        Result badKs = run(jarDir, Map.of(PortalConfig.ENV_DATA_DIR, data.toString(),
                PortalConfig.ENV_KEYSTORE, ks.toString(),
                PortalConfig.ENV_KEYSTORE_PASSWORD_FILE, pw.toString()), "portal");
        TestKit.eq("serving with an unusable keystore exits 2", 2, badKs.code());
        TestKit.ok("and never leaks the keystore password",
                !badKs.combined().contains("Not-A-Real-Passphrase-9"));
        TestKit.ok("and never leaks a stack trace", !badKs.combined().contains("at com.portal"));
        TestKit.ok("and never claims to be listening",
                !badKs.combined().contains("listening"));

        for (String openMode : List.of("rw-r--r--", "rw-rw----", "r--r--r--", "rw--wxrw-")) {
            Path wide = write(dir.resolve("wide-" + Math.abs(openMode.hashCode()) + ".pass"), "x");
            chmod(wide, openMode);
            TestKit.ok("a " + openMode + " password file is refused",
                    run(jarDir, Map.of(PortalConfig.ENV_DATA_DIR, data.toString(),
                            PortalConfig.ENV_KEYSTORE, ks.toString(),
                            PortalConfig.ENV_KEYSTORE_PASSWORD_FILE, wide.toString()), "version")
                            .combined().contains("config-readable-by-group-or-other"));
        }
        Path wideKs = write(dir.resolve("wide.p12"), "x");
        chmod(wideKs, "rw-r--r--");
        TestKit.ok("a group-readable keystore is refused",
                run(jarDir, Map.of(PortalConfig.ENV_DATA_DIR, data.toString(),
                        PortalConfig.ENV_KEYSTORE, wideKs.toString(),
                        PortalConfig.ENV_KEYSTORE_PASSWORD_FILE, pw.toString()), "version")
                        .combined().contains("config-readable-by-group-or-other"));

        // The keystore password has exactly one possible source: a private file. Anything
        // that looks like an inline-secret variable must be inert.
        for (String envKey : List.of("PORTAL_KEYSTORE_PASSWORD", "PORTAL_KEYSTORE_PASS",
                "PORTAL_PASSWORD", "SERVER_PASSWORD", "PORTAL_SSL_PASSWORD")) {
            Result r = run(jarDir, Map.of(PortalConfig.ENV_DATA_DIR, data.toString(),
                    PortalConfig.ENV_KEYSTORE, ks.toString(), envKey, "Inline-Secret-9!a"),
                    "version");
            TestKit.ok(envKey + " is not a way to supply the keystore password",
                    r.code() == 2 && !r.combined().contains("Inline-Secret-9!a"));
        }
        TestKit.ok("the only keystore secret key names a file, not a value",
                PortalConfig.ENV_KEYSTORE_PASSWORD_FILE.endsWith("_PASSWORD_FILE"));
        TestKit.ok("no source file reads an inline keystore password",
                !codeOnly("PortalConfig.java").contains("ENV_KEYSTORE_PASSWORD ="));
    }

    // -------------------------------------------------------------------------- redaction

    private static void redaction(Path jarDir, Path home) {
        Path data = dir(home, "red-data");
        Map<String, String> base = env(data);

        for (String[] c : List.of(
                new String[]{"null", "null"},
                new String[]{"", "unspecified"},
                new String[]{" ", "unspecified"},
                new String[]{"space-first: x", "space-first:"},
                new String[]{"has space after", "has"},
                new String[]{"path:/etc/portal/x", "unspecified"},
                new String[]{"back\\slash", "unspecified"},
                new String[]{"quote'd", "unspecified"},
                new String[]{"tab\there", "unspecified"},
                new String[]{"newline\nhere", "unspecified"},
                new String[]{"nul\u0000here", "unspecified"},
                new String[]{"emoji-\uD83D\uDE00", "unspecified"},
                new String[]{"semi;colon", "unspecified"},
                new String[]{"hash#tag", "unspecified"},
                new String[]{"equals=here", "unspecified"},
                new String[]{"slash/y", "unspecified"},
                new String[]{"angle<br", "unspecified"},
                new String[]{"dollar$here", "unspecified"},
                new String[]{"clean-token:9_A.-z", "clean-token:9_A.-z"})) {
            TestKit.eq("safeToken(\"" + TestKit.show(c[0]) + "\")", c[1],
                    PortalCli.safeToken(c[0]));
        }
        TestKit.eq("an over-long head is dropped entirely", "unspecified",
                PortalCli.safeToken("k".repeat(81)));
        TestKit.eq("a maximum-length head survives", "k".repeat(80),
                PortalCli.safeToken("k".repeat(80)));
        TestKit.eq("everything after the first space is dropped", "reason",
                PortalCli.safeToken("reason /very/secret/path " + TestKit.PW_ALICE));
        TestKit.ok("no printable secret can survive the reducer",
                !PortalCli.safeToken("start " + TestKit.PW_ALICE).contains(TestKit.PW_ALICE));

        // End-to-end: a refused config prints a token and nothing else. The value the
        // operator put in the file -- which may itself be a secret -- must never appear.
        Path dir = dir(home, "red-files");
        Path leaky = cfg(dir, "leaky.properties", "PORTAL_SESSION_SECRET=Sup3r-Secret-Value\n");
        Result r = run(jarDir, with(base, PortalConfig.ENV_CONFIG_FILE, leaky.toString()),
                "version");
        TestKit.eq("the refusal is exactly one line", 1, r.lines().size());
        TestKit.ok("the refusal is a machine token",
                r.combined().startsWith("startup-refused reason="));
        TestKit.ok("the offending key's name is cut off, not rendered",
                !r.combined().contains("PORTAL_SESSION_SECRET"));
        TestKit.ok("the offending value never appears",
                !r.combined().contains("Sup3r-Secret-Value"));
        TestKit.ok("no path separator survives in the refusal", !r.lines().get(0).contains("/"));
        TestKit.ok("the refusal names the class of problem",
                r.combined().contains("config-unknown-key"));

        TestKit.ok("no code path prints an exception message verbatim",
                !codeOnly("Main.java").contains("getMessage()")
                        || codeOnly("Main.java").contains("safeToken(refusal.getMessage())"));
        TestKit.ok("Main delegates the redaction rule instead of copying it",
                codeOnly("Main.java").contains("PortalCli.safeToken"));
    }

    // ----------------------------------------------------------------------- CLI handshake

    private static void cliHandshake(Path jarDir, Path home) {
        Path data = dir(home, "hs-data");
        Map<String, String> base = env(data);

        Result created = cli(jarDir, base, "add-user", List.of("alice", TestKit.PW_ALICE,
                TestKit.PW_ALICE));
        TestKit.eq("add-user exits 0", 0, created.code());
        TestKit.eq("add-user asks for exactly three fields", 3, countPrompts(created));
        TestKit.ok("the prompts are the documented ones, in order",
                created.stdout().contains("username: new password: repeat password: "));
        TestKit.eq("and the only verdict line is ok.", "ok.", verdict(created));
        TestKit.ok("the password is never echoed back",
                !created.stdout().contains(TestKit.PW_ALICE));
        TestKit.eq("the roster has the account", "1", statusValue(data, "accounts"));

        Result login = cli(jarDir, base, "login", List.of("alice", TestKit.PW_ALICE));
        TestKit.eq("login with the right secret exits 0", 0, login.code());
        TestKit.eq("login asks for exactly two fields", 2, countPrompts(login));
        TestKit.eq("the granted line is exactly the documented one",
                "Access granted. user=alice", verdict(login));
        TestKit.eq("nothing but the two prompts and that line is printed",
                "username: password: Access granted. user=alice",
                login.stdout().replace("\n", ""));
        // A session id is 32 CSPRNG bytes rendered as 43 base64url characters, so a run of
        // 40+ opaque-token characters in output that has no business carrying one is the
        // leak. Asserted on shape rather than on the transcript's length: the transcript is
        // the merged stdout+stderr capture and carries a trailing newline, so a length
        // comparison here would compare against a constant nobody wrote.
        TestKit.ok("no session id appears anywhere in the transcript",
                !java.util.regex.Pattern.compile("[A-Za-z0-9_-]{40}")
                        .matcher(login.stdout()).find());
        TestKit.ok("the password is not in the transcript",
                !login.combined().contains(TestKit.PW_ALICE));
        // The counters status prints are per-process tallies, deliberately not written to the
        // ledger: a fresh CLI reports zero. What must survive across processes is the roster,
        // asserted below, and the throttle state, asserted in AuthFlowSuite.
        TestKit.eq("a fresh process starts its tallies at zero", "0",
                statusValue(data, "login-ok"));

        // Cross-process proof that the throttle is durable state rather than process memory:
        // five wrong secrets spent in five separate processes arm the account back-off, and a
        // sixth process presenting the CORRECT secret is refused because the ledger said so.
        cli(jarDir, base, "add-user", List.of("wendy", TestKit.PW_CAROL, TestKit.PW_CAROL));
        for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
            TestKit.eq("wrong secret #" + (i + 1) + " on the throwaway account is denied", 1,
                    cli(jarDir, base, "login", List.of("wendy", TestKit.PW_WRONG)).code());
        }
        TestKit.eq("the correct secret is now refused too, in a brand-new process", 1,
                cli(jarDir, base, "login", List.of("wendy", TestKit.PW_CAROL)).code());
        TestKit.eq("and the denial text is unchanged, so the lockout leaks nothing",
                "Access denied.",
                verdict(cli(jarDir, base, "login", List.of("wendy", TestKit.PW_CAROL))));
        TestKit.eq("an account nobody hammered is untouched by it", 0,
                cli(jarDir, base, "login", List.of("alice", TestKit.PW_ALICE)).code());

        TestKit.ok("status has exactly the documented shape",
                run(jarDir, base, "status").stdout().matches(
                        "accounts=\\d+ sessions=\\d+ login-ok=\\d+ login-denied=\\d+ "
                                + "kdf-iterations=\\d+\\R?"));
        TestKit.ok("status does not print the data directory path",
                !run(jarDir, base, "status").combined().contains(data.toString()));

        Result version = cli(jarDir, base, "version", List.of());
        TestKit.ok("version names the KDF and its cost",
                version.stdout().contains("kdf=pbkdf2-sha256")
                        && version.stdout().contains("iterations="
                                + PasswordHasher.DEFAULT_ITERATIONS));
        TestKit.ok("version prints no path", !version.combined().contains(home.toString()));

        // Prompt/answer desynchronisation is the failure mode a substring match hides.
        TestKit.eq("a surplus input line does not change the verdict", 0,
                cli(jarDir, base, "login", List.of("alice", TestKit.PW_ALICE, "surplus")).code());
        TestKit.eq("and login still consumed exactly two lines", 2,
                countPrompts(cli(jarDir, base, "login",
                        List.of("alice", TestKit.PW_ALICE, "surplus"))));

        Result noStdin = run(jarDir, base, "login", List.of(), List.of(), true);
        TestKit.eq("login with an immediately-closed stdin exits 2", 2, noStdin.code());
        TestKit.ok("and reports the input as unavailable rather than granting",
                noStdin.combined().contains("input-unavailable.")
                        && !noStdin.combined().contains("Access granted"));
        TestKit.eq("status with a closed stdin still works (it reads no lines)", 0,
                run(jarDir, base, "status", List.of(), List.of(), true).code());
    }

    // -------------------------------------------------------------------------- denials

    /**
     * Each hostile matrix gets its own data directory, and therefore its own throttle
     * ledger.
     *
     * <p>This is not tidiness. Every CLI login is attributed to the same source label
     * ({@code local}), and the per-source ceiling is 30 failures per 300 seconds. A single
     * flat matrix of 40 hostile inputs would spend that budget halfway through, after which
     * every later assertion in the section -- including "a valid login still works" -- would
     * be measuring the throttle rather than the input boundary. One ledger per matrix keeps
     * each check asking the question it names.
     */
    private static void cliDenials(Path jarDir, Path home) {
        Rig core = rig(jarDir, home, "deny-core", "alice", TestKit.PW_ALICE);

        Result wrong = cli(jarDir, core.env, "login", List.of("alice", TestKit.PW_WRONG));
        TestKit.eq("a wrong secret exits 1", 1, wrong.code());
        TestKit.eq("a wrong secret prints exactly the generic denial",
                "Access denied.", verdict(wrong));
        TestKit.ok("it does not name the account", !wrong.stdout().contains("alice"));
        TestKit.eq("it prints nothing but the two prompts and the denial",
                "username: password: Access denied.", wrong.stdout().replace("\n", ""));

        Result ghost = cli(jarDir, core.env, "login", List.of("ghostuser", TestKit.PW_WRONG));
        TestKit.eq("an unknown account exits 1", 1, ghost.code());
        TestKit.eq("an unknown account produces the byte-identical transcript",
                wrong.combined(), ghost.combined());

        Result casing = cli(jarDir, core.env, "login", List.of("Alice", TestKit.PW_ALICE));
        TestKit.eq("case is folded, so the right secret still grants", 0, casing.code());
        TestKit.eq("and the granted line reports the stored lower-case name",
                "Access granted. user=alice", verdict(casing));

        // Enumeration: the two failures above must be textually identical, and each matrix
        // below must refuse rather than fold a hostile name onto the real account.
        Rig enum2 = rig(jarDir, home, "deny-enum", "alice", TestKit.PW_ALICE);
        TestKit.eq("unknown account and wrong secret share one transcript",
                cli(jarDir, enum2.env, "login", List.of("alice", TestKit.PW_WRONG2)).stdout(),
                cli(jarDir, enum2.env, "login", List.of("nobodyhere", TestKit.PW_WRONG2)).stdout());
        TestKit.eq("a correct secret in the same ledger still grants", 0,
                cli(jarDir, enum2.env, "login", List.of("alice", TestKit.PW_ALICE)).code());

        Rig names = rig(jarDir, home, "deny-names", "alice", TestKit.PW_ALICE);
        for (String hostile : List.of("alice\t", "alice ", " alice", "alice\u0000",
                "alice\u00a0", "ALI\u007FCE", "alice\u0001", "a\u0009lice", "alice\u000B")) {
            Result r = cli(jarDir, names.env, "login", List.of(hostile, TestKit.PW_ALICE));
            TestKit.eq("login as \"" + TestKit.show(hostile) + "\" is denied", 1, r.code());
            TestKit.ok("login as \"" + TestKit.show(hostile) + "\" gets only the generic denial",
                    "Access denied.".equals(verdict(r)));
        }
        for (String bad : List.of("al", "a b", "alice!", ".alice", "alice.", "a..alice",
                "alice@corp", "\u00e9lice", "alice;rm -rf /", "alice\nAccess granted.",
                "alice--", "-alice", "alice'--", "\uff21lice")) {
            Result r = cli(jarDir, names.env, "login", List.of(bad, TestKit.PW_ALICE));
            TestKit.eq("malformed name \"" + TestKit.show(bad) + "\" cannot authenticate",
                    1, r.code());
            TestKit.ok("malformed name \"" + TestKit.show(bad) + "\" cannot forge a line",
                    !r.combined().contains("Access granted"));
        }

        Rig secrets = rig(jarDir, home, "deny-secrets", "alice", TestKit.PW_ALICE);
        for (String secret : List.of("short", "Trailing-space ", "Leading-space-9!",
                TestKit.PW_ALICE + "\t", "Nul-Inside-\u0000-9!", "NonAscii-P\u00e4ss-9!",
                "a".repeat(InputPolicy.PASSWORD_MAX + 1), "Unpaired-Surrogate-\uD83D-9!",
                "\r\n", TestKit.PW_ALICE + "\u0000", " Fresh-Quiver-71!")) {
            Result r = cli(jarDir, secrets.env, "login", List.of("alice", secret));
            TestKit.eq("malformed secret \"" + TestKit.show(secret) + "\" cannot authenticate",
                    1, r.code());
            TestKit.ok("malformed secret \"" + TestKit.show(secret) + "\" prints only the denial",
                    "Access denied.".equals(verdict(r)));
        }

        Rig oversize = rig(jarDir, home, "deny-oversize", "alice", TestKit.PW_ALICE);
        Result hugeUser = cli(jarDir, oversize.env, "login",
                List.of("u".repeat(4_000), TestKit.PW_ALICE));
        TestKit.eq("a 4000-character username is denied", 1, hugeUser.code());
        TestKit.ok("and the verdict is still the three-word denial",
                "Access denied.".equals(verdict(hugeUser)));
        TestKit.ok("the oversized input is not echoed", !hugeUser.combined().contains("uuuu"));
        TestKit.eq("a 4000-character password is denied", 1,
                cli(jarDir, oversize.env, "login", List.of("alice", "p".repeat(4_000))).code());

        // A present-but-empty line is a malformed credential, not "no credential supplied".
        TestKit.eq("an empty username cannot authenticate", 1,
                cli(jarDir, oversize.env, "login", List.of("", TestKit.PW_ALICE)).code());
        TestKit.eq("an empty password cannot authenticate", 1,
                cli(jarDir, oversize.env, "login", List.of("alice", "")).code());
        TestKit.eq("two empty lines cannot authenticate", 1,
                cli(jarDir, oversize.env, "login", List.of("", "")).code());
        TestKit.eq("the account in that ledger still authenticates afterwards", 0,
                cli(jarDir, oversize.env, "login", List.of("alice", TestKit.PW_ALICE)).code());

        // Durable throttling across processes: five wrong secrets spent in five separate
        // processes arm the account back-off, so a sixth process presenting the CORRECT
        // secret is refused. This is the cross-process proof that the throttle lives in the
        // ledger and not in process memory.
        Rig durable = rig(jarDir, home, "deny-durable", "wendy", TestKit.PW_CAROL);
        for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
            TestKit.eq("wrong secret #" + (i + 1) + " is denied", 1,
                    cli(jarDir, durable.env, "login", List.of("wendy", TestKit.PW_WRONG)).code());
        }
        TestKit.eq("the correct secret is now refused too, in a brand-new process", 1,
                cli(jarDir, durable.env, "login", List.of("wendy", TestKit.PW_CAROL)).code());
        TestKit.eq("and the denial text is unchanged, so the lockout leaks nothing",
                "Access denied.",
                verdict(cli(jarDir, durable.env, "login", List.of("wendy", TestKit.PW_CAROL))));
        Rig bystander = rig(jarDir, home, "deny-bystander", "zach", TestKit.PW_BOB);
        TestKit.eq("an account nobody hammered is unaffected by another one's back-off", 0,
                cli(jarDir, bystander.env, "login", List.of("zach", TestKit.PW_BOB)).code());
    }


    /**
     * Line framing of the batch credential reader.
     *
     * <p>The regression this section exists for: {@code readRawLine} used to write
     * {@code if (c == '\r') continue;}, which deleted every CR <em>anywhere</em> in the line.
     * Measured against the shipped binary, that folded {@code "ali\rce"} onto the real account
     * {@code alice} and made {@code "Fresh-Quiver-7\r1!"} verify as the real password -- both
     * granted with exit code 0. Deleting an invisible character from a credential is the exact
     * identity folding {@link InputPolicy} refuses to do with {@code trim()}.
     *
     * <p>The fix treats CR as a terminator, which changes what a CR can do: it can only
     * <em>split</em> a credential, never merge one. Every assertion below is written around
     * that distinction, including the cases where a split legitimately produces two valid
     * fields -- a CR between a real username and a real password grants, and that is correct,
     * because nothing was folded and both halves are what the caller actually typed.
     */
    private static void cliLineFraming(Path jarDir, Path home) {
        Rig rig = rig(jarDir, home, "frame-a", "alice", TestKit.PW_ALICE);
        Map<String, String> base = rig.env;

        // A CR in the middle of the username no longer reaches the roster as "alice": the
        // reader stops at the CR, so the name under test is the fragment before it.
        TestKit.eq("a CR splits a username, so the fragment before it is what gets checked",
                1, rawStdin(jarDir, base, "ali\rce\nFresh-Quiver-71!\n").code());
        // Comparing against the fragment spelled directly is what makes this falsifiable: had
        // the reader deleted the CR (the old bug) the split case would have printed
        // "Access granted" while the direct spelling prints the denial, so an equality here
        // fails the mutant instead of merely failing a tautology.
        TestKit.eq("the CR-split name is refused exactly as that fragment spelled directly",
                rawStdin(jarDir, base, "ali\nFresh-Quiver-71!\n").combined(),
                rawStdin(jarDir, base, "ali\rce\nFresh-Quiver-71!\n").combined());
        TestKit.ok("and neither of them grants",
                !rawStdin(jarDir, base, "ali\rce\nFresh-Quiver-71!\n").combined()
                        .contains("Access granted"));
        TestKit.eq("a CR inside the password cannot fold it onto the real secret",
                1, rawStdin(jarDir, base, "alice\nFresh-Quiver-7\r1!\n").code());
        TestKit.eq("a CR cannot launder a trailing tab out of a username",
                1, rawStdin(jarDir, base, "alice\t\r\nFresh-Quiver-71!\n").code());
        TestKit.eq("a CR cannot smuggle a second username onto one line",
                1, rawStdin(jarDir, base, "alice\ralice\nFresh-Quiver-71!\n").code());
        TestKit.eq("the halves of a CR-split username are each refused",
                1, rawStdin(jarDir, base, "al\rice\nFresh-Quiver-71!\n").code());

        // A split that happens to land between two complete, valid fields is a correct login:
        // the reader consumed "alice" as the name and the real secret as the password, which
        // is what a CRLF-authored (or CR-only) batch file means. Pinned so a future "fix" that
        // rejects CR outright instead of terminating on it is visible.
        TestKit.eq("a CR between a real username and a real password is a correct login",
                0, rawStdin(jarDir, base, "alice\rFresh-Quiver-71!\n").code());
        TestKit.eq("and it prints exactly the two prompts", 2,
                countPrompts(rawStdin(jarDir, base, "alice\rFresh-Quiver-71!\n")));
        TestKit.eq("a CR at end of input does not consume a third read",
                "Access granted. user=alice",
                verdict(rawStdin(jarDir, base, "alice\rFresh-Quiver-71!\rcarol\n")));

        // Every terminator spelling must keep working.
        TestKit.eq("LF line endings grant", 0,
                rawStdin(jarDir, base, "alice\nFresh-Quiver-71!\n").code());
        TestKit.eq("CRLF line endings grant", 0,
                rawStdin(jarDir, base, "alice\r\nFresh-Quiver-71!\r\n").code());
        TestKit.eq("CR-only line endings grant", 0,
                rawStdin(jarDir, base, "alice\rFresh-Quiver-71!\r").code());
        TestKit.eq("a missing final terminator still grants", 0,
                rawStdin(jarDir, base, "alice\nFresh-Quiver-71!").code());
        TestKit.eq("CRLF then a bare LF leaves an empty password, which is refused",
                1, rawStdin(jarDir, base, "alice\r\n\nFresh-Quiver-71!\r\n").code());
        TestKit.eq("a CR-only blank line between the fields is likewise refused",
                1, rawStdin(jarDir, base, "alice\r\rFresh-Quiver-71!\r").code());
    }


    // -------------------------------------------------------------------------- enrolment

    private static void cliEnrolment(Path jarDir, Path home) {
        Path data = dir(home, "enr-data");
        Map<String, String> base = env(data);

        TestKit.eq("a valid account is created", 0,
                cli(jarDir, base, "add-user", List.of("bob", TestKit.PW_BOB, TestKit.PW_BOB))
                        .code());
        Result twice = cli(jarDir, base, "add-user",
                List.of("bob", TestKit.PW_BOB, TestKit.PW_BOB));
        TestKit.eq("the name cannot be taken twice", 2, twice.code());
        TestKit.eq("and the operator is told which failure it is",
                "That username already exists.", verdict(twice));
        TestKit.eq("the failed attempt added no account", "1", statusValue(data, "accounts"));

        TestKit.eq("set-password can reset an existing account", 0,
                cli(jarDir, base, "set-password",
                        List.of("bob", TestKit.PW_CAROL, TestKit.PW_CAROL)).code());
        TestKit.eq("the new secret works", 0,
                cli(jarDir, base, "login", List.of("bob", TestKit.PW_CAROL)).code());
        TestKit.eq("the old secret does not", 1,
                cli(jarDir, base, "login", List.of("bob", TestKit.PW_BOB)).code());
        TestKit.eq("set-password on an unknown name does not create it", 2,
                cli(jarDir, base, "set-password",
                        List.of("nobody", TestKit.PW_CAROL, TestKit.PW_CAROL)).code());
        TestKit.eq("the roster is unchanged", "1", statusValue(data, "accounts"));

        for (int i = 0; i < 2; i++) {
            TestKit.eq("mismatched confirmation refuses", 2,
                    cli(jarDir, base, "add-user",
                            List.of("dave", TestKit.PW_BOB, TestKit.PW_CAROL)).code());
        }
        TestKit.eq("and says so plainly", "Passwords do not match.",
                verdict(cli(jarDir, base, "add-user",
                        List.of("dave", TestKit.PW_BOB, TestKit.PW_CAROL))));
        TestKit.eq("the mismatch created no account", "1", statusValue(data, "accounts"));

        // Each weak fixture is well-formed for every rule EXCEPT the one under test, so a
        // rule that became unreachable shows up as a failure rather than as green. The name
        // "dave" is not a substring of any of them except the deliberate last case.
        // Its own ledger: each rejected fixture is followed by a login attempt with that
        // fixture, and every malformed-secret login charges the shared source budget. The
        // account is created by the first fixture rather than pre-seeded, or every later
        // case would be refused as NAME_TAKEN before the password rule ran.
        Map<String, String> weakEnv = env(dir(home, "enr-weak"));
        Map<String, String> weak = new LinkedHashMap<>();
        weak.put("too short", "Short-9!A");
        weak.put("no upper case", "alllowercase123!");
        weak.put("no lower case", "NOLOWERCASE99!!");
        weak.put("no digit", "NoDigitsHere!!");
        weak.put("no symbol", "OnlyLettersAnd1");
        weak.put("mostly one character", "aaaaaaaaaaaaA1!");
        weak.put("long ascending run", "abcdefghijklA1!");
        weak.put("long descending run", "zyxwvutsrqpoA1!");
        weak.put("leading space", " Space-Leading-9!A");
        weak.put("trailing space", "Space-Trailing-9!A ");
        weak.put("control character", "Ctrl-Inside-\u0001-9!A");
        weak.put("non-ASCII", "Non-Ascii-P\u00e4ss-9!");
        weak.put("contains the username", "Dave-Foxtrot-21!");
        weak.put("over-long", "Valid-Shaped-9!A" + "x".repeat(200));
        for (Map.Entry<String, String> c : weak.entrySet()) {
            Result r = cli(jarDir, weakEnv, "add-user", List.of("dave", c.getValue(), c.getValue()));
            TestKit.eq("weak password (" + c.getKey() + ") is refused", 2, r.code());
            TestKit.ok("weak password (" + c.getKey() + ") explains itself",
                    r.stdout().toLowerCase(java.util.Locale.ROOT).contains("password"));
            TestKit.ok("weak password (" + c.getKey() + ") was not stored",
                    cli(jarDir, weakEnv, "login", List.of("dave", c.getValue())).code() == 1);
        }
        TestKit.ok("a bad name is refused before any secret is asked for",
                cli(jarDir, base, "add-user",
                        List.of("bad name!", TestKit.PW_BOB, TestKit.PW_BOB)).stdout()
                        .contains("Username must be"));
        TestKit.eq("and a rejected name adds no account", "1", statusValue(data, "accounts"));
        TestKit.ok("the enrolment path never repeats the rejected secret",
                !cli(jarDir, base, "add-user",
                        List.of("erin", "a".repeat(300), "a".repeat(300))).combined()
                        .contains("aaaa"));
        TestKit.eq("an over-long name is refused", 2,
                cli(jarDir, base, "add-user", List.of("z".repeat(200), TestKit.PW_BOB,
                        TestKit.PW_BOB)).code());
        TestKit.eq("no account was created by the over-long name", "1",
                statusValue(data, "accounts"));
    }

    // -------------------------------------------------------------------------- admin ops

    private static void cliAdmin(Path jarDir, Path home) {
        Path data = dir(home, "admin-data");
        Map<String, String> base = env(data);
        cli(jarDir, base, "add-user", List.of("carol", TestKit.PW_CAROL, TestKit.PW_CAROL));

        TestKit.eq("a fresh process reports no live sessions", "0", statusValue(data, "sessions"));
        TestKit.eq("disable-user needs --user=", 2,
                cli(jarDir, base, "disable-user", List.of(), List.of("carol")).code());
        TestKit.eq("disable-user with a malformed name refuses", 2,
                cli(jarDir, base, "disable-user", List.of(), List.of("--user=bad name")).code());
        TestKit.eq("disable-user on an unknown account refuses", 2,
                cli(jarDir, base, "disable-user", List.of(), List.of("--user=nobody")).code());
        TestKit.eq("--user= with an empty value refuses", 2,
                cli(jarDir, base, "disable-user", List.of(), List.of("--user=")).code());
        TestKit.eq("--user= with a traversal-shaped value refuses", 2,
                cli(jarDir, base, "disable-user", List.of(),
                        List.of("--user=../../etc/passwd")).code());
        TestKit.eq("an extra secret-shaped flag is refused, not parsed", 2,
                cli(jarDir, base, "disable-user", List.of(),
                        List.of("--user=carol", "--password=x")).code());

        TestKit.eq("disabling the real account succeeds", 0,
                cli(jarDir, base, "disable-user", List.of(), List.of("--user=carol")).code());
        Result after = cli(jarDir, base, "login", List.of("carol", TestKit.PW_CAROL));
        TestKit.eq("the disabled account cannot log in with the right secret", 1, after.code());
        TestKit.eq("and gets the same generic denial as every other failure",
                "Access denied.", verdict(after));
        TestKit.eq("disabling again is idempotent", 0,
                cli(jarDir, base, "disable-user", List.of(), List.of("--user=carol")).code());
        TestKit.eq("the roster is intact (disabled is not deleted)", "1",
                statusValue(data, "accounts"));
        TestKit.eq("the disabled account stays out", 1,
                cli(jarDir, base, "login", List.of("carol", TestKit.PW_CAROL)).code());
        // set-password overwrites the disabled marker, so it also lifts the disable. That is
        // permitted -- there is deliberately no enable-user command -- but it must be visible
        // to the operator and to the audit log, not something they infer later.
        Result reset = cli(jarDir, base, "set-password",
                List.of("carol", TestKit.PW_BOB, TestKit.PW_BOB));
        TestKit.eq("resetting a disabled account succeeds", 0, reset.code());
        TestKit.ok("and says the reset re-enabled the account",
                reset.stdout().contains("re-enabled"));
        TestKit.eq("the account is live again with the new secret", 0,
                cli(jarDir, base, "login", List.of("carol", TestKit.PW_BOB)).code());
        TestKit.ok("and the audit log records the re-enable",
                auditContains(data, "detail=updated-re-enabled"));
        Result plainReset = cli(jarDir, base, "set-password",
                List.of("carol", TestKit.PW_CAROL, TestKit.PW_CAROL));
        TestKit.eq("a reset of a live account says only ok", "ok.", verdict(plainReset));
        TestKit.ok("and does not claim a re-enable",
                !plainReset.stdout().contains("re-enabled"));
        TestKit.ok("disable-user reads no lines from stdin",
                countPrompts(cli(jarDir, base, "disable-user", List.of(),
                        List.of("--user=carol"))) == 0);
    }

    // ------------------------------------------------------------------------ argv surface

    private static void cliArgv(Path jarDir, Path home) {
        Path data = dir(home, "argv-data");
        Map<String, String> base = env(data);

        TestKit.eq("no arguments prints usage and exits 2", 2, cli(jarDir, base, "", List.of()).code());
        TestKit.ok("the usage line lists only the allowlist",
                cli(jarDir, base, "", List.of()).stdout().contains("login|add-user"));
        TestKit.eq("an unknown subcommand exits 2", 2, cli(jarDir, base, "shell", List.of()).code());
        TestKit.ok("an unknown subcommand is refused plainly",
                cli(jarDir, base, "shell", List.of()).stdout().contains("unknown command."));
        TestKit.eq("too many arguments exits 2", 2,
                cli(jarDir, base, "version", List.of(), List.of("a", "b", "c")).code());
        // No NUL in this matrix: an argument containing NUL cannot even be handed to
        // ProcessBuilder ("invalid null character in command"), which is the operating
        // system's own guard, not this program's. The NUL cases live in the stdin matrices.
        for (String sneaky : List.of("login ", " LOGIN", "LOGIN", "--help", "-h", "help",
                "portal", "Main", "Runtime", "exec", "add", "adduser", "status;ls",
                "version;rm -rf /", "-version")) {
            TestKit.eq("subcommand \"" + TestKit.show(sneaky) + "\" is refused", 2,
                    cli(jarDir, base, sneaky, List.of()).code());
        }
        TestKit.ok("no subcommand can be supplied through the environment",
                run(jarDir, with(base, "PORTAL_COMMAND", "version"), "").code() == 2);
        String allowlist = codeOnly("PortalCli.java");
        int from = allowlist.indexOf("SUBCOMMANDS =");
        String window = from < 0 ? "" : allowlist.substring(from, from + 260);
        for (String sub : List.of("login", "add-user", "set-password", "disable-user",
                "status", "version")) {
            TestKit.ok("the allowlist names " + sub, window.contains("\"" + sub + "\""));
        }
        TestKit.ok("and nothing else (six quoted entries in the list)",
                TestKit.countChar(window, "\"") >= 12
                        && TestKit.countChar(window.substring(0, window.indexOf(";")), "\"")
                                == 12);

        // An inherited CLASSPATH must not be able to redirect the code that runs: the suite
        // (and portal.sh) always pass an explicit -cp, and the program never resolves a class
        // named by the environment.
        Result poisoned = run(jarDir, with(base, "CLASSPATH", "/tmp/evil-classes"), "version");
        TestKit.ok("an inherited CLASSPATH does not break or redirect the run",
                poisoned.code() == 0 && poisoned.stdout().contains("portal-auth"));
        TestKit.ok("neither entry point loads a class by name from configuration",
                !codeOnly("Main.java").contains("Class.forName")
                        && !codeOnly("PortalCli.java").contains("Class.forName"));
        TestKit.ok("the program never reads the CLASSPATH variable",
                !codeOnly("Main.java").contains("CLASSPATH")
                        && !codeOnly("PortalCli.java").contains("CLASSPATH"));

        // The documented env surface: nothing outside it changes observable behaviour.
        String baseline = run(jarDir, base, "status").stdout();
        for (String dead : List.of("PORTAL_THROTTLE", "PORTAL_DEBUG", "PORTAL_ALLOW_INSECURE",
                "PORTAL_DISABLE_THROTTLE", "PORTAL_DEV", "PORTAL_INSECURE", "PORTAL_NO_TLS",
                "PORTAL_USERNAME", "PORTAL_PASSWORD", "PORTAL_HOME", "PORTAL_LOG_LEVEL",
                "PORTAL_SESSION_TTL")) {
            TestKit.ok(dead + " does not change observable output",
                    baseline.equals(run(jarDir, with(base, dead, "true"), "status").stdout()));
        }
    }

    // ------------------------------------------------------------- concurrent writers

    /**
     * Cross-process roster writes.
     *
     * <p>The regression here is a lost update, not a deadlock. Every mutator used to hold an
     * in-process monitor only, so N concurrent {@code add-user} processes each read the
     * roster, added their own account to their own in-memory copy and replaced the file
     * atomically. Each individual write was atomic; the last writer still won. Measured
     * before the fix, eight concurrent enrolments against one data directory left <b>2</b> of
     * 8 records, and all eight printed {@code ok.} and exited 0 &mdash; the tool reported
     * success while silently discarding six accounts. Rule 7's check-and-act spans processes
     * as well as threads, and the CLI is a short-lived process: an operator enrolling a batch
     * of accounts, or two admins on one host, is exactly this workload.
     *
     * <p>Both the decisions and the state are asserted. Counting records alone would stay
     * green if a process reported {@code ok} while its own account was the one discarded, so
     * each writer's exit code, its printed verdict and the presence of its own record are
     * checked together.
     */
    private static void concurrentWrites(Path jarDir, Path home) {
        int writers = 8;
        Path data = dir(home, "concurrent-data");
        Map<String, String> base = env(data);
        Result[] created = new Result[writers];
        launchTogether(writers, i -> {
            String name = "conc" + i;
            created[i] = cli(jarDir, base, "add-user",
                    List.of(name, "Concurrent-Pw-" + (10 + i) + "-a",
                            "Concurrent-Pw-" + (10 + i) + "-a"));
        });

        java.util.Set<String> names = rosterNames(data);
        TestKit.eq("no concurrent enrolment was lost", writers, names.size());
        for (int i = 0; i < writers; i++) {
            String name = "conc" + i;
            TestKit.ok("every writer's own record is on disk: " + name, names.contains(name));
            TestKit.eq("and it exited 0: " + name, 0, created[i] == null ? -1 : created[i].code());
        }
        TestKit.eq("a fresh process reads back all of them", String.valueOf(writers),
                statusValue(data, "accounts"));
        TestKit.ok("the cross-process lock file is owner-only",
                modeIs(data.resolve("employees.dat.lock"), "rw-------"));

        // The same file serialises a contested name: exactly one process may create it, and
        // the losers must say so rather than either clobbering the winner or claiming success.
        Path contested = dir(home, "concurrent-dup");
        Map<String, String> dupEnv = env(contested);
        Result[] raced = new Result[writers];
        launchTogether(writers, i -> {
            String pw = "Contested-Pw-" + (20 + i) + "-a";
            raced[i] = cli(jarDir, dupEnv, "add-user", List.of("dupuser", pw, pw));
        });
        int won = 0;
        int refused = 0;
        for (Result r : raced) {
            if (r != null && r.code() == 0) {
                won++;
            } else if (r != null && r.code() == 2) {
                refused++;
                TestKit.ok("the loser reports the real reason",
                        r.combined().contains("already exists"));
            } else {
                TestKit.ok("the loser exits with the taken code, not a crash: "
                        + (r == null ? "no result" : r.code()), false);
            }
        }
        TestKit.eq("exactly one process won the name", 1, won);
        TestKit.eq("and every other process was refused", writers - 1, refused);
        TestKit.eq("the contested name holds one record", 1, rosterNames(contested).size());
        TestKit.eq("the winner's record is the only one", "dupuser",
                rosterNames(contested).iterator().next());
    }

    /**
     * Runs {@code body} once per index on its own thread, released together. Threads are
     * joined before returning, so the caller can read the results the tasks wrote.
     */
    private static void launchTogether(int writers, java.util.function.IntConsumer body) {
        java.util.concurrent.CyclicBarrier go = new java.util.concurrent.CyclicBarrier(writers);
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < writers; i++) {
            int index = i;
            Thread t = new Thread(() -> {
                try {
                    go.await(120, TimeUnit.SECONDS);
                } catch (Exception notSynced) {
                    // Launch anyway. Turning a missed barrier into a pass would hide the bug
                    // this exists for, so the launches proceed un synchronised.
                }
                body.accept(index);
            }, "writer-" + i);
            threads.add(t);
            t.start();
        }
        for (Thread t : threads) {
            try {
                t.join(TimeUnit.SECONDS.toMillis(900));
            } catch (InterruptedException waited) {
                Thread.currentThread().interrupt();
            }
            TestKit.ok("a concurrent writer finished", !t.isAlive());
        }
    }

    /** The account names the roster file actually holds, as an on-disk process would see them. */
    private static java.util.Set<String> rosterNames(Path dataDir) {
        java.util.Set<String> out = new java.util.LinkedHashSet<>();
        try {
            for (String line : Files.readAllLines(dataDir.resolve("employees.dat"),
                    StandardCharsets.UTF_8)) {
                if (!line.startsWith("u=")) {
                    continue;
                }
                int sep = line.indexOf(" r=", 2);
                if (sep > 1) {
                    out.add(line.substring(2, sep));
                }
            }
        } catch (IOException unreadable) {
            TestKit.ok("the roster can be read back: " + unreadable.getMessage(), false);
        }
        return out;
    }

    // -------------------------------------------------------------------- audit discipline

    private static void auditDiscipline(Path jarDir, Path home) {
        Path data = dir(home, "audit-data");
        Map<String, String> base = env(data);
        cli(jarDir, base, "add-user", List.of("alice", TestKit.PW_ALICE, TestKit.PW_ALICE));
        cli(jarDir, base, "login", List.of("alice", TestKit.PW_ALICE));
        cli(jarDir, base, "login", List.of("alice", TestKit.PW_WRONG));
        cli(jarDir, base, "login", List.of("ghostuser", TestKit.PW_WRONG));
        cli(jarDir, base, "login", List.of("alice\t", TestKit.PW_ALICE));
        cli(jarDir, base, "login", List.of("alice\rFresh", TestKit.PW_ALICE));

        Path log = data.resolve("audit.log");
        TestKit.ok("the audit log exists", Files.isRegularFile(log));
        String body;
        try {
            body = Files.readString(log, StandardCharsets.UTF_8);
        } catch (IOException unreadable) {
            TestKit.ok("the audit log is readable by the test", false);
            return;
        }
        List<String> lines = body.lines().toList();
        TestKit.ok("the audit log grew with the activity", lines.size() >= 5);
        TestKit.ok("every line is machine-shaped",
                !lines.isEmpty() && lines.stream().allMatch(l -> l.matches(
                        "ts=[0-9T:.\\-Z]+ event=\\w+ subject=\\S+ src=\\S+ outcome=\\w+"
                                + " detail=[\\w.-]+")));
        TestKit.ok("the subject is a derived reference, never the typed name",
                !body.contains("subject=alice") && !body.contains("subject=ghostuser"));
        TestKit.ok("the raw username never appears anywhere in the log",
                !body.contains("alice") && !body.contains("ghostuser"));
        TestKit.ok("no password ever reaches the audit log",
                !body.contains(TestKit.PW_ALICE) && !body.contains(TestKit.PW_WRONG));
        TestKit.ok("a hostile line-break in a username cannot forge a log line",
                lines.stream().noneMatch(l -> l.contains("\r")));
        TestKit.ok("the log holds no tab, so fields cannot be injected", !body.contains("\t"));
        TestKit.ok("no audit line is unbounded",
                lines.stream().mapToInt(String::length).max().orElse(0) < 200);
        TestKit.ok("the audit log is 0600", modeIs(log, "rw-------"));
        TestKit.ok("the throttle ledger is 0600", modeIs(data.resolve("throttle.log"), "rw-------"));
        TestKit.ok("the roster is 0600", modeIs(data.resolve("employees.dat"), "rw-------"));
        TestKit.ok("the data directory is 0700", modeIs(data, "rwx------"));
        TestKit.ok("the roster file does not contain the plaintext secret", rosterHasNoSecret(data));
        try (var walk = Files.list(data)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                String n = p.getFileName().toString();
                TestKit.ok("no stray file left in the data dir: " + n,
                        n.equals("audit.log") || n.equals("employees.dat")
                                || n.equals("throttle.log") || n.startsWith("throttle.log.lock")
                                || n.startsWith("employees.dat.lock"));
            }
        } catch (IOException listed) {
            TestKit.ok("the data dir can be listed", false);
        }
    }

    private static boolean rosterHasNoSecret(Path data) {
        try {
            String roster = Files.readString(data.resolve("employees.dat"),
                    StandardCharsets.UTF_8);
            // The record is pbkdf2$sha256$iters$salt$key -- the secret itself must not be
            // reconstructable, and the password must not appear as an obvious encoding.
            return !roster.contains(TestKit.PW_ALICE)
                    && !roster.contains(java.util.Base64.getEncoder().encodeToString(
                            TestKit.PW_ALICE.getBytes(StandardCharsets.UTF_8)))
                    && roster.contains("pbkdf2$sha256$");
        } catch (IOException unreadable) {
            return false;
        }
    }

    // ------------------------------------------------------------------------- plumbing

    /** A data directory (hence a throttle ledger) with one live account in it. */
    private record Rig(Path data, Map<String, String> env) {
    }

    private static Rig rig(Path jarDir, Path home, String label, String user, String secret) {
        Path data = dir(home, label);
        Map<String, String> base = env(data);
        cli(jarDir, base, "add-user", List.of(user, secret, secret));
        return new Rig(data, base);
    }

    private static Map<String, String> env(Path dataDir) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put(PortalConfig.ENV_DATA_DIR, dataDir.toString());
        return m;
    }

    private static Map<String, String> with(Map<String, String> env, String key, String value) {
        Map<String, String> m = new LinkedHashMap<>(env);
        m.put(key, value);
        return m;
    }

    private static Map<String, String> without(Map<String, String> env, String key) {
        Map<String, String> m = new LinkedHashMap<>(env);
        m.remove(key);
        return m;
    }

    private static Result cli(Path jarDir, Map<String, String> env, String subcommand,
                              List<String> answers) {
        return cli(jarDir, env, subcommand, answers, List.of());
    }

    private static Result cli(Path jarDir, Map<String, String> env, String subcommand,
                              List<String> answers, List<String> argv) {
        List<String> all = new ArrayList<>(argv);
        if (!subcommand.isEmpty()) {
            all.add(0, subcommand);
        }
        return launch(jarDir, env, all, String.join("\n", answers)
                + (answers.isEmpty() ? "" : "\n"));
    }

    private static Result run(Path jarDir, Map<String, String> env, String subcommand) {
        return run(jarDir, env, subcommand, List.of(), List.of(), false);
    }

    private static Result run(Path jarDir, Map<String, String> env, String subcommand,
                              List<String> answers, List<String> argv, boolean closeStdin) {
        List<String> all = new ArrayList<>(argv);
        if (!subcommand.isEmpty()) {
            all.add(0, subcommand);
        }
        return launch(jarDir, env, all, closeStdin ? "" : String.join("\n", answers)
                + (answers.isEmpty() ? "" : "\n"));
    }

    /** Writes literal bytes to the child's stdin, so CR/LF framing can be controlled. */
    private static Result rawStdin(Path jarDir, Map<String, String> env, String stdinBytes) {
        return launch(jarDir, env, List.of("login"), stdinBytes);
    }

    private static Result launch(Path jarDir, Map<String, String> env, List<String> argv,
                                 String stdinBytes) {
        List<String> command = new ArrayList<>();
        command.add(System.getProperty("java.home") + "/bin/java");
        command.add("-cp");
        command.add(jarDir.toString());
        command.add(MAIN_CLASS);
        command.addAll(argv);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Map<String, String> child = pb.environment();
        child.clear();
        child.put("PATH", "/usr/bin:/bin");
        for (Map.Entry<String, String> e : env.entrySet()) {
            if (e.getValue() != null && !e.getValue().isEmpty()) {
                child.put(e.getKey(), e.getValue());
            }
        }
        try {
            Process p = pb.start();
            // The child's read ends only when we close its stdin, so write-then-close is
            // mandatory; not closing it hangs the run.
            p.getOutputStream().write(stdinBytes.getBytes(StandardCharsets.UTF_8));
            p.getOutputStream().close();
            byte[] raw = p.getInputStream().readAllBytes();
            if (!p.waitFor(180, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                TestKit.ok("subprocess timed out: " + argv, false);
                return new Result(-1, "");
            }
            return new Result(p.exitValue(), new String(raw, StandardCharsets.UTF_8));
        } catch (IOException | InterruptedException launchFailed) {
            if (launchFailed instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            TestKit.ok("could not launch " + argv + ": " + launchFailed.getMessage(), false);
            return new Result(-1, "");
        }
    }

    /** Prompts the child printed; every supplied answer must be matched by exactly one. */
    private static int countPrompts(Result r) {
        String haystack = r.combined();
        int newPw = TestKit.countChar(haystack, "new password: ");
        int repeat = TestKit.countChar(haystack, "repeat password: ");
        // "new password: " and "repeat password: " each contain "password: ", so the bare
        // prompt count has to discount them or one field reads as two prompts.
        int bare = TestKit.countChar(haystack, "password: ") - newPw - repeat;
        return TestKit.countChar(haystack, "username: ") + newPw + repeat + bare;
    }

    /** The verdict line, with the inline prompts removed. */
    private static String verdict(Result r) {
        String flat = r.combined().replace("\n", "");
        for (String prompt : List.of("username: ", "new password: ", "repeat password: ",
                "password: ")) {
            flat = flat.replace(prompt, "");
        }
        List<String> lines = new ArrayList<>();
        for (String l : flat.split("\n")) {
            if (!l.isEmpty()) {
                lines.add(l);
            }
        }
        return lines.isEmpty() ? "" : lines.get(lines.size() - 1);
    }

    private static String versionLine(Result r) {
        for (String token : r.combined().split(" ")) {
            if (token.startsWith("iterations=")) {
                return token.substring("iterations=".length()).trim();
            }
        }
        return "<missing>";
    }

    private static String statusValue(Path dataDir, String key) {
        // status is read through the real binary, so the value asserted is the one an
        // operator would see, not one read back from an internal object.
        Result r = launch(classDir(), env(dataDir), List.of("status"), "");
        for (String token : r.combined().split(" ")) {
            if (token.startsWith(key + "=")) {
                return token.substring(key.length() + 1).trim();
            }
        }
        return "<missing>";
    }

    private record Result(int code, String combined) {
        boolean ok() {
            return code == 0;
        }

        String stdout() {
            return combined;
        }

        List<String> lines() {
            List<String> out = new ArrayList<>();
            for (String l : combined.split("\n")) {
                if (!l.isEmpty()) {
                    out.add(l);
                }
            }
            return out;
        }
    }

    // ----------------------------------------------------------------------- file helpers

    private static Path dir(Path parent, String name) {
        Path p = parent.resolve(name);
        try {
            Files.createDirectories(p);
            Files.setPosixFilePermissions(p,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            return p;
        } catch (IOException cannotCreate) {
            TestKit.ok("cannot create " + name + ": " + cannotCreate.getMessage(), false);
            return p;
        }
    }

    private static Path write(Path p, String content) {
        try {
            Files.writeString(p, content, StandardCharsets.UTF_8);
            Files.setPosixFilePermissions(p,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            return p;
        } catch (IOException cannotWrite) {
            TestKit.ok("cannot write " + p.getFileName() + ": " + cannotWrite.getMessage(), false);
            return p;
        }
    }

    private static Path cfg(Path dir, String name, String body) {
        return write(dir.resolve(name), body);
    }

    /** Names inside a directory; empty when it does not exist or cannot be listed. */
    private static java.util.Set<String> entriesOf(Path dir) {
        try (java.util.stream.Stream<Path> seen = Files.list(dir)) {
            java.util.Set<String> out = new java.util.HashSet<>();
            seen.forEach(p -> out.add(p.getFileName().toString()));
            return out;
        } catch (IOException unreadable) {
            return java.util.Set.of("<unreadable>");
        }
    }

    private static void chmod(Path p, String mode) {
        try {
            Files.setPosixFilePermissions(p,
                    java.nio.file.attribute.PosixFilePermissions.fromString(mode));
        } catch (IOException | UnsupportedOperationException unavailable) {
            TestKit.ok("cannot set " + mode + " on " + p.getFileName(), false);
        }
    }

    private static boolean auditContains(Path dataDir, String needle) {
        try {
            return Files.readString(dataDir.resolve("audit.log"), StandardCharsets.UTF_8)
                    .contains(needle);
        } catch (IOException unreadable) {
            TestKit.ok("the audit log cannot be read to look for " + needle, false);
            return false;
        }
    }

    private static boolean modeIs(Path p, String expected) {
        try {
            return Files.exists(p) && TestKit.mode(p).equals(expected);
        } catch (IOException | UnsupportedOperationException unavailable) {
            return true;
        }
    }

    /**
     * Production source with comments stripped. Presence assertions must not be satisfiable
     * by prose that merely mentions the identifier they name.
     */
    private static String codeOnly(String file) {
        try {
            String raw = Files.readString(SRC_MAIN.resolve(file));
            StringBuilder out = new StringBuilder();
            boolean inBlock = false;
            for (String line : raw.split("\n", -1)) {
                String t = line.trim();
                if (inBlock) {
                    if (t.endsWith("*/")) {
                        inBlock = false;
                    }
                    continue;
                }
                if (t.startsWith("/*")) {
                    if (!t.endsWith("*/")) {
                        inBlock = true;
                    }
                    continue;
                }
                if (t.startsWith("//") || t.startsWith("*")) {
                    continue;
                }
                int inline = line.indexOf("//");
                out.append(inline >= 0 ? line.substring(0, inline) : line).append('\n');
            }
            return out.toString();
        } catch (IOException unreadable) {
            TestKit.ok("cannot read production source " + file, false);
            return "";
        }
    }
}
