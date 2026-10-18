package app;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * Operator-supplied configuration: the input surface with no user in front of it. Everything here
 * comes from the environment or argv, and every value decides a security outcome, so each guard is
 * exercised by making the real call and asserting both the refusal and the absence of a leak.
 */
public final class ConfigTest {

    private static final String SECRET = "Store-Secret-Do-Not-Print-01";

    public static void main(String[] argv) throws Exception {
        Path base = Harness.scratch("config");
        Harness.remove(base);
        requiredValues(base);
        keyDerivationFloor(base);
        passwordFileRules(base);
        directoryRules(base);
        storeFileRules(base);
        jdbcUrlIsHardened();

        System.exit(Harness.report("ConfigTest"));
    }

    private static void requiredValues(Path base) throws Exception {
        Harness.section("a missing or ambiguous secret stops startup instead of picking a default");
        Harness.check(refuses(env(base, null, null), "register"),
            "no database password at all is a hard stop");
        Harness.check(message(env(base, null, null)).contains(Config.ENV_DB_PASSWORD),
            "the message names the setting that is missing");

        Map<String, String> both = env(base, SECRET, null);
        Path file = writeSecret(base.resolve("both.txt"), SECRET);
        both.put(Config.ENV_DB_PASSWORD_FILE, file.toString());
        Harness.check(refuses(both, "register"),
            "supplying both APP_DB_PASSWORD and APP_DB_PASSWORD_FILE is refused - no precedence guessing");

        Map<String, String> shortInline = env(base, "too-short", null);
        Harness.check(refuses(shortInline, "register"), "a database password under 16 characters is refused");
        Harness.check(!message(shortInline).contains("too-short"),
            "the refusal never echoes the supplied secret");

        Harness.check(!refuses(env(base, SECRET, null), "register"),
            "a well-formed environment is accepted - the guards above are not blanket refusals");
    }

    private static void keyDerivationFloor(Path base) throws Exception {
        Harness.section("the key-derivation cost cannot be configured below an approved work factor");
        for (String memory : List.of("1024", "16384", "19455", "0", "-1", "nope", "99999999999")) {
            Map<String, String> weak = env(base, SECRET, null);
            weak.put(Config.ENV_ARGON2_MEMORY, memory);
            Harness.check(refuses(weak, "register"),
                "APP_ARGON2_MEMORY_KIB=" + memory + " is refused (OWASP Argon2id floor is 19456 KiB)");
            Harness.check(!message(weak).contains(SECRET),
                "a refusal about a cost setting never carries the database password");
        }
        for (String iterations : List.of("1", "0", "21", "x")) {
            Map<String, String> weak = env(base, SECRET, null);
            weak.put(Config.ENV_ARGON2_ITERATIONS, iterations);
            Harness.check(refuses(weak, "register"), "APP_ARGON2_ITERATIONS=" + iterations + " is refused");
        }
        for (String parallelism : List.of("0", "9", "-3")) {
            Map<String, String> weak = env(base, SECRET, null);
            weak.put(Config.ENV_ARGON2_PARALLELISM, parallelism);
            Harness.check(refuses(weak, "register"), "APP_ARGON2_PARALLELISM=" + parallelism + " is refused");
        }

        Map<String, String> atFloor = env(base, SECRET, null);
        atFloor.put(Config.ENV_ARGON2_MEMORY, "19456");
        atFloor.put(Config.ENV_ARGON2_ITERATIONS, "2");
        atFloor.put(Config.ENV_ARGON2_PARALLELISM, "8");
        Config accepted = attempt(atFloor);
        Harness.check(accepted != null, "the exact approved floor is accepted");
        Harness.equal(19_456, accepted == null ? -1 : accepted.argon2MemoryKib(),
            "the accepted memory cost is what was configured");

        Config defaults = attempt(env(base, SECRET, null));
        Harness.check(defaults != null, "the default configuration is accepted");
        if (defaults != null) {
            Harness.check(defaults.argon2MemoryKib() >= 19_456
                    && defaults.argon2Iterations() >= 2 && defaults.argon2Parallelism() >= 1,
                "the shipped defaults are at or above the Argon2id floor");
            Harness.note("shipped defaults are m=" + defaults.argon2MemoryKib() + "KiB,t="
                + defaults.argon2Iterations() + ",p=" + defaults.argon2Parallelism()
                + "; refused floor is m=19456KiB,t=2,p=1");
            defaults.close();
        }
    }

    private static void passwordFileRules(Path base) throws Exception {
        Harness.section("a password file must be a private regular file");
        Map<String, String> viaFile = env(base, null, null);

        Path worldReadable = writeSecret(base.resolve("world.txt"), SECRET);
        Files.setPosixFilePermissions(worldReadable, EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OTHERS_READ));
        viaFile.put(Config.ENV_DB_PASSWORD_FILE, worldReadable.toString());
        Harness.check(refuses(viaFile, "register"), "a group- or world-readable password file is refused");

        Path groupReadable = writeSecret(base.resolve("group.txt"), SECRET);
        Files.setPosixFilePermissions(groupReadable, EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ));
        Map<String, String> groupEnv = env(base, null, null);
        groupEnv.put(Config.ENV_DB_PASSWORD_FILE, groupReadable.toString());
        Harness.check(refuses(groupEnv, "register"), "a group-readable password file is refused too");

        Path missing = base.resolve("absent.txt");
        Map<String, String> missingEnv = env(base, null, null);
        missingEnv.put(Config.ENV_DB_PASSWORD_FILE, missing.toString());
        Harness.check(refuses(missingEnv, "register"), "a password file that does not exist is refused");

        Path link = base.resolve("link.txt");
        Files.deleteIfExists(link);
        Files.createSymbolicLink(link, writeSecret(base.resolve("target.txt"), SECRET));
        Map<String, String> linkEnv = env(base, null, null);
        linkEnv.put(Config.ENV_DB_PASSWORD_FILE, link.toString());
        Harness.check(refuses(linkEnv, "register"),
            "a symbolic link cannot stand in for the password file - it could be repointed at anything");

        Path shortContent = writeSecret(base.resolve("short.txt"), "short");
        Map<String, String> shortEnv = env(base, null, null);
        shortEnv.put(Config.ENV_DB_PASSWORD_FILE, shortContent.toString());
        Harness.check(refuses(shortEnv, "register"),
            "a password file whose content is under 16 characters is refused");

        Path good = writeSecret(base.resolve("good.txt"), SECRET + "\n");
        Map<String, String> goodEnv = env(base, null, null);
        goodEnv.put(Config.ENV_DB_PASSWORD_FILE, good.toString());
        Harness.check(!refuses(goodEnv, "register"),
            "a 0600 file is accepted, and its trailing newline is stripped rather than hashed in");

        // The secret must never be echoed by any refusal on this path.
        Harness.check(!message(linkEnv).contains(SECRET) && !message(shortEnv).contains(SECRET),
            "no configuration message carries the file's contents");
    }

    private static void directoryRules(Path base) throws Exception {
        Harness.section("the data directory must not be writable by anybody else");
        Path worldWritable = base.resolve("ww");
        Files.createDirectories(worldWritable);
        Files.setPosixFilePermissions(worldWritable, EnumSet.allOf(PosixFilePermission.class));
        Harness.check(refuses(env(worldWritable, SECRET, null), "register"),
            "a world-writable data directory is refused - another user could swap the store");

        Path loose = base.resolve("loose");
        Files.createDirectories(loose);
        Files.setPosixFilePermissions(loose, Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE,
            PosixFilePermission.GROUP_READ));
        Config tightened = attempt(env(loose, SECRET, null));
        Harness.check(tightened != null, "a group-readable data directory is not a hard stop");
        Harness.equal("rwx------", Harness.permissionString(loose),
            "the program tightens the directory it is about to fill with secrets");
        if (tightened != null) {
            tightened.close();
        }

        Path linkDir = base.resolve("linkdir");
        Path real = base.resolve("real");
        Files.createDirectories(real);
        Files.deleteIfExists(linkDir);
        Files.createSymbolicLink(linkDir, real);
        Harness.check(refuses(env(linkDir, SECRET, null), "register"),
            "the data directory may not be a symbolic link");

        Path notDir = base.resolve("notdir");
        Files.writeString(notDir, "x");
        Harness.check(refuses(env(notDir, SECRET, null), "register"),
            "a regular file cannot be used as the data directory");

        Path fresh = base.resolve("fresh");
        Config created = attempt(env(fresh, SECRET, null));
        Harness.check(created != null, "a data directory that does not exist yet is created");
        Harness.equal("rwx------", Harness.permissionString(fresh),
            "and it is created 0700, not with the process umask");
        if (created != null) {
            created.close();
        }

        Harness.check(refuses(mapOf(Config.ENV_DATA_DIR, "", Config.ENV_DB_PASSWORD, SECRET), "register"),
            "an empty APP_DATA_DIR is refused rather than taken to mean the working directory");
    }

    private static void storeFileRules(Path base) throws Exception {
        Harness.section("the account store file must already be owner-only");
        Path dir = base.resolve("store");
        Config first = attempt(env(dir, SECRET, null));
        Harness.check(first != null, "the store file is created before the database is opened");
        if (first != null) {
            first.close();
        }
        Path store = dir.resolve("accounts.mv.db");
        Harness.check(Files.exists(store), "the pre-created store file is where the JDBC url points");
        Harness.equal("rw-------", Harness.permissionString(store),
            "the store file is 0600, so H2 preserves it instead of creating it 0644");

        Files.setPosixFilePermissions(store, EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OTHERS_READ));
        Harness.check(refuses(env(dir, SECRET, null), "register"),
            "startup stops if the store has been widened, instead of quietly narrowing it back later");
        Files.setPosixFilePermissions(store, Harness.OWNER_ONLY);

        Path storeLink = base.resolve("storelink");
        Files.createDirectories(storeLink);
        Files.createSymbolicLink(storeLink.resolve("accounts.mv.db"), store);
        Harness.check(refuses(env(storeLink, SECRET, null), "register"),
            "the store may not be a symbolic link to somewhere else");

        Harness.check(refuses(mapOf(Config.ENV_DATA_DIR, "", Config.ENV_DB_PASSWORD, SECRET),
            "--data-dir"), "a bare --data-dir with no path is refused");
        Harness.check(refuses(mapOf(Config.ENV_DATA_DIR, "", Config.ENV_DB_PASSWORD, SECRET),
            "--data-dir="), "--data-dir= with an empty path is refused");
        Harness.check(refuses(mapOf(Config.ENV_DATA_DIR, "", Config.ENV_DB_PASSWORD, SECRET),
            "--data-dir=" + dir, "--data-dir=" + dir),
            "--data-dir given twice is refused - one flag must not silently win");
    }

    private static void jdbcUrlIsHardened() throws Exception {
        Harness.section("the JDBC url carries no credentials and disables H2's extra surfaces");
        Path dir = Harness.scratch("config-url");
        Harness.remove(dir);
        Config config = attempt(env(dir, SECRET, null));
        Harness.check(config != null, "the url fixture builds");
        if (config == null) {
            return;
        }
        String url = config.jdbcUrl();
        Harness.check(!url.contains(SECRET), "the database password is never part of the url");
        Harness.check(!url.toLowerCase().contains("auto_server=true"),
            "AUTO_SERVER is off - the store is single-process and opens no listening socket");
        Harness.check(url.contains("DB_CLOSE_ON_EXIT=FALSE"),
            "no shutdown hook, so the connection is closed deliberately");
        Harness.check(url.contains("TRACE_LEVEL_FILE=0"),
            "H2 tracing is off - a trace file would contain SQL text");
        Harness.check(!url.toLowerCase().contains("init="),
            "no INIT clause - the url cannot be made to run SQL on connect");
        config.close();
    }

    // ------------------------------------------------------------------ helpers

    private static Map<String, String> env(Path dataDir, String inlinePassword, String unused) {
        return mapOf(Config.ENV_DATA_DIR, dataDir.toString(),
            Config.ENV_DB_PASSWORD, inlinePassword == null ? "" : inlinePassword);
    }

    private static Map<String, String> mapOf(String... pairs) {
        Map<String, String> values = new HashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            if (pairs[i + 1] != null && !pairs[i + 1].isEmpty()) {
                values.put(pairs[i], pairs[i + 1]);
            }
        }
        return values;
    }

    private static Function<String, String> lookup(Map<String, String> values) {
        return values::get;
    }

    private static Config attempt(Map<String, String> values, String... argv) {
        try {
            return Config.fromEnvironment(lookup(values), argv);
        } catch (Config.ConfigException refused) {
            LAST_MESSAGE.set(refused.getMessage());
            return null;
        }
    }

    private static final ThreadLocal<String> LAST_MESSAGE = ThreadLocal.withInitial(() -> "");

    private static boolean refuses(Map<String, String> values, String... argv) {
        return attempt(values, argv) == null;
    }

    private static String message(Map<String, String> values) {
        attempt(values);
        return LAST_MESSAGE.get();
    }

    private static Path writeSecret(Path path, String value) throws IOException {
        Files.deleteIfExists(path);
        Files.writeString(path, value, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(path, Harness.OWNER_ONLY);
        return path;
    }
}
