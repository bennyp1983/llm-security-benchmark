package com.example.auth;

import java.io.IOException;
import java.security.SecureRandom;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Suite 1: trust boundaries, configuration validation, credential-store parsing, session
 * identifiers. Runs without performing logins, so it stays fast enough to run repeatedly.
 */
public final class Suite1Validation {

    private static final int FAST_ITERATIONS = AuthConfig.MIN_PBKDF2_ITERATIONS;

    /*
     * Control characters are built from code points rather than written as unicode
     * escapes: javac decodes those before lexing, so a carriage-return escape in a comment or
     * a literal becomes a real line break in the source stream and breaks compilation.
     * Building the characters here also keeps the source file free of invisible bytes.
     */
    private static final String NUL = String.valueOf((char) 0x00);
    private static final String CR = String.valueOf((char) 0x0d);
    private static final String ESC = String.valueOf((char) 0x1b);
    private static final String DEL = String.valueOf((char) 0x7f);
    private static final String ZWSP = String.valueOf((char) 0x200b);
    private static final String COMBINING_ACUTE = String.valueOf((char) 0x0301);
    private static final String SOFT_HYPHEN = String.valueOf((char) 0x00ad);
    private static final String RTL_OVERRIDE = String.valueOf((char) 0x202e);
    private static final String SMALL_HYPHEN = String.valueOf((char) 0xFE63);
    private static final String CYRILLIC_I = String.valueOf((char) 0x0456);

    /*
     * A java unicode escape is exactly four hex digits, so "\u1f600" in source is U+1F60 followed by
     * the digit zero -- two characters, not one supplementary code point. Anything here that is meant
     * to exercise surrogate handling is built from an int code point instead, and the tests below
     * assert the resulting character count so a mistake of that kind cannot pass silently.
     */
    private static String cp(int codePoint) {
        return new String(Character.toChars(codePoint));
    }

    private static String supplementarySeries(int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(cp(0x1F600 + i));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        try (Fixture fx = new Fixture("suite1")) {
            sourceAddressRules(fx);
            usernameRules(fx);
            passwordRules(fx);
            configValidation(fx);
            environmentPathEnforcesCrossFieldRules(fx);
            credentialStoreRules(fx);
            storedWorkFactorIsCappedAtThePolicy(fx);
            unverifiableModeCountsAsExposure(fx);
            lookALikeNamesAreDistinctAccounts(fx);
            encodingLeavesNoUnwritableCopy(fx);
            sessionRules(fx);
            sweepIsReachedOnlyByAShapedIdentifier();
            shippedTreeKeepsProvisioningOutOfProduction(fx);
            eventRedactionRules(fx);
        }
        Check.summary("suite1-validation");
    }

    // ---------------------------------------------------------------- addresses

    private static void sourceAddressRules(Fixture fx) {
        String[] valid = {"203.0.113.7", "8.8.8.8", "0.0.0.0", "255.255.255.255"};
        for (String value : valid) {
            Check.eq("accepts address " + value, value, InputValidator.normalizeSourceAddress(value));
        }
        // Every spelling of one host must produce one throttle bucket, so the accepted value is the
        // JDK's uncompressed canonical form, not the submitted text. Measured, not assumed: this JDK
        // expands "::" to eight groups and lower-cases hex digits.
        String[][] canonical = {
                {"::1", "0:0:0:0:0:0:0:1"},
                {"0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:1"},
                {"2001:db8::1", "2001:db8:0:0:0:0:0:1"},
                {"2001:DB8::1", "2001:db8:0:0:0:0:0:1"},
                {"fe80::1", "fe80:0:0:0:0:0:0:1"},
                {"::FFFF:127.0.0.1", "127.0.0.1"},
                {"::ffff:203.0.113.7", "203.0.113.7"},
                {"::1", "0:0:0:0:0:0:0:1"},
                {"64:ff9b::192.0.2.33", "64:ff9b:0:0:0:0:c000:221"},
        };
        for (String[] pair : canonical) {
            Check.eq("canonicalises " + pair[0], pair[1], InputValidator.normalizeSourceAddress(pair[0]));
        }
        Check.eq("every v6 spelling of the loopback host shares one bucket",
                InputValidator.normalizeSourceAddress("0:0:0:0:0:0:0:1"),
                InputValidator.normalizeSourceAddress("::1"));
        Check.ok("a canonical address is itself re-acceptable",
                InputValidator.normalizeSourceAddress(InputValidator.normalizeSourceAddress("2001:db8::1")) != null);

        String[] rejected = {
                null, "", " ", "  ", "\t", "\n", "localhost", "LOCALHOST", "example.com",
                "203.0.113.7 ", " 203.0.113.7", "203.0.113.07", "203.0.113.256", "203.0.113", "203.0.113.7.1",
                "3232235777", "0x7f.1", "127.1", "203.0.113.7:8443", "[::1]", "http://203.0.113.7",
                "fe80::1%eth0", "fe80::1%25", "::1/", "203.0.113.7/24", "user@203.0.113.7", "::1#",
                "2001:db8::1;", "203.0.113.7\nseq=1 ts=1 type=login_success", "0377.0.0.1", "1.2.3.4\t",
                "2030.113.7.1", ":::1", "1:2:3:4:5:6:7:8:9", "::ffff:203.0.113.007",
                "::ffff:203.0.113.256", "::ffff:1.2.3.4.5", "::ffff:"};
        for (String value : rejected) {
            Check.ok("rejects address " + describe(value), InputValidator.normalizeSourceAddress(value) == null);
        }
        Check.ok("longest accepted address is bounded",
                InputValidator.normalizeSourceAddress("f".repeat(46) + ":1") == null);
    }

    // ---------------------------------------------------------------- usernames

    private static void usernameRules(Fixture fx) {
        String[] valid = {"abc", "alice", "Alice", "alice.wu", "_private", "a-user", "user@example.com",
                "u1", "a".repeat(64), "\u00dcn\u00efcode-user", "\u7528\u6237\u540d", "ab@cd.ef-gh_ij"};
        for (String value : valid) {
            Check.eq("accepts username " + describe(value), value, InputValidator.validateUsername(value));
        }
        String[] rejected = {null, "", "a", "a".repeat(65), "alice ", " alice", "al ice", "ali\nce",
                "alice\r", "alice\t", "alice" + NUL, "..", "a..b", ".alice", "alice.", "alice_",
                "-alice", "alice-", "alice:admin", "alice;ls", "alice|ls", "alice$(id)", "alice*",
                "alice" + ESC + "[31m", "alice" + ZWSP, "alice" + COMBINING_ACUTE,
                "alice\u00e9" + COMBINING_ACUTE, SOFT_HYPHEN + "alice",
                "alice" + RTL_OVERRIDE, "alice" + DEL, "alice%00", "alice/dir", "alice\\admin",
                "alice\"", "alice'", "alice<>", "alice=", "alice+admin", "alice#", "alice" + SMALL_HYPHEN + "admin"};
        for (String value : rejected) {
            Check.ok("rejects username " + describe(value), InputValidator.validateUsername(value) == null);
        }
        // Case is preserved, never folded into the stored name: two spellings must not become one
        // name here (the store rejects case collisions instead).
        Check.eq("case is preserved", "Alice", InputValidator.validateUsername("Alice"));
        Check.ok("no trimming happens", InputValidator.validateUsername(" alice") == null
                && InputValidator.validateUsername("alice ") == null);
        Check.ok("isValidUsername agrees with validateUsername",
                InputValidator.isValidUsername("alice") && !InputValidator.isValidUsername("a"));
    }

    // ---------------------------------------------------------------- passwords

    private static void passwordRules(Fixture fx) throws Exception {
        String[] valid = {"Fresh-Ingress-21", "0123456789", "A-very-long-password-value-9",
                "p\u00e4ssw\u00f6rd-value", "p" + cp(0x1F511) + "assw\u00f6rd-value-x"};
        for (String value : valid) {
            char[] copy = InputValidator.validatePassword(value.toCharArray());
            Check.ok("accepts password of length " + value.length(), copy != null && copy.length == value.length());
            java.util.Arrays.fill(copy, (char) 0);
        }
        // The caller's array must not be retained.
        char[] callerOwned = "Fresh-Ingress-21".toCharArray();
        char[] returned = InputValidator.validatePassword(callerOwned);
        Check.ok("returns a private copy, not the caller's array", returned != callerOwned);
        java.util.Arrays.fill(callerOwned, (char) 0);
        Check.ok("wiping the caller's array does not wipe the copy", new String(returned).length() > 0);
        java.util.Arrays.fill(returned, (char) 0);

        String[] tooShort = {"", "Tiny-1", "123456789"};
        for (String value : tooShort) {
            Check.ok("rejects short password of length " + value.length(),
                    fails(value.toCharArray(), Diagnostic.PASSWORD_TOO_SHORT));
        }
        Check.ok("rejects a null password", fails(null, Diagnostic.PASSWORD_ENCODING_UNSUPPORTED));
        Check.ok("rejects an over-long password",
                fails("p".repeat(InputValidator.MAX_PASSWORD_CODEPOINTS + 1).toCharArray(),
                        Diagnostic.PASSWORD_TOO_SHORT));

        // Control characters, including a trailing tab that String.trim() would silently delete.
        Check.ok("rejects a trailing tab",
                fails("Fresh-Ingress-21\t".toCharArray(), Diagnostic.PASSWORD_CONTROL_CHARACTER));
        Check.ok("rejects a leading tab",
                fails("\tFresh-Ingress-21".toCharArray(), Diagnostic.PASSWORD_CONTROL_CHARACTER));
        Check.ok("rejects a trailing NUL",
                fails(("Fresh-Ingress-21" + NUL).toCharArray(), Diagnostic.PASSWORD_CONTROL_CHARACTER));
        Check.ok("rejects an embedded newline",
                fails("Fresh\nIngress-21".toCharArray(), Diagnostic.PASSWORD_CONTROL_CHARACTER));
        Check.ok("rejects DEL",
                fails(("Fresh-Ingress-2" + DEL + "1").toCharArray(), Diagnostic.PASSWORD_CONTROL_CHARACTER));
        Check.ok("rejects an embedded ESC (terminal control)",
                fails(("Fresh" + ESC + "[31m-Ingress").toCharArray(), Diagnostic.PASSWORD_CONTROL_CHARACTER));
        Check.ok("rejects a space", fails("Fresh Ingress 21".toCharArray(), Diagnostic.PASSWORD_CONTROL_CHARACTER));

        // Unpaired surrogates would be folded to '?' by getBytes, merging two distinct passwords.
        Check.ok("rejects an unpaired high surrogate",
                fails("Fresh-Ingress-21\uD83D".toCharArray(), Diagnostic.PASSWORD_ENCODING_UNSUPPORTED));
        Check.ok("rejects an unpaired low surrogate",
                fails("Fresh-Ingress-21\uDE00".toCharArray(), Diagnostic.PASSWORD_ENCODING_UNSUPPORTED));
        Check.ok("accepts a paired surrogate",
                !fails(("p" + cp(0x1F511) + "assw\u00f6rd-value").toCharArray(),
                Diagnostic.PASSWORD_ENCODING_UNSUPPORTED));
        Check.eq("that fixture really contains a surrogate pair", 2,
                Integer.valueOf(cp(0x1F511).length()));

        // An all-NUL buffer must not satisfy the length policy by being long: the control scan runs
        // before the length checks, so the reported reason is the real defect.
        Check.ok("an all-NUL buffer is rejected, not accepted for its length",
                fails(new char[1024], Diagnostic.PASSWORD_CONTROL_CHARACTER));

        // Code point counting, not char counting: 10 supplementary characters are 10 code points.
        String tenCodePoints = supplementarySeries(10);
        Check.eq("supplementary characters count as code points (10 chars -> 20 Java chars)",
                20, tenCodePoints.length());
        Check.ok("a 10-code-point supplementary password is accepted",
                InputValidator.validatePassword(tenCodePoints.toCharArray()) != null);

        // Encoding round trip must be exact.
        byte[] encoded = InputValidator.encodePassword("p\u00e4ssw\u00f6rd".toCharArray());
        Check.eq("UTF-8 encoding is used", 10, encoded.length);
        java.util.Arrays.fill(encoded, (byte) 0);
    }

    private static boolean fails(char[] value, Diagnostic expected) {
        try {
            char[] copy = InputValidator.validatePassword(value);
            java.util.Arrays.fill(copy, (char) 0);
            return false;
        } catch (AuthException e) {
            return e.diagnostic() == expected;
        }
    }

    // ---------------------------------------------------------------- configuration

    private static void configValidation(Fixture fx) throws Exception {
        // The base configuration below must be accepted, which means the files it names have to exist
        // and the keystore have to be readable before the first case runs.
        fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
        fx.writeAccounts(FAST_ITERATIONS, new String[][]{{Fixture.USER_ALICE, Fixture.PASSWORD_A}});

        Map<String, String> base = baseEnv(fx);
        Check.ok("the unmutated configuration is accepted", !refuses(base));
        Check.ok("a complete environment is accepted", AuthConfig.from(mapSource(base), fx.time) != null);

        // Every required key must be present: absence is a failure, never a permissive default.
        for (String key : List.of(AuthConfig.KEY_ACCOUNTS_FILE, AuthConfig.KEY_EVENT_LOG_FILE,
                AuthConfig.KEY_KEYSTORE_FILE, AuthConfig.KEY_KEYSTORE_PASSWORD,
                AuthConfig.KEY_PASSWORD_ENTRY_ALIAS, AuthConfig.KEY_PBKDF2_ITERATIONS,
                AuthConfig.KEY_ACCOUNT_LOCK_AFTER, AuthConfig.KEY_SOURCE_MAX_ATTEMPTS)) {
            Map<String, String> missing = new LinkedHashMap<>(base);
            missing.remove(key);
            Check.ok("absent " + key + " is refused", refuses(missing));
            Map<String, String> blank = new LinkedHashMap<>(base);
            blank.put(key, "");
            Check.ok("blank " + key + " is refused", refuses(blank));
        }

        // Numeric bounds: below-minimum, above-maximum and non-numeric must all be refused.
        String[][] outOfRange = {
                {AuthConfig.KEY_PBKDF2_ITERATIONS, "1000"},
                {AuthConfig.KEY_PBKDF2_ITERATIONS, String.valueOf(AuthConfig.MIN_PBKDF2_ITERATIONS - 1)},
                {AuthConfig.KEY_PBKDF2_ITERATIONS, "999999999"},
                {AuthConfig.KEY_PBKDF2_ITERATIONS, "not-a-number"},
                {AuthConfig.KEY_PBKDF2_ITERATIONS, "120000.5"},
                {AuthConfig.KEY_PBKDF2_ITERATIONS, "-120000"},
                {AuthConfig.KEY_ACCOUNT_LOCK_AFTER, "1"},
                {AuthConfig.KEY_ACCOUNT_LOCK_AFTER, "2"},
                {AuthConfig.KEY_ACCOUNT_LOCK_AFTER, "1000"},
                {AuthConfig.KEY_ACCOUNT_LOCK_SECONDS, "5"},
                {AuthConfig.KEY_ACCOUNT_LOCK_SECONDS, "999999"},
                {AuthConfig.KEY_SOURCE_MAX_ATTEMPTS, "2"},
                {AuthConfig.KEY_SOURCE_MAX_ATTEMPTS, "100000"},
                {AuthConfig.KEY_SESSION_TTL_SECONDS, "30"},
                {AuthConfig.KEY_SESSION_TTL_SECONDS, "99999999"},
                {AuthConfig.KEY_MAX_ACTIVE_SESSIONS, "2"},
                {AuthConfig.KEY_MAX_EVENTS, "3"},
                {AuthConfig.KEY_MIN_FREE_BYTES, "10"},
                {AuthConfig.KEY_SOURCE_WINDOW_SECONDS, "10"},
                {AuthConfig.KEY_SOURCE_BLOCK_SECONDS, "1"},
        };
        for (String[] pair : outOfRange) {
            Map<String, String> mutated = new LinkedHashMap<>(base);
            mutated.put(pair[0], pair[1]);
            Check.ok("refuses " + pair[0] + "=" + pair[1], refuses(mutated));
        }

        // Unknown keys in the namespace are refused rather than ignored.
        Map<String, String> typo = new LinkedHashMap<>(base);
        typo.put("AUTH_ACCOUNT_LOCK_AFETR", "4");
        Check.ok("a misspelled key in the AUTH_ namespace is refused", refuses(typo));
        Map<String, String> foreign = new LinkedHashMap<>(base);
        foreign.put("PATH", "/usr/bin");
        Check.ok("a key outside the namespace is ignored", !refuses(foreign));

        // Path shape.
        Map<String, String> relative = new LinkedHashMap<>(base);
        relative.put(AuthConfig.KEY_ACCOUNTS_FILE, "accounts.pwd");
        Check.ok("a relative path is refused", refuses(relative));
        Map<String, String> missingFile = new LinkedHashMap<>(base);
        missingFile.put(AuthConfig.KEY_ACCOUNTS_FILE, fx.root.resolve("no-such-file.pwd").toString());
        Check.ok("a path to a missing file is refused", refuses(missingFile));
        Map<String, String> directory = new LinkedHashMap<>(base);
        directory.put(AuthConfig.KEY_ACCOUNTS_FILE, fx.root.toString());
        Check.ok("a directory where a file is required is refused", refuses(directory));
        Map<String, String> withNul = new LinkedHashMap<>(base);
        withNul.put(AuthConfig.KEY_ACCOUNTS_FILE, fx.accountsFile + NUL + ".txt");
        Check.ok("a path containing NUL is refused", refuses(withNul));

        // The keystore must not be reachable by other users.
        Fixture perms = new Fixture("suite1-perms");
        perms.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
        perms.writeAccounts(FAST_ITERATIONS, new String[][]{{Fixture.USER_ALICE, Fixture.PASSWORD_A}});
        Map<String, String> permsBase = baseEnv(perms);
        for (Set<PosixFilePermission> worldReadable : List.of(
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OTHERS_READ),
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.GROUP_READ))) {
            Fixture.restrict(perms.keystoreFile, worldReadable);
            Check.ok("refuses a keystore with permissions " + worldReadable, refuses(permsBase));
        }
        Fixture.restrict(perms.keystoreFile, Check.OWNER_ONLY);
        Check.ok("accepts the keystore again once permissions are restored",
                AuthConfig.from(mapSource(permsBase), perms.time) != null);

        // A wrong keystore password must be refused, and the reason must not leak the value.
        Map<String, String> wrongPassword = new LinkedHashMap<>(permsBase);
        wrongPassword.put(AuthConfig.KEY_KEYSTORE_PASSWORD, "Wrong-Keystore-Pass-1");
        Check.ok("a wrong keystore password is refused", refuses(wrongPassword));

        // A world-writable directory for the log is refused.
        Map<String, String> worldDir = new LinkedHashMap<>(permsBase);
        worldDir.put(AuthConfig.KEY_EVENT_LOG_FILE, perms.root.resolve("log-from-world-dir.log").toString());
        Fixture.restrict(perms.root, EnumSet.allOf(PosixFilePermission.class));
        Check.ok("a world-writable log directory is refused", refuses(worldDir));
        Fixture.restrict(perms.root, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE));

        // An alias that is not a key name is refused.
        Map<String, String> badAlias = new LinkedHashMap<>(permsBase);
        badAlias.put(AuthConfig.KEY_PASSWORD_ENTRY_ALIAS, "../etc/passwd");
        Check.ok("a path-like alias is refused", refuses(badAlias));
        Map<String, String> missingAlias = new LinkedHashMap<>(permsBase);
        missingAlias.put(AuthConfig.KEY_PASSWORD_ENTRY_ALIAS, "not-in-store");
        Check.ok("an alias absent from the keystore is refused", refuses(missingAlias));

        // Problem strings must name keys, never values.
        Map<String, String> leaking = new LinkedHashMap<>(base);
        leaking.put(AuthConfig.KEY_PBKDF2_ITERATIONS, "1");
        try {
            AuthConfig.from(mapSource(leaking), fx.time);
            Check.ok("an out-of-range value reaches the operator as a problem", false);
        } catch (InvalidConfigException e) {
            String rendered = String.join(" | ", e.problems());
            Check.ok("the problem text names the key", rendered.contains(AuthConfig.KEY_PBKDF2_ITERATIONS));
            Check.lacks("the problem text omits the configured value", rendered, "keystore-password-value");
            Check.ok("AuthConfig.toString omits every path", !safeToString(base));
        }
        perms.close();
    }

    private static boolean safeToString(Map<String, String> base) throws Exception {
        AuthConfig config = AuthConfig.from(mapSource(base), TimeSource.mutable(1L));
        String text = config.toString();
        return text.contains("accounts.pwd") || text.contains(base.get(AuthConfig.KEY_KEYSTORE_PASSWORD))
                || text.contains("pepper");
    }

    private static boolean refuses(Map<String, String> env) {
        try {
            AuthConfig.from(mapSource(env), TimeSource.mutable(1_700_000_000_000L));
            return false;
        } catch (InvalidConfigException e) {
            return !e.problems().isEmpty();
        }
    }

    private static Map<String, String> baseEnv(Fixture fx) {
        Map<String, String> env = new LinkedHashMap<>();
        env.put(AuthConfig.KEY_ACCOUNTS_FILE, fx.accountsFile.toString());
        env.put(AuthConfig.KEY_EVENT_LOG_FILE, fx.logFile.toString());
        env.put(AuthConfig.KEY_KEYSTORE_FILE, fx.keystoreFile.toString());
        env.put(AuthConfig.KEY_KEYSTORE_PASSWORD, new String(AuthTestKeys.STORE_PASSWORD));
        env.put(AuthConfig.KEY_PASSWORD_ENTRY_ALIAS, AuthTestKeys.ALIAS);
        env.put(AuthConfig.KEY_PBKDF2_ITERATIONS, "120000");
        env.put(AuthConfig.KEY_MIN_ACCEPTED_ITERATIONS, "50000");
        env.put(AuthConfig.KEY_ACCOUNT_LOCK_AFTER, "5");
        env.put(AuthConfig.KEY_ACCOUNT_LOCK_SECONDS, "600");
        env.put(AuthConfig.KEY_SOURCE_WINDOW_SECONDS, "600");
        env.put(AuthConfig.KEY_SOURCE_MAX_ATTEMPTS, "200");
        env.put(AuthConfig.KEY_SOURCE_BLOCK_SECONDS, "600");
        env.put(AuthConfig.KEY_SESSION_TTL_SECONDS, "900");
        env.put(AuthConfig.KEY_MAX_ACTIVE_SESSIONS, "512");
        env.put(AuthConfig.KEY_MAX_EVENTS, "2000");
        env.put(AuthConfig.KEY_MIN_FREE_BYTES, "1048576");
        return env;
    }

    private static ConfigSource mapSource(Map<String, String> values) {
        return ConfigSource.ofMap(values);
    }

    // ---------------------------------------------------------------- store

    private static void credentialStoreRules(Fixture fx) throws Exception {
        fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);

        List<String> cases = new ArrayList<>();
        // One defect per case, so the reported reason is the guard under test.
        cases.add("bad name!:AAAAAAAAAAAAAAAAAAAAAA==:120000:" + digest64());
        cases.add("alice:not-base64!!!:120000:" + digest64());
        cases.add("alice:" + salt64() + ":0:" + digest64());
        cases.add("alice:" + salt64() + ":99999999:" + digest64());
        cases.add("alice:" + salt64() + ":120000:short");
        cases.add("alice:" + salt64() + ":120000");
        cases.add("alice::120000:" + digest64());
        cases.add("alice:" + salt64() + ":120000:" + digest64() + ":extra");

        for (String line : cases) {
            fx.writeAccountsRaw(line);
            List<String> problems = new ArrayList<>();
            FileCredentialStore store = FileCredentialStore.load(fx.accountsFile, fx.standardConfig(FAST_ITERATIONS), problems);
            Check.ok("store rejects [" + line.substring(0, Math.min(28, line.length())) + "...]",
                    !problems.isEmpty() && store.size() == 0);
        }

        // Case collision: two records that one spelling could name.
        fx.writeAccountsRaw(List.of(
                "alice:" + salt64() + ":120000:" + digest64(),
                "Alice:" + salt64() + ":120000:" + digest64()));
        List<String> collision = new ArrayList<>();
        FileCredentialStore collided = FileCredentialStore.load(fx.accountsFile, fx.standardConfig(FAST_ITERATIONS), collision);
        Check.ok("a case-colliding record pair is refused", !collision.isEmpty() && collided.size() == 0);

        // A record whose iteration count is below the accepted minimum is refused.
        fx.writeAccountsRaw(List.of("dave:" + salt64() + ":10000:" + digest64()));
        List<String> weakIteration = new ArrayList<>();
        FileCredentialStore weakStore = FileCredentialStore.load(fx.accountsFile,
                fx.config(FAST_ITERATIONS).minAcceptedIterations(50_000).build(), weakIteration);
        Check.ok("a record with a too-low iteration count is refused",
                !weakIteration.isEmpty() && weakStore.size() == 0);

        // A non-canonical Base64 salt is refused: two texts must not denote one salt.
        fx.writeAccountsRaw(List.of("erin:" + nonCanonicalSalt() + ":120000:" + digest64()));
        List<String> nonCanonical = new ArrayList<>();
        FileCredentialStore.load(fx.accountsFile, fx.standardConfig(FAST_ITERATIONS), nonCanonical);
        Check.ok("non-canonical Base64 in a record is refused", !nonCanonical.isEmpty());

        // The same trap on the digest field, which is the longer field and the one an attacker would
        // target to make two stored digests compare equal.
        fx.writeAccountsRaw(List.of("frank:" + salt64() + ":120000:" + nonCanonicalDigest()));
        List<String> nonCanonicalDigest = new ArrayList<>();
        FileCredentialStore.load(fx.accountsFile, fx.standardConfig(FAST_ITERATIONS), nonCanonicalDigest);
        Check.ok("non-canonical Base64 in the digest field is refused", !nonCanonicalDigest.isEmpty());

        // Iteration counts are parsed by hand rather than with Integer.parseInt, which accepts a
        // leading '+', a leading zero and any Unicode digit. Each of those would let a second text
        // denote the same work factor as a stored record.
        for (String spelling : List.of("+120000", "0120000", "120000 ", " 120000", "\u0661\u0662\u0660\u0660\u0660\u0660")) {
            fx.writeAccountsRaw(List.of("gina:" + salt64() + ":" + spelling + ":" + digest64()));
            List<String> problems = new ArrayList<>();
            FileCredentialStore store = FileCredentialStore.load(fx.accountsFile,
                    fx.standardConfig(FAST_ITERATIONS), problems);
            Check.ok("the iteration spelling [" + spelling + "] is refused", !problems.isEmpty() && store.size() == 0);
        }

        // The store's own bounds, each asserted by the reason it produces: a file that is oversized
        // would also be rejected for having too many records, so only the named reason shows which
        // guard ran.
        storeSizeBoundsAreEnforced(fx);
        storeLineLengthBoundIsEnforced(fx);

        // Valid records load, and lookup ignores ASCII case only.
        fx.writeAccounts(FAST_ITERATIONS, new String[][]{
                {Fixture.USER_ALICE, Fixture.PASSWORD_A},
                {Fixture.USER_BOB, Fixture.PASSWORD_B}});
        FileCredentialStore good = FileCredentialStore.load(fx.accountsFile, fx.standardConfig(FAST_ITERATIONS), new ArrayList<>());
        Check.eq("two valid records load", 2, good.size());
        Check.ok("lookup by exact name finds the record", good.lookup("alice").isPresent());
        Check.ok("lookup by other ASCII case finds the same record", good.lookup("ALICE").isPresent());
        Check.ok("lookup of an absent name is empty", good.lookup("nobody").isEmpty());
        Check.ok("lookup of a null name is empty", good.lookup(null).isEmpty());
        Check.ok("a homoglyph does not resolve to a real account", good.lookup("al\u0456ce").isEmpty());

        // Record text must not carry the digest into a rendered object.
        String rendered = good.lookup("alice").orElseThrow().toString();
        Check.lacksAllNonEmpty("a rendered record omits the digest", rendered,
                FixtureProvisioner.base64(good.lookup("alice").orElseThrow().digest()));
    }

    /**
     * The record-count bound. Asserted by the reason string, because a file big enough to trip the
     * byte bound trips this one first and the two guards would otherwise be indistinguishable.
     */
    private static void storeSizeBoundsAreEnforced(Fixture fx) throws Exception {
        StringBuilder many = new StringBuilder();
        for (int i = 0; i < 20_001; i++) {
            many.append("user").append(i).append(':').append(salt64()).append(":120000:").append(digest64())
                    .append('\n');
        }
        Files.write(fx.accountsFile, many.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Check.ok("the record-count fixture is under the byte bound",
                Files.size(fx.accountsFile) < 8L * 1024 * 1024);
        List<String> problems = new ArrayList<>();
        FileCredentialStore store = FileCredentialStore.load(fx.accountsFile, fx.standardConfig(FAST_ITERATIONS),
                problems);
        Check.contains("too many records is refused by name", String.join(" | ", problems), "more records");
        Check.eq("an oversized store loads nothing", 0, Integer.valueOf(store.size()));

        // The byte bound, with a file whose record count is legal but whose total size is not. A
        // valid record cannot exceed ~142 bytes, so 20 000 valid ones stay under 8 MB and the size
        // guard is unreachable through valid content alone - which is exactly why the guard reads the
        // file size before parsing. The padding here is deliberately over-long lines: if the size
        // guard were removed the failure reason would become "too long", so the needle below still
        // identifies which guard ran.
        StringBuilder wide = new StringBuilder();
        for (int i = 0; i < 20_000; i++) {
            wide.append("u").append(i).append(':').append("z".repeat(400)).append(":120000:").append(digest64())
                    .append('\n');
        }
        Check.ok("the byte-bound fixture stays under the record bound",
                wide.toString().split("\n").length <= 20_000);
        Files.write(fx.accountsFile, wide.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Check.ok("the byte-bound fixture really exceeds the byte bound",
                Files.size(fx.accountsFile) > 8L * 1024 * 1024);
        List<String> wideProblems = new ArrayList<>();
        FileCredentialStore wideStore = FileCredentialStore.load(fx.accountsFile, fx.standardConfig(FAST_ITERATIONS),
                wideProblems);
        Check.contains("an over-large file is refused by name", String.join(" | ", wideProblems), "larger than");
        Check.eq("an over-large store loads nothing", 0, Integer.valueOf(wideStore.size()));
    }

    /** A single record longer than the line bound is refused, not truncated. */
    private static void storeLineLengthBoundIsEnforced(Fixture fx) throws Exception {
        String longName = "a".repeat(600);
        Check.ok("the long-name fixture exceeds the line bound", longName.length() > 512);
        fx.writeAccountsRaw(List.of(longName + ":" + salt64() + ":120000:" + digest64()));
        List<String> problems = new ArrayList<>();
        FileCredentialStore store = FileCredentialStore.load(fx.accountsFile, fx.standardConfig(FAST_ITERATIONS),
                problems);
        Check.contains("an over-long record line is refused by name", String.join(" | ", problems), "too long");
        Check.eq("an over-long record loads nothing", 0, Integer.valueOf(store.size()));
    }

    private static String salt64() {
        byte[] salt = new byte[PasswordHasher.SALT_BYTES];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) (i * 7 + 3);
        }
        return FixtureProvisioner.base64(salt);
    }

    /**
     * Builds a salt text that decodes to the same bytes as {@link #salt64()} but is not what the
     * encoder emits, by changing the trailing bits of the final character. The test asserts the
     * fixture really is non-canonical before asserting that it is refused, so a future change to the
     * codec cannot turn this check into a no-op.
     */
    private static String nonCanonicalSalt() {
        String canonical = salt64();
        // A 16-byte salt is 128 bits, so the last non-padding character carries only its top two
        // bits of real data; the other four are spare. Setting a spare bit changes the text without
        // changing the decoded bytes -- exactly the non-canonical input a codec must not accept.
        int index = canonical.length() - 3;
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int value = alphabet.indexOf(canonical.charAt(index));
        Check.ok("the salt fixture is 16 bytes of 64 characters ending in padding",
                canonical.length() == 24 && canonical.endsWith("==") && (value & 0x0F) == 0);
        char swapped = alphabet.charAt(value + 1);
        String mutated = canonical.substring(0, index) + swapped + canonical.substring(index + 1);
        Check.ok("the non-canonical fixture decodes to the same bytes",
                java.util.Arrays.equals(java.util.Base64.getDecoder().decode(mutated),
                        java.util.Base64.getDecoder().decode(canonical)));
        Check.ok("the non-canonical fixture is not encoder output",
                !java.util.Base64.getEncoder().encodeToString(
                        java.util.Base64.getDecoder().decode(mutated)).equals(mutated));
        return mutated;
    }

    private static String digest64() {
        byte[] digest = new byte[32];
        for (int i = 0; i < digest.length; i++) {
            digest[i] = (byte) (i * 5 + 1);
        }
        return FixtureProvisioner.base64(digest);
    }

    /**
     * A digest text that decodes to {@link #digest64()}'s bytes but is not encoder output. A 32-byte
     * digest ends in one padding character, so the last real character carries two spare bits.
     */
    private static String nonCanonicalDigest() {
        String canonical = digest64();
        int index = canonical.length() - 2;
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int value = alphabet.indexOf(canonical.charAt(index));
        Check.ok("the digest fixture is 32 bytes of 44 characters ending in one pad",
                canonical.length() == 44 && canonical.endsWith("=") && (value & 0x03) == 0);
        String mutated = canonical.substring(0, index) + alphabet.charAt(value + 1) + canonical.substring(index + 1);
        Check.ok("the non-canonical digest fixture decodes to the same bytes",
                java.util.Arrays.equals(java.util.Base64.getDecoder().decode(mutated),
                        java.util.Base64.getDecoder().decode(canonical)));
        Check.ok("the non-canonical digest fixture is not encoder output",
                !java.util.Base64.getEncoder().encodeToString(
                        java.util.Base64.getDecoder().decode(mutated)).equals(mutated));
        return mutated;
    }

    // ---------------------------------------------------------------- sessions

    private static void sessionRules(Fixture fx) throws Exception {
        SecureRandom random = new SecureRandom();
        TimeSource.Mutable clock = TimeSource.mutable(1_700_000_000_000L);
        SessionTokenStore tokens = new SessionTokenStore(random, 900, 8, clock);

        String token = tokens.issue();
        Check.ok("an issued identifier is present", token != null);
        Check.eq("an identifier is 32 hex characters", 32, token.length());
        Check.ok("an identifier is lower-case hex", token.matches("[0-9a-f]{32}"));
        Check.ok("a fresh identifier validates", tokens.isValid(token));
        Check.ok("null is not valid", !tokens.isValid(null));
        Check.ok("an empty identifier is not valid", !tokens.isValid(""));
        Check.ok("a wrong-length identifier is not valid", !tokens.isValid(token.substring(0, 31)));
        Check.ok("an uppercase identifier is not valid (no case folding)", !tokens.isValid(token.toUpperCase()));
        Check.ok("a random identifier is not valid", !tokens.isValid("0".repeat(32)));
        tokens.revoke(token);
        Check.ok("a revoked identifier is not valid", !tokens.isValid(token));
        tokens.revoke(token);
        Check.ok("revoking twice is harmless", !tokens.isValid(token));

        Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; i < 200; i++) {
            SessionTokenStore pool = new SessionTokenStore(random, 900, 4096, clock);
            String candidate = pool.issue();
            seen.add(candidate);
        }
        Check.eq("200 issued identifiers are all distinct", 200, seen.size());

        // Expiry follows server-side time.
        clock.advanceMillis(900_000L);
        SessionTokenStore expiring = new SessionTokenStore(random, 900, 8, clock);
        String shortLived = expiring.issue();
        Check.ok("a live identifier validates", expiring.isValid(shortLived));
        clock.advanceMillis(900_001L);
        Check.ok("an expired identifier does not validate", !expiring.isValid(shortLived));

        // Sliding expiry: a used identifier stays alive.
        TimeSource.Mutable sliding = TimeSource.mutable(1_700_000_000_000L);
        SessionTokenStore slider = new SessionTokenStore(random, 900, 8, sliding);
        String slidingToken = slider.issue();
        for (int i = 0; i < 10; i++) {
            sliding.advanceMillis(800_000L);
            Check.ok("use within the window keeps the identifier alive (step " + i + ")", slider.isValid(slidingToken));
        }

        // Capacity is bounded and refusing to issue is the answer, not unbounded growth.
        SessionTokenStore bounded = new SessionTokenStore(random, 900, 4, clock);
        TimeSource.Mutable boundedClock = TimeSource.mutable(1_700_000_000_000L);
        SessionTokenStore capped = new SessionTokenStore(random, 900, 4, boundedClock);
        for (int i = 0; i < 4; i++) {
            Check.ok("issuing within capacity succeeds", capped.issue() != null);
        }
        Check.eq("the table never exceeds its cap", 4, capped.activeCount());
        // Nothing is old enough to evict yet, so the fifth issue must be refused.
        Check.ok("issuing beyond capacity is refused rather than growing the table", capped.issue() == null);
        Check.eq("the refusal did not grow the table", 4, capped.activeCount());
        boundedClock.advanceMillis(2_000L);
        Check.ok("after the grace period a slot can be reclaimed", capped.issue() != null);
        Check.ok("the table still respects its cap", capped.activeCount() <= 4);

        // Cookie directive.
        SessionTokenStore cookieStore = new SessionTokenStore(random, 900, 8, TimeSource.mutable(1L));
        String cookieToken = cookieStore.issue();
        String directive = cookieStore.cookieDirectiveFor(cookieToken, "sid", "/app", true);
        Check.ok("a cookie directive is produced over TLS", directive != null);
        Check.contains("the cookie is HttpOnly", directive, "HttpOnly");
        Check.contains("the cookie is Secure", directive, "Secure");
        Check.contains("the cookie is SameSite=Strict", directive, "SameSite=Strict");
        Check.contains("the cookie has the requested path", directive, "Path=/app");
        Check.contains("the cookie Max-Age matches the configured ttl", directive, "Max-Age=900");
        Check.contains("the cookie carries the identifier", directive, cookieToken);
        Check.ok("no cookie is produced over plaintext",
                cookieStore.cookieDirectiveFor(cookieToken, "sid", "/app", false) == null);
        Check.ok("a path-traversal cookie name is refused",
                cookieStore.cookieDirectiveFor(cookieToken, "../sid", "/app", true) == null);
        Check.ok("a path with a CR is refused",
                cookieStore.cookieDirectiveFor(cookieToken, "sid", "/a" + CR + "b", true) == null);
        Check.ok("a non-absolute cookie path is refused",
                cookieStore.cookieDirectiveFor(cookieToken, "sid", "app", true) == null);
        Check.ok("a cookie name with a separator is refused",
                cookieStore.cookieDirectiveFor(cookieToken, "sid=evil", "/app", true) == null);
        Check.ok("a non-hex identifier gets no cookie",
                cookieStore.cookieDirectiveFor("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "sid", "/app", true) == null);
    }

    /**
     * The expiry sweep is a scan of the whole session table, and the table is capped by configuration
     * rather than by the traffic an attacker can generate. If a caller-supplied string reached that
     * scan before its shape was checked, anyone with a keyboard could make every validity check cost
     * the deployment's maximum session count instead of a hash lookup.
     *
     * <p>The property is a bound on work, not an outcome: a scan and a hash probe both answer
     * {@code false} for a malformed identifier, so no deterministic assertion on the return value can
     * tell the two orders apart and a timing assertion would be a suite-3 flake. The shipped order is
     * therefore checked in the shipped source, with the needles pinned to the two shape conditions so
     * that removing either one fails here rather than silently re-opening the cost.
     */
    private static void sweepIsReachedOnlyByAShapedIdentifier() throws IOException {
        String source = ProductionSource.of("SessionTokenStore.java", "the session store");
        String body = ProductionSource.compact(
                ProductionSource.methodBody(source, "boolean isValid(String candidate)", "the validity check"));

        int sweep = body.indexOf("dropExpiredLocked(now)");
        int lengthCheck = body.indexOf("candidate.length()!=TOKEN_HEX_LENGTH");
        int hexCheck = body.indexOf("!isHex(candidate)");
        Check.ok("the validity check does sweep expired entries", sweep > 0);
        Check.ok("it requires the exact identifier length", lengthCheck >= 0);
        Check.ok("it requires the identifier to be hex, so no case folding is possible", hexCheck >= 0);
        Check.ok("both shape conditions are evaluated before the sweep",
                lengthCheck >= 0 && hexCheck >= 0 && lengthCheck < sweep && hexCheck < sweep);

        // The behavioural half: the shape check must not turn a valid identifier into an invalid one.
        SessionTokenStore store = new SessionTokenStore(new SecureRandom(), 900, 8,
                TimeSource.mutable(1_700_000_000_000L));
        String token = store.issue();
        Check.ok("a shaped identifier still validates", store.isValid(token));
    }

    /**
     * The iteration count is read out of the credential file, so a record can order this process to
     * do arbitrary work per sign-in. Bounded two ways: the store refuses a record above the
     * deployment's own configured cost at load time, and the hasher refuses one at derivation time, so
     * a record that arrives by another route still cannot buy more CPU than every other account costs.
     */
    private static void storedWorkFactorIsCappedAtThePolicy(Fixture fx) throws Exception {
        fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
        int policy = FAST_ITERATIONS;

        // One defect per record: the salt and digest are the accepted canonical texts, so only the
        // work factor can be the reason for a refusal.
        fx.writeAccountsRaw(List.of("over-policy:" + salt64() + ":" + (policy + 1) + ":" + digest64()));
        List<String> overPolicy = new ArrayList<>();
        FileCredentialStore refused = FileCredentialStore.load(fx.accountsFile,
                fx.config(policy).build(), overPolicy);
        Check.ok("a record that orders more work than the policy costs is refused at load",
                !overPolicy.isEmpty() && refused.size() == 0);
        Check.contains("and the refusal names the work factor", String.join(" | ", overPolicy),
                "unacceptable iteration count");

        // The bound is the configured count, not the parser's absolute ceiling, and it must not be
        // off by one: a record at exactly the policy is the ordinary case.
        fx.writeAccountsRaw(List.of("at-policy:" + salt64() + ":" + policy + ":" + digest64()));
        List<String> atPolicy = new ArrayList<>();
        FileCredentialStore accepted = FileCredentialStore.load(fx.accountsFile,
                fx.config(policy).build(), atPolicy);
        Check.ok("a record at exactly the configured cost loads", atPolicy.isEmpty() && accepted.size() == 1);

        // The second layer, for a record that reaches the hasher without going through the loader.
        PasswordHasher hasher = new PasswordHasher(Fixture.PEPPER.clone(), policy, new SecureRandom());
        byte[] salt = new byte[PasswordHasher.SALT_BYTES];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) (i + 1);
        }
        byte[] password = Fixture.PASSWORD_A.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] digest = hasher.derive(password, salt, policy);
        Check.eq("the configured cost still derives", PasswordHasher.MAX_DIGEST_BYTES, digest.length);
        Arrays.fill(digest, (byte) 0);

        Diagnostic beyond = null;
        try {
            byte[] never = hasher.derive(password, salt, policy + 1);
            Arrays.fill(never, (byte) 0);
        } catch (AuthException e) {
            beyond = e.diagnostic();
        }
        Check.eq("deriving above the configured cost is refused rather than performed",
                Diagnostic.STORE_UNAVAILABLE, beyond);
    }

    /**
     * Rule 2 says no credential or audit file is reachable by another user. Every mode question this
     * component asks must therefore answer "exposed" when it cannot be asked at all - a file system
     * without POSIX bits, or an entry that vanished mid-check - because reporting "safe" there is what
     * makes an unreadable file system look like it passed. Each predicate is driven into that branch
     * with a path that cannot be stat'ed, and the shipped source is checked to keep the guard in all
     * three places rather than in whichever one a test happened to exercise.
     */
    private static void unverifiableModeCountsAsExposure(Fixture fx) throws Exception {
        Path missing = fx.root.resolve("absent-file");
        Files.deleteIfExists(missing);
        Check.ok("a path that cannot be examined reports no mode at all",
                PosixMode.permissionsOf(missing) == null);
        Check.ok("a mode that cannot be read counts as exposed to others",
                PosixMode.exposedToGroupOrOther(missing));
        Check.ok("a mode that cannot be read counts as writable by others",
                PosixMode.writableByGroupOrOther(missing));
        Check.ok("a mode that cannot be read is not accepted as owner-only",
                PosixMode.notExactlyOwnerOnly(missing));
        Check.ok("a null path is refused rather than trusted", PosixMode.exposedToGroupOrOther(null));

        int guards = 0;
        for (String name : List.of("exposedToGroupOrOther", "writableByGroupOrOther", "notExactlyOwnerOnly")) {
            String body = ProductionSource.compact(ProductionSource.methodBody(
                    ProductionSource.of("PosixMode.java", "the mode gate"),
                    "static boolean " + name + "(Path path) {", name));
            if (body.contains("if(permissions==null){returntrue;}")) {
                guards++;
            }
        }
        Check.eq("all three predicates fail closed on an unreadable mode", 3, guards);

        // The ordinary answers, so the fail-closed branch above cannot be satisfied by a gate that
        // simply refuses everything.
        Path clean = fx.root.resolve("mode-clean.pwd");
        Files.write(clean, new byte[0]);
        Fixture.restrict(clean, Check.OWNER_ONLY);
        Check.ok("an owner-only file is not exposed", !PosixMode.exposedToGroupOrOther(clean));
        Check.ok("an owner-only file is not group- or other-writable",
                !PosixMode.writableByGroupOrOther(clean));
        Check.ok("an owner-only file passes the strict check", !PosixMode.notExactlyOwnerOnly(clean));

        Path groupRead = fx.root.resolve("mode-groupread.pwd");
        Files.write(groupRead, new byte[0]);
        Fixture.restrict(groupRead, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ));
        Check.ok("group read is exposure", PosixMode.exposedToGroupOrOther(groupRead));
        Check.ok("group read is not the writable case", !PosixMode.writableByGroupOrOther(groupRead));

        Path otherWrite = fx.root.resolve("mode-otherwrite.pwd");
        Files.write(otherWrite, new byte[0]);
        Fixture.restrict(otherWrite, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OTHERS_WRITE));
        Check.ok("other write is the writable case", PosixMode.writableByGroupOrOther(otherWrite));

        // The directory case, which is what lets another user pre-create a symlink at the log's name.
        Path looseDir = fx.root.resolve("loose-dir");
        Files.createDirectories(looseDir);
        Fixture.restrict(looseDir, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_WRITE));
        Check.ok("group write on a directory is enough to reject it",
                PosixMode.writableByGroupOrOther(looseDir));

        Path tightDir = fx.root.resolve("tight-dir");
        Files.createDirectories(tightDir);
        Fixture.restrict(tightDir, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE));
        Check.ok("an owner-only directory is accepted", !PosixMode.writableByGroupOrOther(tightDir));

        // Judged without following links: a symlink is 0777 in its own right and must be refused on
        // those bits rather than judged through to whatever owner-only file it points at.
        Path link = fx.root.resolve("mode-link");
        Files.deleteIfExists(link);
        Files.createSymbolicLink(link, clean);
        Check.ok("a symlink is refused on its own bits", PosixMode.exposedToGroupOrOther(link));
        Check.ok("and never accepted as owner-only", PosixMode.notExactlyOwnerOnly(link));
    }

    // ---------------------------------------------------------------- configuration, cross-field

    /**
     * The two rules that relate one setting to another - the per-source budget must be at least the
     * account lock threshold, and the work factor must not be below the minimum the store will accept -
     * are what make rule 3's "the limit cannot lock out a legitimate user" true. Both are only
     * breakable by a deployment that writes the numbers by hand, which is exactly what the environment
     * path is. If the environment path constructed its config directly instead of through
     * {@code Builder.build()}, these two would be dead code and every real deployment would skip them.
     */
    private static void environmentPathEnforcesCrossFieldRules(Fixture fx) throws Exception {
        fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
        fx.writeAccounts(FAST_ITERATIONS, new String[][]{{Fixture.USER_ALICE, Fixture.PASSWORD_A}});
        Map<String, String> base = baseEnv(fx);

        // A source budget below the account lock threshold: both values are individually in range, so
        // only the cross-field rule can catch it.
        Map<String, String> starvedSource = new LinkedHashMap<>(base);
        starvedSource.put(AuthConfig.KEY_ACCOUNT_LOCK_AFTER, "100");
        starvedSource.put(AuthConfig.KEY_SOURCE_MAX_ATTEMPTS, "10");
        Check.ok("the environment path refuses a source budget below the account lock threshold",
                refuses(starvedSource));
        Check.contains("and it names the sizing rule, not a range",
                problemsOf(starvedSource), "per-source attempt budget");
        Map<String, String> equalBudget = new LinkedHashMap<>(starvedSource);
        equalBudget.put(AuthConfig.KEY_SOURCE_MAX_ATTEMPTS, "100");
        Check.ok("the same pair is accepted once the budget reaches the threshold",
                !refuses(equalBudget));

        // A minimum accepted iteration count above the configured work factor means no record in the
        // file can ever verify, and the store would refuse to load while the config looked healthy.
        Map<String, String> unreachableMinimum = new LinkedHashMap<>(base);
        unreachableMinimum.put(AuthConfig.KEY_MIN_ACCEPTED_ITERATIONS, "130000");
        Check.ok("the environment path refuses a minimum above the configured iteration count",
                refuses(unreachableMinimum));
        Check.contains("and it names the relation between the two",
                problemsOf(unreachableMinimum), "must not be below the minimum accepted");
        Map<String, String> matchedMinimum = new LinkedHashMap<>(unreachableMinimum);
        matchedMinimum.put(AuthConfig.KEY_MIN_ACCEPTED_ITERATIONS, "120000");
        Check.ok("a minimum equal to the configured count is accepted", !refuses(matchedMinimum));

        // The programmatic path must refuse the identical pairs - otherwise the two constructors have
        // two different security policies and only one of them is the deployed one.
        Check.ok("the builder refuses a starved source budget too",
                refusesAtBuild(fx.config(FAST_ITERATIONS).accountLockAfter(100).sourceMaxAttempts(10)));
        Check.ok("the builder refuses an unreachable minimum too",
                refusesAtBuild(fx.config(FAST_ITERATIONS).minAcceptedIterations(130_000)));

        // An unknown key's name is attacker-chosen: it comes from the environment, and an operator
        // copying a template can put terminal control codes in it. It must be rendered, not echoed.
        Map<String, String> hostileKey = new LinkedHashMap<>(base);
        hostileKey.put("AUTH_" + ESC + "TAKEOVER", "1");
        Check.ok("a namespace key holding a control character is refused", refuses(hostileKey));
        String rendered = problemsOf(hostileKey);
        Check.contains("and the problem text describes it as unsupported", rendered,
                "an unsupported configuration key");
        Check.lacks("the raw key name is not echoed into the problem text", rendered, ESC);
        Check.lacks("no terminal control sequence survives", rendered, "TAKEOVER");

        // A printable key name is genuinely useful to an operator, so it is still named.
        Map<String, String> misspelled = new LinkedHashMap<>(base);
        misspelled.put("AUTH_ACCOUNT_LOCK_AFETR", "4");
        Check.contains("an ordinary misspelling is still named exactly", problemsOf(misspelled),
                "AUTH_ACCOUNT_LOCK_AFETR");
    }

    private static String problemsOf(Map<String, String> env) {
        try {
            AuthConfig.from(mapSource(env), TimeSource.mutable(1_700_000_000_000L));
            return "";
        } catch (InvalidConfigException e) {
            return String.join(" | ", e.problems());
        }
    }

    private static boolean refusesAtBuild(AuthConfig.Builder builder) {
        try {
            builder.build();
            return false;
        } catch (InvalidConfigException e) {
            return !e.problems().isEmpty();
        }
    }

    // ---------------------------------------------------------------- identity

    /**
     * The username allow-list is Unicode-wide, so a name written in another script is <em>not</em>
     * refused as a look-alike of a Latin name - a documented property, not an accident. What must be
     * true is that such a name is a separate account everywhere: the lookup, the throttle key and the
     * logged identifier all fold ASCII case only, so a homoglyph can neither reach nor shadow the
     * account it resembles. If any of those ever gained a Unicode-aware fold, this is the suite that
     * notices the collision.
     */
    private static void lookALikeNamesAreDistinctAccounts(Fixture fx) throws Exception {
        char cyrA = 0x0430;
        char cyrL = 0x043B;
        char cyrM = 0x043c;
        char cyrI = 0x0456;
        char cyrS = 0x0441;
        char cyrT = 0x0442;
        String latin = "alice";
        String cyrillic = "" + cyrA + cyrL + cyrI + cyrS + cyrT + cyrM;
        Check.ok("a Cyrillic name passes the allow-list (documented, not refused)",
                InputValidator.isValidUsername(cyrillic + ".example"));
        Check.ok("the Latin name is unaffected", InputValidator.isValidUsername(latin));

        Check.ok("the two spellings are not the same text", !latin.equals(cyrillic));
        Check.ok("the logged identifier distinguishes them",
                !AccountField.accountId(latin).equals(AccountField.accountId(cyrillic)));
        Check.ok("the throttle key distinguishes them",
                !AttemptThrottle.canonicalize(latin).equals(AttemptThrottle.canonicalize(cyrillic)));

        fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
        fx.writeAccounts(FAST_ITERATIONS, new String[][]{
                {latin, Fixture.PASSWORD_A},
                {cyrillic, Fixture.PASSWORD_B}});
        List<String> problems = new ArrayList<>();
        FileCredentialStore store = FileCredentialStore.load(fx.accountsFile,
                fx.standardConfig(FAST_ITERATIONS), problems);
        Check.ok("one file may hold both spellings", problems.isEmpty());
        Check.eq("and the store keeps two records, not one", 2, store.size());
        Check.ok("the Latin record resolves", store.lookup(latin).isPresent());
        Check.ok("the Cyrillic record resolves", store.lookup(cyrillic).isPresent());
        Check.ok("neither resolves to the other's credential",
                store.lookup(latin).get().digest().length > 0
                        && !java.util.Arrays.equals(store.lookup(latin).get().digest(),
                        store.lookup(cyrillic).get().digest()));
    }

    // ---------------------------------------------------------------- encoding hygiene

    /**
     * The password must never be copied into an object the code cannot wipe. {@code new String(chars)}
     * is the one way to get it into an immutable, collector-owned heap block while still calling it
     * "cleared", so the encoding path is checked at the source level - an API response cannot show the
     * difference - and the behaviour it replaced is checked at runtime.
     */
    private static void encodingLeavesNoUnwritableCopy(Fixture fx) throws Exception {
        String validatorText = ProductionSource.of("InputValidator.java", "the password encoder");
        String encodeBody = ProductionSource.compact(ProductionSource.methodBody(validatorText,
                "public static byte[] encodePassword(", "encodePassword"));
        Check.ok("the encoder builds no String from the password", !encodeBody.contains("newString("));
        Check.ok("nor a char array from a String", !encodeBody.contains(".toCharArray("));
        Check.ok("it reports rather than substitutes on an unencodable character",
                encodeBody.contains("CodingErrorAction.REPORT"));
        Check.ok("and it wipes the oversized scratch buffer it encoded into",
                encodeBody.contains("Arrays.fill(oversized,(byte)0)"));

        String hasher = ProductionSource.compact(ProductionSource.of("PasswordHasher.java", "the pepper path"));
        Check.ok("the pepper is encoded through the same String-free path",
                !hasher.contains("newString(") && hasher.contains("InputValidator.encodePassword("));

        // Behaviour the String round trip used to guarantee, now asserted directly on the encoder.
        String accented = "caf" + (char) 0xe9 + "-passphrase";
        String folded = "caf?-passphrase";
        byte[] real = InputValidator.encodePassword(accented.toCharArray());
        byte[] lookALike = InputValidator.encodePassword(folded.toCharArray());
        Check.ok("an accented password encodes", real.length > 0);
        Check.eq("and uses two bytes for the accented character", accented.length() + 1, real.length);
        Check.ok("an accented password and a literal question mark do not encode alike",
                !java.util.Arrays.equals(real, lookALike));

        byte[] supplementary = InputValidator.encodePassword((cp(0x1F600) + "passphrase").toCharArray());
        Check.eq("a supplementary code point encodes to four bytes", "passphrase".length() + 4,
                Integer.valueOf(supplementary.length));

        String[] unencodable = {"short" + (char) 0xD800 + "tail", "short" + (char) 0xDE00 + "tail"};
        for (String value : unencodable) {
            boolean refused = false;
            try {
                byte[] wasted = InputValidator.encodePassword(value.toCharArray());
                java.util.Arrays.fill(wasted, (byte) 0);
            } catch (AuthException e) {
                refused = e.diagnostic() == Diagnostic.PASSWORD_ENCODING_UNSUPPORTED;
            }
            Check.ok("an unpaired surrogate is refused rather than mapped to '?'", refused);
        }

        // The gate that keeps a credential file from being world-readable must not treat "the file
        // system would not tell me" as "not exposed". Matched on whitespace-normalised text so the
        // assertion is about the decision, not about indentation.
        String modeHelper = ProductionSource.compact(
                ProductionSource.of("PosixMode.java", "the permission gate"));
        Check.ok("an unreadable mode counts as exposed",
                modeHelper.contains("permissions==null){returntrue;"));
        Check.ok("and never as safe", !modeHelper.contains("permissions==null){returnfalse;"));
        Check.ok("every predicate in the gate answers the null case",
                countOccurrences(modeHelper, "permissions==null){returntrue;") == 3);
        Check.ok("a directory is checked for group write as well as other write",
                modeHelper.contains("GROUP_WRITE"));

        // The encoder must be reached from the shipped paths that handle a password, not just exist.
        String validator = ProductionSource.compact(validatorText);
        Check.ok("validatePassword proves the value encodable before returning a copy",
                validator.contains("byte[]encoded=encodePassword(raw);"));
    }

    private static int countOccurrences(String haystack, String needle) {
        int at = 0;
        int n = 0;
        while ((at = haystack.indexOf(needle, at)) >= 0) {
            n++;
            at += needle.length();
        }
        return n;
    }

    /**
     * Provisioning is account creation by another name, and the task limits this component to
     * authentication and event logging. A package-private serializer in {@code src/main} would be a
     * production path that hashes a caller-supplied password into a stored record, so the shipped tree
     * is checked to contain none, and the tests are checked to build their own.
     */
    private static void shippedTreeKeepsProvisioningOutOfProduction(Fixture fx) throws Exception {
        // Every shipped source is inspected, not just the obvious one: a serialiser that survives in
        // a file this test forgot to read is exactly the finding this check exists to prevent.
        Path mainDir = ProductionSource.pathOf("AccountCredentials.java").getParent();
        int shippedFiles = 0;
        List<String> recordWriters = new ArrayList<>();
        try (java.nio.file.DirectoryStream<Path> files = Files.newDirectoryStream(mainDir, "*.java")) {
            for (Path file : files) {
                shippedFiles++;
                String code = ProductionSource.compact(ProductionSource.stripComments(
                        new String(Files.readAllBytes(file), java.nio.charset.StandardCharsets.UTF_8)));
                if (code.contains("serialize(") || code.contains("encodeBytes(")) {
                    recordWriters.add(file.getFileName().toString());
                }
            }
        }
        Check.ok("every shipped source was inspected, " + shippedFiles + " files", shippedFiles >= 20);
        Check.ok("no shipped source renders a credential record: " + recordWriters, recordWriters.isEmpty());

        String store = ProductionSource.compact(
                ProductionSource.of("FileCredentialStore.java", "the credential store"));
        Check.ok("the credential store has no write path at all",
                !store.contains("FileChannel.open(") && !store.contains("Files.write(")
                        && !store.contains("newOutputStream("));

        String hasher = ProductionSource.compact(
                ProductionSource.of("PasswordHasher.java", "the hasher"));
        Check.ok("the shipped hasher exposes no encoder for a stored field",
                !hasher.contains("staticStringencodeBytes("));

        String service = ProductionSource.compact(
                ProductionSource.of("AuthenticationService.java", "the service"));
        Check.ok("the service exposes no credential serialiser", !service.contains("serializeRecords("));
        Check.ok("and no provisioning record type", !service.contains("FixtureRecord"));
        Check.eq("the service performs exactly one derivation", 1, countOccurrences(service, ".derive("));
        Check.ok("and that one is the decoy, never a stored record",
                service.contains(".derive(\"decoy-placeholder\""));
        Check.ok("the fixture provisioner is the only place that renders records, in the test tree",
                ProductionSource.isInTestTree("FixtureProvisioner.java")
                        && !ProductionSource.isInMainTree("FixtureProvisioner.java"));

        // The provisioner must still produce something the real loader accepts, or moving it out of
        // the shipped tree would have silently turned every fixture into a malformed store.
        fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
        List<String> lines = FixtureProvisioner.records(Fixture.PEPPER.clone(), FAST_ITERATIONS,
                new String[][]{{"provisioned-one", Fixture.PASSWORD_A}, {"provisioned-two", Fixture.PASSWORD_B}});
        fx.writeAccountsRaw(lines);
        List<String> problems = new ArrayList<>();
        FileCredentialStore loaded = FileCredentialStore.load(fx.accountsFile,
                fx.standardConfig(FAST_ITERATIONS), problems);
        Check.ok("records built outside src/main load cleanly", problems.isEmpty());
        Check.eq("both records are there", 2, loaded.size());
        Check.ok("and the name resolves", loaded.lookup("provisioned-one").isPresent());
    }

    // ---------------------------------------------------------------- event redaction

    private static void eventRedactionRules(Fixture fx) throws Exception {
        long now = 1_700_000_000_000L;
        AuthEvent event = AuthEvent.builder()
                .timestampMillis(now)
                .type(EventType.LOGIN_FAILURE)
                .outcome("failure")
                .account("alice", true)
                .source("203.0.113.7")
                .reason(Diagnostic.CREDENTIAL_MISMATCH)
                .latencyMicros(1234)
                .build();
        String line = event.renderOrReject(1);
        Check.ok("a well-formed event renders", line != null);
        Check.lacksAllNonEmpty("the rendered line omits the username", line, "alice", "Alice", "ALICE");
        Check.lacksAllNonEmpty("the rendered line omits any password", line, Fixture.PASSWORD_A, "password=");
        Check.lacksAllNonEmpty("the rendered line omits any token", line, "session=");
        Check.ok("the rendered line is one line", line.indexOf('\n') < 0 && line.indexOf('\r') < 0);
        Check.contains("the account is a one-way identifier", line, "account_id=");
        Check.contains("the account presence flag is recorded", line, "account_present=true");

        // The identifier is stable across spellings and unpredictable from the text alone.
        Check.eq("case-folded names share one identifier",
                AccountField.accountId("Alice"), AccountField.accountId("aLiCe"));
        Check.ok("different names get different identifiers",
                !AccountField.accountId("alice").equals(AccountField.accountId("bob")));
        Check.eq("the identifier is 64 hex characters", 64, AccountField.accountId("alice").length());
        Check.eq("a null name still yields a well-formed identifier", 64, AccountField.accountId(null).length());
        Check.eq("the distinct-code-point hint counts code points", 5, AccountField.distinctCodePoints("alice"));
        // The hint is a saturating sketch, not an exact count (see AccountField#distinctCodePoints):
        // it must never exceed the number of distinct code points, and must flatten any name that
        // reuses characters no matter how long it is.
        Check.eq("surrogate pairs count once", 3,
                Integer.valueOf(AccountField.distinctCodePoints("a" + cp(0x1F600) + cp(0x1F601))));
        Check.eq("a name that reuses one character hints 1", 1, AccountField.distinctCodePoints("a".repeat(300)));
        Check.eq("a long name with many repeats saturates rather than counting",
                AccountField.distinctCodePoints("ab".repeat(300)), AccountField.distinctCodePoints("ab"));

        // Unsafe lines are refused rather than written.
        AuthEvent badSource = AuthEvent.builder()
                .timestampMillis(now)
                .type(EventType.LOGIN_FAILURE)
                .outcome("failure")
                .account("alice", false)
                .source("203.0.113.7; rm -rf /")
                .latencyMicros(1)
                .build();
        Check.ok("a source that is not a canonical address is refused", badSource.renderOrReject(1) == null);

        AuthEvent nonCanonical = AuthEvent.builder()
                .timestampMillis(now)
                .type(EventType.LOGIN_FAILURE)
                .outcome("failure")
                .account("alice", false)
                .source("203.0.113.07")
                .latencyMicros(1)
                .build();
        Check.ok("a non-canonical address form is refused", nonCanonical.renderOrReject(1) == null);

        AuthEvent badSequence = AuthEvent.builder()
                .timestampMillis(now)
                .type(EventType.LOGIN_SUCCESS)
                .outcome("success")
                .account("alice", true)
                .source("203.0.113.7")
                .latencyMicros(1)
                .build();
        Check.ok("sequence 0 is refused", badSequence.renderOrReject(0) == null);

        // The fixture must really be unusable, or this asserts nothing about the guard.
        String unusableSuffix = "not-hex!";
        Check.ok("the non-hex suffix fixture is long enough to reach the guard",
                unusableSuffix.length() >= 6);
        AuthEvent badSuffix = AuthEvent.builder()
                .timestampMillis(now)
                .type(EventType.LOGIN_SUCCESS)
                .outcome("success")
                .account("alice", true)
                .source("203.0.113.7")
                .latencyMicros(1)
                .sessionSuffix(unusableSuffix)
                .build();
        Check.ok("a session suffix that is not hex is refused", badSuffix.renderOrReject(1) == null);

        AuthEvent goodSuffix = AuthEvent.builder()
                .timestampMillis(now)
                .type(EventType.LOGIN_SUCCESS)
                .outcome("success")
                .account("alice", true)
                .source("203.0.113.7")
                .latencyMicros(1)
                .sessionSuffix("0123ab")
                .build();
        String suffixLine = goodSuffix.renderOrReject(1);
        Check.ok("a hex session suffix is accepted", suffixLine != null);
        Check.contains("only six characters of the identifier are recorded", suffixLine, "session=0123ab");
        Check.lacks("the whole identifier is never recorded", suffixLine, "0123ab456789");

        Check.ok("an absurd latency is refused", AuthEvent.builder()
                .timestampMillis(now).type(EventType.LOGIN_FAILURE).outcome("failure")
                .account("alice", false).source("203.0.113.7").latencyMicros(-1).build().renderOrReject(1) == null);
        Check.ok("an absurd retry hint is refused", AuthEvent.builder()
                .timestampMillis(now).type(EventType.LOGIN_FAILURE).outcome("failure")
                .account("alice", false).source("203.0.113.7").latencyMicros(1)
                .retryAfterSeconds(10_000_000).build().renderOrReject(1) == null);

        // Rendered length is bounded.
        Check.ok("a rendered line stays within the bound",
                suffixLine.length() <= AuthEvent.MAX_LINE_CHARS);

        // A rendered object cannot add detail beyond the redacted shape.
        Check.lacksAllNonEmpty("toString of an event omits the account", event.toString(),
                AccountField.accountId("alice"));
    }

    private static String describe(String value) {
        if (value == null) {
            return "<null>";
        }
        StringBuilder out = new StringBuilder("<");
        for (int i = 0; i < Math.min(value.length(), 18); i++) {
            char c = value.charAt(i);
            if (c < 0x21 || c > 0x7e) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        if (value.length() > 18) {
            out.append("...");
        }
        return out.append('>').toString();
    }

}
