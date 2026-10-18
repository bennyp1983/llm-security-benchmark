package secureaccount;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Verification suite for the credential store. Run with {@code java secureaccount.Tests}.
 *
 * <p>The suite is organised around the one requirement that cannot be checked by a happy-path
 * test: that nothing written to disk can be turned back into a password. Those assertions scan
 * every byte the program produced rather than trusting the code path that produced it.
 */
public final class Tests {

    private static int passed;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        long t0 = System.currentTimeMillis();
        run("hasher emits a self-describing record", Tests::hasherEmitsSelfDescribingRecord);
        run("hasher salts every record", Tests::hasherSaltsEveryRecord);
        run("verifier accepts the right password only", Tests::verifierAcceptsRightPasswordOnly);
        run("verifier ignores password object identity", Tests::verifierIgnoresObjectIdentity);
        run("hasher leaves caller buffer intact", Tests::hasherLeavesCallerBufferIntact);
        run("empty and oversized passwords rejected", Tests::emptyAndOversizedPasswordsRejected);
        run("STORAGE: record never contains the password", Tests::recordNeverContainsPassword);
        run("STORAGE: record is a genuine PBKDF2 derivation", Tests::recordIsGenuinePbkdf2);
        run("STORAGE: same password yields different records", Tests::samePasswordDifferentRecords);
        run("foreign algorithm record rejected", Tests::foreignAlgorithmRejected);
        run("weak or tampered record rejected", Tests::weakOrTamperedRecordRejected);
        run("needsUpgrade flags weaker parameters", Tests::needsUpgradeFlagsWeakerParams);
        run("store round-trips accounts", Tests::storeRoundTrips);
        run("STORAGE: store file is owner-only", Tests::storeFileIsOwnerOnly);
        run("STORAGE: no plaintext anywhere on disk", Tests::noPlaintextAnywhereOnDisk);
        run("store rejects a corrupt file", Tests::storeRejectsCorruptFile);
        run("store rejects a foreign-format file", Tests::storeRejectsForeignFormat);
        run("store leaves no temp files", Tests::storeLeavesNoTempFiles);
        run("register then authenticate", Tests::registerThenAuthenticate);
        run("duplicate registration rejected", Tests::duplicateRegistrationRejected);
        run("username matching is case-insensitive", Tests::usernameMatchingIsCaseInsensitive);
        run("invalid usernames rejected", Tests::invalidUsernamesRejected);
        run("failure message is uniform", Tests::failureMessageIsUniform);
        run("credentials survive a reload", Tests::credentialsSurviveReload);
        run("login upgrades weak parameters", Tests::loginUpgradesWeakParameters);
        run("unknown user costs a derivation too", Tests::unknownUserCostsADerivation);
        run("CLI register and login end to end", Tests::cliEndToEnd);
        run("CLI never echoes the password", Tests::cliNeverEchoesPassword);
        run("STORAGE: CLI store has no plaintext", Tests::cliStoreHasNoPlaintext);

        long ms = System.currentTimeMillis() - t0;
        System.out.println();
        System.out.println(passed + " passed, " + failures.size() + " failed (" + ms + " ms)");
        if (!failures.isEmpty()) {
            System.out.println();
            for (String failure : failures) {
                System.out.println("FAILED: " + failure);
            }
            System.exit(1);
        }
        System.out.println("ALL TESTS PASSED");
    }

    // ---------------------------------------------------------------- hasher

    private static void hasherEmitsSelfDescribingRecord() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        String encoded = hasher.hash(SECRET);
        Matcher m = Pattern.compile(
                "^\\$PBKDF2WithHmacSHA256\\$i=(\\d+)\\$l=(\\d+)\\$s=([A-Za-z0-9_-]+)\\$h=([A-Za-z0-9_-]+)\\$$")
                .matcher(encoded);
        check(m.matches(), "record shape: " + encoded);
        check(Integer.parseInt(m.group(1)) == FAST, "recorded iterations");
        check(Integer.parseInt(m.group(2)) == 256, "recorded key length");
        check(Base64.getUrlDecoder().decode(m.group(3)).length == PasswordHasher.SALT_BYTES,
                "salt is 16 bytes");
        check(Base64.getUrlDecoder().decode(m.group(4)).length == PasswordHasher.KEY_BYTES,
                "hash is 32 bytes");
    }

    private static void hasherSaltsEveryRecord() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        String a = hasher.hash(SECRET);
        String b = hasher.hash(SECRET);
        check(!a.equals(b), "two hashes of the same password are identical");
        check(saltOf(a) != null && saltOf(b) != null, "both carry a salt");
        check(!java.util.Arrays.equals(saltOf(a), saltOf(b)), "the salts repeat");
    }

    private static void verifierAcceptsRightPasswordOnly() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        String encoded = hasher.hash(SECRET);
        check(hasher.matches(SECRET, encoded), "correct password rejected");
        check(!hasher.matches("hunter3!".toCharArray(), encoded), "wrong password accepted");
        check(!hasher.matches("hunter".toCharArray(), encoded), "prefix password accepted");
        check(!hasher.matches("hunter2".toCharArray(), encoded), "shortened password accepted");
        check(!hasher.matches("HUNTER2!".toCharArray(), encoded), "case-flipped password accepted");
        check(!hasher.matches("hunter2! ".toCharArray(), encoded), "padded password accepted");
        check(!hasher.matches(new char[0], encoded), "empty password accepted");
        check(!hasher.matches(null, encoded), "null password accepted");
    }

    private static void verifierIgnoresObjectIdentity() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        char[] original = {'h', 'u', 'n', 't', 'e', 'r', '2', '!'};
        String encoded = hasher.hash(original);
        // A login rebuilds the array from the prompt buffer, so equality must not depend on
        // reference identity or on the array's history.
        char[] rebuilt = new StringBuilder("hunter2!").toString().toCharArray();
        check(hasher.matches(rebuilt, encoded), "an equal but distinct char[] was rejected");
    }

    private static void hasherLeavesCallerBufferIntact() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        char[] password = "hunter2!".toCharArray();
        char[] expected = password.clone();
        hasher.hash(password);
        check(java.util.Arrays.equals(expected, password),
                "hash() mutated the caller's buffer, so the caller cannot wipe what it thinks it holds");
    }

    private static void emptyAndOversizedPasswordsRejected() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        expectThrows(IllegalArgumentException.class, () -> hasher.hash(new char[0]),
                "empty password");
        expectThrows(IllegalArgumentException.class, () -> hasher.hash(null), "null password");
        char[] huge = new char[PasswordHasher.MAX_PASSWORD_CHARS + 1];
        java.util.Arrays.fill(huge, 'a');
        expectThrows(IllegalArgumentException.class, () -> hasher.hash(huge), "oversized password");
        expectThrows(IllegalArgumentException.class, () -> new PasswordHasher(10),
                "iteration count below the floor");
        expectThrows(IllegalArgumentException.class, () -> new PasswordHasher(50_000_000),
                "iteration count above the ceiling");
    }

    // -------------------------------------------------- non-recoverability

    private static void recordNeverContainsPassword() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        // The accented secret is built from a code point rather than a backslash-u escape:
        // javac translates those in a source file before lexing, which on this machine's
        // US-ASCII default encoding is a compile error rather than a character literal.
        String[] secrets = {"hunter2!", "correct horse battery staple",
                "p" + (char) 0xE9 + "ssw0rd"};
        for (String secret : secrets) {
            char[] password = secret.toCharArray();
            String encoded = hasher.hash(password);
            for (String form : encodingsOf(secret)) {
                check(!encoded.contains(form),
                        "verifier contains the password for <" + secret + "> as " + form);
            }
            String lower = secret.toLowerCase(java.util.Locale.ROOT);
            check(!encoded.toLowerCase(java.util.Locale.ROOT).contains(lower),
                    "verifier contains a case-folded copy of the password");
        }
    }

    /**
     * Re-derives the stored tag with a plain {@code SecretKeyFactory}, from only the salt and
     * iteration count in the record, and requires it to match.
     *
     * <p>This is what separates a real one-way store from an encoding: any reversible
     * representation (base64, XOR, an encrypted blob) fails, because no salted iterated-hash
     * path reproduces it from the salt alone.
     */
    private static void recordIsGenuinePbkdf2() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        String encoded = hasher.hash(SECRET);
        byte[] salt = saltOf(encoded);
        byte[] storedHash = hashOf(encoded);
        int iterations = iterationsOf(encoded);

        PBEKeySpec spec = new PBEKeySpec(SECRET, salt, iterations, storedHash.length * 8);
        byte[] recomputed = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
        spec.clearPassword();
        check(java.util.Arrays.equals(storedHash, recomputed),
                "the stored tag is not PBKDF2-HMAC-SHA256 of the password under the stored salt");

        // And the same recomputation must not work for a different password, i.e. the salt
        // really is what pins the value down.
        byte[] otherSalt = saltOf(hasher.hash("not-the-password".toCharArray()));
        PBEKeySpec wrong = new PBEKeySpec(SECRET, otherSalt, iterations, storedHash.length * 8);
        byte[] wrongKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(wrong).getEncoded();
        wrong.clearPassword();
        check(!java.util.Arrays.equals(storedHash, wrongKey),
                "the tag survives a change of salt, so the salt is not binding");
    }

    private static void samePasswordDifferentRecords() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        Path dir = tempDir("dup");
        AccountStore store = new AccountStore(dir.resolve("accounts"), hasher);
        AccountService service = new AccountService(store, hasher);
        service.register("alice", SECRET);
        service.register("bob", SECRET);
        Map<String, Account> accounts = store.loadAll();
        String a = accounts.get("alice").passwordHash();
        String b = accounts.get("bob").passwordHash();
        check(!a.equals(b), "two accounts with the same password share a verifier");
        check(!java.util.Arrays.equals(saltOf(a), saltOf(b)), "the salt is reused across accounts");
        // Cross-check: alice's verifier must not authenticate bob's identical password any
        // less well than her own -- the salt changes the bytes, not the semantics.
        check(hasher.matches(SECRET, b), "per-account salting broke verification");
    }

    // ------------------------------------------------------------ hardening

    private static void foreignAlgorithmRejected() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        String valid = hasher.hash(SECRET);
        // A crafted record claiming a cheaper primitive must not be honoured.
        String sha = "$SHA-256$i=1$l=256$s=" + b64(saltOf(valid)) + "$h=" + b64(hashOf(valid)) + "$";
        expectThrows(IllegalArgumentException.class, () -> hasher.matches(SECRET, sha),
                "a record naming a different algorithm");
        expectThrows(IllegalArgumentException.class, () -> hasher.validateStoredHash(sha),
                "loading a record that names a different algorithm");
        String none = "$none$l=256$s=" + b64(saltOf(valid)) + "$h=" + b64(hashOf(valid)) + "$";
        expectThrows(IllegalArgumentException.class, () -> hasher.matches(SECRET, none),
                "a record with no algorithm");
        // Malformed records throw rather than returning false, so corruption surfaces as a
        // store fault instead of looking like a wrong password.
        for (String junk : new String[] {valid.substring(0, valid.length() - 1), "hunter2!", "",
                "$$", valid + "$$", "$PBKDF2WithHmacSHA256$i=1$l=8$s=AA$h=AA$"}) {
            expectThrows(IllegalArgumentException.class, () -> hasher.matches(SECRET, junk),
                    "the malformed record <" + junk + ">");
        }
    }

    private static void weakOrTamperedRecordRejected() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        String valid = hasher.hash(SECRET);
        String lowIterations = valid.replace("i=" + FAST, "i=7");
        expectThrows(IllegalArgumentException.class, () -> hasher.matches(SECRET, lowIterations),
                "a record with 7 iterations");
        String hugeIterations = valid.replace("i=" + FAST, "i=999999999");
        expectThrows(IllegalArgumentException.class, () -> hasher.matches(SECRET, hugeIterations),
                "a record with a denial-of-service iteration count");
        // Claim a longer key than the record actually carries, i.e. a field that lies.
        String lyingLength = valid.replace("l=256", "l=512");
        expectThrows(IllegalArgumentException.class, () -> hasher.matches(SECRET, lyingLength),
                "a record whose length field does not match its hash");
        expectThrows(IllegalArgumentException.class,
                () -> hasher.matches(SECRET, valid.replace("s=", "x=")), "a renamed field");
        expectThrows(IllegalArgumentException.class,
                () -> hasher.matches(SECRET, valid.replace("i=" + FAST, "i=abc")), "a non-numeric field");
        expectThrows(IllegalArgumentException.class,
                () -> hasher.matches(SECRET, valid + "x"), "trailing garbage");
    }

    private static void needsUpgradeFlagsWeakerParams() throws Exception {
        String weak = new PasswordHasher(2_000).hash(SECRET);
        PasswordHasher policy = new PasswordHasher(20_000);
        check(policy.needsUpgrade(weak), "a weaker record was not flagged for upgrade");
        check(!new PasswordHasher(2_000).needsUpgrade(weak),
                "a record at the current policy was flagged");
        check(!policy.needsUpgrade(policy.hash(SECRET)), "a current record was flagged");
    }

    // ----------------------------------------------------------------- store

    private static void storeRoundTrips() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        Path dir = tempDir("roundtrip");
        AccountStore store = new AccountStore(dir.resolve("accounts"), hasher);
        check(store.loadAll().isEmpty(), "a nonexistent store is not empty");
        AccountService service = new AccountService(store, hasher);
        service.register("alice", SECRET);
        service.register("bob", "s3cret-pw".toCharArray());
        Map<String, Account> loaded = store.loadAll();
        check(loaded.size() == 2, "expected 2 accounts, found " + loaded.size());
        check(loaded.get("alice").passwordHash().equals(
                        store.loadAll().get("alice").passwordHash()),
                "the verifier changed between reads");
        String text = Files.readString(dir.resolve("accounts"), StandardCharsets.UTF_8);
        check(text.startsWith(AccountStore.HEADER), "missing format header");
        check(AccountStore.format(loaded.get("alice")).contains("salted_pbkdf2_sha256="),
                "field name is not self-describing");
    }

    private static void storeFileIsOwnerOnly() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        Path dir = tempDir("perms");
        Path file = dir.resolve("accounts");
        new AccountService(new AccountStore(file, hasher), hasher).register("alice", SECRET);
        String perms = PosixFilePermissions.toString(Files.getPosixFilePermissions(file));
        check("rw-------".equals(perms), "store permissions are " + perms + ", expected rw-------");
    }

    private static void noPlaintextAnywhereOnDisk() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        Path dir = tempDir("scan");
        AccountStore store = new AccountStore(dir.resolve("accounts"), hasher);
        AccountService service = new AccountService(store, hasher);
        String[] secrets = {"hunter2!", "Tr0ub4dor&3", "a-pass-wo" + "rd-with-digits-99"};
        service.register("alice", secrets[0].toCharArray());
        service.register("bob", secrets[1].toCharArray());
        service.register("carol", secrets[2].toCharArray());
        // A failed login and a param upgrade both touch the file; scan after real traffic.
        expectThrows(AccountService.AuthenticationFailedException.class,
                () -> service.authenticate("alice", "wrong".toCharArray()), "wrong password");
        service.authenticate("alice", secrets[0].toCharArray());

        List<Path> files = regularFiles(dir);
        check(!files.isEmpty(), "nothing was written to scan");
        for (Path file : files) {
            byte[] bytes = Files.readAllBytes(file);
            String asText = new String(bytes, StandardCharsets.UTF_8);
            for (String secret : secrets) {
                for (String form : encodingsOf(secret)) {
                    check(!asText.contains(form),
                            file.getFileName() + " contains <" + form + ">");
                }
                // A hash of the password is fine; the password itself never is. Check the
                // whole-file byte scan too, in case a secret landed outside any text form.
                check(indexOfBytes(bytes, secret.getBytes(StandardCharsets.UTF_8)) < 0,
                        file.getFileName() + " contains the password bytes");
                check(indexOfBytes(bytes, secret.getBytes(StandardCharsets.UTF_16LE)) < 0,
                        file.getFileName() + " contains UTF-16LE password bytes");
            }
        }
    }

    private static void storeRejectsCorruptFile() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        Path dir = tempDir("corrupt");
        Path file = dir.resolve("accounts");
        AccountStore store = new AccountStore(file, hasher);
        String good = AccountStore.format(new Account("alice", hasher.hash(SECRET),
                java.time.Instant.parse("2026-01-01T00:00:00Z")));

        expectThrows(IOException.class, () -> readCorrupt(store, file,
                AccountStore.HEADER + "\nusername=alice password_plaintext=hunter2!\n"),
                "a legacy plaintext line");
        expectThrows(IOException.class, () -> readCorrupt(store, file,
                AccountStore.HEADER + "\n" + good + " extra_field=boom\n"), "an unknown field");
        expectThrows(IOException.class, () -> readCorrupt(store, file,
                AccountStore.HEADER + "\n" + good + "\n" + good + "\n"), "a duplicate username");
        expectThrows(IOException.class, () -> readCorrupt(store, file,
                AccountStore.HEADER + "\nusername=alice salted_pbkdf2_sha256=$bogus$ created_at=2026-01-01T00:00:00Z\n"),
                "an unparseable verifier");
        expectThrows(IOException.class, () -> readCorrupt(store, file,
                AccountStore.HEADER + "\nusername=al!\tsalted_pbkdf2_sha256=" + hasher.hash(SECRET)
                        + " created_at=2026-01-01T00:00:00Z\n"),
                "an invalid username in the file");
        // The good record still loads, so the checks above are specific and not a blanket
        // failure to read anything.
        Files.writeString(file, AccountStore.HEADER + "\n" + good + "\n", StandardCharsets.UTF_8);
        check(store.loadAll().size() == 1, "a well-formed record failed to load");
    }

    private static void readCorrupt(AccountStore store, Path file, String content)
            throws IOException {
        Files.writeString(file, content, StandardCharsets.UTF_8);
        store.loadAll();
    }

    private static void storeRejectsForeignFormat() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        Path dir = tempDir("format");
        Path file = dir.resolve("accounts");
        Files.writeString(file, "user,pass\nalice,hunter2!\n", StandardCharsets.UTF_8);
        expectThrows(IOException.class, () -> new AccountStore(file, hasher).loadAll(),
                "a foreign-format file was accepted");
        // A directory in place of the file must be an error, not an empty store.
        Path asDir = dir.resolve("adir");
        Files.createDirectory(asDir);
        expectThrows(IOException.class, () -> new AccountStore(asDir, hasher).loadAll(),
                "a directory was accepted as a store");
    }

    private static void storeLeavesNoTempFiles() throws Exception {
        PasswordHasher hasher = new PasswordHasher(FAST);
        Path dir = tempDir("temp");
        AccountStore store = new AccountStore(dir.resolve("accounts"), hasher);
        AccountService service = new AccountService(store, hasher);
        for (int i = 0; i < 5; i++) {
            service.register("user" + i, SECRET);
        }
        for (Path file : regularFiles(dir)) {
            check(!file.getFileName().toString().endsWith(AccountStore.TEMP_SUFFIX),
                    "a temp file was left behind: " + file);
        }
        check(regularFiles(dir).size() == 2,
                "expected the store and its lock file only, found " + regularFiles(dir));
    }

    // --------------------------------------------------------------- service

    private static void registerThenAuthenticate() throws Exception {
        Fixture f = fixture();
        Account account = f.service.register("alice", SECRET);
        check("alice".equals(account.username()), "username was not normalised as expected");
        check(f.service.authenticate("alice", SECRET), "a valid login was rejected");
        expectThrows(AccountService.AuthenticationFailedException.class,
                () -> f.service.authenticate("alice", "nope".toCharArray()), "an invalid login");
        check(f.service.listAccounts().size() == 1, "unexpected account listing");
        check(f.service.listAccounts().containsKey("alice"), "listing lost the account");
    }

    private static void duplicateRegistrationRejected() throws Exception {
        Fixture f = fixture();
        f.service.register("alice", SECRET);
        expectThrows(AccountService.UsernameAlreadyTakenException.class,
                () -> f.service.register("alice", "other-secret".toCharArray()),
                "a duplicate registration");
        expectThrows(AccountService.UsernameAlreadyTakenException.class,
                () -> f.service.register("ALICE", "other-secret".toCharArray()),
                "a duplicate registration under a different case");
        check(f.service.listAccounts().size() == 1, "the duplicate was created anyway");
    }

    private static void usernameMatchingIsCaseInsensitive() throws Exception {
        Fixture f = fixture();
        f.service.register("  Alice_99  ", SECRET);
        check(f.service.exists("alice_99"), "the stored name is not the canonical one");
        check(f.service.authenticate("ALICE_99", SECRET), "uppercase login rejected");
        check(f.service.authenticate(" alice_99 ", SECRET), "padded login rejected");
        check(f.service.listAccounts().size() == 1, "case variants created extra accounts");
    }

    private static void invalidUsernamesRejected() throws Exception {
        Fixture f = fixture();
        for (String bad : new String[] {null, "", "  ", "al", "a b", "alice@example",
                "alice/", "ali" + (char) 0xE7 + "e",
                "very-long-username-that-goes-on-for-ever-and-ever",
                "alice;rm -rf /", "$(whoami)", "..\\..\\etc\\passwd", "alice\nbob"}) {
            expectThrows(IllegalArgumentException.class, () -> f.service.register(bad, SECRET),
                    "username <" + bad + ">");
        }
        check(f.service.listAccounts().isEmpty(),
                "an invalid username still reached the store: " + f.service.listAccounts());
    }

    private static void failureMessageIsUniform() throws Exception {
        Fixture f = fixture();
        f.service.register("alice", SECRET);
        String unknownUser = message(() -> f.service.authenticate("nobody", SECRET));
        String wrongPassword = message(() -> f.service.authenticate("alice", "x".toCharArray()));
        String malformedName = message(() -> f.service.authenticate("a b", SECRET));
        check(AccountService.BAD_CREDENTIALS.equals(unknownUser), "unknown-user message: " + unknownUser);
        check(AccountService.BAD_CREDENTIALS.equals(wrongPassword),
                "wrong-password message: " + wrongPassword);
        check(AccountService.BAD_CREDENTIALS.equals(malformedName),
                "malformed-name message: " + malformedName);
        check(!unknownUser.toLowerCase(java.util.Locale.ROOT).contains("alice"),
                "the failure message names the account");
        check(!unknownUser.equals("user not found") && !wrongPassword.equals("bad password"),
                "the two failure modes are distinguishable");
    }

    private static void credentialsSurviveReload() throws Exception {
        Fixture first = fixture();
        first.service.register("alice", SECRET);
        // New store and service instances: the only channel is the file on disk.
        Fixture second = new Fixture(first.dir, first.hasher);
        check(second.service.authenticate("alice", SECRET),
                "credentials did not survive a reload");
        expectThrows(AccountService.AuthenticationFailedException.class,
                () -> second.service.authenticate("alice", "wrong".toCharArray()),
                "a wrong password passed after a reload");
        // And a *third* process-equivalent view with a different policy still reads it,
        // because the parameters travel with the record.
        AccountStore reread = new AccountStore(first.dir.resolve("accounts"),
                new PasswordHasher(20_000));
        check(new AccountService(reread, new PasswordHasher(20_000))
                        .authenticate("alice", SECRET),
                "a record written at one policy is unreadable at another");
    }

    private static void loginUpgradesWeakParameters() throws Exception {
        Path dir = tempDir("upgrade");
        Path file = dir.resolve("accounts");
        AccountStore weakStore = new AccountStore(file, new PasswordHasher(2_000));
        new AccountService(weakStore, new PasswordHasher(2_000)).register("alice", SECRET);
        Map<String, Account> weak = load(dir);
        int before = iterationsOf(weak.get("alice").passwordHash());
        byte[] saltBefore = saltOf(weak.get("alice").passwordHash());
        check(before == 2_000, "expected the account to start weak, got " + before);

        PasswordHasher policy = new PasswordHasher(20_000);
        AccountService upgraded = new AccountService(new AccountStore(file, policy), policy);
        check(upgraded.authenticate("alice", SECRET), "a weak account could not log in");
        Map<String, Account> after = load(dir);
        int afterIterations = iterationsOf(after.get("alice").passwordHash());
        check(afterIterations == 20_000,
                "parameters were not raised on login: " + before + " -> " + afterIterations);
        check(!java.util.Arrays.equals(saltBefore, saltOf(after.get("alice").passwordHash())),
                "the record was rewritten with the same salt, so it was copied rather than rederived");
        check(upgraded.authenticate("alice", SECRET), "login broke after the upgrade");
        check(iterationsOf(load(dir).get("alice").passwordHash()) == 20_000,
                "the upgrade did not stick");
        // The old record is gone, not appended alongside the new one.
        String text = Files.readString(file, StandardCharsets.UTF_8);
        check(text.split("\n", -1).length == 3, "expected exactly one account line, saw:\n" + text);
        check(text.contains("$i=20000$") && !text.contains("$i=2000$"),
                "the weak verifier is still on disk");
    }

    private static void unknownUserCostsADerivation() throws Exception {
        // The point of the throwaway derivation: a fast "unknown user" answer is a timing
        // oracle for account enumeration. Assert the two paths cost the same order of time.
        PasswordHasher hasher = new PasswordHasher(40_000);
        Fixture f = new Fixture(tempDir("timing"), hasher);
        f.service.register("alice", SECRET);

        double known = median(() -> timeLogin(f.service, "alice", "wrong-password"));
        double unknown = median(() -> timeLogin(f.service, "no-such-user", "wrong-password"));
        double ratio = unknown / known;
        check(ratio > 0.5 && ratio < 2.0,
                "unknown-user login took " + String.format("%.0f", unknown) + " ms against "
                        + String.format("%.0f", known) + " ms for a known user (ratio "
                        + String.format("%.2f", ratio) + ")");
    }

    // ------------------------------------------------------------------- CLI

    private static void cliEndToEnd() throws Exception {
        Path dir = tempDir("cli");
        Path file = dir.resolve("accounts");
        String secret = "hunter2!";
        int rc = cli(file, secret + "\n" + secret + "\n", "register", "alice");
        check(rc == 0, "register exit code was " + rc);
        rc = cli(file, secret + "\n", "login", "alice");
        check(rc == 0, "login exit code was " + rc);
        rc = cli(file, "wrong\n", "login", "alice");
        check(rc == 1, "a bad login exited " + rc + ", expected 1");
        rc = cli(file, "", "login", "ghost");
        check(rc == 1, "an unknown-user login exited " + rc + ", expected 1");
        rc = cli(file, "", "list");
        check(rc == 0, "list exit code was " + rc);
        rc = cli(file, "", "bogus-command");
        check(rc == 2, "an unknown command exited " + rc + ", expected 2");
        rc = cli(file, "", "register");
        check(rc == 2, "register without a username exited " + rc + ", expected 2");
    }

    private static void cliNeverEchoesPassword() throws Exception {
        Path dir = tempDir("cli-echo");
        Path file = dir.resolve("accounts");
        String secret = "sUp3r-s3cr3t-cli";
        Capture out = new Capture();
        int rc = cliCaptured(out, file, secret + "\n" + secret + "\n", "register", "alice");
        check(rc == 0, "register exit code was " + rc);
        check(!out.stdout.contains(secret), "the password appeared on stdout");
        check(!out.stderr.contains(secret), "the password appeared on stderr");
        // The verifier is printed on purpose: it is not a secret, and printing it proves the
        // program stores a derived value rather than the input.
        check(out.stdout.contains("$PBKDF2WithHmacSHA256$"),
                "the CLI did not show the stored verifier");
        check(out.stdout.contains("registered 'alice'"), "no confirmation line");
        check(out.stderr.contains("Password: "), "no prompt on stderr");
    }

    private static void cliStoreHasNoPlaintext() throws Exception {
        Path dir = tempDir("cli-store");
        Path file = dir.resolve("accounts");
        String secret = "n0-plain73xt-ever";
        check(cli(file, secret + "\n" + secret + "\n", "register", "alice") == 0, "register failed");
        check(cli(file, secret + "\n", "login", "alice") == 0, "login failed");
        for (Path candidate : regularFiles(dir)) {
            String text = new String(Files.readAllBytes(candidate), StandardCharsets.UTF_8);
            for (String form : encodingsOf(secret)) {
                check(!text.contains(form),
                        candidate.getFileName() + " contains <" + form + ">");
            }
        }
        String text = Files.readString(file, StandardCharsets.UTF_8);
        check(text.contains("salted_pbkdf2_sha256=$PBKDF2WithHmacSHA256$"),
                "the store does not describe its own scheme:\n" + text);
    }

    // ---------------------------------------------------------------- helpers

    private static final int FAST = 2_000;
    private static final char[] SECRET = "hunter2!".toCharArray();

    private interface Case {
        void run() throws Exception;
    }

    private static void run(String name, Case body) {
        try {
            body.run();
            passed++;
            System.out.println("ok   " + name);
        } catch (Throwable t) {
            String detail = t.getMessage() == null ? t.toString() : t.getMessage();
            failures.add(name + " :: " + detail);
            System.out.println("FAIL " + name + " :: " + detail);
            if (!(t instanceof AssertionError) && !(t instanceof IllegalArgumentException)) {
                t.printStackTrace(System.out);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static void expectThrows(Class<? extends Exception> expected, ThrowingRunnable body,
                                     String what) {
        try {
            body.run();
        } catch (Exception e) {
            if (expected.isInstance(e)) {
                return;
            }
            throw new AssertionError(what + ": expected " + expected.getSimpleName() + " but got "
                    + e.getClass().getName() + " (" + e.getMessage() + ")");
        }
        throw new AssertionError(what + ": expected " + expected.getSimpleName() + ", nothing thrown");
    }

    private interface ThrowingSupplier {
        void run() throws Exception;
    }

    private static String message(ThrowingSupplier body) {
        try {
            body.run();
        } catch (Exception e) {
            return e.getMessage();
        }
        throw new AssertionError("expected an exception, none was thrown");
    }

    private static final class Fixture {
        final Path dir;
        final PasswordHasher hasher;
        final AccountService service;

        Fixture(Path dir, PasswordHasher hasher) {
            this.dir = dir;
            this.hasher = hasher;
            this.service = new AccountService(new AccountStore(dir.resolve("accounts"), hasher),
                    hasher);
        }
    }

    private static Fixture fixture() throws IOException {
        PasswordHasher hasher = new PasswordHasher(FAST);
        return new Fixture(tempDir("svc"), hasher);
    }

    private static Map<String, Account> load(Path dir) throws IOException {
        PasswordHasher hasher = new PasswordHasher(FAST);
        return new AccountStore(dir.resolve("accounts"), hasher).loadAll();
    }

    private static int cli(Path store, String stdin, String... args) throws Exception {
        return cliCaptured(new Capture(), store, stdin, args);
    }

    private static final class Capture {
        String stdout = "";
        String stderr = "";
    }

    private static int cliCaptured(Capture capture, Path store, String stdin, String... args)
            throws Exception {
        String[] full = new String[args.length + 2];
        full[0] = "--store";
        full[1] = store.toString();
        System.arraycopy(args, 0, full, 2, args.length);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        java.io.InputStream originalIn = System.in;
        try {
            System.setIn(new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8)));
            // The CLI writes through the streams it is handed, so only stdin is swapped here.
            int rc = Main.run(full, new PrintStream(out, true, StandardCharsets.UTF_8),
                    new PrintStream(err, true, StandardCharsets.UTF_8));
            if (capture != null) {
                capture.stdout = out.toString(StandardCharsets.UTF_8);
                capture.stderr = err.toString(StandardCharsets.UTF_8);
            }
            return rc;
        } finally {
            System.setIn(originalIn);
        }
    }

    private static Path tempDir(String name) throws IOException {
        Path dir = Path.of("/tmp/secureaccount-tests", name + "-" + System.nanoTime());
        Files.createDirectories(dir);
        return dir;
    }

    private static List<Path> regularFiles(Path dir) throws IOException {
        List<Path> files = new ArrayList<>();
        try (var stream = Files.walk(dir)) {
            for (Path candidate : (Iterable<Path>) stream::iterator) {
                if (Files.isRegularFile(candidate)) {
                    files.add(candidate);
                }
            }
        }
        java.util.Collections.sort(files);
        return files;
    }

    /** The secret and the encodings a sloppy implementation might have written it in. */
    private static List<String> encodingsOf(String secret) {
        List<String> forms = new ArrayList<>();
        forms.add(secret);
        forms.add(Base64.getEncoder().encodeToString(secret.getBytes(StandardCharsets.UTF_8)));
        forms.add(Base64.getEncoder().withoutPadding()
                .encodeToString(secret.getBytes(StandardCharsets.UTF_8)));
        return forms;
    }

    private static int indexOfBytes(byte[] haystack, byte[] needle) {
        if (needle.length == 0) {
            return 0;
        }
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    // Deliberately an independent parser, so a bug in PasswordHasher's own decoder cannot hide.
    private static final Pattern RECORD = Pattern.compile(
            "^\\$([A-Za-z0-9-]+)\\$i=(\\d+)\\$l=(\\d+)\\$s=([A-Za-z0-9_-]+)\\$h=([A-Za-z0-9_-]+)\\$$");

    private static byte[] saltOf(String encoded) {
        Matcher m = RECORD.matcher(encoded);
        if (!m.matches()) {
            throw new AssertionError("record does not parse: " + encoded);
        }
        return Base64.getUrlDecoder().decode(m.group(4));
    }

    private static byte[] hashOf(String encoded) {
        Matcher m = RECORD.matcher(encoded);
        if (!m.matches()) {
            throw new AssertionError("record does not parse: " + encoded);
        }
        return Base64.getUrlDecoder().decode(m.group(5));
    }

    private static int iterationsOf(String encoded) {
        Matcher m = RECORD.matcher(encoded);
        if (!m.matches()) {
            throw new AssertionError("record does not parse: " + encoded);
        }
        return Integer.parseInt(m.group(2));
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static double timeLogin(AccountService service, String username, String password) {
        long start = System.nanoTime();
        try {
            service.authenticate(username, password.toCharArray());
        } catch (Exception expected) {
            // Both outcomes are the path being timed.
        }
        return (System.nanoTime() - start) / 1_000_000.0;
    }

    private interface TimedCall {
        double call();
    }

    private static double median(TimedCall call) {
        double[] samples = new double[5];
        for (int i = 0; i < samples.length; i++) {
            samples[i] = call.call();
        }
        java.util.Arrays.sort(samples);
        return samples[samples.length / 2];
    }
}
