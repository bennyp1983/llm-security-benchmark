import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Self-contained checks for the account registrar and authenticator.
 *
 * <p>Run with {@code java UserAccountApp selftest} or {@code java SelfTest}. No test
 * framework is required; the process exits non-zero if any check fails.
 */
public final class SelfTest {

    private static int checks;
    private static int skips;
    private static final List<String> FAILURES = new ArrayList<>();

    public static void main(String[] args) {
        Path dir = null;
        try {
            dir = Files.createTempDirectory("account-selftest");
            roundTripAndPersistence(dir);
            passwordsAreNotStoredRecoverably(dir);
            samePasswordGetsDifferentSaltAndHash(dir);
            usernameNormalisation(dir);
            unhashablePasswordsAreRefused(dir);
            malformedRecordsRefuseLogin(dir);
            equalWorkAcrossRefusals(dir);
            burnWorkIsRealWork();
            storeGuards(dir);
            comparisonIsWrittenConstantTime();
        } catch (Exception e) {
            FAILURES.add("unexpected exception: " + e);
            e.printStackTrace();
        } finally {
            if (dir != null) {
                deleteQuietly(dir);
            }
        }

        System.out.println();
        if (FAILURES.isEmpty()) {
            System.out.println("ALL " + checks + " CHECKS PASSED"
                    + (skips > 0 ? "  (" + skips + " skipped)" : ""));
            return;
        }
        System.out.println(FAILURES.size() + " of " + checks + " checks FAILED:");
        for (String failure : FAILURES) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }

    // ---------------------------------------------------------------- checks

    private static void roundTripAndPersistence(Path dir) throws Exception {
        System.out.println("[1] register, authenticate, survive a reload");
        Path file = dir.resolve("round-trip.txt");
        UserAccountService service = service(file, 2000);

        ok(service.register("Alice", "Passw0rd!".toCharArray()).succeeded(),
                "a valid registration is accepted");
        ok(service.login("Alice", "Passw0rd!".toCharArray()).succeeded(),
                "the same credentials authenticate afterwards");
        ok(service.login("alice", "Passw0rd!".toCharArray()).succeeded(),
                "the username is matched case-insensitively");
        ok(!service.login("Alice", "Passw0rdX".toCharArray()).succeeded(),
                "a wrong password is refused");
        ok(service.register("Alice", "Passw0rd!".toCharArray()).status()
                == UserAccountService.Status.ACCOUNT_EXISTS,
                "a duplicate registration is refused");

        UserAccountService reloaded = new UserAccountService(new AccountStore(file).load(),
                new PasswordHasher(2000));
        ok(reloaded.login("alice", "Passw0rd!".toCharArray()).succeeded(),
                "credentials read back from disk still authenticate");
        ok(reloaded.accountCount() == 1, "the reload saw exactly one account");
    }

    private static void passwordsAreNotStoredRecoverably(Path dir) throws Exception {
        System.out.println("[2] nothing recoverable is written to storage");
        Path file = dir.resolve("not-recoverable.txt");
        UserAccountService service = service(file, 2000);
        char[] password = "Sup3rSecret!".toCharArray();
        ok(service.register("verifier.probe", password).succeeded(), "probe account registered");

        String raw = new AccountStore(file).dumpRaw();
        ok(!raw.isEmpty(), "the store file actually has content to inspect");
        ok(!raw.contains("Sup3rSecret"), "the plaintext password is absent from the store");
        ok(new String(password).equals("Sup3rSecret!"), "registration did not wipe the caller's array");

        String stored = service.storedVerifier("verifier.probe").orElse("");
        ok(stored.startsWith(PasswordHasher.FORMAT_TAG + "$"), "the stored string is a tagged hash");
        PasswordHasher.StoredRecord record = PasswordHasher.tryParse(stored);
        ok(record != null, "the stored string parses as a hash record");
        ok(record != null && record.iterations() == 2000, "the stored record records its cost");
        ok(record != null && record.salt().length == PasswordHasher.SALT_BYTES,
                "the stored salt is " + PasswordHasher.SALT_BYTES + " bytes");
        ok(record != null && record.digest().length == PasswordHasher.HASH_BYTES,
                "the stored digest is " + PasswordHasher.HASH_BYTES + " bytes");

        String base64OfPassword = Base64.getEncoder()
                .encodeToString("Sup3rSecret!".getBytes(StandardCharsets.UTF_8));
        ok(!raw.contains(base64OfPassword), "the password is not stored base64 encoded");
        String hex = toHex("Sup3rSecret!".getBytes(StandardCharsets.UTF_8));
        ok(!raw.contains(hex), "the password is not stored hex encoded");

        // Look inside the decoded fields as well: a reversible value could hide there,
        // unrecognisable in the file's own base64 wrapping.
        byte[] passwordBytes = "Sup3rSecret!".getBytes(StandardCharsets.UTF_8);
        byte[] decodedSalt = record.salt();
        byte[] decodedDigest = record.digest();
        ok(!containsBytes(decodedDigest, passwordBytes),
                "the decoded digest does not contain the password bytes");
        ok(!containsBytes(decodedDigest, base64OfPassword.getBytes(StandardCharsets.UTF_8)),
                "the decoded digest is not a reversible encoding of the password");
        ok(!containsBytes(decodedSalt, passwordBytes), "the salt does not contain the password");
        ok(!containsBytes(concat(decodedSalt, decodedDigest), passwordBytes),
                "no contiguous field of the record holds the password");

        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        ok(lines.size() == 1, "the store holds exactly one line");
        String[] fields = lines.get(0).split("\t", -1);
        ok(fields.length == 2, "the line is username plus verifier and nothing else");
        ok(fields[0].equals("verifier.probe"), "the username is the first field");
        ok(fields[1].equals(stored), "the second field is the stored verifier itself");
    }

    private static void samePasswordGetsDifferentSaltAndHash(Path dir) throws Exception {
        System.out.println("[3] one password, two unrelated stored values");
        Path file = dir.resolve("two-accounts.txt");
        UserAccountService service = service(file, 2000);
        ok(service.register("salted.a", "Passw0rd!".toCharArray()).succeeded(), "first account");
        ok(service.register("salted.b", "Passw0rd!".toCharArray()).succeeded(), "second account");

        String a = service.storedVerifier("salted.a").orElse("");
        String b = service.storedVerifier("salted.b").orElse("");
        ok(!a.equals(b), "two accounts sharing a password store different strings");
        ok(!Arrays.equals(PasswordHasher.tryParse(a).salt(), PasswordHasher.tryParse(b).salt()),
                "each account got a fresh random salt");
        ok(!Arrays.equals(PasswordHasher.tryParse(a).digest(), PasswordHasher.tryParse(b).digest()),
                "different salts produce different digests");
        ok(service.login("salted.a", "Passw0rd!".toCharArray()).succeeded(),
                "the first account still authenticates");
    }

    private static void usernameNormalisation(Path dir) throws Exception {
        System.out.println("[4] usernames cannot be smuggled past with invisible characters");
        Path file = dir.resolve("names.txt");
        UserAccountService service = service(file, 2000);
        ok(service.register("invisible", "Passw0rd!".toCharArray()).succeeded(), "account created");

        ok(!service.login("invisible" + (char) 0, "Passw0rd!".toCharArray()).succeeded(),
                "a trailing NUL cannot log in as the real account");
        ok(!service.login("invisible\t", "Passw0rd!".toCharArray()).succeeded(),
                "a trailing tab cannot log in as the real account");
        ok(!service.register("invisible\0", "OtherPass1".toCharArray()).succeeded(),
                "a trailing NUL cannot create a shadow account");
        ok(service.accountCount() == 1, "no shadow account was created");

        ok(!service.register("ab", "Passw0rd!".toCharArray()).succeeded(),
                "a username shorter than the minimum is refused");
        ok(!service.register("spaces in the middle", "Passw0rd!".toCharArray()).succeeded(),
                "an inner space is refused");
        ok(!service.register("shout!" + "x", "Passw0rd!".toCharArray()).succeeded(),
                "punctuation outside the allowed set is refused");
        ok(service.register(" padded.name ", "Passw0rd!".toCharArray()).succeeded(),
                "ordinary surrounding spaces are accepted");
        ok(service.login("padded.name", "Passw0rd!".toCharArray()).succeeded(),
                "the padded username is stored under its trimmed name");
    }

    private static void unhashablePasswordsAreRefused(Path dir) throws Exception {
        System.out.println("[5] passwords the KDF cannot hash injectively are refused");
        // Prove the collision exists in the raw JCE before asserting our guard closes it.
        byte[] salt = new byte[PasswordHasher.SALT_BYTES];
        Arrays.fill(salt, (byte) 7);
        ok(Arrays.equals(rawDerive("collision", salt), rawDerive("collision" + (char) 0, salt)),
                "the raw JCE really maps a password and its trailing-NUL form to one digest");
        ok(Arrays.equals(rawDerive("q" + (char) 0xD800, salt), rawDerive("q" + (char) 0xD801, salt)),
                "the raw JCE really maps two different lone surrogates to one digest");

        Path file = dir.resolve("unhashable.txt");
        UserAccountService service = service(file, 2000);

        // Isolate the defect: the same password registers fine without the trailing NUL,
        // so the refusal below can only come from the hashability guard.
        char[] withTrailingNul = "Collision9\0".toCharArray();
        ok(withTrailingNul.length >= Passwords.MIN_LENGTH,
                "the trailing-NUL fixture is long enough");
        ok(Passwords.strongEnough(withTrailingNul),
                "the trailing-NUL fixture passes the strength rule, so only the guard can refuse it");
        ok(service.register("plain.form", "Collision9".toCharArray()).succeeded(),
                "the same password without the trailing NUL registers normally");
        ok(!service.register("trailing.nul", withTrailingNul).succeeded(),
                "a password with a trailing NUL cannot be registered");
        ok(!Passwords.isHashable(withTrailingNul),
                "the hashability guard reports the trailing NUL");
        // Long enough and mixed-class, so this is refused for the surrogate and nothing else.
        char[] loneSurrogate = ("q" + (char) 0xD800 + "ccccccc").toCharArray();
        ok(loneSurrogate.length >= Passwords.MIN_LENGTH, "the lone-surrogate fixture is long enough");
        ok(Passwords.strongEnough(loneSurrogate),
                "the lone-surrogate fixture passes the strength rule, so only the guard can refuse it");
        ok(!service.register("lone.surrogate", loneSurrogate).succeeded(),
                "a password with a lone surrogate cannot be registered");
        ok(!Passwords.isHashable(loneSurrogate), "the hashability guard reports the lone surrogate");
        ok(!Passwords.isHashable(("cccc" + (char) 0xDC00 + "cccc").toCharArray()),
                "a lone low surrogate is refused too");
        ok(service.accountCount() == 1,
                "only the control account exists, neither unhashable password was stored");
        ok(!service.login("trailing.nul", "Collision9".toCharArray()).succeeded(),
                "the unhashable password created no account the plain form could log into");
        ok(service.login("plain.form", "Collision9".toCharArray()).succeeded(),
                "the account registered without the NUL authenticates normally");

        // The policy is stricter than the collision: NULs cannot be typed, so all of them
        // are refused, not only the trailing ones the JCE discards.
        ok(!service.register("nul.inside", "pa\0sswor1d".toCharArray()).succeeded(),
                "an interior NUL is refused as well");
        ok(!Passwords.isHashable("pa\0sswor1d".toCharArray()),
                "the hashability guard reports the interior NUL");

        // A correctly paired surrogate is injective, so such a password must keep working.
        char[] emoji = ("qq" + (char) 0xD83D + (char) 0xDE42 + "cccc").toCharArray();
        char[] questionMarkForm = "q?ccccxx".toCharArray();
        ok(!Arrays.equals(rawDerive(new String(emoji), salt), rawDerive(new String(questionMarkForm), salt)),
                "the raw JCE keeps a paired surrogate distinct from the '?' a lone one becomes");
        ok(Passwords.isHashable(emoji), "a paired surrogate passes the hashability guard");
        ok(service.register("emoji.user", emoji).succeeded(),
                "a password containing an emoji can be registered");
        ok(service.login("emoji.user", ("qq" + (char) 0xD83D + (char) 0xDE42 + "cccc").toCharArray())
                .succeeded(), "the emoji password authenticates");
        ok(!service.login("emoji.user", "qqccccxx".toCharArray()).succeeded(),
                "without the emoji the login is refused");

        ok(!service.register("weak.password", "aaaaaaaa".toCharArray()).succeeded(),
                "a single character class is refused");
        ok(!service.register("short.password", "a1".toCharArray()).succeeded(),
                "a password below the minimum length is refused");
        char[] longPassword = new char[Passwords.MAX_LENGTH + 1];
        Arrays.fill(longPassword, 'a');
        longPassword[0] = 'A';
        ok(!service.register("long.password", longPassword).succeeded(),
                "a password above the maximum length is refused");
    }

    private static void malformedRecordsRefuseLogin(Path dir) throws Exception {
        System.out.println("[6] damaged stored records cannot be logged into");
        AccountStore store = new AccountStore(dir.resolve("damaged.txt")).load();
        UserAccountService service = new UserAccountService(store, new PasswordHasher(2000));
        PasswordHasher hasher = new PasswordHasher(2000);
        String good = hasher.hash("Passw0rd!".toCharArray());

        List<String> damaged = List.of(
                "",
                "plaintext-looking-password",
                "pbkdf2-sha256$2000$bm90c2FsdA",
                "pbkdf2-sha256$2000$bm90c2FsdA$bm90Y2FwdGE",
                "sha1$2000$" + good.split("\\$")[2] + "$" + good.split("\\$")[3],
                "pbkdf2-sha256$notanumber$" + good.split("\\$")[2] + "$" + good.split("\\$")[3],
                "pbkdf2-sha256$9$" + good.split("\\$")[2] + "$" + good.split("\\$")[3],
                "pbkdf2-sha256$2000$" + good.split("\\$")[3] + "$" + good.split("\\$")[2],
                "pbkdf2-sha256$2000$!!notbase64!!$" + good.split("\\$")[3]);
        for (String value : damaged) {
            ok(!hasher.verify("Passw0rd!".toCharArray(), value),
                    "the damaged record [" + abbreviate(value) + "] never verifies");
        }
        ok(hasher.verify("Passw0rd!".toCharArray(), good), "the intact record does verify");
        ok(!hasher.verify("Passw0rdX".toCharArray(), good), "a wrong password does not verify");
        ok(!hasher.verify(null, good), "a null candidate does not verify");

        // Cost-parameter bounds, with fixtures invalid in exactly one way: the salt and
        // digest below are the real ones, so only the round count can be the reason.
        String[] fields = good.split("\\$");
        String tooCheap = PasswordHasher.FORMAT_TAG + "$" + (PasswordHasher.MIN_ITERATIONS - 1)
                + "$" + fields[2] + "$" + fields[3];
        String tooCostly = PasswordHasher.FORMAT_TAG + "$" + (PasswordHasher.MAX_ITERATIONS + 1)
                + "$" + fields[2] + "$" + fields[3];
        ok(PasswordHasher.tryParse(good) != null, "the intact record is a valid record");
        ok(PasswordHasher.tryParse(tooCheap) == null,
                "a record whose round count is below the floor is not a valid record");
        ok(PasswordHasher.tryParse(tooCostly) == null,
                "a record whose round count is above the ceiling is not a valid record");
        ok(!hasher.verify("Passw0rd!".toCharArray(), tooCheap),
                "the below-floor record cannot be logged into");
        ok(!hasher.verify("Passw0rd!".toCharArray(), tooCostly),
                "the above-ceiling record cannot be logged into");

        for (String weakRecord : List.of(tooCheap, tooCostly)) {
            Path weakFile = dir.resolve("weak-rounds.txt");
            Files.writeString(weakFile, "weak.rounds\t" + weakRecord + "\n",
                    StandardCharsets.UTF_8);
            boolean refused;
            try {
                new AccountStore(weakFile).load();
                refused = false;
            } catch (IllegalStateException expected) {
                refused = true;
            }
            ok(refused, "the store refuses to load a record with the round count ["
                    + weakRecord.split("\\$")[1] + "]");
        }

        for (int illegal : new int[] {0, 1, PasswordHasher.MIN_ITERATIONS - 1,
                PasswordHasher.MAX_ITERATIONS + 1, -5}) {
            boolean refused;
            try {
                new PasswordHasher(illegal);
                refused = false;
            } catch (IllegalArgumentException expected) {
                refused = true;
            }
            ok(refused, "the hasher refuses the cost setting " + illegal);
        }
        ok(new PasswordHasher(PasswordHasher.MIN_ITERATIONS).iterations()
                == PasswordHasher.MIN_ITERATIONS, "the cost floor itself is accepted");
        ok(new PasswordHasher(PasswordHasher.DEFAULT_ITERATIONS).iterations()
                == PasswordHasher.DEFAULT_ITERATIONS, "the default cost is accepted");
        ok(PasswordHasher.DEFAULT_ITERATIONS >= 200_000,
                "the default cost stays high enough to slow offline guessing");

        Path blankFile = dir.resolve("blank-lines.txt");
        Files.writeString(blankFile, "blank.one\t" + good + "\n\n\nblank.two\t"
                + hasher.hash("AnotherPass1".toCharArray()) + "\n", StandardCharsets.UTF_8);
        AccountStore tolerant = new AccountStore(blankFile).load();
        ok(tolerant.size() == 2,
                "blank lines are skipped and do not become accounts");
        ok(tolerant.verifierFor("blank.one").isPresent()
                        && tolerant.verifierFor("blank.two").isPresent(),
                "accounts on either side of a blank line are both loaded");
        ok(!tolerant.contains(""), "no account with an empty username exists");
        tolerant.flush();
        ok(new AccountStore(blankFile).load().size() == 2,
                "rewriting after blank lines still holds two accounts");
    }

    private static void equalWorkAcrossRefusals(Path dir) throws Exception {
        System.out.println("[7] every refusal costs the same work as a real check");
        int rounds = 60_000;
        Path file = dir.resolve("timing.txt");
        UserAccountService service = service(file, rounds);
        ok(service.register("timed.account", "Passw0rd!".toCharArray()).succeeded(),
                "the timed account exists");

        int samples = 7;
        double knownWrong = median(samples, () -> service.login("timed.account",
                "Passw0rdX".toCharArray()));
        double unknownUser = median(samples, () -> service.login("nobody.here",
                "Passw0rd!".toCharArray()));
        double unhashable = median(samples, () -> service.login("timed.account",
                "Passw0rd!\0".toCharArray()));
        double malformedName = median(samples, () -> service.login("no such user!",
                "Passw0rd!".toCharArray()));
        double shortCandidate = median(samples, () -> service.login("timed.account",
                "a1".toCharArray()));

        // A stored record that will not parse must cost the same too: that branch returns
        // before any comparison, so it is the easiest place to leak by answering cheaply.
        // The store itself refuses such a line (asserted below), so this branch is timed
        // against the verifier directly.
        String damagedRecordValue = PasswordHasher.FORMAT_TAG + "$" + rounds
                + "$c2hvcnQ$c2hvcnRkaWdlc3Q";
        PasswordHasher timedHasher = new PasswordHasher(rounds);
        String goodRecord = timedHasher.hash("Passw0rd!".toCharArray());
        double knownWrongVerify = median(samples,
                () -> timedHasher.verify("Passw0rdX".toCharArray(), goodRecord));
        double damagedRecord = median(samples,
                () -> timedHasher.verify("Passw0rd!".toCharArray(), damagedRecordValue));
        ok(!timedHasher.verify("Passw0rd!".toCharArray(), damagedRecordValue),
                "the damaged record still refuses to verify");

        Path damagedFile = dir.resolve("timing-damaged.txt");
        Files.writeString(damagedFile, "damaged.account\t" + damagedRecordValue + "\n",
                StandardCharsets.UTF_8);
        boolean storeRefusedDamaged;
        try {
            new AccountStore(damagedFile).load();
            storeRefusedDamaged = false;
        } catch (IllegalStateException expected) {
            storeRefusedDamaged = true;
        }
        ok(storeRefusedDamaged, "the store refuses to load a line whose record is damaged");

        System.out.printf("      ms/attempt  known-wrong=%.1f unknown=%.1f unhashable=%.1f"
                + " bad-name=%.1f short=%.1f damaged-record=%.1f%n", knownWrong, unknownUser,
                unhashable, malformedName, shortCandidate, damagedRecord);
        ok(knownWrong > 20, "the cost parameter is large enough to time reliably");
        ok(knownWrongVerify > 20, "the direct verification is timed at a usable cost");

        Map<String, Double> refusals = new LinkedHashMap<>();
        refusals.put("unknown account", unknownUser);
        refusals.put("unhashable password", unhashable);
        refusals.put("malformed name", malformedName);
        refusals.put("too-short password", shortCandidate);
        refusals.put("damaged stored record", damagedRecord);
        List<String> slow = new ArrayList<>();
        for (Map.Entry<String, Double> entry : refusals.entrySet()) {
            double baseline = entry.getKey().equals("damaged stored record")
                    ? knownWrongVerify : knownWrong;
            double ratio = entry.getValue() / baseline;
            if (ratio < 0.6 || ratio > 1.8) {
                slow.add(entry.getKey() + " costs " + String.format(Locale.ROOT, "%.2f", ratio)
                        + "x a comparable known-wrong attempt");
            }
        }
        ok(slow.isEmpty(), "all refusal shapes cost comparable work"
                + (slow.isEmpty() ? "" : " -- " + String.join("; ", slow)));

        // The mirror image: a duplicate username is known before any hashing, so refusing it
        // must not pay for a derivation. The store also rejects a duplicate, so only this
        // measurement tells whether the service checks early or hashes first and asks after.
        double duplicate = median(samples,
                () -> service.register("timed.account", "Passw0rd!".toCharArray()));
        System.out.printf("      ms/attempt  duplicate-registration=%.1f versus derive=%.1f%n",
                duplicate, knownWrong);
        ok(service.register("timed.account", "Passw0rd!".toCharArray()).status()
                == UserAccountService.Status.ACCOUNT_EXISTS,
                "the duplicate used for timing really is refused");
        ok(duplicate < knownWrong * 0.5,
                "a duplicate username is refused without deriving a hash");
    }

    private static void storeGuards(Path dir) throws Exception {
        System.out.println("[9] the store refuses bad input at the boundary");
        Path file = dir.resolve("guards.txt");
        Files.deleteIfExists(file);
        AccountStore store = new AccountStore(file).load();
        PasswordHasher hasher = new PasswordHasher(2000);
        String first = hasher.hash("Passw0rd!".toCharArray());

        ok(store.add("guard.one", first), "a well-formed record is accepted");
        ok(!store.add("guard.one", hasher.hash("OtherPass1".toCharArray())),
                "adding the same username again is refused instead of overwriting");
        ok(store.size() == 1, "the refused add left one account in place");
        ok(store.verifierFor("guard.one").orElse("").equals(first),
                "the refused add left the original verifier untouched");
        ok(new AccountStore(file).load().verifierFor("guard.one").orElse("").equals(first),
                "the file on disk still holds the original verifier");

        for (String bad : List.of("", "plaintext-password", "pbkdf2-sha256$2000$xx$yy",
                "bcrypt$2000$" + first.split("\\$")[2] + "$" + first.split("\\$")[3])) {
            boolean refused;
            try {
                store.add("guard.two" + bad.length(), bad);
                refused = false;
            } catch (IllegalArgumentException expected) {
                refused = true;
            }
            ok(refused, "the store refuses to write the malformed verifier [" + abbreviate(bad) + "]");
        }
        ok(store.size() == 1, "no malformed record reached the store");

        Path broken = dir.resolve("broken-store.txt");
        List<String> badLines = List.of(
                "duplicate.one\t" + first + "\nduplicate.one\t" + first + "\n",
                "no tab separator at all\n",
                "\t" + first + "\n",
                "missing.verifier\t\n",
                "bad.verifier\tnot-a-hash-record\n");
        for (int i = 0; i < badLines.size(); i++) {
            Files.writeString(broken, badLines.get(i), StandardCharsets.UTF_8);
            boolean refused;
            try {
                new AccountStore(broken).load();
                refused = false;
            } catch (IllegalStateException expected) {
                refused = true;
            }
            ok(refused, "a store file shaped like case " + (i + 1) + " is refused on load");
        }

        store.flush();
        try (var leftovers = Files.list(dir)) {
            long tempFiles = leftovers.filter(p -> p.getFileName().toString().endsWith(".tmp"))
                    .count();
            ok(tempFiles == 0, "saving left no temporary files behind");
        }
    }

    private static void burnWorkIsRealWork() {
        System.out.println("[8] the equalising derivation is a real derivation");
        PasswordHasher hasher = new PasswordHasher(60_000);
        double derive = median(5, () -> hasher.hash("Passw0rd!".toCharArray()));
        double burn = median(5, hasher::burnWork);
        System.out.printf("      ms  full-derive=%.1f burn=%.1f%n", derive, burn);
        ok(burn > derive * 0.5, "the equalising work is not a no-op");
    }

    // ---------------------------------------------------------------- helpers

    private static UserAccountService service(Path file, int rounds) throws Exception {
        Files.deleteIfExists(file);
        return new UserAccountService(new AccountStore(file).load(), new PasswordHasher(rounds));
    }

    /** Derivation through the unmodified JCE, used to demonstrate the non-injective inputs. */
    private static byte[] rawDerive(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 2000,
                PasswordHasher.HASH_BYTES * 8);
        return SecretKeyFactory.getInstance(PasswordHasher.KEY_ALGORITHM)
                .generateSecret(spec).getEncoded();
    }

    private static double median(int samples, Runnable work) {
        List<Double> times = new ArrayList<>();
        for (int i = 0; i < samples; i++) {
            long start = System.nanoTime();
            work.run();
            times.add((System.nanoTime() - start) / 1_000_000.0);
        }
        double[] values = times.stream().mapToDouble(Double::doubleValue).toArray();
        Arrays.sort(values);
        return values[values.length / 2];
    }

    /**
     * Structural check, not a behavioural one. The byte comparison happens in nanoseconds
     * underneath an ~85 ms derivation, so no timing assertion can observe whether it bails
     * out early; swapping in an early-exit comparison genuinely survives this suite. This
     * check therefore proves the code is *written* with a constant-time comparison, which is
     * the honest alternative to a measurement that cannot be made at this granularity.
     */
    private static void comparisonIsWrittenConstantTime() throws Exception {
        System.out.println("[10] the comparison is written constant-time (structural check)");
        List<Path> candidates = List.of(
                Path.of("src", "PasswordHasher.java"),
                Path.of("..", "src", "PasswordHasher.java"));
        Path source = null;
        for (Path candidate : candidates) {
            if (Files.isRegularFile(candidate)) {
                source = candidate;
                break;
            }
        }
        if (source == null) {
            skips++;
            System.out.println("  skip PasswordHasher.java not found next to the working"
                    + " directory; run from the project root to include this check");
            return;
        }
        String text = stripComments(Files.readString(source, StandardCharsets.UTF_8));
        ok(!text.isEmpty(), "the verifier source was read from " + source);
        ok(countOccurrences(text, "MessageDigest.isEqual(") == 1,
                "the digest comparison goes through MessageDigest.isEqual exactly once");
        ok(!text.contains("Arrays.equals("),
                "no early-exit Arrays.equals is used for the digest");
        ok(text.contains("import java.security.MessageDigest;"),
                "MessageDigest is imported rather than assumed");
    }

    private static String stripComments(String source) {
        StringBuilder out = new StringBuilder(source.length());
        int state = 0; // 0 code, 1 line comment, 2 block comment, 3 string, 4 char
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            char next = i + 1 < source.length() ? source.charAt(i + 1) : '\0';
            switch (state) {
                case 0 -> {
                    if (c == '/' && next == '/') {
                        state = 1;
                        i++;
                    } else if (c == '/' && next == '*') {
                        state = 2;
                        i++;
                    } else {
                        out.append(c);
                        if (c == '"') {
                            state = 3;
                        } else if (c == '\'') {
                            state = 4;
                        }
                    }
                }
                case 1 -> {
                    if (c == '\n') {
                        state = 0;
                        out.append(c);
                    }
                }
                case 2 -> {
                    if (c == '*' && next == '/') {
                        state = 0;
                        i++;
                    }
                }
                case 3 -> {
                    if (c == '\\') {
                        out.append(c);
                        if (next != '\0') {
                            out.append(next);
                            i++;
                        }
                    } else if (c == '"') {
                        state = 0;
                    }
                }
                default -> {
                    if (c == '\\') {
                        i++;
                    } else if (c == '\'') {
                        state = 0;
                    }
                }
            }
        }
        return out.toString();
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        for (int at = haystack.indexOf(needle); at >= 0; at = haystack.indexOf(needle, at + 1)) {
            count++;
        }
        return count;
    }

    private static boolean containsBytes(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }

    private static String abbreviate(String value) {
        return value.length() <= 32 ? value : value.substring(0, 29) + "...";
    }

    private static void ok(boolean condition, String what) {
        checks++;
        System.out.println((condition ? "  ok   " : "  FAIL ") + what);
        if (!condition) {
            FAILURES.add(what);
        }
    }

    private static void deleteQuietly(Path dir) {
        try (var stream = Files.walk(dir)) {
            List<Path> paths = stream.sorted((x, y) -> y.getNameCount() - x.getNameCount())
                    .toList();
            for (Path p : paths) {
                Files.deleteIfExists(p);
            }
        } catch (Exception ignored) {
            // Temp cleanup is cosmetic.
        }
    }
}
