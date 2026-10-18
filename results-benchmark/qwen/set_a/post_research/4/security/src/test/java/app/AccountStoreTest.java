package app;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;

/**
 * Store tests: what actually lands in the database, what the schema refuses even if application
 * code is bypassed, and what must never be present in the store file's bytes.
 */
public final class AccountStoreTest {

    private static final String EMAIL = "dana@corp.example";
    private static final String NAME = "pool-user";

    public static void main(String[] argv) throws Exception {
        storesOnlyTheCredential(Harness.freshFixture("store-shape"));
        duplicates(Harness.freshFixture("store-dup"));
        registerBudget(Harness.freshFixture("store-budget"));
        schemaRefusesRawWrites(Harness.freshFixture("store-schema"));
        secretsNeverOnDiskOrInTrail(Harness.freshFixture("store-disk"));
        upgradeIsGuarded(Harness.freshFixture("store-upgrade"));
        System.exit(Harness.report("AccountStoreTest"));
    }

    private static void storesOnlyTheCredential(Harness.Fixture fixture) throws Exception {
        Harness.section("a registered account stores an Argon2id credential and the canonical identity");
        Harness.equal(Harness.registerStatus(fixture, "Dana@Corp.Example", NAME, Harness.PW_ONE, "src-a"),
            AccountStore.RegisterStatus.CREATED, "registration is accepted");

        AccountStore.Account stored = fixture.accounts().findByEmail(EMAIL);
        Harness.check(stored != null, "the account can be read back by its canonical email");
        Harness.equal(stored.email(), EMAIL, "the stored email is the lower-cased canonical form");
        Harness.equal(stored.username(), NAME, "the stored username is unchanged");
        Harness.equal(stored.passwordHash().length(), 97, "the stored credential is a canonical Argon2id string");
        Harness.check(stored.passwordHash().startsWith("$argon2id$v=19$m="),
            "the stored credential names its algorithm");
        Harness.equal(stored.kdfMemoryKib(), Harness.TEST_MEMORY_KIB,
            "the memory column agrees with the credential");
        Harness.check(stored.passwordHash().contains("m=" + stored.kdfMemoryKib() + ",t="
                + stored.kdfIterations() + ",p=" + stored.kdfParallelism()),
            "the cost columns cannot drift from the credential they describe");
        Harness.equal(stored.passwordUpdatedAt(), Harness.BASE_EPOCH, "the credential timestamp is recorded");
        Harness.check(!stored.toString().contains(Harness.PW_ONE),
            "the row record does not carry the password");

        Harness.check(fixture.accounts().findByUsername(NAME) != null, "the account is findable by username");
        // The store compares exactly; canonicalisation is what makes two spellings one account.
        // This is why every lookup goes through InputPolicy first rather than passing raw input.
        Harness.check(fixture.accounts().findByEmail(InputPolicy.email(Harness.chars("DANA@CORP.EXAMPLE"))) != null,
            "a differently spelled mailbox canonicalises onto the same row");
        Harness.check(fixture.accounts().findByEmail("DANA@CORP.EXAMPLE") == null,
            "the store itself does not fold case, so raw input must never reach a lookup");
        Harness.check(fixture.accounts().findByUsername("Pool-User") == null,
            "a differently spelled username is a different (missing) account, not a fold");
        fixture.close();
    }

    private static void duplicates(Harness.Fixture fixture) throws Exception {
        Harness.section("a taken mailbox or username cannot be distinguished from a success");
        Harness.equal(Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-b"),
            AccountStore.RegisterStatus.CREATED, "the first registration is accepted");

        AccountStore.RegisterOutcome sameMail = outcome(fixture, "dana@corp.example", "other-user",
            Harness.PW_TWO, "src-b");
        Harness.equal(sameMail.status(), AccountStore.RegisterStatus.DUPLICATE,
            "the same mailbox is refused as a duplicate");

        AccountStore.RegisterOutcome sameName = outcome(fixture, "fresh@corp.example", NAME,
            Harness.PW_TWO, "src-b");
        Harness.equal(sameName.status(), AccountStore.RegisterStatus.DUPLICATE,
            "the same username is refused as a duplicate");

        Harness.equal(sameMail.message(), AccountStore.OUTCOME_MESSAGE,
            "a duplicate is reported with the shared wording");
        Harness.equal(sameMail.message(), outcome(fixture, "third@corp.example", "third-user",
            Harness.PW_TWO, "src-b").message(), "created and duplicate print the same sentence");
        Harness.check(!sameMail.message().toLowerCase().contains("exist")
                && !sameMail.message().toLowerCase().contains("taken")
                && !sameMail.message().toLowerCase().contains("duplicate")
                && !sameMail.message().toLowerCase().contains("alread"),
            "the shared wording does not disclose that the account exists: " + sameMail.message());
        Harness.check(!sameMail.message().contains(EMAIL) && !sameMail.message().contains(NAME),
            "the shared wording does not echo the supplied identity");

        // A duplicate forces the full key-derivation and a store write, so it must cost the caller a
        // budget token like any other expensive attempt. Charging it even though the insert rolls back
        // is what stops "always submit a taken mailbox" from being a free derivation amplifier; a flood
        // of duplicates now runs into the same source budget as anything else.
        int answered = 0;
        int throttled = 0;
        for (int attempt = 0; attempt < 12; attempt++) {
            AccountStore.RegisterStatus status = outcome(fixture, EMAIL, NAME, Harness.PW_ONE, "src-b").status();
            if (status == AccountStore.RegisterStatus.DUPLICATE) {
                answered++;
            } else if (status == AccountStore.RegisterStatus.THROTTLED) {
                throttled++;
            }
        }
        Harness.atLeast((long) throttled, 1L,
            "a flood of duplicates is bounded by the source budget - it is not a free key-derivation "
                + "amplifier, because the consume is charged even though the rejected insert rolls back");
        Harness.equal((long) (answered + throttled), 12L,
            "every duplicate attempt is still answered with the generic outcome - being bounded never"
                + " turns into an existence disclosure");
        Harness.note("duplicates answered before the budget was spent: " + answered + ", then throttled: "
            + throttled);
        // Bounded, never permanent: after the window the caller can register a fresh account again, so
        // charging a duplicate cannot lock out a legitimate user whose mailbox merely happened to be taken.
        fixture.clock().advanceSeconds(Throttle.SOURCE_WINDOW_SECONDS + 1L);
        Harness.check(outcome(fixture, "recovered@corp.example", "recovered-user", Harness.PW_ONE, "src-b")
                .status() == AccountStore.RegisterStatus.CREATED,
            "after the window the source can register again - the charge is a temporary rate limit, not"
                + " a permanent denial");
        fixture.close();
    }

    private static void registerBudget(Harness.Fixture fixture) throws Exception {
        Harness.section("registration is rate limited per source, and recovers");
        int accepted = 0;
        int throttled = 0;
        for (int attempt = 0; attempt < Throttle.SOURCE_MAX_ATTEMPTS + 4; attempt++) {
            AccountStore.RegisterStatus status = outcome(fixture, "user" + attempt + "@corp.example",
                "bulk-user-" + attempt, Harness.PW_ONE, "src-c").status();
            if (status == AccountStore.RegisterStatus.CREATED) {
                accepted++;
            } else if (status == AccountStore.RegisterStatus.THROTTLED) {
                throttled++;
            }
        }
        Harness.equal(accepted, Throttle.SOURCE_MAX_ATTEMPTS,
            "exactly the source budget is honoured before refusal");
        Harness.atLeast(throttled, 1L, "the spent source budget refuses further registration");
        Harness.check(fixture.accounts().findByUsername("bulk-user-" + (Throttle.SOURCE_MAX_ATTEMPTS + 1)) == null,
            "a throttled registration created no account");
        Harness.equal(outcome(fixture, "other@corp.example", "different-name", Harness.PW_ONE, "src-d").status(),
            AccountStore.RegisterStatus.CREATED, "a different source is unaffected - the budget is per source");

        fixture.clock().advanceSeconds(Throttle.SOURCE_WINDOW_SECONDS);
        Harness.equal(outcome(fixture, "later@corp.example", "later-user", Harness.PW_ONE, "src-c").status(),
            AccountStore.RegisterStatus.CREATED, "the window refills and the same source is served again");
        fixture.close();
    }

    /**
     * The schema mirrors the Java policy in SQL. These fixtures are written straight through
     * JDBC, so they prove the constraint itself holds even if a future code path forgets to
     * validate - the "never let a validated-elsewhere value decide a security outcome" rule.
     */
    private static void schemaRefusesRawWrites(Harness.Fixture fixture) throws Exception {
        Harness.section("the schema refuses bad rows even when application code is bypassed");
        String goodHash = fixture.hasher().encode(Harness.chars(Harness.PW_ONE));
        Harness.equal(goodHash.length(), 97, "the schema fixture is a canonical credential");

        refusedAccount("email with a trailing newline", EMAIL + "\n", NAME, goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("uppercase email", "Dana@Corp.Example", NAME, goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("email above the column width", "a".repeat(250) + "@corp.example", "wide-user", goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("double dot in the email", "da..na@corp.example", "dot-user", goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("domain without a dot", "dana@corpexample", "flat-user", goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("username with markup", "other@corp.example", "<pool>", goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("uppercase username", "other@corp.example", "Pool-User", goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("username ending in a hyphen", "other@corp.example", "pool-", goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("username with a trailing newline", "other@corp.example", "pool-user\n", goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("username below three characters", "other@corp.example", "po", goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("credential truncated by one character", "other@corp.example", "short-hash",
            goodHash.substring(0, 96), Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("credential with a trailing newline", "other@corp.example", "newline-hash",
            goodHash + "\n", Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("credential that is not Argon2id", "other@corp.example", "bcrypt-hash",
            "$2a$10$" + "A".repeat(53), Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS,
            Harness.TEST_PARALLELISM);
        refusedAccount("credential that is a bare SHA-256", "other@corp.example", "sha-hash",
            Digests.sha256Hex(Harness.PW_ONE.getBytes(StandardCharsets.UTF_8)), Harness.TEST_MEMORY_KIB,
            Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        // The two rows below are syntactically valid Argon2id strings whose parameters sit below
        // the approved floor. They are written out rather than derived, because PasswordHasher
        // itself refuses to construct a sub-floor hasher - the schema must not be the only layer
        // that catches such a row arriving by another route (a restore, a hand edit, a migration).
        refusedAccount("a KDF below the approved memory floor", "other@corp.example", "weak-mem",
            argon2WithParams("m=16384,t=2,p=1"), 16_384, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);
        refusedAccount("a KDF below the approved iteration floor", "other@corp.example", "weak-t",
            argon2WithParams("m=19456,t=1,p=1"), Harness.TEST_MEMORY_KIB, 1, Harness.TEST_PARALLELISM);
        refusedAccount("a KDF above the approved memory ceiling", "other@corp.example", "huge-mem",
            argon2WithParams("m=2097152,t=2,p=1"), 2_097_152, Harness.TEST_ITERATIONS,
            Harness.TEST_PARALLELISM);
        refusedAccount("a KDF naming something else", "other@corp.example", "weak-kdf", goodHash,
            Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM, "scrypt");
        refusedAccount("cost columns that disagree with the credential", "other@corp.example", "drift-user",
            goodHash, Harness.TEST_MEMORY_KIB * 2, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM);

        Harness.section("the sessions table accepts only well-formed, consistent rows");
        String goodTokenHash = Digests.sha256Hex(
            "a".repeat(SessionStore.TOKEN_CHARS).getBytes(StandardCharsets.US_ASCII));
        // Every session fixture registers its own account first, so a refusal can only be about
        // the stated defect and never about a parent row that happens to be absent.
        refusedTokenShape("token hash that is not hexadecimal", "Z".repeat(64));
        refusedTokenShape("uppercase token hash", goodTokenHash.toUpperCase());
        refusedTokenShape("token hash with one non-hex character at the end",
            goodTokenHash.substring(0, 63) + "g");
        refusedTokenShape("token hash shorter than the column", goodTokenHash.substring(0, 63));
        refusedExpiry("expiry before issue", Harness.BASE_EPOCH + 5, Harness.BASE_EPOCH);
        refusedExpiry("expiry equal to issue", Harness.BASE_EPOCH, Harness.BASE_EPOCH);
        refusedMissingAccount("session pointing at an account that does not exist");
        Harness.check(acceptSession(goodTokenHash), "a well-formed session row is accepted");
        fixture.close();
    }

    /**
     * Scans the bytes the program actually leaves on disk. The store must hold only the Argon2id
     * credential, and the trail must hold only code-supplied constants and salted digests - a
     * reader of either file must not be able to sign in.
     */
    private static void secretsNeverOnDiskOrInTrail(Harness.Fixture fixture) throws Exception {
        Harness.section("the store file and the audit trail never carry a credential");
        Harness.equal(Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-e"),
            AccountStore.RegisterStatus.CREATED, "the disk fixture registers an account");
        AuthService.Result signedIn = Harness.login(fixture, EMAIL, Harness.PW_ONE);
        Harness.check(signedIn.authenticated(), "the disk fixture signs in, so a session token exists");
        String token = signedIn.session().token();
        Harness.requireNotEmpty(token, "the issued session token");
        fixture.close();

        Path store = fixture.dataDir().resolve("accounts.mv.db");
        Harness.check(Files.exists(store), "the store file exists to be inspected");
        byte[] bytes = Files.readAllBytes(store);
        Harness.atLeast(bytes.length, 1L, "the store file has content to scan");

        List<String> needles = List.of(
            Harness.PW_ONE,
            Harness.PW_ONE.substring(0, 6),
            Digests.sha256Hex(Harness.PW_ONE.getBytes(StandardCharsets.UTF_8)));
        for (int n = 0; n < needles.size(); n++) {
            Harness.check(!contains(bytes, needles.get(n).getBytes(StandardCharsets.UTF_8)),
                "the store holds no UTF-8 copy of needle " + (n + 1) + " ("
                    + needles.get(n).length() + " chars)");
            Harness.check(!contains(bytes, needles.get(n).getBytes(StandardCharsets.UTF_16BE)),
                "the store holds no UTF-16BE copy of needle " + (n + 1));
            Harness.check(!contains(bytes, needles.get(n).getBytes(StandardCharsets.UTF_16LE)),
                "the store holds no UTF-16LE copy of needle " + (n + 1));
        }
        Harness.check(!contains(bytes, token.getBytes(StandardCharsets.US_ASCII)),
            "the store holds no copy of the bearer token it issued");

        // Anti-vacuity: the scan above must be able to find something. The Argon2 salt field is
        // stored verbatim, so if it is absent the scan was looking at the wrong file.
        AccountStore.Account row;
        Harness.Fixture reopened = Harness.fixture(fixture.dataDir(), new Harness.MutableClock(Harness.BASE_EPOCH));
        try {
            row = reopened.accounts().findByEmail(EMAIL);
        } finally {
            reopened.close();
        }
        Harness.check(row != null, "the store reopens and the row is still readable");
        String saltField = row.passwordHash().split("\\$")[4];
        Harness.check(contains(bytes, saltField.getBytes(StandardCharsets.US_ASCII)),
            "the scan can find the stored credential, so the absence results above are meaningful");
        Harness.note("scanned " + bytes.length + " store bytes for " + (needles.size() * 3 + 1)
            + " secret encodings");

        Path audit = fixture.dataDir().resolve("audit.log");
        Harness.check(Files.exists(audit), "the audit trail was written during registration and sign-in");
        List<String> lines = Harness.auditLines(fixture);
        Harness.requireNotEmpty(lines, "audit records");
        String trail = String.join("\n", lines);
        Harness.atLeast(lines.size(), 3L, "registration and sign-in each produced a record");
        Harness.check(!trail.contains(Harness.PW_ONE), "the trail never contains the password");
        Harness.check(!trail.contains(token), "the trail never contains the bearer token");
        Harness.check(!trail.contains(EMAIL), "the trail never contains the email address");
        Harness.check(!trail.contains(NAME), "the trail never contains the username");
        Harness.check(!trail.contains(saltField), "the trail never copies the stored credential");
        for (String line : lines) {
            Harness.check(line.startsWith("{") && line.endsWith("}"),
                "every trail record is one JSON object");
            Harness.check(!line.contains("\n\""), "no trail record embeds a newline inside a value");
        }
        Harness.note("trail holds " + lines.size() + " records, all JSON, none carrying a secret");

        Harness.section("the secret-bearing files are private to the owner");
        Harness.equal(Harness.permissionString(store), "rw-------", "the account store is 0600");
        Harness.equal(Harness.permissionString(fixture.dataDir()), "rwx------", "the data directory is 0700");
        Harness.equal(Harness.permissionString(audit), "rw-------", "the audit trail is 0600");
    }

    private static void upgradeIsGuarded(Harness.Fixture fixture) throws Exception {
        Harness.section("re-hashing is guarded against a concurrent change");
        AccountStore.RegisterStatus created = Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-f");
        Harness.equal(created, AccountStore.RegisterStatus.CREATED, "the upgrade fixture registers an account");
        AccountStore.Account row = fixture.accounts().findByUsername(NAME);
        long staleExpected = row.passwordUpdatedAt();
        char[] password = Harness.chars(Harness.PW_ONE);
        try {
            // The clock must move first: with a frozen clock the upgrade re-writes the very same
            // timestamp, and the "stale" second call would then match for an unrelated reason and
            // look like a passing guard.
            fixture.clock().advanceSeconds(60);
            Harness.check(fixture.accounts().upgradePasswordHash(row.id(), password, staleExpected),
                "an upgrade with the expected timestamp is applied");
            Harness.check(!fixture.accounts().upgradePasswordHash(row.id(), password, staleExpected),
                "a stale expected timestamp loses to the current row instead of clobbering it");
            AccountStore.Account after = fixture.accounts().findByUsername(NAME);
            Harness.check(fixture.hasher().verify(Harness.chars(Harness.PW_ONE), after.passwordHash()),
                "the credential still verifies after the upgrade");
            Harness.equal(after.passwordUpdatedAt(), staleExpected + 60,
                "the credential timestamp moved forward exactly once");
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
        fixture.close();
    }

    // ------------------------------------------------------------------ JDBC helpers

    private static AccountStore.RegisterOutcome outcome(Harness.Fixture fixture, String email, String username,
        String password, String sourceId) throws SQLException, AuditLog.AuditException,
        InputPolicy.ValidationException {
        String canonicalEmail = InputPolicy.email(Harness.chars(email));
        String canonicalUsername = InputPolicy.username(Harness.chars(username));
        char[] buffer = Harness.chars(password);
        try {
            return fixture.accounts().register(buffer, canonicalEmail, canonicalUsername, sourceId);
        } finally {
            java.util.Arrays.fill(buffer, '\0');
        }
    }

    /** Constraint violations arrive as SQLException; the audit guard arrives as something else. */
    private static String state(Throwable failure) {
        return failure instanceof SQLException sql ? sql.getSQLState() : failure.getClass().getSimpleName();
    }

    /**
     * A syntactically canonical Argon2id string carrying the given parameter field. The digest is
     * filler - these fixtures exist to exercise the schema's parameter bounds, not verification.
     */
    private static String argon2WithParams(String parameters) {
        return "$argon2id$v=19$" + parameters + "$AAAAAAAAAAAAAAAAAAAAAA$" + "A".repeat(43);
    }

    private static void refusedAccount(String what, String email, String username, String hash,
        int memoryKib, int iterations, int parallelism) {
        refusedAccount(what, email, username, hash, memoryKib, iterations, parallelism, "argon2id");
    }

    private static void refusedAccount(String what, String email, String username, String hash,
        int memoryKib, int iterations, int parallelism, String kdf) {
        Harness.Fixture fixture = Harness.freshFixture("schema-" + Math.abs(what.hashCode()));
        try {
            fixture.db().inTransaction(connection -> {
                try (PreparedStatement insert = connection.prepareStatement("""
                    INSERT INTO accounts (email, username, password_hash, kdf, kdf_memory_kib,
                                          kdf_iterations, kdf_parallelism, created_at, password_updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """)) {
                    insert.setString(1, email);
                    insert.setString(2, username);
                    insert.setString(3, hash);
                    insert.setString(4, kdf);
                    insert.setInt(5, memoryKib);
                    insert.setInt(6, iterations);
                    insert.setInt(7, parallelism);
                    insert.setLong(8, Harness.BASE_EPOCH);
                    insert.setLong(9, Harness.BASE_EPOCH);
                    insert.executeUpdate();
                }
                return Boolean.TRUE;
            });
            Harness.check(false, "schema refused: " + what + " - the row was accepted");
        } catch (SQLException | AuditLog.AuditException rejected) {
            Harness.check(true, "schema refused: " + what + " [" + state(rejected) + "]");
        } finally {
            fixture.close();
        }
    }

    private static void refusedSessionRow(String what, String tokenHash, long issuedAt, long expiresAt,
        boolean withAccount) throws Exception {
        Harness.Fixture fixture = Harness.freshFixture("schema-sess-" + Math.abs(what.hashCode()));
        try {
            long accountId = 999_999L;
            if (withAccount) {
                Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-schema");
                accountId = fixture.accounts().findByUsername(NAME).id();
            }
            final long subject = accountId;
            fixture.db().inTransaction(connection -> {
                try (PreparedStatement insert = connection.prepareStatement(
                    "INSERT INTO sessions (token_hash, account_id, issued_at, expires_at) VALUES (?, ?, ?, ?)")) {
                    insert.setString(1, tokenHash);
                    insert.setLong(2, subject);
                    insert.setLong(3, issuedAt);
                    insert.setLong(4, expiresAt);
                    insert.executeUpdate();
                }
                return Boolean.TRUE;
            });
            Harness.check(false, "schema refused: " + what + " - the row was accepted");
        } catch (SQLException | AuditLog.AuditException rejected) {
            Harness.check(true, "schema refused: " + what + " [" + state(rejected) + "]");
        } finally {
            fixture.close();
        }
    }

    private static void refusedTokenShape(String what, String tokenHash) throws Exception {
        refusedSessionRow(what, tokenHash, Harness.BASE_EPOCH, Harness.BASE_EPOCH + 3600, true);
    }

    private static void refusedExpiry(String what, long issuedAt, long expiresAt) throws Exception {
        refusedSessionRow(what, Digests.sha256Hex(
            "a".repeat(64).getBytes(StandardCharsets.US_ASCII)), issuedAt, expiresAt, true);
    }

    private static void refusedMissingAccount(String what) throws Exception {
        refusedSessionRow(what, Digests.sha256Hex(
            "a".repeat(64).getBytes(StandardCharsets.US_ASCII)), Harness.BASE_EPOCH,
            Harness.BASE_EPOCH + 3600, false);
    }

    /** The positive control: a well-formed session row must be accepted, or the refusals prove nothing. */
    private static boolean acceptSession(String tokenHash) throws InputPolicy.ValidationException {
        Harness.Fixture fixture = Harness.freshFixture("schema-sess-ok");
        try {
            Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-ok");
            return fixture.db().inTransaction(connection -> {
                AccountStore.Account row = fixture.accounts().findByUsername(NAME);
                try (PreparedStatement insert = connection.prepareStatement(
                    "INSERT INTO sessions (token_hash, account_id, issued_at, expires_at) VALUES (?, ?, ?, ?)")) {
                    insert.setString(1, tokenHash);
                    insert.setLong(2, row.id());
                    insert.setLong(3, Harness.BASE_EPOCH);
                    insert.setLong(4, Harness.BASE_EPOCH + 3600);
                    return insert.executeUpdate() == 1;
                }
            });
        } catch (SQLException | AuditLog.AuditException rejected) {
            Harness.check(false, "a well-formed session row was refused: " + rejected.getMessage());
            return false;
        } finally {
            fixture.close();
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || needle.length > haystack.length) {
            return false;
        }
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
}
