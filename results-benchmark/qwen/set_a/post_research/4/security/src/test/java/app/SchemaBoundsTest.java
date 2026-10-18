package app;

import java.nio.file.Path;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

/**
 * The storage limit and the key-derivation policy are one fact, and this suite is what proves it.
 *
 * <p>The defect that motivated it: the credential column was {@code VARCHAR(97)}, which is the
 * exact length of a hash made with the shipped parameters, while the configuration accepted memory
 * values whose string is 100 characters long. A legal configuration therefore produced a credential
 * the schema refused - registration failed at the database, on the operator's strongest setting.
 * Nothing in the unit suites noticed because they all hashed at the floor cost.
 *
 * <p>So the checks here are about the boundary: the longest string the accepted parameter range can
 * produce must be storable, the column width must be that length rather than a number someone
 * remembered, and the cost bounds written into the DDL must be the same numbers the hasher enforces.
 * The last section shrinks the column on a throwaway store to show the width really binds - a
 * column width assertion would be vacuous if H2 ignored it.
 */
public final class SchemaBoundsTest {

    private static final String EMAIL = "kdf-max@corp.example";
    private static final String NAME = "kdf-max-user";
    private static final String PASSWORD = "Violet-Harbor-42";

    /** A canonical salt field: 22 base64 characters decode to 16 bytes with no leftover bits. */
    private static final String SALT_FIELD = "A".repeat(22);
    /** Likewise 43 characters decode to exactly 32 bytes, and re-encode identically. */
    private static final String HASH_FIELD = "A".repeat(43);

    public static void main(String[] argv) throws Exception {
        costPolicyIsOneFactNotThree();
        widestCredentialStringIsStorable(Harness.freshFixture("bounds-shape"));
        narrowestColumnReproducesTheDefect(Harness.freshFixture("bounds-narrow"));
        strongestConfiguredCostRegisters(Harness.freshFixture("bounds-real"));

        System.exit(Harness.report("SchemaBoundsTest"));
    }

    private static void costPolicyIsOneFactNotThree() {
        Harness.section("the accepted cost range is stated once and the schema quotes it");
        String ddl = Db.ACCOUNTS_DDL;
        Harness.check(ddl.contains("VARCHAR(" + PasswordHasher.MAX_STORED_HASH_CHARS + ")"),
            "the credential column is sized from the hasher's own maximum, not a hand-typed number");
        Harness.check(!ddl.contains("VARCHAR(97)"),
            "the width that fitted only the default parameters is gone");
        Harness.check(ddl.contains("kdf_memory_kib BETWEEN "
                + PasswordHasher.STORED_MIN_MEMORY_KIB + " AND " + PasswordHasher.STORED_MAX_MEMORY_KIB),
            "the memory CHECK quotes PasswordHasher's bounds");
        Harness.check(ddl.contains("kdf_iterations BETWEEN "
                + PasswordHasher.STORED_MIN_ITERATIONS + " AND " + PasswordHasher.STORED_MAX_ITERATIONS),
            "the iteration CHECK quotes them too");
        Harness.check(ddl.contains("kdf_parallelism BETWEEN "
                + PasswordHasher.STORED_MIN_PARALLELISM + " AND " + PasswordHasher.STORED_MAX_PARALLELISM),
            "and so does the parallelism CHECK");
        String widestSpelledOut = "$argon2id$v=19$m=" + PasswordHasher.STORED_MAX_MEMORY_KIB + ",t="
            + PasswordHasher.STORED_MAX_ITERATIONS + ",p=" + PasswordHasher.STORED_MAX_PARALLELISM
            + "$" + SALT_FIELD + "$" + HASH_FIELD;
        Harness.equal((long) widestSpelledOut.length(), (long) PasswordHasher.MAX_STORED_HASH_CHARS,
            "the derived width is the width of the widest parameter set, spelled out");

        // Configuration must not accept anything the storage would later refuse.
        Harness.check(acceptsMemory(PasswordHasher.STORED_MAX_MEMORY_KIB),
            "the widest memory the hasher accepts is also a valid configuration");
        Harness.check(!acceptsMemory(PasswordHasher.STORED_MAX_MEMORY_KIB + 1),
            "one KiB above that is refused by configuration rather than by the schema on first use");
        Harness.check(!acceptsMemory(4_194_304),
            "the 4 GiB setting the old configuration accepted is now refused - it could not be stored");
        Harness.check(!acceptsMemory(PasswordHasher.STORED_MIN_MEMORY_KIB - 1),
            "and one KiB below the Argon2id floor still is");
        Harness.note("the credential column is " + PasswordHasher.MAX_STORED_HASH_CHARS
            + " characters, the exact width of m=" + PasswordHasher.STORED_MAX_MEMORY_KIB
            + ",t=" + PasswordHasher.STORED_MAX_ITERATIONS + ",p=" + PasswordHasher.STORED_MAX_PARALLELISM);
    }

    private static void widestCredentialStringIsStorable(Harness.Fixture fixture) throws Exception {
        Harness.section("the longest credential the policy can emit is stored, not truncated");
        String widest = widestCredential();
        Harness.equal((long) widest.length(), (long) PasswordHasher.MAX_STORED_HASH_CHARS,
            "the fabricated credential really is the maximum length");

        storeRaw(fixture, widest, PasswordHasher.STORED_MAX_MEMORY_KIB,
            PasswordHasher.STORED_MAX_ITERATIONS, PasswordHasher.STORED_MAX_PARALLELISM);
        String readBack = readBack(fixture, EMAIL);
        Harness.equal(readBack, widest,
            "the value came back byte for byte - the column took it without truncation");

        int declaredWidth = declaredWidth(fixture);
        Harness.equal((long) declaredWidth, (long) PasswordHasher.MAX_STORED_HASH_CHARS,
            "H2 reports the column width the DDL asked for");
        Harness.atLeast(declaredWidth, 100L,
            "the width is at least the widest derivable string, so no legal cost can overflow it");
        fixture.close();
    }

    /**
     * Shrinks the column on a throwaway store and shows the same 100-character credential is then
     * rejected. Without this, "the column is wide enough" could be green for a column that quietly
     * accepts anything, and it recreates the original failure so the fix is tested against a real
     * boundary rather than a number.
     */
    private static void narrowestColumnReproducesTheDefect(Harness.Fixture fixture) throws Exception {
        Harness.section("the width is a real bound: shrinking it brings the original failure back");
        try (Statement alter = fixture.db().connection().createStatement()) {
            alter.execute("ALTER TABLE accounts ALTER COLUMN password_hash VARCHAR(97)");
            fixture.db().connection().commit();
        }
        Harness.equal(97L, (long) declaredWidth(fixture), "the column was narrowed for the experiment");

        boolean refused = false;
        String reason = "";
        try {
            storeRaw(fixture, widestCredential(), PasswordHasher.STORED_MAX_MEMORY_KIB,
                PasswordHasher.STORED_MAX_ITERATIONS, PasswordHasher.STORED_MAX_PARALLELISM);
        } catch (SQLException tooLong) {
            refused = true;
            reason = tooLong.getSQLState();
        }
        Harness.check(refused,
            "a 97-character column really does refuse the widest legal credential (SQLState " + reason + ")"
                + " - this is the defect the derived width removes");

        try (Statement alter = fixture.db().connection().createStatement()) {
            alter.execute("ALTER TABLE accounts ALTER COLUMN password_hash VARCHAR("
                + PasswordHasher.MAX_STORED_HASH_CHARS + ")");
            fixture.db().connection().commit();
        }
        storeRaw(fixture, widestCredential(), PasswordHasher.STORED_MAX_MEMORY_KIB,
            PasswordHasher.STORED_MAX_ITERATIONS, PasswordHasher.STORED_MAX_PARALLELISM);
        Harness.equal(readBack(fixture, EMAIL), widestCredential(),
            "restoring the derived width lets the same row in - the fix, isolated to the width");
        fixture.close();
    }

    /**
     * One real derivation at the maximum accepted memory, written and read back through the
     * production code path. Deliberately one: this costs seconds and a gigabyte of heap, and the
     * sections above already pin the exact maximum string, so the marginal value here is proving the
     * whole register path with a seven-digit cost embedded in the credential.
     */
    private static void strongestConfiguredCostRegisters(Harness.Fixture fixture) throws Exception {
        Harness.section("a sign-up hashed at the strongest accepted cost is stored and readable");
        PasswordHasher strongest = new PasswordHasher(PasswordHasher.STORED_MAX_MEMORY_KIB,
            PasswordHasher.STORED_MIN_ITERATIONS, PasswordHasher.STORED_MIN_PARALLELISM);
        AccountStore upgraded = new AccountStore(fixture.db(), strongest, fixture.throttle(),
            fixture.gate(), fixture.clock());
        long started = System.nanoTime();
        AccountStore.RegisterStatus status = createWith(upgraded, fixture);
        Harness.note("a registration at m=" + PasswordHasher.STORED_MAX_MEMORY_KIB + "KiB,t="
            + PasswordHasher.STORED_MIN_ITERATIONS + " took "
            + ((System.nanoTime() - started) / 1_000_000L) + " ms");
        Harness.equal(AccountStore.RegisterStatus.CREATED, status,
            "the strongest configured cost registers successfully");

        String stored = readBack(fixture, EMAIL);
        Harness.atLeast(stored.length(), 99L,
            "the stored credential is longer than the 97 characters the schema used to allow");
        Harness.atMost(stored.length(), (long) PasswordHasher.MAX_STORED_HASH_CHARS,
            "and within the width the column was sized to (" + stored.length() + " of "
                + PasswordHasher.MAX_STORED_HASH_CHARS + ")");
        Harness.check(strongest.costOf(stored).memoryKib() == PasswordHasher.STORED_MAX_MEMORY_KIB,
            "the stored string really carries the maximum memory cost");
        Harness.check(strongest.verify(Harness.chars(PASSWORD), stored),
            "the credential verifies against the password it was created with, byte for byte through"
                + " the column");
        Harness.check(!strongest.verify(Harness.chars(Harness.PW_WRONG), stored),
            "and a wrong password is refused rather than passing on an odd length");

        // The upgrade decision must agree with the stored cost: a credential already at policy is
        // never re-derived, and the same row looks weak next to a stronger policy.
        Harness.check(!strongest.weakerThanPolicy(stored),
            "a credential at the current policy is not flagged for upgrade");
        Harness.check(Harness.hasher().weakerThanPolicy(stored) == false,
            "measured against the fixture's floor policy, this stored cost is not weaker");
        Harness.check(strongerPolicyThan(stored),
            "measured against a policy one step stronger, it is flagged - the upgrade path still works");
        Harness.equal(1L, rows(fixture, "SELECT COUNT(*) FROM accounts"),
            "exactly one account exists - the run did not half-write anything");
        fixture.close();
    }

    private static boolean strongerPolicyThan(String stored) throws java.security.GeneralSecurityException {
        PasswordHasher stronger = new PasswordHasher(PasswordHasher.STORED_MAX_MEMORY_KIB,
            PasswordHasher.STORED_MIN_ITERATIONS + 1, PasswordHasher.STORED_MIN_PARALLELISM);
        return stronger.weakerThanPolicy(stored);
    }

    // ------------------------------------------------------------------ helpers

    private static AccountStore.RegisterStatus createWith(AccountStore store, Harness.Fixture fixture)
        throws SQLException, AuditLog.AuditException, InputPolicy.ValidationException {
        String email = InputPolicy.email(Harness.chars(EMAIL));
        String username = InputPolicy.username(Harness.chars(NAME));
        char[] password = Harness.chars(PASSWORD);
        try {
            return store.register(password, email, username, "src-max").status();
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static String widestCredential() {
        return "$argon2id$v=19$m=" + PasswordHasher.STORED_MAX_MEMORY_KIB + ",t="
            + PasswordHasher.STORED_MAX_ITERATIONS + ",p=" + PasswordHasher.STORED_MAX_PARALLELISM
            + "$" + SALT_FIELD + "$" + HASH_FIELD;
    }

    private static void storeRaw(Harness.Fixture fixture, String credential, int memory, int iterations,
        int parallelism) throws SQLException {
        String sql = "INSERT INTO accounts (email, username, password_hash, kdf, kdf_memory_kib,"
            + " kdf_iterations, kdf_parallelism, created_at, password_updated_at)"
            + " VALUES (?, ?, ?, 'argon2id', ?, ?, ?, ?, ?)";
        try (PreparedStatement insert = fixture.db().connection().prepareStatement(sql)) {
            insert.setString(1, EMAIL);
            insert.setString(2, NAME);
            insert.setString(3, credential);
            insert.setInt(4, memory);
            insert.setInt(5, iterations);
            insert.setInt(6, parallelism);
            insert.setLong(7, fixture.clock().instant().getEpochSecond());
            insert.setLong(8, fixture.clock().instant().getEpochSecond());
            insert.executeUpdate();
            fixture.db().connection().commit();
        } catch (SQLException rejected) {
            fixture.db().connection().rollback();
            throw rejected;
        }
    }

    private static String readBack(Harness.Fixture fixture, String address) throws SQLException {
        String sql = "SELECT password_hash FROM accounts WHERE email = ?";
        try (PreparedStatement read = fixture.db().connection().prepareStatement(sql)) {
            read.setString(1, address);
            try (ResultSet found = read.executeQuery()) {
                if (!found.next()) {
                    throw new IllegalStateException("the credential under test is not in the store");
                }
                String value = found.getString(1);
                fixture.db().connection().commit();
                return value;
            }
        } catch (SQLException failed) {
            fixture.db().connection().rollback();
            throw failed;
        }
    }

    private static int declaredWidth(Harness.Fixture fixture) throws SQLException {
        String sql = "SELECT CHARACTER_MAXIMUM_LENGTH FROM INFORMATION_SCHEMA.COLUMNS"
            + " WHERE TABLE_NAME = 'ACCOUNTS' AND COLUMN_NAME = 'PASSWORD_HASH'";
        try (Statement read = fixture.db().connection().createStatement();
             ResultSet found = read.executeQuery(sql)) {
            if (!found.next()) {
                throw new IllegalStateException("the credential column is not in the schema");
            }
            int width = found.getInt(1);
            fixture.db().connection().commit();
            return width;
        } catch (SQLException failed) {
            fixture.db().connection().rollback();
            throw failed;
        }
    }

    private static long rows(Harness.Fixture fixture, String sql) throws SQLException {
        try (Statement read = fixture.db().connection().createStatement();
             ResultSet found = read.executeQuery(sql)) {
            found.next();
            long count = found.getLong(1);
            fixture.db().connection().commit();
            return count;
        } catch (SQLException failed) {
            fixture.db().connection().rollback();
            throw failed;
        }
    }

    private static boolean acceptsMemory(int memoryKib) {
        Map<String, String> values = new HashMap<>();
        values.put(Config.ENV_DB_PASSWORD, Harness.DB_PASSWORD);
        values.put(Config.ENV_ARGON2_MEMORY, Integer.toString(memoryKib));
        try {
            // The option is one argument in the shipped form; passing "--data-dir" and the path as
            // two would be refused as a malformed option and read as a refused cost.
            Config.fromEnvironment(values::get,
                new String[] {"--data-dir=" + Harness.scratch("bounds-config-" + memoryKib)});
            return true;
        } catch (Config.ConfigException refused) {
            return false;
        }
    }
}
