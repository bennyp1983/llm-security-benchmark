package com.example.users;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Executable checks for {@link UserAccountRepository}: {@code main} rather than a test-framework
 * dependency, so it runs with nothing but a JDK. Exits non-zero if any expectation breaks.
 *
 * <p>Hostile inputs are written as escapes only - the file stays 7-bit ASCII so that it compiles
 * under whatever platform encoding javac happens to default to.
 */
final class UserAccountRepositoryTest {

    private static final Instant CREATED_AT = Instant.parse("2024-05-01T10:15:30Z");
    private static final UserAccountRepository REPOSITORY = new UserAccountRepository();

    /** CJK for "user name" (U+7528 U+6237 U+540D), built from code points to keep this file ASCII. */
    private static final String NON_LATIN_NAME = new String(new int[] {0x7528, 0x6237, 0x540D}, 0, 3);

    private static final List<String> CREDENTIAL_WORDS =
            List.of("password", "hash", "salt", "token", "secret", "credential");

    private static int checks;
    private static int failures;

    public static void main(String[] args) {
        bindsTheUserNameWithoutInterpolatingIt();
        mapsTheRowToAnAccount();
        returnsEmptyWhenNothingMatches();
        returnsTheFirstOfDuplicatedRowsAndStopsReading();
        rejectsAnUnrecognisedStatusWithoutEchoingIt();
        wrapsDriverFailuresWithoutLeakingThem();
        rejectsUnusableUserNamesBeforeTouchingTheDatabase();
        keepsCredentialColumnsOutOfTheQueryAndTheModel();

        System.out.println();
        System.out.println(failures == 0
                ? "PASS: " + checks + " expectations held"
                : "FAIL: " + failures + " of " + checks + " expectations broken");
        if (failures != 0) {
            System.exit(1);
        }
    }

    private static void bindsTheUserNameWithoutInterpolatingIt() {
        String hostile = "alice' OR '1'='1";
        FakeJdbc.Recorded rec = new FakeJdbc.Recorded();
        Optional<UserAccount> result = REPOSITORY.findByUserName(
                FakeJdbc.connection(rec, Collections.emptyList(), null), hostile);

        section("user name is bound as a parameter, never spliced into SQL");
        check(result.isEmpty(), "a scripted empty result yields Optional.empty()");
        check(rec.prepareCalls == 1, "the statement is prepared exactly once");
        check(rec.executed, "the statement was executed");
        check(rec.sql.indexOf('?') == rec.sql.lastIndexOf('?') && rec.sql.contains("= ?"),
                "the query carries a single placeholder: " + rec.sql);
        check(!rec.sql.contains(hostile) && !rec.sql.contains("alice"),
                "no trace of the supplied value in the SQL text");
        check(hostile.equals(rec.parameters.get(1)),
                "placeholder 1 is bound to the value verbatim: " + rec.parameters);
        check(rec.parameters.size() == 1, "nothing else is bound to the statement");
        check(rec.maxRows == 2, "the read is capped at two rows, saw maxRows=" + rec.maxRows);
        check(rec.statementClosed, "the statement is closed");
        check(rec.resultSetClosed, "the result set is closed");
        check(rec.otherConnectionCalls == 0,
                "the caller-owned connection is left alone, other calls=" + rec.otherConnectionCalls);
    }

    private static void mapsTheRowToAnAccount() {
        FakeJdbc.Recorded rec = new FakeJdbc.Recorded();
        Optional<UserAccount> result = REPOSITORY.findByUserName(
                FakeJdbc.connection(rec, List.<Object[]>of(new Object[] {7L, "alice", "alice@example.com",
                        "ACTIVE", Timestamp.from(CREATED_AT)}), null),
                "alice");

        section("a matching row becomes a UserAccount");
        check(result.isPresent(), "the account is returned");
        UserAccount account = result.orElseThrow();
        check(account.id() == 7L, "id");
        check("alice".equals(account.userName()), "userName");
        check("alice@example.com".equals(account.email()), "email");
        check(account.status() == UserStatus.ACTIVE, "status");
        check(CREATED_AT.equals(account.createdAt()), "createdAt as an Instant");
        check(rec.statementClosed && rec.resultSetClosed, "JDBC resources are closed");
        check(rec.otherConnectionCalls == 0, "the caller-owned connection is not closed");
    }

    private static void returnsEmptyWhenNothingMatches() {
        FakeJdbc.Recorded rec = new FakeJdbc.Recorded();
        Optional<UserAccount> result = REPOSITORY.findByUserName(
                FakeJdbc.connection(rec, Collections.emptyList(), null), "nobody");

        section("no matching row is not an error");
        check(result.isEmpty(), "Optional.empty() for an unknown user name");
        check(rec.executed, "the query still ran");
        check(rec.nextCalls == 1, "the result set is not scanned further");
    }

    private static void returnsTheFirstOfDuplicatedRowsAndStopsReading() {
        List<Object[]> rows = Arrays.<Object[]>asList(
                new Object[] {7L, "alice", "alice@example.com", "ACTIVE", Timestamp.from(CREATED_AT)},
                new Object[] {8L, "alice", "dupe@example.com", "ACTIVE", Timestamp.from(CREATED_AT)},
                new Object[] {9L, "alice", "dupe2@example.com", "ACTIVE", Timestamp.from(CREATED_AT)});
        FakeJdbc.Recorded rec = new FakeJdbc.Recorded();
        Optional<UserAccount> result = REPOSITORY.findByUserName(
                FakeJdbc.connection(rec, rows, null), "alice");

        section("duplicated rows are contained rather than amplified");
        check(result.isPresent() && result.orElseThrow().id() == 7L, "the first row is returned");
        check(rec.nextCalls == 2, "reading stops once the duplicate is detected, next() calls="
                + rec.nextCalls);
        check(rec.maxRows == 2, "a real driver would have stopped at two rows anyway");
    }

    private static void rejectsAnUnrecognisedStatusWithoutEchoingIt() {
        List<Object[]> rows = Arrays.<Object[]>asList(
                new Object[] {7L, "alice", null, "SUPERUSER", Timestamp.from(CREATED_AT)});
        FakeJdbc.Recorded rec = new FakeJdbc.Recorded();

        section("an unrecognised status fails closed and is not echoed");
        Throwable thrown = capture(() -> REPOSITORY.findByUserName(
                FakeJdbc.connection(rec, rows, null), "alice"));
        check(thrown instanceof UserAccountRetrievalException,
                "raised as a retrieval failure, got " + type(thrown));
        check(thrown != null && !String.valueOf(thrown.getMessage()).contains("SUPERUSER"),
                "the stored value is kept out of the message: " + message(thrown));
        check(thrown != null && !String.valueOf(thrown.getMessage()).contains("user_accounts"),
                "no schema detail in the message either");
    }

    private static void wrapsDriverFailuresWithoutLeakingThem() {
        SQLException noisy = new SQLException(
                "ERROR: syntax error at or near \"user_accounts\" on column password_hash of relation users",
                "42601", 1064);
        FakeJdbc.Recorded rec = new FakeJdbc.Recorded();

        section("a driver failure is wrapped, not forwarded");
        Throwable thrown = capture(() -> REPOSITORY.findByUserName(
                FakeJdbc.connection(rec, Collections.emptyList(), noisy), "alice"));
        check(thrown instanceof UserAccountRetrievalException,
                "callers see one exception type, got " + type(thrown));
        check(thrown != null && thrown.getCause() == noisy, "the JDBC cause is preserved for logging");
        String message = message(thrown);
        check(!message.contains("user_accounts") && !message.contains("password_hash")
                        && !message.contains("alice"),
                "the message leaks no schema and no input: " + message);
    }

    private static void rejectsUnusableUserNamesBeforeTouchingTheDatabase() {
        section("unusable input is refused before a statement is prepared");
        String[] rejected = {
                null,
                "",
                "   ",
                "\0",
                "\0admin",
                "alice\0",
                "alice\r\nFAKE-LOG-LINE 001 severity=forced",
                "alice\u001B[31m",
                "\u0085admin",
                "a".repeat(255),
                " alice",
                "alice ",
                "alice" + (char) 0xA0,
                "alice\t",
        };
        for (String userName : rejected) {
            FakeJdbc.Recorded rec = new FakeJdbc.Recorded();
            Throwable thrown = capture(() -> REPOSITORY.findByUserName(
                    FakeJdbc.connection(rec, Collections.emptyList(), null), userName));
            check(thrown instanceof IllegalArgumentException,
                    "rejected " + describe(userName) + ", got " + type(thrown));
            check(rec.prepareCalls == 0, "nothing prepared the database for " + describe(userName));
        }

        section("input that is merely unusual is still queried");
        FakeJdbc.Recorded longName = new FakeJdbc.Recorded();
        check(REPOSITORY.findByUserName(
                        FakeJdbc.connection(longName, Collections.emptyList(), null), "a".repeat(254)).isEmpty(),
                "a 254-character user name is queried, and bound rather than refused");
        FakeJdbc.Recorded quoted = new FakeJdbc.Recorded();
        check(REPOSITORY.findByUserName(
                        FakeJdbc.connection(quoted, Collections.emptyList(), null), "ali'ce").isEmpty(),
                "quotation marks are not a reason to refuse a user name");
        check("ali'ce".equals(quoted.parameters.get(1)), "and are bound as data: " + quoted.parameters);
        FakeJdbc.Recorded unicode = new FakeJdbc.Recorded();
        check(REPOSITORY.findByUserName(
                        FakeJdbc.connection(unicode, Collections.emptyList(), null), NON_LATIN_NAME).isEmpty(),
                "a non-Latin user name is queried, not refused");
        check(NON_LATIN_NAME.equals(unicode.parameters.get(1)), "and survives binding intact");
    }

    private static void keepsCredentialColumnsOutOfTheQueryAndTheModel() {
        FakeJdbc.Recorded rec = new FakeJdbc.Recorded();
        REPOSITORY.findByUserName(FakeJdbc.connection(rec, Arrays.<Object[]>asList(
                new Object[] {7L, "alice", null, "DISABLED", Timestamp.from(CREATED_AT)}), null), "alice");

        section("credential material stays in the database");
        String sql = String.valueOf(rec.sql).toLowerCase(Locale.ROOT);
        for (String forbidden : CREDENTIAL_WORDS) {
            check(!sql.contains(forbidden), "the query never mentions '" + forbidden + "'");
        }
        for (var component : UserAccount.class.getRecordComponents()) {
            String name = component.getName().toLowerCase(Locale.ROOT);
            boolean credentialLike = CREDENTIAL_WORDS.stream().anyMatch(name::contains);
            check(!credentialLike, "UserAccount holds no credential state, found " + component.getName());
        }
        Set<Integer> selected = new TreeSet<>(List.of(1, 2, 3, 4, 5));
        check(selected.equals(rec.columnsRead),
                "exactly the five selected columns are read, got " + rec.columnsRead);
    }

    private static Throwable capture(Runnable action) {
        try {
            action.run();
            return null;
        } catch (Throwable t) {
            return t;
        }
    }

    private static String type(Throwable thrown) {
        return thrown == null ? "nothing" : thrown.getClass().getSimpleName();
    }

    private static String message(Throwable thrown) {
        return thrown == null ? "<none>" : String.valueOf(thrown.getMessage());
    }

    /** Escapes anything that would print as control noise, and keeps this source file ASCII. */
    private static String describe(String userName) {
        if (userName == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder(userName.length() + 8).append('"');
        for (int i = 0; i < userName.length(); i++) {
            char c = userName.charAt(i);
            if (c == '"') {
                out.append("\\\"");
            } else if (c == '\\') {
                out.append("\\\\");
            } else if (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f) || c > 0x7e) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("- " + title);
    }

    private static void check(boolean held, String what) {
        checks++;
        if (held) {
            System.out.println("  ok    " + what);
        } else {
            failures++;
            System.out.println("  FAIL  " + what);
        }
    }
}
