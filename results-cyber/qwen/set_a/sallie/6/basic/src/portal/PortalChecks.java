package portal;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Base64;
import java.nio.file.attribute.PosixFilePermission;

/**
 * Checks for the portal, run with {@code java -cp out portal.PortalChecks}.
 *
 * <p>Half of the checks drive the classes directly, the other half start the real
 * command line program as a child process with piped input, because a scripted
 * in-memory answer does not reproduce how a terminal consumes lines.
 *
 * <p>Prints one line per check plus a summary, and exits non-zero on any failure.
 */
public final class PortalChecks {

    private static final char TAB = (char) 0x09;
    private static final char NUL = (char) 0x00;
    private static final char NEWLINE = (char) 0x0A;

    /** Passwords used by the command line checks must not contain the username. */
    private static final String CLI_PASS = "Sup3r-Sentinel-77";
    private static final String CLI_CAROL_PASS = "Turbine-Op3rate-55";

    private static int passed;
    private static final List<String> failures = new ArrayList<>();
    private static Path scratch;

    public static void main(String[] args) throws Exception {
        scratch = Files.createTempDirectory("portal-checks-" + ProcessHandle.current().pid());
        Runtime.getRuntime().addShutdownHook(new Thread(PortalChecks::deleteTree));
        try {
            passwordPolicy();
            usernameRules();
            storageRoundTrip();
            authentication();
            lockoutIsPerAccount();
            equalCostBranches();
            auditTrail();
            auditTrailCannotBeForged();
            failClosedWhenUnrecordable();
            sessionLifecycle();
            commandLine();
        } catch (Throwable unexpected) {
            unexpected.printStackTrace(System.out);
            fail("an unexpected error escaped a check: " + unexpected);
        }
        System.out.println();
        System.out.println("SUMMARY passed=" + passed + " failed=" + failures.size()
                + " total=" + (passed + failures.size()));
        for (String failure : failures) {
            System.out.println("FAILED " + failure);
        }
        System.out.println("NOTE scratch=" + scratch);
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    // ---------------------------------------------------------------- policy

    private static void passwordPolicy() {
        ok("a four character password is rejected", rejected("Ab1c", "alice") != null, "short accepted");
        ok("ten characters is accepted", rejected("Abcd-1234!", "alice") == null,
                rejected("Abcd-1234!", "alice"));
        ok("a password containing the username is rejected",
                rejected("Alice-Tester-99", "alice") != null, "username leak accepted");
        ok("a password without a digit is rejected", rejected("abcdefghij!", "alice") != null,
                "letter-only accepted");
        ok("a password without a letter is rejected", rejected("1234567890!", "alice") != null,
                "digit-only accepted");
        ok("a two-character-class password is rejected", rejected("aaaaaaaaa1", "alice") != null,
                "lower-plus-digit accepted");
        ok("a trailing null character is refused", rejected("Abcd-1234!" + NUL, "alice") != null,
                "trailing NUL accepted");
        ok("an embedded null character is refused", rejected("Abcd" + NUL + "-1234!", "alice") != null,
                "embedded NUL accepted");
        ok("an unpaired high surrogate is refused", rejected("Abcd-1234" + (char) 0xD842, "alice") != null,
                "lone high surrogate accepted");
        ok("an unpaired low surrogate is refused", rejected("Abcd-1234" + (char) 0xDE42, "alice") != null,
                "lone low surrogate accepted");
        ok("a paired surrogate is accepted",
                rejected("Abcd-1234!" + (char) 0xD842 + (char) 0xDE42, "alice") == null,
                rejected("Abcd-1234!" + (char) 0xD842 + (char) 0xDE42, "alice"));
        ok("an oversized password is refused",
                rejected("Abcd-1234!" + "x".repeat(PasswordPolicy.MAX_CHARS), "alice") != null,
                "oversized accepted");
        ok("a null password is refused", PasswordPolicy.structural(null) != null, "null accepted");
        ok("an empty password is refused", PasswordPolicy.structural(new char[0]) != null,
                "empty accepted");
        ok("a full password of 1024 characters is accepted",
                rejected("Abcd-1234!" + "y".repeat(PasswordPolicy.MAX_CHARS - 10), "alice") == null,
                rejected("Abcd-1234!" + "y".repeat(PasswordPolicy.MAX_CHARS - 10), "alice"));
    }

    private static String rejected(String password, String username) {
        return PasswordPolicy.check(password.toCharArray(), username);
    }

    // -------------------------------------------------------------- usernames

    private static void usernameRules() {
        ok("names are lower-cased", "alice".equals(Names.normalize("Alice")),
                Names.normalize("Alice"));
        ok("a leading space is refused, not trimmed", throwsIae(() -> Names.normalize(" alice")),
                "space-padded name accepted");
        ok("a trailing tab is refused, not trimmed",
                throwsIae(() -> Names.normalize("alice" + TAB)), "tab-padded name accepted");
        ok("a trailing newline is refused", throwsIae(() -> Names.normalize("alice" + NEWLINE)),
                "newline-padded name accepted");
        ok("a trailing null is refused", throwsIae(() -> Names.normalize("alice" + NUL)),
                "NUL-padded name accepted");
        ok("an embedded tab is refused", throwsIae(() -> Names.normalize("al" + TAB + "ce")),
                "tab inside name accepted");
        ok("an embedded space is refused", throwsIae(() -> Names.normalize("ali ce")),
                "space inside name accepted");
        ok("a two character name is refused", throwsIae(() -> Names.normalize("al")),
                "two character name accepted");
        ok("an over-long name is refused",
                throwsIae(() -> Names.normalize("a".repeat(Names.MAX_LENGTH + 1))),
                "oversized name accepted");
        ok("a slash is refused", throwsIae(() -> Names.normalize("../etc/passwd")),
                "path-like name accepted");
        ok("a doubled dot is refused", throwsIae(() -> Names.normalize("a..b")),
                "double dot accepted");
        ok("a reserved name is refused", throwsIae(() -> Names.normalize("admin-portal")),
                "reserved name accepted");
        ok("an ordinary name is kept", "carol_2".equals(Names.normalize("carol_2")),
                Names.normalize("carol_2"));
    }

    // ---------------------------------------------------------------- storage

    private static void storageRoundTrip() throws Exception {
        Path file = scratch.resolve("store-roundtrip.tsv");
        CredentialStore first = new CredentialStore(file);
        first.put("alice", "Alice-Passw0rd-1".toCharArray(), Roles.SUPERVISOR);
        first.put("bob", "Bob-Passw0rd-22".toCharArray(), Roles.OPERATOR);

        String onDisk = Files.readString(file, StandardCharsets.UTF_8);
        ok("no plaintext password is written",
                !onDisk.contains("Alice-Passw0rd-1") && !onDisk.contains("Bob-Passw0rd-22"),
                "plaintext found in the store");
        ok("each stored row has exactly five fields", onDisk.lines()
                .filter(line -> !line.startsWith("#"))
                .allMatch(line -> line.chars().filter(c -> c == TAB).count() == 4),
                quoted(onDisk));
        ok("the credential file is owner read-write only", ownerOnly(file),
                "permissions " + Files.getPosixFilePermissions(file));

        CredentialStore reopened = new CredentialStore(file);
        ok("both rows survive a reload", reopened.size() == 2, "size " + reopened.size());
        ok("a reloaded row keeps the stored salt",
                reopened.find("alice").salt().length == Pbkdf2.SALT_BYTES, "wrong salt length");
        ok("removing an account persists",
                reopened.remove("bob") && new CredentialStore(file).size() == 1,
                "removal not persisted");

        Path broken = scratch.resolve("store-broken.tsv");
        Files.writeString(broken, "# comment" + NEWLINE
                + "goodrow\t100000\t" + saltB64() + "\t" + keyB64() + "\tsupervisor" + NEWLINE
                + "shortsalt\t100000\t" + shortSaltB64() + "\t" + keyB64() + "\tsupervisor" + NEWLINE
                + "badrole\t100000\t" + saltB64() + "\t" + keyB64() + "\twizard" + NEWLINE
                + "junkrow" + NEWLINE
                + "tinyiter\t99\t" + saltB64() + "\t" + keyB64() + "\tsupervisor" + NEWLINE
                + "shortkey\t100000\t" + saltB64() + "\t" + shortKeyB64() + "\toperator" + NEWLINE,
                StandardCharsets.UTF_8);
        CredentialStore loaded = new CredentialStore(broken);
        ok("one good row is loaded from a messy file", loaded.size() == 1, "size " + loaded.size());
        ok("the five bad rows are counted as unreadable", loaded.malformedRows() == 5,
                "malformedRows " + loaded.malformedRows());

        Path notAFile = scratch.resolve("store-is-a-directory");
        Files.createDirectories(notAFile);
        boolean threw = false;
        try {
            new CredentialStore(notAFile);
        } catch (IOException expected) {
            threw = true;
        }
        ok("a directory where the store belongs is an error", threw, "directory accepted as store");

        Path tamperedPath = scratch.resolve("store-tampered.tsv");
        AuditLog tamperAudit = new AuditLog(scratch.resolve("store-tampered-audit.log"));
        CredentialStore live = new CredentialStore(tamperedPath);
        live.put("carol", "Carol-Passw0rd-3".toCharArray(), Roles.SUPERVISOR);
        CredentialStore.AdminCredential before = live.find("carol");
        Files.writeString(tamperedPath, "carol\t100000\t" + saltB64() + "\t" + keyB64()
                + "\tsupervisor" + NEWLINE, StandardCharsets.UTF_8);
        CredentialStore tampered = new CredentialStore(tamperedPath);
        LoginService tamperService = new LoginService(tampered, tamperAudit, 40,
                LoginService.DEFAULT_LOCKOUT_MILLIS, LoginService.DEFAULT_SESSION_TTL_MILLIS);
        ok("the real salt of the original row was 16 bytes",
                before.salt().length == Pbkdf2.SALT_BYTES, "fixture salt already wrong");
        ok("the replaced row really differs from the original",
                !Arrays.equals(before.key(), tampered.find("carol").key()), "key unchanged");
        ok("the genuine password stops working once the key is swapped",
                tamperService.verify("carol", "Carol-Passw0rd-3".toCharArray())
                        .status() == LoginService.Status.DENIED,
                "swapped key still logged in");
    }

    // ----------------------------------------------------------- authenticate

    private static void authentication() throws Exception {
        Fixture f = fixture("auth", 40);
        char[] callerArray = "Alice-Passw0rd-1".toCharArray();
        LoginService.AuthResult good = f.service.verify("alice", callerArray);
        ok("the right password is granted", good.status() == LoginService.Status.GRANTED,
                String.valueOf(good.status()));
        ok("the granted result carries the stored role", Roles.SUPERVISOR.equals(good.role()),
                String.valueOf(good.role()));
        ok("the password array of the caller is wiped after a grant", isAllNul(callerArray),
                "characters left in the caller array");

        char[] wrongArray = "Alice-Passw0rd-9".toCharArray();
        LoginService.AuthResult wrong = f.service.verify("alice", wrongArray);
        ok("the wrong password is denied", wrong.status() == LoginService.Status.DENIED,
                String.valueOf(wrong.status()));
        ok("a denial gives away nothing", "the username or password is not correct"
                .equals(wrong.message()), wrong.message());
        ok("the password array of the caller is wiped after a denial", isAllNul(wrongArray),
                "characters left in the caller array");

        ok("the username is matched case-insensitively", f.service.verify("ALICE",
                "Alice-Passw0rd-1".toCharArray()).status() == LoginService.Status.GRANTED,
                "mixed case refused");

        LoginService.AuthResult ghost = f.service.verify("nobody",
                "Alice-Passw0rd-9".toCharArray());
        ok("an unknown username is denied", ghost.status() == LoginService.Status.DENIED,
                String.valueOf(ghost.status()));

        LoginService.AuthResult blank = f.service.verify("alice", new char[0]);
        ok("an empty password is refused cheaply, without the derivation",
                blank.status() == LoginService.Status.REJECTED && blank.elapsedNanos() < 50_000_000L,
                blank.status() + " in " + ms(blank.elapsedNanos()) + " ms");

        LoginService.AuthResult nul = f.service.verify("alice", ("Alice-Passw0rd-1" + NUL).toCharArray());
        ok("the right password plus a trailing null is refused",
                nul.status() == LoginService.Status.REJECTED, String.valueOf(nul.status()));
        LoginService.AuthResult tabbed = f.service.verify("alice" + TAB,
                "Alice-Passw0rd-1".toCharArray());
        ok("the right password for a tab-padded name is refused",
                tabbed.status() == LoginService.Status.REJECTED, String.valueOf(tabbed.status()));
        LoginService.AuthResult surrogate = f.service.verify("alice",
                ("Alice-Passw0rd-" + (char) 0xD842).toCharArray());
        ok("an unpaired surrogate password is refused",
                surrogate.status() == LoginService.Status.REJECTED, String.valueOf(surrogate.status()));

        Path storePath = f.store.path();
        CredentialStore.AdminCredential aliceRow = f.store.find("alice");
        Files.writeString(storePath, "alice\t100000\t" + shortSaltB64() + "\t" + keyB64()
                + "\tsupervisor" + NEWLINE, StandardCharsets.UTF_8);
        CredentialStore reloaded = new CredentialStore(storePath);
        ok("a row with a short salt is never loaded", reloaded.size() == 0, "size " + reloaded.size());
        ok("the rewritten row was really the fixture row",
                aliceRow.salt().length == Pbkdf2.SALT_BYTES && reloaded.find("alice") == null,
                "fixture row not replaced as intended");
    }

    private static boolean isAllNul(char[] value) {
        for (char c : value) {
            if (c != '\0') {
                return false;
            }
        }
        return true;
    }

    // -------------------------------------------------------- lockout per name

    private static void lockoutIsPerAccount() throws Exception {
        Fixture f = fixture("lockout", 3);
        for (int i = 0; i < 2; i++) {
            f.service.verify("alice", "Alice-Passw0rd-9".toCharArray());
        }
        ok("two failures leave the account usable", f.service.verify("alice",
                "Alice-Passw0rd-1".toCharArray()).status() == LoginService.Status.GRANTED,
                "locked too early");
        ok("a successful sign in clears the count", f.service.failuresFor("alice") == 0,
                "count " + f.service.failuresFor("alice"));

        LoginService.AuthResult third = null;
        for (int i = 0; i < 3; i++) {
            third = f.service.verify("alice", "Alice-Passw0rd-9".toCharArray());
        }
        ok("the attempt that reaches the limit says locked",
                third != null && third.status() == LoginService.Status.LOCKED,
                String.valueOf(third == null ? null : third.status()));
        LoginService.AuthResult whileLocked = f.service.verify("alice",
                "Alice-Passw0rd-1".toCharArray());
        ok("the right password is refused while locked",
                whileLocked.status() == LoginService.Status.LOCKED,
                String.valueOf(whileLocked.status()));
        LoginService.AuthResult otherName = f.service.verify("bob", "Bob-Passw0rd-22".toCharArray());
        ok("another administrator is not locked out",
                otherName.status() == LoginService.Status.GRANTED, String.valueOf(otherName.status()));
        ok("the failure count for the other name is still zero",
                f.service.failuresFor("bob") == 0, "count " + f.service.failuresFor("bob"));
        f.service.clearLock("alice");
        ok("a supervisor unlock restores access", f.service.verify("alice",
                "Alice-Passw0rd-1".toCharArray()).status() == LoginService.Status.GRANTED,
                "unlock did not help");
    }

    // -------------------------------------------------------------- equal cost

    private static void equalCostBranches() throws Exception {
        Fixture plain = fixture("cost", 400);
        Fixture locked = fixture("cost-lock", 2, 24L * 60L * 60L * 1000L);
        for (int i = 0; i < 2; i++) {
            locked.service.verify("alice", "Alice-Passw0rd-9".toCharArray());
        }
        ok("the timing fixture account is locked before the run",
                locked.service.isLockedOut("alice"), "not locked");

        List<Long> knownBad = new ArrayList<>();
        List<Long> unknown = new ArrayList<>();
        List<Long> whileLocked = new ArrayList<>();
        List<Long> badName = new ArrayList<>();
        List<Long> unusablePassword = new ArrayList<>();
        for (int round = 0; round < 3; round++) {
            knownBad.add(plain.service.verify("alice", "Alice-Passw0rd-9".toCharArray())
                    .elapsedNanos());
            unknown.add(plain.service.verify("nobody-here", "Alice-Passw0rd-9".toCharArray())
                    .elapsedNanos());
            whileLocked.add(locked.service.verify("alice", "Alice-Passw0rd-1".toCharArray())
                    .elapsedNanos());
            badName.add(plain.service.verify("x" + TAB, "Alice-Passw0rd-9".toCharArray())
                    .elapsedNanos());
            unusablePassword.add(plain.service.verify("alice", ("p" + NUL).toCharArray())
                    .elapsedNanos());
        }
        long realWork = median(knownBad);
        ok("a real derivation is timed, not a rounding artefact", realWork > 20_000_000L,
                "median " + ms(realWork) + " ms");
        ok("an unknown username costs the same as a known one",
                withinFactor(unknown, knownBad, 2.0), ratio(unknown, knownBad) + " ("
                        + ms(median(unknown)) + " against " + ms(realWork) + " ms)");
        ok("an attempt while locked costs the same",
                withinFactor(whileLocked, knownBad, 2.0), ratio(whileLocked, knownBad) + " ("
                        + ms(median(whileLocked)) + " ms)");
        ok("a malformed username costs the same as a real check",
                withinFactor(badName, knownBad, 2.0), ratio(badName, knownBad) + " ("
                        + ms(median(badName)) + " ms)");
        ok("the four timed branches stay inside one band",
                spread(knownBad, unknown, whileLocked, badName) <= 2.0,
                "spread " + String.format(Locale.ROOT, "%.2f",
                        spread(knownBad, unknown, whileLocked, badName)) + " times");
        ok("an unusable password is refused at least ten times cheaper",
                median(unusablePassword) < realWork / 10, ms(median(unusablePassword))
                        + " ms against " + ms(realWork) + " ms");
    }

    // ------------------------------------------------------------- audit trail

    private static void auditTrail() throws Exception {
        Fixture f = fixture("audit", 40);
        f.service.verify("alice", "Alice-Passw0rd-1".toCharArray());
        f.service.verify("alice", "Alice-Passw0rd-9".toCharArray());
        f.service.verify("nobody", "Alice-Passw0rd-9".toCharArray());
        List<String> lines = f.audit.tail(100);
        ok("every attempt is written down", lines.size() == 3, "records " + lines.size());
        ok("grants and denials are labelled", lines.get(0).contains("AUTH_GRANTED")
                && lines.get(1).contains("AUTH_DENIED") && lines.get(2).contains("AUTH_DENIED"),
                String.join(" | ", lines));
        ok("records are numbered in order", lines.get(0).startsWith("1" + TAB)
                && lines.get(2).startsWith("3" + TAB), "numbering " + lines.get(2));
        ok("no password reaches the log",
                !Files.readString(f.audit.path()).contains("Alice-Passw0rd"),
                "password found in the log");
        ok("a reopened log continues the numbering",
                new AuditLog(f.audit.path()).tail(100).get(2).startsWith("3" + TAB),
                "numbering reset on reopen");
    }

    private static void auditTrailCannotBeForged() throws Exception {
        Fixture f = fixture("audit-sanitise", 40);
        f.audit.record("EVA", "alice" + NEWLINE + "9999" + TAB + "FORGED", "detail");
        List<String> lines = f.audit.tail(10);
        ok("hostile input stays inside one record", lines.size() == 1, "records " + lines.size());
        ok("newlines and tabs are replaced", lines.get(0).contains("alice?9999?FORGED"),
                lines.get(0));
        ok("a record keeps exactly five fields",
                lines.get(0).chars().filter(c -> c == TAB).count() == 4, "field count off");
        f.audit.record("EVB", "x".repeat(300), "d");
        List<String> after = f.audit.tail(10);
        ok("an over-long field is truncated",
                after.get(1).split("\t", -1)[3].length() == AuditLog.MAX_FIELD_CHARS,
                "field not truncated");
        ok("an empty field is written as a dash", "-".equals(AuditLog.clean("")),
                AuditLog.clean(""));
        ok("the sanitiser is applied to the event name too", AuditLog.clean("A" + NEWLINE + "B")
                .equals("A?B"), AuditLog.clean("A" + NEWLINE + "B"));
    }

    // -------------------------------------------------------------- fail closed

    private static void failClosedWhenUnrecordable() throws Exception {
        Path control = scratch.resolve("audit-control.log");
        AuditLog good = new AuditLog(control);
        good.record("CTRL", "alice", "one");
        good.record("CTRL", "alice", "two");
        ok("the control log really accepts records",
                Files.readString(control).lines().count() == 2, "control log did not fill");

        Path blocked = scratch.resolve("audit-blocked.log");
        Files.createDirectories(blocked);
        CredentialStore store = new CredentialStore(scratch.resolve("failclosed.tsv"));
        store.put("alice", "Alice-Passw0rd-1".toCharArray(), Roles.SUPERVISOR);
        Fixture f = new Fixture(store, new AuditLog(blocked));
        LoginService.AuthResult refused = f.service.verify("alice",
                "Alice-Passw0rd-1".toCharArray());
        ok("the right password is refused when the log cannot be written",
                refused.status() == LoginService.Status.RECORDING_FAILED,
                String.valueOf(refused.status()));
        ok("the refusal explains itself", refused.message().contains("could not be recorded"),
                refused.message());
        ok("no role is handed out with the refusal", refused.role() == null,
                String.valueOf(refused.role()));
        ok("a session without a role cannot run admin commands",
                !f.service.authorized(f.service.issueSession("alice", null)),
                "a role-less session was accepted");

        String transcript = runPortal(f, "alice" + NEWLINE + "Alice-Passw0rd-1" + NEWLINE
                + "whoami" + NEWLINE);
        ok("the command line portal also grants nothing without a log",
                transcript.contains("access denied.") && !transcript.contains("signed in as alice"),
                quoted(transcript));
    }

    // ---------------------------------------------------------------- sessions

    private static void sessionLifecycle() throws Exception {
        Fixture f = fixture("session", 40);
        LoginService.AuthResult granted = f.service.verify("alice",
                "Alice-Passw0rd-1".toCharArray());
        LoginService.Session live = f.service.issueSession(granted.username(), granted.role());
        ok("a fresh session authorises admin commands", f.service.authorized(live),
                "fresh session refused");
        LoginService.Session expired = new LoginService.Session(live.token(), live.username(),
                live.role(), System.currentTimeMillis() - 1);
        ok("an expired session does not", !f.service.authorized(expired), "expired session kept");
        ok("a session with no token does not",
                !f.service.authorized(new LoginService.Session(null, "alice", Roles.SUPERVISOR,
                        System.currentTimeMillis() + 60_000)), "tokenless session kept");
        ok("a session with an unknown role does not",
                !f.service.authorized(new LoginService.Session(live.token(), "alice", "wizard",
                        System.currentTimeMillis() + 60_000)), "unknown role kept");
        LoginService.Session second = f.service.issueSession(granted.username(), granted.role());
        ok("sessions get a different token each time", !live.token().equals(second.token()),
                "token reused");
        ok("only a supervisor may manage accounts",
                Roles.mayManageAccounts(Roles.SUPERVISOR) && !Roles.mayManageAccounts(Roles.OPERATOR),
                "role table wrong");
        ok("an auditor may still read the trail", Roles.mayReadAudit(Roles.AUDITOR),
                "auditor refused");

        String keyComparison = methodBody("src/portal/Pbkdf2.java", "static boolean matches(");
        ok("the key comparison method was located at all", !keyComparison.isEmpty(),
                "an empty capture would make the two checks below pass for nothing");
        ok("the key comparison is constant time", keyComparison.contains("MessageDigest.isEqual("),
                quoted(keyComparison));
        ok("the key comparison does not stop at the first differing byte",
                !keyComparison.contains("Arrays.equals("), quoted(keyComparison));
    }

    /**
     * Returns the source text of one method, comments stripped, so that a property
     * with no observable behaviour (a comparison that must not short-circuit) can
     * still be pinned. Throws if the file or the method is missing.
     */
    private static String methodBody(String relativeSource, String signatureStart)
            throws IOException {
        Path file = Path.of(System.getProperty("portal.source.root", "."), relativeSource);
        if (!Files.isRegularFile(file)) {
            throw new IOException("cannot read " + file.toAbsolutePath());
        }
        String text = stripComments(Files.readString(file, StandardCharsets.UTF_8));
        int start = text.indexOf(signatureStart);
        if (start < 0) {
            throw new IOException("no method starting with " + signatureStart + " in " + file);
        }
        int open = text.indexOf('{', start);
        if (open < 0) {
            throw new IOException("no body for " + signatureStart + " in " + file);
        }
        int depth = 0;
        for (int i = open; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return text.substring(start, i + 1);
                }
            }
        }
        throw new IOException("unbalanced braces after " + signatureStart + " in " + file);
    }

    /** Removes block and line comments while respecting string and character literals. */
    private static String stripComments(String source) {
        StringBuilder out = new StringBuilder(source.length());
        boolean inString = false;
        boolean inChar = false;
        boolean escaped = false;
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            char next = i + 1 < source.length() ? source.charAt(i + 1) : '\0';
            if (escaped) {
                escaped = false;
                out.append(c);
                continue;
            }
            if (c == '\\' && (inString || inChar)) {
                escaped = true;
                out.append(c);
                continue;
            }
            if (c == '"' && !inChar) {
                inString = !inString;
            } else if (c == '\'' && !inString) {
                inChar = !inChar;
            }
            if (!inString && !inChar && c == '/' && next == '/') {
                while (i < source.length() && source.charAt(i) != '\n') {
                    i++;
                }
                out.append('\n');
                continue;
            }
            if (!inString && !inChar && c == '/' && next == '*') {
                int close = source.indexOf("*/", i + 2);
                i = close < 0 ? source.length() : close + 1;
                out.append('\n');
                continue;
            }
            out.append(c);
        }
        return out.toString();
    }

    // -------------------------------------------------------- child process CLI

    private static void commandLine() throws Exception {
        Path home = scratch.resolve("cli-bootstrap");
        String out = runCli(home, line("alice", "weak", CLI_PASS, CLI_PASS, "alice", CLI_PASS,
                "whoami", "quit"), null);
        ok("the child creates the first supervisor",
                out.contains("created alice with role supervisor"), tail(out));
        ok("a weak password asks to be repeated once",
                count(out, "new password: ") == 2 && count(out, "repeat password: ") == 1,
                "new=" + count(out, "new password: ") + " repeat=" + count(out, "repeat password: "));
        ok("the weak password names its own problem", out.contains("rejected: the password must be"),
                tail(out));
        ok("the child signs in and answers whoami",
                out.contains("signed in as alice")
                        && out.contains("you are alice with role supervisor"), tail(out));
        ok("the child closes when asked", out.contains("the portal is closing."), tail(out));

        String afterQuit = runCli(home, line("alice", CLI_PASS, "admins", "quit"), null);
        ok("the account written by the first child survived",
                afterQuit.contains("alice  supervisor"), tail(afterQuit));

        Path second = scratch.resolve("cli-roles");
        runCli(second, line("alice", CLI_PASS, CLI_PASS, "alice", CLI_PASS, "create carol",
                CLI_CAROL_PASS, CLI_CAROL_PASS, "quit"), null);
        String asOperator = runCli(second, line("carol", CLI_CAROL_PASS, "create dave", "audit 5",
                "quit"), null);
        ok("an operator cannot create accounts",
                asOperator.contains("refused: only a supervisor may do that.")
                        && !asOperator.contains("created dave"), tail(asOperator));
        ok("an operator can still read the audit trail",
                asOperator.contains("the last ") && asOperator.contains("AUTH_GRANTED"),
                tail(asOperator));

        Path refusal = scratch.resolve("cli-refusal");
        runCli(refusal, line("alice", CLI_PASS, CLI_PASS), null);
        String wrongPassword = denialLine(runCli(refusal, line("alice", "Nope-Passw0rd-9"), null));
        String unknownUser = denialLine(runCli(refusal, line("no-such-admin", "Nope-Passw0rd-9"), null));
        ok("a wrong password and an unknown username answer identically",
                wrongPassword.equals(unknownUser) && wrongPassword.startsWith("the username or"),
                quoted(wrongPassword) + " against " + quoted(unknownUser));
        ok("the denial text is the generic one",
                "the username or password is not correct".equals(wrongPassword), quoted(wrongPassword));

        Path dead = scratch.resolve("cli-nolog");
        runCli(dead, line("alice", CLI_PASS, CLI_PASS), null);
        Path deadLog = dead.resolve("audit.log");
        ok("the child had written an audit file to begin with", Files.isRegularFile(deadLog),
                "no audit file was ever created");
        blockLogByDirectory(deadLog);
        String noLog = runCli(dead, line("alice", CLI_PASS, "whoami"), null);
        ok("without a usable log the child grants nothing",
                noLog.contains("access denied.") && !noLog.contains("signed in as alice"),
                tail(noLog));
        ok("and it says the login could not be recorded",
                noLog.contains("access refused: the login could not be recorded"), tail(noLog));

        String aborted = runCli(scratch.resolve("cli-empty-abort"), line("al", ""), null);
        ok("an unusable bootstrap keeps the portal locked",
                aborted.contains("the portal stays locked."), tail(aborted));

        Path self = scratch.resolve("cli-selftest");
        String report = runCli(self, line("alice", CLI_PASS, CLI_PASS), "self-test");
        ok("self-test refuses all three probes",
                report.contains("wrong password   -> DENIED")
                        && report.contains("unknown username -> DENIED")
                        && report.contains("blank password   -> REJECTED"), tail(report));
        ok("self-test prints a measurable cost per probe",
                report.contains("wrong password   -> DENIED in ") && report.contains(" ms"),
                tail(report));
    }

    private static String line(String... parts) {
        return String.join(NEWLINE + "", parts) + NEWLINE;
    }

    /** Runs the portal in a child JVM with piped standard input, returning its output. */
    private static String runCli(Path home, String stdin, String extraArgument) throws Exception {
        List<String> command = new ArrayList<>(List.of(
                System.getProperty("java.home") + File.separator + "bin" + File.separator + "java",
                "-cp", new File(System.getProperty("java.class.path")).getAbsolutePath(),
                "-Dportal.home=" + home.toAbsolutePath(), "portal.AdminPortal"));
        if (extraArgument != null) {
            command.add(extraArgument);
        }
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process child = builder.start();
        try (OutputStream stdinStream = child.getOutputStream()) {
            stdinStream.write(stdin.getBytes(StandardCharsets.UTF_8));
            stdinStream.flush();
        }
        String output;
        try (InputStream in = child.getInputStream()) {
            output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        int code = child.waitFor();
        if (code != 0 && code != 2) {
            fail("the portal child exited with " + code + ": " + tail(output));
        }
        return output;
    }

    /** Runs an in-process portal with piped input, returning its whole output. */
    private static String runPortal(Fixture f, String stdin) {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        AdminPortal portal = new AdminPortal(f.store(), f.audit(), f.service(), new StringReader(stdin),
                new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            portal.run(new String[0]);
        } catch (IOException failure) {
            return captured + " (io: " + failure + ")";
        }
        return captured.toString(StandardCharsets.UTF_8);
    }

    // ----------------------------------------------------------------- plumbing

    private record Fixture(CredentialStore store, AuditLog audit, LoginService service) {

        Fixture(CredentialStore store, AuditLog audit) {
            this(store, audit, new LoginService(store, audit));
        }
    }

    private static Fixture fixture(String name, int maxFailures) throws Exception {
        return fixture(name, maxFailures, LoginService.DEFAULT_LOCKOUT_MILLIS);
    }

    private static Fixture fixture(String name, int maxFailures, long lockoutMillis)
            throws Exception {
        Path dir = scratch.resolve(name);
        Files.createDirectories(dir);
        CredentialStore store = new CredentialStore(dir.resolve("credentials.tsv"));
        store.put("alice", "Alice-Passw0rd-1".toCharArray(), Roles.SUPERVISOR);
        store.put("bob", "Bob-Passw0rd-22".toCharArray(), Roles.OPERATOR);
        AuditLog audit = new AuditLog(dir.resolve("audit.log"));
        LoginService service = new LoginService(store, audit, maxFailures, lockoutMillis,
                LoginService.DEFAULT_SESSION_TTL_MILLIS);
        return new Fixture(store, audit, service);
    }

    /** Encodes the way {@link CredentialStore} writes, so hand written rows load. */
    private static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static String saltB64() {
        byte[] salt = new byte[Pbkdf2.SALT_BYTES];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) (i + 1);
        }
        return b64(salt);
    }

    private static String keyB64() {
        byte[] key = new byte[Pbkdf2.KEY_BYTES];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (200 - i);
        }
        return b64(key);
    }

    private static String shortSaltB64() {
        return b64(new byte[8]);
    }

    private static String shortKeyB64() {
        return b64(new byte[12]);
    }

    /**
     * Makes an append target unwriteable by putting a directory in its place: a
     * permission bit would be ignored because this machine runs as root, and
     * deleting the file alone is not enough because the log is recreated on write.
     */
    private static void blockLogByDirectory(Path log) throws IOException {
        Files.deleteIfExists(log);
        Files.createDirectories(log);
    }

    private static boolean ownerOnly(Path file) throws IOException {
        return Files.getPosixFilePermissions(file).equals(EnumSet.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
    }

    private static boolean throwsIae(Runnable body) {
        try {
            body.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static long median(List<Long> samples) {
        List<Long> sorted = new ArrayList<>(samples);
        sorted.sort(Long::compare);
        return sorted.get(sorted.size() / 2);
    }

    private static boolean withinFactor(List<Long> sample, List<Long> reference, double factor) {
        double ratio = (double) median(sample) / (double) median(reference);
        return ratio >= 1.0 / factor && ratio <= factor;
    }

    private static String ratio(List<Long> sample, List<Long> reference) {
        return String.format(Locale.ROOT, "%.2f times",
                (double) median(sample) / (double) median(reference));
    }

    @SafeVarargs
    private static double spread(List<Long>... groups) {
        long low = Long.MAX_VALUE;
        long high = 0;
        for (List<Long> group : groups) {
            long middle = median(group);
            low = Math.min(low, middle);
            high = Math.max(high, middle);
        }
        return low == 0 ? 0 : (double) high / (double) low;
    }

    private static String ms(long nanos) {
        return String.format(Locale.ROOT, "%.1f", nanos / 1_000_000.0);
    }

    private static int count(String haystack, String needle) {
        int found = 0;
        int from = 0;
        while (true) {
            int at = haystack.indexOf(needle, from);
            if (at < 0) {
                return found;
            }
            found++;
            from = at + needle.length();
        }
    }

    /** The refusal sentence on its own, without the prompts printed before it. */
    private static String denialLine(String output) {
        int at = output.indexOf("the username or");
        if (at < 0) {
            return output.isEmpty() ? "" : output.split("\n")[0].trim();
        }
        int end = output.indexOf('\n', at);
        return output.substring(at, end < 0 ? output.length() : end).trim();
    }

    private static String tail(String output) {
        String flat = output.replace("\n", " | ");
        return flat.length() <= 320 ? flat : "..." + flat.substring(flat.length() - 320);
    }

    private static String quoted(String value) {
        return "[" + value.replace("\n", " | ") + "]";
    }

    private static void ok(String what, boolean condition, Object detail) {
        if (condition) {
            passed++;
            System.out.println("PASS " + what);
        } else {
            fail(what + " -- saw " + detail);
        }
    }

    private static void fail(String what) {
        System.out.println("FAIL " + what);
        failures.add(what);
    }

    private static void deleteTree() {
        try {
            if (scratch == null || !Files.exists(scratch)) {
                return;
            }
            Files.walk(scratch).sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException stillThere) {
                    p.toFile().delete();
                }
            });
        } catch (IOException couldNotWalk) {
            scratch.toFile().deleteOnExit();
        }
    }
}
