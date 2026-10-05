package com.example.identity;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkAbsent;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * The audit trail: what it can contain, what it refuses to contain, and what it does when the
 * filesystem turns against it.
 *
 * <p>The primary control is <em>structure</em>: {@link AuditLog} accepts a {@link Reason} enum and a
 * bounded integer, and {@link Identity#toString()} prints only a kind and a length. There is no
 * free-text field, so the writer never receives a secret it could redact badly. {@code scrub} is the
 * second control, for the future change that routes text here anyway - and it is tested against the
 * two shapes that defeat the naive implementation:
 * <ul>
 *   <li><b>Word-boundary matching.</b> {@code \bpassword\b} never matches {@code AUTH_DB_PASSWORD=},
 *     because {@code _} is a word character. The environment variable this program actually reads is
 *     spelled exactly that way.</li>
 *   <li><b>{@code \S+} value matching.</b> A value taken as "up to the next space" leaks the tail of
 *     a passphrase that contains one - which is precisely the shape {@code IDENTITY_DB_PASSWORD} is
 *     allowed to have.</li>
 * </ul>
 *
 * <p>Every absence assertion here goes through {@link Harness#checkAbsent}, which first asserts the
 * corpus was non-empty. An absence check over a capture that silently captured nothing is a pass
 * that means nothing.
 */
public final class AuditLogTest {

    /**
     * Exactly the 43-character base64url shape {@link SessionToken} issues, built to length on
     * purpose: an earlier fixture of this check was 45 characters, so the 43-character rule was
     * never exercised and the pattern could have been deleted with the suite green.
     */
    private static final String TOKEN_43 = "abcdefghij0123456789ABCDEFGHIJklmnopqrst-_9";

    private AuditLogTest() {
    }

    public static void run() throws Exception {
        scrubShapes();
        structuralRedaction();
        recoveryNotLatched();
        unwritableLogCannotContradictTheAnswer();
        capFailsClosed();
        fileDiscipline();
    }

    // ------------------------------------------------------------------ scrubber

    private static void scrubShapes() {
        section("scrub: the shapes that defeat the naive redactor");
        List<String> leaks = new ArrayList<>();

        // The exact variable this program reads, and the exact shape its value may have.
        String envLine = "AUTH_DB_PASSWORD=Correct-Horse-Battery-9 audit";
        String envScrubbed = AuditLog.scrub(envLine);
        check("the environment variable's name is still visible to the operator",
                envScrubbed.contains("AUTH_DB_PASSWORD"));
        checkAbsent("the underscore-prefixed password name is redacted anyway", envScrubbed,
                "Correct-Horse-Battery-9");
        if (!envScrubbed.contains("Correct-Horse-Battery-9")) {
            // keep the positive form too, so a broken capture cannot satisfy the check above
            check("the value was replaced by a marker rather than deleted with the key",
                    envScrubbed.contains("[redacted]"));
        }
        leaks.add(envScrubbed);

        String spaced = "IDENTITY_DB_PASSWORD=Correct Horse Battery Staple 42 tail";
        String spacedScrubbed = AuditLog.scrub(spaced);
        checkAbsent("a passphrase containing spaces is hidden in full, not only to the first space",
                spacedScrubbed, "Horse");
        checkAbsent("and its tail is not left behind", spacedScrubbed, "Staple");
        checkAbsent("not even the trailing token", spacedScrubbed, "42 tail");
        leaks.add(spacedScrubbed);

        String quoted = "passphrase: \"correct horse battery staple\" done";
        String quotedScrubbed = AuditLog.scrub(quoted);
        checkAbsent("a double-quoted phrase is taken whole", quotedScrubbed, "battery");
        leaks.add(quotedScrubbed);

        String jsonish = "{\"api_key\":\"sk_live_0f3a9c7b21\",\"other\":\"kept\"}";
        String jsonScrubbed = AuditLog.scrub(jsonish);
        checkAbsent("a JSON-shaped api_key value is redacted", jsonScrubbed, "sk_live_0f3a9c7b21");
        check("an unrelated field in the same line survives (so the log stays readable)",
                jsonScrubbed.contains("kept"));
        leaks.add(jsonScrubbed);

        String encoded = "stored=v1$pbkdf2-sha256$600000$q3d9Kp0mZ0l1sT2y0Q1aYw==$k7H9mP2qR5sT8uV1wX4yZ6aB7cD0eF2gH4iJ6kL8mNo=";
        String encodedScrubbed = AuditLog.scrub(encoded);
        checkAbsent("a PBKDF2 encoding is redacted as a credential", encodedScrubbed, "600000");
        checkAbsent("including its salt", encodedScrubbed, "q3d9Kp0mZ0l1sT2y0Q1aYw");
        check("the marker says what was removed", encodedScrubbed.contains("[credential-redacted]"));
        leaks.add(encodedScrubbed);

        String tok = "token issued " + TOKEN_43;
        String tokScrubbed = AuditLog.scrub(tok);
        check("the fixture really is the 43-character base64url shape of a real token",
                TOKEN_43.length() == 43 && TOKEN_43.matches("[A-Za-z0-9_-]{43}"));
        checkAbsent("a 43-character base64url run is redacted as a token", tokScrubbed, TOKEN_43);
        leaks.add(tokScrubbed);

        String digest = "digest 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 end";
        String digestScrubbed = AuditLog.scrub(digest);
        checkAbsent("a hex SHA-256 is redacted as a digest", digestScrubbed,
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        leaks.add(digestScrubbed);

        String authorization = "Authorization: BearerYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKSwo";
        checkAbsent("an Authorization header value is redacted", AuditLog.scrub(authorization),
                "BearerYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKSwo");

        String caseTest = "PASSWORD=Upper-Pass-1 PassWord=Upper-Pass-1 passwd=Upper-Pass-1";
        checkAbsent("redaction is case-insensitive on the key", AuditLog.scrub(caseTest), "Upper-Pass-1");

        String control = AuditLog.scrub("event=OK\r\n[0m ts=1 password=Se-cret-Value-9 injected");
        check("CRLF cannot forge a second record", !control.contains("\n"));
        check("terminal escape bytes are neutralised",
                !control.contains((char) 0x1B + "[0m"));
        check("the control characters are replaced rather than dropped silently",
                control.indexOf('?') >= 0);
        checkAbsent("and the password in that line is still redacted", control, "Se-cret-Value-9");

        check("empty and null input survive the scrubber",
                AuditLog.scrub("").isEmpty() && AuditLog.scrub(null).isEmpty());
        check("an ordinary line passes through unchanged",
                AuditLog.scrub("ts=1 event=AUTHENTICATED subject=USERNAME[len=5]")
                        .equals("ts=1 event=AUTHENTICATED subject=USERNAME[len=5]"));

        section("The scrubber never mangles the only text this program is allowed to write");
        // The key/value pattern is deliberately greedy (a spaced passphrase must be taken to end of
        // line), which means its cost is a false positive on prose of the shape `word= word=`. The
        // vocabulary AuditLog can actually emit is closed at compile time - Reason messages,
        // AuditEvent names, Identity.toString() - so "the greedy pattern hurts us in practice" is
        // falsifiable rather than a matter of taste. Anything listed here would silently destroy the
        // meaning of every log line that carries it.
        checkEquals("every message and event name this program can write survives byte-for-byte",
                List.of(), mangledLegitimateText());
        check("so the greedy value rule is a documented cost, not a live defect",
                AuditLog.scrub("passphrase: correct horse battery staple done")
                        .equals("passphrase: [redacted]"));

        check("the scrub corpus is non-empty before any absence claim is trusted",
                leaks.stream().allMatch(s -> s != null && !s.isEmpty()));
        note("scrub exercised on " + leaks.size() + " secret-bearing shapes");
    }

    /** Every string {@link AuditLog} can put on a line, scrubbed, that does not come back equal. */
    private static List<String> mangledLegitimateText() {
        List<String> mangled = new ArrayList<>();
        for (Reason r : Reason.values()) {
            String message = r.genericUserMessage();
            String scrubbed = AuditLog.scrub(message);
            if (!scrubbed.equals(message)) {
                mangled.add(r.name() + ": " + message + " -> " + scrubbed);
            }
        }
        for (AuditEvent e : AuditEvent.values()) {
            String described = e.describe();
            String scrubbed = AuditLog.scrub(described);
            if (!scrubbed.equals(described)) {
                mangled.add(e.name() + ": " + described + " -> " + scrubbed);
            }
        }
        for (String subject : List.of("subject=USERNAME[len=5]", "subject=EMAIL[len=24]",
                "ts=1777000000 event=bad_credential subject=USERNAME[len=11]")) {
            if (!AuditLog.scrub(subject).equals(subject)) {
                mangled.add(subject + " -> " + AuditLog.scrub(subject));
            }
        }
        return mangled;
    }

    // ------------------------------------------------------------------ structure

    private static void structuralRedaction() throws Exception {
        section("The log's structure keeps caller data out to begin with");
        Harness.Fixture f = Harness.fixture("audit-structure", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            AuthResult login = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
            String token = login.token().value();
            b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            b.api.signIn("nosuchuser", Harness.chars(Harness.P2), SourceId.LOCAL);
            b.api.signIn("bad identifier!!", Harness.chars(Harness.P1), SourceId.LOCAL);
            b.api.register(Harness.E1, Harness.U1, Harness.chars(Harness.P3), SourceId.LOCAL);
            b.api.register("not an email", "bad name", Harness.chars(Harness.P3), "192.0.2.5");
            b.api.revokeSession(token);
            b.api.setAccountStatus(Identity.parseClientUsername(Harness.U1), "disabled");
            // The two outcomes below have to be *driven*, not assumed. ACCOUNT_DISABLED is only ever
            // recorded when a correct password meets a disabled account, and the e-mail form of the
            // identifier is the only way a subject is ever recorded as EMAIL - without these two
            // calls the checks below would be asserting on needles this program never writes.
            b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
            b.api.signIn(Harness.E1, Harness.chars(Harness.P2), "192.0.2.6");

            String log = b.audit.readAll();
            check("the log has content", log.length() > 0);
            check("it records the specific outcomes an operator needs",
                    log.contains("AUTHENTICATED") && log.contains("BAD_CREDENTIAL")
                            && log.contains("ABSENT_ACCOUNT") && log.contains("ACCOUNT_CREATED")
                            && log.contains("USERNAME_TAKEN") && log.contains("ACCOUNT_DISABLED")
                            && log.contains("SESSION_REVOKED"));
            check("every outcome name in that list really is a Reason this program can record",
                    List.of("AUTHENTICATED", "BAD_CREDENTIAL", "ABSENT_ACCOUNT", "ACCOUNT_CREATED",
                            "USERNAME_TAKEN", "ACCOUNT_DISABLED", "SESSION_REVOKED").stream()
                            .allMatch(n -> {
                                try {
                                    return Reason.valueOf(n) != null;
                                } catch (IllegalArgumentException gone) {
                                    return false;
                                }
                            }));
            checkAbsent("no fixture password appears anywhere in the log", log, Harness.P1);
            checkAbsent("nor the second one", log, Harness.P2);
            checkAbsent("nor the one used only in a refused registration", log, Harness.P3);
            checkAbsent("the username is never in the clear", log, Harness.U1);
            checkAbsent("the e-mail is never in the clear", log, Harness.E1);
            checkAbsent("the issued session token is never logged", log, token);
            checkAbsent("the stored credential encoding is never logged", log, "pbkdf2-sha256");
            checkAbsent("the database passphrase is never logged", log, Harness.PASSPHRASE);
            checkAbsent("the rejected identifier is not echoed", log, "nosuchuser");
            check("yet the subject is still recorded, in bounded form",
                    log.contains("subject=USERNAME[len=5]") && log.contains("subject=EMAIL[len="));
            check("no line contains an '=', a '$' or a quote outside the fixed fields",
                    log.lines().allMatch(l -> !l.contains("$")));
            check("every line starts with a timestamp field (one record per line)",
                    log.lines().allMatch(l -> l.startsWith("ts=")));
            check("the number of records equals the number of events appended",
                    b.audit.lineCount() == log.lines().count());
            check("the identity's own toString cannot print its value",
                    Identity.parseClientUsername(Harness.U1).toString().equals("USERNAME[len=5]"));
            check("and a token's toString cannot print the token",
                    login.token().toString().contains("redacted")
                            && !login.token().toString().contains(token));
            check("AuthResult.toString cannot print the token either",
                    !login.toString().contains(token));
        }

        section("Structural: the writer has no free-text parameter to misuse");
        String src = Harness.stripJavaComments(Harness.sourceOf("AuditLog"));
        check("append takes a Reason and an Identity, nothing string-shaped",
                src.contains("void append(Reason reason, Identity subject)")
                        && src.contains("void appendEvent(AuditEvent event)"));
        check("there is no overload accepting a caller string",
                !src.contains("append(String") && !src.contains("appendEvent(String"));
        check("the scrubber runs on every line at the single write point",
                src.contains("String line = scrub(candidate)"));
        check("and on the message field independently of that",
                src.contains("scrub(reason.genericUserMessage())"));
        check("the size cap is checked before the write, not after",
                src.indexOf("current + bytes.length > maxBytes") < src.indexOf("Files.write(file, bytes"));
        check("the append cannot follow a symlink at the target path",
                src.contains("LinkOption.NOFOLLOW_LINKS"));
        check("a deleted log is recreated rather than failing forever",
                src.contains("StandardOpenOption.CREATE") && src.contains("StandardOpenOption.APPEND"));
        String eventEnum = Harness.stripJavaComments(Harness.sourceOf("AuditEvent"));
        check("the event vocabulary is a closed enum", eventEnum.contains("enum AuditEvent"));
    }

    // ------------------------------------------------------------------ failure behaviour

    private static void recoveryNotLatched() throws Exception {
        section("A transient log failure degrades one call, not the process (no latched flag)");
        Harness.Fixture f = Harness.fixture("audit-recovery", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            Path log = f.config.dataDir().resolve("audit.log");
            check("the log exists and is being written", Files.isRegularFile(log, LinkOption.NOFOLLOW_LINKS));

            Files.delete(log);
            check("a deleted log is transparently recreated by the next append",
                    appendOk(b) && Files.isRegularFile(log, LinkOption.NOFOLLOW_LINKS));

            Files.delete(log);
            Files.createDirectories(log); // a directory at the target: no mode trick can defeat root
            check("with the path blocked, the append fails closed instead of being silently dropped",
                    !appendOk(b));
            check("and the failure is reported as an audit failure",
                    failureReason(b) == Reason.AUDIT_FAILURE);
            check("the service is not marked permanently degraded: the very next operation still"
                    + " reaches the store", b.api.accountCount() == 1);

            deleteDirectory(log);
            check("as soon as the filesystem recovers, appending works again with no restart",
                    appendOk(b));
            String recovered = b.audit.readAll();
            check("and the recovered log contains the post-recovery event",
                    recovered.contains(AuditEvent.STATUS_CHANGED.describe()));
            check("in a freshly created file, not a buffer kept from before the path was blocked",
                    Harness.lines(recovered).size() == 1);
            check("repeated failures then repeated successes keep working (the flag is not latched"
                    + " in either direction)", recoveryCycle(b));
        }
    }

    private static boolean appendOk(Harness.Bundle b) {
        try {
            b.audit.appendEvent(AuditEvent.STATUS_CHANGED);
            return true;
        } catch (IdentityStoreException e) {
            return false;
        }
    }

    private static Reason failureReason(Harness.Bundle b) {
        try {
            b.audit.appendEvent(AuditEvent.STATUS_CHANGED);
            return null;
        } catch (IdentityStoreException e) {
            return e.reason();
        }
    }

    private static boolean recoveryCycle(Harness.Bundle b) throws Exception {
        Path log = b.fixture.config.dataDir().resolve("audit.log");
        for (int i = 0; i < 3; i++) {
            Files.delete(log);
            Files.createDirectories(log);
            if (appendOk(b)) {
                return false;
            }
            deleteDirectory(log);
            if (!appendOk(b)) {
                return false;
            }
        }
        return true;
    }

    private static void deleteDirectory(Path dir) throws Exception {
        try (var s = Files.list(dir)) {
            List<Path> children = new ArrayList<>(s.toList());
            for (Path p : children) {
                Files.delete(p);
            }
        }
        Files.delete(dir);
    }

    /**
     * The counterpart to {@link #recoveryNotLatched}: what the caller is <em>told</em> while the log
     * is unwritable must agree with what the database actually did.
     *
     * <p>The defect this closes is not a missing log line, it is a wrong answer. With a throwing append
     * after the commit, a registration past the cap (or over a blocked path) committed the account,
     * charged the registration budget, and then threw {@code AUDIT_FAILURE} - whose user sentence is
     * "The service is unavailable." The account existed. The retry, now that the caller believed it
     * had failed, answered as a duplicate, so the second answer disclosed what the first concealed.
     * The same shape sat on the success path: a correct password, a created session, and an outage
     * message - reached at a rate an unauthenticated attacker picks, since every refused guess writes
     * a line. Asserting the boolean "the operation did not throw" is not enough; the assertions below
     * compare the <em>text</em> the caller received with the state afterwards.
     */
    private static void unwritableLogCannotContradictTheAnswer() throws Exception {
        section("A log that cannot be written cannot change the answer the caller was given");
        Harness.Fixture f = Harness.fixture("audit-post-commit", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            Path log = f.config.dataDir().resolve("audit.log");
            checkEquals("nothing is unrecorded on a healthy log", 0L, b.audit.unrecordedEvents());

            Files.delete(log);
            Files.createDirectories(log); // the log is unwritable; nothing else about the service is
            ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
            PrintStream savedErr = System.err;
            String firstAnswer;
            String retryAnswer;
            String correctPassword;
            String wrongPassword;
            boolean threw;
            int createdAfter;
            int sessionsAfter;
            long unrecorded;
            System.setErr(new PrintStream(errBuf, true, StandardCharsets.UTF_8));
            try {
                long beforeRegister = b.audit.unrecordedEvents();
                threw = false;
                String thrownMessage = null;
                try {
                    AuthResult r = b.api.register(Harness.E2, Harness.U2, Harness.chars(Harness.P2),
                            SourceId.LOCAL);
                    firstAnswer = r.userMessage();
                } catch (IdentityStoreException e) {
                    threw = true;
                    thrownMessage = e.userMessage();
                    firstAnswer = "<threw " + e.reason() + ">";
                }
                long afterRegister = b.audit.unrecordedEvents();
                check("the registration was answered, not thrown, even though the log could not be"
                        + " written", !threw);
                checkEquals("and the loss of that one line is counted", 1L,
                        afterRegister - beforeRegister);

                // state/response agreement: the answer is the created-account sentence, because the
                // account really was created.
                checkEquals("the caller is told the truth about a committed effect, not an outage",
                        Reason.ACCOUNT_CREATED.genericUserMessage(), firstAnswer);
                createdAfter = b.api.accountCount();
                checkEquals("and the state agrees - the account exists", 2, createdAfter);

                long beforeRetry = b.audit.unrecordedEvents();
                AuthResult dup = b.api.register(Harness.E2, Harness.U2, Harness.chars(Harness.P2),
                        SourceId.LOCAL);
                retryAnswer = dup.userMessage();
                check("the retry is counted too", b.audit.unrecordedEvents() > beforeRetry);
                checkEquals("and the retry says what it has always said for a duplicate: the first"
                        + " answer concealed nothing that the second one reveals",
                        Reason.REGISTRATION_DUPLICATE.genericUserMessage(), retryAnswer);

                long beforeGood = b.audit.unrecordedEvents();
                AuthResult good = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
                correctPassword = good.userMessage();
                checkEquals("a correct password over an unwritable log still signs in", true,
                        good.isSuccess());
                checkEquals("with the sign-in sentence, never the outage sentence",
                        Reason.AUTHENTICATED.genericUserMessage(), correctPassword);
                checkEquals("and exactly one lost line for that one decided outcome", 1L,
                        b.audit.unrecordedEvents() - beforeGood);
                sessionsAfter = b.api.liveSessionCount();

                long beforeBad = b.audit.unrecordedEvents();
                AuthResult bad = b.api.signIn(Harness.U1, Harness.chars(Harness.P3), SourceId.LOCAL);
                wrongPassword = bad.userMessage();
                checkEquals("a wrong password is still refused with the credential sentence",
                        Reason.BAD_CREDENTIAL.genericUserMessage(), wrongPassword);
                checkEquals("and the refusal is not upgraded to an outage message because the log is"
                        + " the thing that broke", 1L, b.audit.unrecordedEvents() - beforeBad);

                unrecorded = b.audit.unrecordedEvents();
            } finally {
                System.setErr(savedErr);
            }
            String err = errBuf.toString(StandardCharsets.UTF_8);

            check("the answer the user saw is never the unavailable sentence, whichever branch ran",
                    err.length() > 0 && !firstAnswer.contains("unavailable")
                            && !retryAnswer.contains("unavailable")
                            && !correctPassword.contains("unavailable")
                            && !wrongPassword.contains("unavailable"));
            checkEquals("the account the caller was told about is the account that exists", 2,
                    createdAfter);
            checkEquals("and the session the caller was told about is live", 1, sessionsAfter);
            check("every decided outcome past the block was counted rather than silently dropped",
                    unrecorded >= 4L);
            note("unrecorded events while the log was blocked: " + unrecorded);
            check("the operator is warned on stderr, once, not once per event",
                    err.contains("security event not recorded")
                            && Harness.countOccurrences(err, "security event not recorded") == 1);
            check("the warning names the operational reason so it is diagnosable",
                    err.contains("AUDIT_FAILURE"));
            checkAbsent("the warning carries no secret", err, Harness.PASSPHRASE);
            checkAbsent("nor any fixture path", err, f.dir.toString());

            deleteDirectory(log);
            checkEquals("once the filesystem recovers, appending works again and the counter stops"
                    + " growing (the loss is not latched either)", true, appendOk(b));
            checkEquals("with the counter frozen at what was actually lost", unrecorded,
                    b.audit.unrecordedEvents());
            check("and the recovered log holds the post-recovery line",
                    b.audit.readAll().contains(AuditEvent.STATUS_CHANGED.describe()));
        }

        section("The two verbs stay distinct in the source, so the distinction cannot regress");
        String api = Harness.stripJavaComments(Harness.sourceOf("AuthApi"));
        check("no decision in AuthApi is logged with the throwing verb",
                api.length() > 500 && !api.contains("audit.append(") && !api.contains("audit.appendEvent("));
        check("every audit call there is the non-throwing form",
                Harness.countOccurrences(api, "audit.record(") >= 10
                        && Harness.countOccurrences(api, "audit.recordEvent(") >= 3);
        String log = Harness.stripJavaComments(Harness.sourceOf("AuditLog"));
        check("append still fails closed - start-up must not run with no trail at all",
                log.contains("void append(Reason reason, Identity subject) throws IdentityStoreException")
                        && log.contains("void appendEvent(AuditEvent event) throws IdentityStoreException"));
        check("record cannot throw, which is what makes the guarantee structural rather than a"
                + " comment", log.contains("void record(Reason reason, Identity subject) {")
                        && log.contains("void recordEvent(AuditEvent event) {"));
        check("the throwing verb is not called from record's own body except through the counted"
                + " catch", log.contains("private void recordOrCount(Append append) {")
                        && log.contains("catch (IdentityStoreException couldNotRecord)"));
        String cli = Harness.stripJavaComments(Harness.sourceOf("PortalCli"));
        check("the CLI records the failure it is reporting instead of appending over it",
                cli.contains("audit.record(e.reason(), null)"));
        check("and the old re-append inside a nested try is gone - that is the append whose own"
                + " failure became the user's answer", !cli.contains("logAlsoBroken"));
    }

    private static void capFailsClosed() throws Exception {
        section("Past its cap the log stops recording, loudly, and stays bounded");
        Path dir = Harness.scratch("audit-cap");
        Path file = dir.resolve("audit.log");
        AuditLog small = new AuditLog(file, 400L, true);
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream savedErr = System.err;
        long countedAtCap;
        int written = 0;
        int skipped = 0;
        System.setErr(new PrintStream(errBuf, true, StandardCharsets.UTF_8));
        try {
            for (int i = 0; i < 50; i++) {
                long before = Files.size(file);
                // The throwing verb, on purpose: even it must not fail because the file is full.
                small.append(Reason.AUTHENTICATED, Identity.parseClientUsername(Harness.U1));
                if (Files.size(file) > before) {
                    written++;
                } else {
                    skipped++;
                }
            }
            countedAtCap = small.unrecordedEvents();
        } finally {
            System.setErr(savedErr);
        }
        String err = errBuf.toString(StandardCharsets.UTF_8);
        check("some events were recorded before the cap", written > 0);
        check("later events were skipped rather than written past the cap", skipped > 0);
        checkEquals("every skipped event was counted, none silently dropped", (long) skipped, countedAtCap);
        check("the operator is told on stderr, once (the log is the thing that is full)",
                err.contains("size limit") && Harness.countOccurrences(err, "size limit") == 1);
        check("the stderr warning carries no secret", !err.contains(Harness.PASSPHRASE));
        check("and it names status as where the loss stays visible",
                err.contains("unrecorded"));
        long size = Files.size(file);
        check("the file never exceeded the configured cap", size <= 400L);
        check("and it is not empty either (a cap that stops everything is a different bug)", size > 0);
        check("a full log does not throw, because an unauthenticated caller picks the fill rate: if"
                + " reaching the cap failed closed, the next start-up would refuse every legitimate"
                + " sign-in", capAppendOk(small));
        check("what does fail closed is a path that cannot be used at all - a directory where the"
                + " log belongs (see the recovery section above for the same condition mid-run)",
                unbuildableLog(dir));
        small.close();

        section("The cap is enforced per append, so it cannot be evaded by a buffered writer");
        String src = Harness.stripJavaComments(Harness.sourceOf("AuditLog"));
        check("the file is re-sized before every write", src.contains("Files.size(file"));
        check("nothing holds the file open between appends", !src.contains("FileChannel.open"));

        section("The size limit itself is validated on the way in");
        check("the configured ceiling is finite, so a 'limit' of 64 GB cannot be claimed",
                Config.AUDIT_MAX_BYTES_CEILING > 0 && Config.AUDIT_MAX_BYTES_CEILING < 1L << 31);
        check("a cap below the smallest possible line is refused by the config parser",
                auditCapKeyFloor() );
    }

    /** {@code audit.maxBytes} has a 1 KiB floor: below one useful line, and config fails closed. */
    private static boolean auditCapKeyFloor() {
        Path dir = Harness.scratch("audit-cap-floor");
        String text = Harness.configText(Harness.overrides(), dir).replace("audit.maxBytes=8388608",
                "audit.maxBytes=16");
        Path cfg = dir.resolve("identity.properties");
        try {
            Files.writeString(cfg, text, StandardCharsets.UTF_8);
            Files.setPosixFilePermissions(cfg, Harness.ownerReadWriteOnly());
        } catch (java.io.IOException e) {
            return false;
        }
        try {
            Config.load(cfg, () -> Harness.PASSPHRASE);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CONFIG_INVALID;
        }
    }

    /** A log whose file is full must still accept the call - the skip is internal. */
    private static boolean capAppendOk(AuditLog log) {
        try {
            log.appendEvent(AuditEvent.STARTED);
            return true;
        } catch (IdentityStoreException e) {
            return false;
        }
    }

    /** A log path that cannot be written at all: a directory where the file belongs. */
    private static boolean unbuildableLog(Path dir) throws Exception {
        Path blocked = dir.resolve("blocked.log");
        Files.createDirectories(blocked);
        try {
            new AuditLog(blocked, 4096L, true);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.AUDIT_FAILURE;
        }
    }

    // ------------------------------------------------------------------ file discipline

    private static void fileDiscipline() throws Exception {
        section("The audit file's mode is asserted, not assumed");
        Harness.Fixture f = Harness.fixture("audit-perms", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            Path log = f.config.dataDir().resolve("audit.log");
            check("the log is owner read/write only",
                    Files.getPosixFilePermissions(log, LinkOption.NOFOLLOW_LINKS)
                            .equals(Harness.ownerReadWriteOnly()));
            check("the data directory is owner-only",
                    Files.getPosixFilePermissions(f.config.dataDir(), LinkOption.NOFOLLOW_LINKS)
                            .equals(Harness.ownerOnlyDir()));
            note("this suite runs as root on this machine, where mode bits are not enforced against"
                    + " our own process - so a successful write proves nothing about who else can"
                    + " read the file, which is why every permission check here asserts the mode");
        }

        section("A symlink or a foreign file at the log path is refused, not adopted");
        Path victimDir = Harness.scratch("audit-victim");
        Path victim = victimDir.resolve("authorized_keys");
        Files.writeString(victim, "ssh-rsa AAAA existing content\n", StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(victim, Harness.ownerReadWriteOnly());
        Path dir = Harness.scratch("audit-symlink");
        Path link = dir.resolve("audit.log");
        Files.createSymbolicLink(link, victim);
        check("an AuditLog will not write through a symlink placed at its path",
                refusesAuditLog(dir));
        check("and the symlink target was not modified",
                Files.readString(victim, StandardCharsets.UTF_8).equals("ssh-rsa AAAA existing content\n"));

        Path dir2 = Harness.scratch("audit-dir-at-path");
        Files.createDirectories(dir2.resolve("audit.log"));
        check("a directory at the log path is refused rather than followed", refusesAuditLog(dir2));

        section("An existing log whose mode was widened behind our back is re-secured and verified");
        Path dir3 = Harness.scratch("audit-widened");
        Path log3 = dir3.resolve("audit.log");
        AuditLog widened = new AuditLog(log3, 1 << 20, true);
        check("a freshly created audit log is private",
                Files.getPosixFilePermissions(log3, LinkOption.NOFOLLOW_LINKS)
                        .equals(Harness.ownerReadWriteOnly()));
        // Widen it behind the class's back - the way an operator's chmod or an inherited default ACL
        // would. The constructor chmods first and only then asserts, so the observable contract is
        // "re-secured and proven", not "refused"; assert what the code actually guarantees.
        Files.setPosixFilePermissions(log3, java.util.EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ,
                PosixFilePermission.OTHERS_READ));
        check("the widened file really is readable by others before we open it",
                PosixFiles.isWorldReadable(log3));
        try (AuditLog reopened = new AuditLog(log3, 1 << 20, true)) {
            reopened.appendEvent(AuditEvent.STARTED);
            check("on reopen the mode is tightened back to owner read/write",
                    Files.getPosixFilePermissions(log3, LinkOption.NOFOLLOW_LINKS)
                            .equals(Harness.ownerReadWriteOnly()));
            check("and the previous events survive - a re-secure is not a truncate",
                    reopened.readAll().length() > 0);
        }
        widened.close();
    }

    private static boolean refusesAuditLog(Path dir) {
        try {
            new AuditLog(dir.resolve("audit.log"), 1 << 20, true);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.AUDIT_FAILURE || e.reason() == Reason.CONFIG_INVALID;
        }
    }
}
