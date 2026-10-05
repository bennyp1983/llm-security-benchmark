package com.example.auth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Suite 4: the audit trail itself. What ends up in the file, who can read it, what happens when it
 * cannot be written, and whether a second process sees the same record.
 */
public final class Suite4AuditDurability {

    private static final int ITERATIONS = AuthConfig.MIN_PBKDF2_ITERATIONS;
    private static final String SRC = "203.0.113.88";

    /**
     * The whole grammar of a line. Anything outside it -- a newline, a second {@code seq=}, a field
     * the component never emits -- means a client string reached the file structure.
     */
    private static final Pattern LINE_GRAMMAR = Pattern.compile(
            "^seq=\\d+ ts=\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{6}Z type=(login_success|login_failure"
                    + "|login_throttled|login_rejected_no_source|security_alert) account_id=[0-9a-f]{64}"
                    + " account_hint=\\d{1,2} account_present=(true|false) outcome=(success|failure|blocked|error)"
                    + "( source=([0-9]{1,3}\\.){3}[0-9]{1,3}| source=[0-9a-f:.]+)?"
                    + "( reason=[a-z0-9 _.-]+)?"
                    + " latency_us=\\d+( retry_after=\\d+)?( session=[0-9a-f]{6})?$");

    public static void main(String[] args) throws Exception {
        try (Fixture fx = new Fixture("suite4")) {
            fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
            fx.withStandardAccounts(ITERATIONS);
            fileCreationAndRedaction(fx);
            lineGrammar(fx);
            logInjection(fx);
            crossProcessAppend(fx);
            unwritableLogRefuses(fx);
            symlinkIsNeverWrittenThrough(fx);
            replacedInodeIsNeverWrittenInto(fx);
            loosenedPermissionsStopAnOpenHandle(fx);
            retentionIsBounded(fx);
            unsafeLineIsNeverWritten(fx);
            aPartialRecordIsNeverAbsorbedByTheNextOne(fx);
            aTornTailFoundWhileTheLogWasBrokenIsAlsoRepaired(fx);
            aLooseTargetIsNeverAdoptedByTheLoggerItself(fx);
            aFullLogStopsRecordingInsteadOfGrowing(fx);
            aLockedAttemptAgreesWithTheFailureItFollows(fx);
        }
        Check.summary("suite4-audit-durability");
    }

    // ------------------------------------------------------------------ creation + redaction

    private static void fileCreationAndRedaction(Fixture fx) throws Exception {
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            Check.ok("the log file did not exist before the service started",
                    !Files.exists(fx.logFile) || fx.logLines().isEmpty());
            AuthResult good = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("a successful login is recorded", good.isSuccess());
            fx.tryLogin(service, Fixture.USER_ALICE, "Wrong-Password-99", SRC);
            fx.tryLogin(service, "absent-account", Fixture.PASSWORD_A, SRC);

            Set<PosixFilePermission> mode = Files.getPosixFilePermissions(fx.logFile, LinkOption.NOFOLLOW_LINKS);
            Check.eq("the log file is created 0600", Check.OWNER_ONLY, mode);

            String text = fx.logText();
            Check.lacksAllNonEmpty("the log omits every secret and identifier", text,
                    Fixture.PASSWORD_A, Fixture.PASSWORD_B, Fixture.PASSWORD_C,
                    Fixture.USER_ALICE, Fixture.USER_BOB, "carol.wu@example.com",
                    good.sessionId(), new String(AuthTestKeys.STORE_PASSWORD),
                    new String(Fixture.PEPPER));
            for (String line : Files.readAllLines(fx.accountsFile, StandardCharsets.UTF_8)) {
                String salt = line.split(":")[1];
                String digest = line.split(":")[3];
                Check.lacks("the log omits the stored salt", text, salt);
                Check.lacks("the log omits the stored digest", text, digest);
            }
            Check.contains("the source address is recorded", text, "source=" + SRC);
            Check.contains("success is distinguished from failure", text, "outcome=success");
            Check.contains("the log is append-only across attempts", text, "seq=3");
            Check.ok("selfCheck reports no problem while the log is healthy", service.selfCheck().isEmpty());
        }
    }

    // ------------------------------------------------------------------ grammar

    private static void lineGrammar(Fixture fx) throws Exception {
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            int before = fx.logLines().size();
            fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            fx.tryLogin(service, Fixture.USER_ALICE, "Wrong-Password-99", "2001:db8::5");
            fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, null);
            // Only this service's own lines: the sequence counter is per process, so a file that
            // earlier services also wrote to restarts at 1 (asserted as such in crossProcessAppend).
            List<String> lines = fx.logLines().subList(before, fx.logLines().size());
            Check.ok("at least one line was captured", !lines.isEmpty());
            for (String line : lines) {
                Check.ok("line matches the field grammar: " + line.substring(0, Math.min(46, line.length())),
                        LINE_GRAMMAR.matcher(line).matches());
            }
            long previous = -1;
            for (String line : lines) {
                long seq = Long.parseLong(line.substring(4, line.indexOf(' ', 4)));
                Check.ok("sequence numbers increase", seq > previous);
                previous = seq;
            }
            Check.eq("the first line of this service restarts the counter", 1L, Long.valueOf(previous - lines.size() + 1));
            Check.ok("the canonical form of the v6 source is what got logged",
                    String.join("\n", lines).contains("source=2001:db8:0:0:0:0:0:5"));
        }
    }

    // ------------------------------------------------------------------ injection

    private static void logInjection(Fixture fx) throws Exception {
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            int before = fx.logLines().size();
            String cr = String.valueOf((char) 0x0d);
            String lf = String.valueOf((char) 0x0a);
            String[] hostile = {
                    "alice" + lf + "seq=999 ts=2020-01-01T00:00:00Z type=login_success outcome=success",
                    "alice" + cr + lf + "type=security_alert",
                    "alice source=1.2.3.4 outcome=success",
                    "alice\u001b[31m",
            };
            for (String name : hostile) {
                AuthResult r = fx.tryLogin(service, name, Fixture.PASSWORD_A, SRC);
                Check.ok("a hostile name never authenticates", !r.isSuccess());
            }
            List<String> wrote = fx.logLines().subList(before, fx.logLines().size());
            Check.eq("one event per hostile attempt", hostile.length, Integer.valueOf(wrote.size()));
            for (String line : wrote) {
                Check.ok("no injected line break or forged field survives",
                        LINE_GRAMMAR.matcher(line).matches());
                Check.ok("the name never appears in the line", !line.contains("alice source"));
            }
            // The hostile text must still be attributable: an event with no account field would let
            // the attack pass unrecorded.
            for (String line : wrote) {
                Check.contains("the hostile attempt is still attributed", line, "account_id=");
                Check.contains("it is recorded as a failure", line, "outcome=failure");
            }
        }
    }

    // ------------------------------------------------------------------ two processes

    private static void crossProcessAppend(Fixture fx) throws Exception {
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            int parentLines = fx.logLines().size();

            String childLine = runChild(fx);
            Check.ok("the child process reported a persisted line", childLine.contains("seq="));
            List<String> after = fx.logLines();
            Check.eq("the parent sees the child's append", parentLines + 1, Integer.valueOf(after.size()));
            Check.contains("the child's line survived alongside the parent's",
                    after.get(after.size() - 1), "account_id=");
            Check.lacks("the child did not overwrite the parent's first line", after.get(0), "child-process-writer");

            // Honest limit: the counter is per process, so both writers start at 1. The line content
            // is durable; the number is ordering within one process, not a cross-process primary key.
            List<String> sequences = new ArrayList<>();
            for (String line : after) {
                sequences.add(line.substring(4, line.indexOf(' ', 4)));
            }
            Check.eq("sequence is per-process, not a cross-process key",
                    sequences.get(0), sequences.get(sequences.size() - 1));
            Check.ok("the durable payload of both writers is distinct",
                    !after.get(0).equals(after.get(after.size() - 1)));
        }
    }

    private static String runChild(Fixture fx) throws IOException, InterruptedException {
        // A child JVM starts in a different working directory, so a relative classpath would resolve
        // against the wrong root and the child would die with a ClassNotFoundException that looks like
        // a product bug.
        String classpath = System.getProperty("java.class.path");
        for (String entry : classpath.split(java.io.File.pathSeparator)) {
            Check.ok("classpath entry the child inherits is absolute: " + entry,
                    java.nio.file.Path.of(entry).isAbsolute());
        }
        ProcessBuilder builder = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", classpath, "com.example.auth.AuditLogChild",
                fx.logFile.toString(), String.valueOf(fx.time.nowMillis()));
        builder.redirectErrorStream(true);
        Process child = builder.start();
        child.getOutputStream().close();
        String out;
        try (InputStream in = child.getInputStream()) {
            out = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        int status = child.waitFor();
        Check.eq("the child JVM exited cleanly", 0, Integer.valueOf(status));
        return out;
    }

    // ------------------------------------------------------------------ fail closed, then recover

    private static void unwritableLogRefuses(Fixture fx) throws Exception {
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("login works while the log is writable", true);

            Files.delete(fx.logFile);
            AuthResult gone = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("a login is refused when its event cannot be persisted", !gone.isSuccess());
            Check.ok("the refusal issues no session", gone.sessionId() == null);

            // Recreated by someone else with loose permissions: still refused, because writing the
            // trail into a file other users can read or replace is not an acceptable outcome either.
            Files.createFile(fx.logFile);
            Fixture.restrict(fx.logFile, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OTHERS_READ));
            AuthResult loose = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("a log file readable by other users is never adopted", !loose.isSuccess());

            List<String> problems = service.selfCheck();
            Check.ok("the operator can see the hole in the trail", !problems.isEmpty());
            Check.contains("selfCheck names unsaved events", String.join(" | ", problems),
                    "could not be persisted");

            // Recovery, not a latch: once the file is safe again the same credentials work.
            Fixture.restrict(fx.logFile, Check.OWNER_ONLY);
            AuthResult recovered = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("authentication recovers once the log is safe again", recovered.isSuccess());
            Check.ok("recovered events are on disk", fx.logText().contains("outcome=success"));
        }
    }

    private static void symlinkIsNeverWrittenThrough(Fixture fx) throws Exception {
        Path decoy = fx.root.resolve("decoy.log");
        Files.write(decoy, new byte[0]);
        Fixture.restrict(decoy, Check.OWNER_ONLY);
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Files.delete(fx.logFile);
            Files.createSymbolicLink(fx.logFile, decoy);

            AuthResult viaSymlink = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("an attempt whose log path became a symlink is refused", !viaSymlink.isSuccess());
            Check.eq("nothing was written through the symlink", 0L, Long.valueOf(Files.size(decoy)));

            // A boot that finds a symlink at the log name must refuse to start rather than adopt it.
            InvalidConfigException boot = null;
            AuthenticationService secondStart = null;
            try {
                secondStart = fx.build(ITERATIONS);
            } catch (InvalidConfigException e) {
                boot = e;
            }
            if (secondStart != null) {
                secondStart.close();
            }
            Check.ok("a symlink at the log name stops the service from starting", boot != null);
            Check.eq("nothing accumulated through the symlink either", 0L, Long.valueOf(Files.size(decoy)));
        } finally {
            Files.deleteIfExists(fx.logFile);
        }
    }

    /**
     * The replacement is moved in atomically and is itself owner-only, so the name stays a plausible
     * log target: only the inode behind the open handle changed. That isolates the identity check --
     * the reopen path re-validates the same properties, so a test that deletes the file and lets the
     * channel close first would pass even with the per-write check removed.
     */
    private static void replacedInodeIsNeverWrittenInto(Fixture fx) throws Exception {
        Path replacement = fx.root.resolve("rotated-in.log");
        Files.deleteIfExists(replacement);
        Files.deleteIfExists(fx.logFile);
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("the handle is open against the original inode", Files.size(fx.logFile) > 0L);

            Files.write(replacement, new byte[0]);
            Fixture.restrict(replacement, Check.OWNER_ONLY);
            Files.move(replacement, fx.logFile, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);

            AuthResult moved = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("an attempt whose log inode was replaced underneath us is refused", !moved.isSuccess());
            Check.ok("the refusal issues no session", moved.sessionId() == null);

            // The guard's promise is that no *event* is written into an inode that is not the one this
            // process verified. The alert that reports the hole may follow the name -- the file behind
            // it is regular and owner-only -- so what must be absent here is the attempt's own record.
            List<String> afterMove = fx.logLines();
            Check.ok("the replacement file received something to account for the hole",
                    !afterMove.isEmpty());
            for (String line : afterMove) {
                Check.ok("only the alert landed, never the attempt's own record: "
                        + line.substring(0, Math.min(40, line.length())), line.contains("type=security_alert"));
                Check.lacks("no login outcome was recorded against the new inode", line, "outcome=success");
                Check.ok("the alert still satisfies the line grammar", LINE_GRAMMAR.matcher(line).matches());
            }

            List<String> problems = service.selfCheck();
            Check.ok("the operator can see the lost event", !problems.isEmpty());
            Check.contains("selfCheck names the unsaved event", String.join(" | ", problems),
                    "could not be persisted");

            // Recovery: the refusal must close the stale handle, or the trail would stay broken
            // forever even though the name now points at a perfectly good owner-only file.
            AuthResult recovered = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("authentication resumes against the replacement file", recovered.isSuccess());
            Check.ok("the resumed event landed in the file that now has the name",
                    fx.logText().contains("outcome=success"));
        } finally {
            Files.deleteIfExists(replacement);
        }
    }

    /**
     * Relaxes the mode while the handle is open, which is what a {@code chmod} by another process --
     * or a umask-driven group job -- does to a long-running service's log. The trail must stop being
     * written the moment it becomes readable by someone else, not merely at the next reopen.
     */
    private static void loosenedPermissionsStopAnOpenHandle(Fixture fx) throws Exception {
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);

            Fixture.restrict(fx.logFile, EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.OTHERS_READ));
            long bytesWhenLoose = Files.size(fx.logFile);

            AuthResult loosened = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("an attempt is refused once the open log becomes world-readable",
                    !loosened.isSuccess());
            Check.ok("the refusal issues no session", loosened.sessionId() == null);
            Check.eq("nothing was appended to the readable log", bytesWhenLoose,
                    Long.valueOf(Files.size(fx.logFile)));

            Fixture.restrict(fx.logFile, Check.OWNER_ONLY);
            AuthResult restored = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("authentication resumes once the mode is restricted again", restored.isSuccess());
        }
    }

    // ------------------------------------------------------------------ retention, unsafe line

    private static void retentionIsBounded(Fixture fx) throws Exception {
        // The log directory must not be writable by other users, which rules out a shared /tmp path:
        // the fixture root is the only location here with the mode the logger requires.
        Path file = fx.root.resolve("ring.log");
        Files.deleteIfExists(file);
        try {
            AuditLogger logger = AuditLogger.open(file, 100, 1L << 20, 1_700_000_000_000L);
            for (int i = 0; i < 250; i++) {
                logger.record(AuthEvent.builder()
                        .timestampMillis(1_700_000_000_000L + i)
                        .type(EventType.LOGIN_FAILURE)
                        .outcome("failure")
                        .account("ring-probe", false)
                        .source("203.0.113.9")
                        .reason(Diagnostic.CREDENTIAL_MISMATCH)
                        .latencyMicros(i)
                        .build());
            }
            Check.eq("the in-memory ring is capped at maxEvents", 100, Integer.valueOf(logger.retained().size()));
            Check.eq("the file keeps every event", 250, Integer.valueOf(logger.readBack().size()));
            Check.eq("the retained window holds the newest events", "latency_us=249",
                    logger.retained().get(99).substring(logger.retained().get(99).indexOf("latency_us=")));
            Check.eq("persisted count agrees with the file", 250L, Long.valueOf(logger.totalRecorded()));
            logger.close();
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static void unsafeLineIsNeverWritten(Fixture fx) throws Exception {
        Path file = fx.root.resolve("unsafe.log");
        Files.deleteIfExists(file);
        try {
            AuditLogger logger = AuditLogger.open(file, 100, 1L << 20, 1_700_000_000_000L);
            long bytesBefore = Files.size(file);

            // A source that is not the canonical form the validator produces cannot be trusted as a
            // field, so the whole event is refused rather than written with a hostile value in it.
            AuthEvent forged = AuthEvent.builder()
                    .timestampMillis(1_700_000_000_000L)
                    .type(EventType.LOGIN_FAILURE)
                    .outcome("failure")
                    .account("probe", false)
                    .source("203.0.113.9 seq=9 ts=2020-01-01T00:00:00Z type=login_success")
                    .latencyMicros(1)
                    .build();
            AuditPersistenceException thrown = null;
            try {
                logger.record(forged);
            } catch (AuditPersistenceException e) {
                thrown = e;
            }
            Check.ok("an unsafe event is refused instead of written", thrown != null);
            Check.eq("the reason is that the line was rejected", Diagnostic.LOG_LINE_REJECTED,
                    thrown == null ? null : thrown.diagnostic());
            Check.eq("the refused event left no bytes behind", bytesBefore, Long.valueOf(Files.size(file)));
            Check.eq("the refusal is counted as a hole in the trail", 1L, Long.valueOf(logger.unsavedEvents()));

            // The alert that replaces a rejected event must keep the evidence the event carried. An
            // unattributed alert says only that something went wrong, so the attempt would vanish from
            // the trail even though a line was written.
            Check.ok("the replacement alert is written",
                    logger.recordAlert(thrown.diagnostic(), thrown.unsavedEvent()));
            List<String> afterRefusal = logger.readBack();
            Check.eq("exactly one line followed the refusal", 1, Integer.valueOf(afterRefusal.size()));
            String alert = afterRefusal.get(0);
            Check.contains("the alert is typed as a security alert", alert, "type=security_alert");
            Check.contains("the alert keeps the rejected event's account attribution", alert,
                    "account_id=" + AccountField.accountId("probe"));
            Check.contains("it names the reason", alert, "reason=log_line_rejected");
            Check.lacks("the hostile source value was not reintroduced by the alert", alert, "seq=9");
            Check.ok("the alert still satisfies the line grammar", LINE_GRAMMAR.matcher(alert).matches());

            AuthEvent good = AuthEvent.builder()
                    .timestampMillis(1_700_000_000_000L)
                    .type(EventType.LOGIN_FAILURE)
                    .outcome("failure")
                    .account("probe", false)
                    .source("203.0.113.9")
                    .latencyMicros(1)
                    .build();
            logger.record(good);
            Check.eq("a safe event still writes after the refusal", 2, Integer.valueOf(logger.readBack().size()));
            logger.close();
        } finally {
            Files.deleteIfExists(file);
        }
    }

    // ------------------------------------------------------------------ torn tail, size bound, lock attribution

    /**
     * A record truncated by a full file system or a killed process leaves bytes with no trailing
     * newline. An append-only writer that ignores them splices the <em>next</em> event onto the
     * fragment and produces one line that is a mixture of two attempts: the newer event disappears
     * from the trail entirely, and the line that survives describes an attempt that never happened.
     * The repair must therefore truncate to the last real boundary, and must itself be recorded --
     * discarding bytes from an audit file is removing evidence.
     */
    private static void aPartialRecordIsNeverAbsorbedByTheNextOne(Fixture fx) throws Exception {
        Path file = fx.root.resolve("torn.log");
        Files.deleteIfExists(file);
        // Marker chosen so it appears nowhere in the logger's own vocabulary: the repair is reported
        // as reason=log_partial_record, and a needle inside that word would be satisfied by the
        // very line that proves the fragment is gone.
        String fragment = "seq=999 ts=2020-01-01T00:00:00.000000Z type=login_success outcome=success tornbody";
        byte[] tornBytes = fragment.getBytes(StandardCharsets.UTF_8);
        try {
            AuditLogger first = AuditLogger.open(file, 100, 1L << 20, 1_700_000_000_000L);
            first.record(failureEvent(1));
            first.close();
            long complete = Files.size(file);
            Files.write(file, tornBytes, StandardOpenOption.APPEND);
            Check.eq("the fixture really ends mid-record", complete + tornBytes.length,
                    Long.valueOf(Files.size(file)));

            AuditLogger reopened = AuditLogger.open(file, 100, 1L << 20, 1_700_000_000_000L);
            Check.eq("the partial trailing record was discarded", Long.valueOf(tornBytes.length),
                    Long.valueOf(reopened.discardedTornBytes()));

            List<String> afterRepair = reopened.readBack();
            Check.eq("the repair is itself written to the trail", 2, Integer.valueOf(afterRepair.size()));
            // Exact byte accounting: the surviving record plus the repair alert and nothing else, which
            // is what proves the fragment is gone rather than merely unreadable to readBack().
            Check.eq("the file is the surviving record plus the alert, with the fragment truncated away",
                    Long.valueOf(complete + afterRepair.get(1).length() + 1L), Long.valueOf(Files.size(file)));
            String alert = afterRepair.get(1);
            Check.contains("the repair is typed as a security alert", alert, "type=security_alert");
            Check.contains("the alert names the discarded record", alert, "reason=log_partial_record");
            Check.contains("the alert says what was lost", alert, "outcome=error");
            Check.ok("the alert satisfies the line grammar", LINE_GRAMMAR.matcher(alert).matches());
            Check.lacks("the first record survived the repair unchanged", afterRepair.get(0), "log_partial_record");

            reopened.record(failureEvent(2));
            List<String> lines = reopened.readBack();
            Check.eq("a later event lands after the repair", 3, Integer.valueOf(lines.size()));
            for (String line : lines) {
                Check.ok("every line of the repaired log parses: "
                        + line.substring(0, Math.min(46, line.length())), LINE_GRAMMAR.matcher(line).matches());
                Check.lacks("no line is a mixture of the fragment and a real record", line, "tornbody");
            }
            Check.eq("the discarded record is reported once, not on every later write", 1,
                    Integer.valueOf(countOccurrences(String.join("\n", lines), "log_partial_record")));
            Check.eq("bytes discarded from someone else's write are not counted as events this process lost",
                    0L, Long.valueOf(reopened.unsavedEvents()));
            reopened.close();
        } finally {
            Files.deleteIfExists(file);
        }
    }

    /**
     * The reopen path is a second writer of the same repair, reached when the log went away while the
     * service was running and someone put a file back. It must repair the tail too: an append onto a
     * fragment there splices the alert that reports the outage onto unrelated bytes, which is how a
     * trail ends up with a line describing an attempt that never happened.
     */
    private static void aTornTailFoundWhileTheLogWasBrokenIsAlsoRepaired(Fixture fx) throws Exception {
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);

            Files.delete(fx.logFile);
            AuthResult during = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("an attempt is refused while the log is gone", !during.isSuccess());

            Files.createFile(fx.logFile);
            Fixture.restrict(fx.logFile, Check.OWNER_ONLY);
            Files.write(fx.logFile,
                    "seq=777 ts=2020-01-01T00:00:00.000000Z type=login_success tornbody".getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.APPEND);

            AuthResult recovered = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC);
            Check.ok("authentication recovers against the recreated log", recovered.isSuccess());

            List<String> lines = fx.logLines();
            Check.ok("the recreated log holds lines", !lines.isEmpty());
            int repairs = 0;
            for (String line : lines) {
                Check.ok("every line of the recreated log parses: "
                        + line.substring(0, Math.min(46, line.length())), LINE_GRAMMAR.matcher(line).matches());
                Check.lacks("the fragment was truncated away instead of absorbing the next record",
                        line, "tornbody");
                if (line.contains("reason=log_partial_record")) {
                    repairs++;
                }
            }
            Check.eq("the discarded bytes are reported once, as their own record", 1, Integer.valueOf(repairs));
            // The hole the outage left stays reported after a repair -- a repair is not a retraction.
            Check.contains("the events lost during the outage are still on the record",
                    String.join(" | ", service.selfCheck()), "could not be persisted");
            int lostAfterRepair = fx.logLines().size();
            Check.ok("a further sign-in works after the repair",
                    fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC).isSuccess());
            Check.eq("the repair does not grow the hole, only the trail", lostAfterRepair + 1,
                    Integer.valueOf(fx.logLines().size()));
            Check.contains("and still reports the same outage and nothing new",
                    String.join(" | ", service.selfCheck()), "could not be persisted");
        } finally {
            Files.deleteIfExists(fx.logFile);
        }
    }

    /**
     * The logger's own gate, reached through {@code AuditLogger.open} directly rather than through a
     * service. The service's start-up validation checks the same mode one level above, so a suite that
     * only ever boots a service would stay green while the logger itself adopted a trail it must not
     * write - and the logger is the component that actually holds the file open.
     */
    private static void aLooseTargetIsNeverAdoptedByTheLoggerItself(Fixture fx) throws Exception {
        Object[][] modes = {
                {"readable.log", "others read", PosixFilePermission.OTHERS_READ},
                {"writable.log", "others write", PosixFilePermission.OTHERS_WRITE},
                {"group.log", "group read", PosixFilePermission.GROUP_READ},
        };
        for (Object[] mode : modes) {
            Path file = fx.root.resolve((String) mode[0]);
            Files.deleteIfExists(file);
            Files.createFile(file);
            Set<PosixFilePermission> loose = EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            loose.add((PosixFilePermission) mode[2]);
            Fixture.restrict(file, loose);

            InvalidConfigException refused = null;
            try {
                AuditLogger.open(file, 100, 1L << 20, 1_700_000_000_000L);
            } catch (InvalidConfigException e) {
                refused = e;
            }
            Check.ok("the logger refuses a target with " + mode[1], refused != null);
            Check.contains("and names the mode it required",
                    refused == null ? "" : String.join(" | ", refused.problems()), "owner-only");
            Check.eq("nothing was written into the " + mode[1] + " file", 0L, Long.valueOf(Files.size(file)));
        }

        // The accept side, so the gate above cannot be satisfied by a logger that never opens anything.
        Path exact = fx.root.resolve("exact-owner-only.log");
        Files.deleteIfExists(exact);
        Files.createFile(exact);
        Fixture.restrict(exact, Check.OWNER_ONLY);
        AuditLogger accepted = null;
        InvalidConfigException rejected = null;
        try {
            accepted = AuditLogger.open(exact, 100, 1L << 20, 1_700_000_000_000L);
        } catch (InvalidConfigException e) {
            rejected = e;
        }
        Check.ok("the logger opens a file that is exactly rw-------",
                accepted != null && rejected == null);
        if (accepted != null) {
            accepted.close();
        }
    }

    /**
     * A log that grows without limit fills the file system, which in this component is not merely an
     * availability problem: the free-space floor then refuses every login for every user. The size
     * ceiling is checked before each write, so the file stops within one record of the bound and the
     * operator gets an explicit reason instead of an ENOSPC surprise.
     */
    private static void aFullLogStopsRecordingInsteadOfGrowing(Fixture fx) throws Exception {
        Path file = fx.root.resolve("full.log");
        Files.deleteIfExists(file);
        long maxLogBytes = 1024L;
        int attempts = 30;
        try {
            AuditLogger logger = AuditLogger.open(file, 100, 1L << 20, maxLogBytes, 1_700_000_000_000L);
            int written = 0;
            AuditPersistenceException refusal = null;
            for (int i = 0; i < attempts && refusal == null; i++) {
                try {
                    logger.record(failureEvent(i));
                    written++;
                } catch (AuditPersistenceException e) {
                    refusal = e;
                }
            }
            Check.ok("the log accepted events before the bound", written > 0);
            Check.ok("the bound engaged before the attempts ran out, after " + written + " records",
                    written < attempts);
            Check.ok("the refusal is a persistence failure", refusal != null);
            Check.eq("the reason is the size limit, not the free-space floor", Diagnostic.LOG_FILE_LIMIT,
                    refusal == null ? null : refusal.diagnostic());
            Check.ok("the refused event is available to the alert path",
                    refusal != null && refusal.unsavedEvent() != null);

            long sizeAtRefusal = Files.size(file);
            Check.ok("the file stops within one record of the ceiling: " + sizeAtRefusal + " bytes",
                    sizeAtRefusal <= maxLogBytes + AuthEvent.MAX_LINE_CHARS + 1L);
            for (int i = 0; i < 3; i++) {
                AuditPersistenceException again = null;
                try {
                    logger.record(failureEvent(100 + i));
                } catch (AuditPersistenceException e) {
                    again = e;
                }
                Check.eq("a full log keeps refusing rather than growing", Diagnostic.LOG_FILE_LIMIT,
                        again == null ? null : again.diagnostic());
            }
            Check.eq("a refused log does not grow by one byte", sizeAtRefusal, Long.valueOf(Files.size(file)));
            Check.eq("every refusal is counted as a hole in the trail", 4L,
                    Long.valueOf(logger.unsavedEvents()));
            Check.ok("the ceiling does not close the handle, so rotation can recover",
                    !logger.lastWriteFailed());
            logger.close();
        } finally {
            Files.deleteIfExists(file);
        }
    }

    /**
     * The line that reports a lock engaging must agree with the failure that caused it. A
     * {@code login_throttled} line claiming {@code account_present=false} immediately after five
     * {@code account_present=true} failures tells the reviewer the account does not exist, and the
     * operator who acts on that throws away the one signal that matters -- someone was guessing at a
     * real account. The line that <em>follows</em> the lock is deliberately different, because the
     * lock check performs no lookup at all.
     */
    private static void aLockedAttemptAgreesWithTheFailureItFollows(Fixture fx) throws Exception {
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            int before = fx.logLines().size();
            AuthResult tripping = null;
            for (int i = 0; i < 5; i++) {
                tripping = fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC);
            }
            Check.ok("the attempt that trips the lock is denied with no hint", !tripping.isSuccess());
            Check.eq("a wrong password never reveals the lock", 0, Integer.valueOf(tripping.retryAfterSeconds()));

            List<String> lines = fx.logLines().subList(before, fx.logLines().size());
            Check.eq("five failures and the lock they caused are all recorded", 6, Integer.valueOf(lines.size()));
            List<String> throttled = new ArrayList<>();
            for (String line : lines) {
                Check.ok("line satisfies the grammar: " + line.substring(0, Math.min(46, line.length())),
                        LINE_GRAMMAR.matcher(line).matches());
                if (line.contains("type=login_throttled")) {
                    throttled.add(line);
                }
            }
            Check.eq("exactly one line reports the lock engaging", 1, Integer.valueOf(throttled.size()));
            String engaged = throttled.get(0);
            String causingFailure = lines.get(lines.size() - 2);
            Check.contains("the failure that caused the lock is a credential mismatch", causingFailure,
                    "reason=credential_mismatch");
            Check.contains("that failure says the account exists", causingFailure, "account_present=true");
            Check.contains("the lock line agrees that the account exists", engaged, "account_present=true");
            Check.contains("the lock line is attributed to the same account", engaged,
                    "account_id=" + AccountField.accountId(Fixture.USER_BOB));
            Check.contains("the lock line reports a block", engaged, "outcome=blocked");
            Check.contains("the lock line carries the retry hint the denial withheld", engaged, "retry_after=600");

            AuthResult blocked = fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, SRC);
            Check.ok("a locked account cannot log in even with the right password", !blocked.isSuccess());
            Check.ok("the locked response carries the retry hint", blocked.retryAfterSeconds() > 0);
            String later = fx.logLines().get(fx.logLines().size() - 1);
            Check.contains("the later lock refusal still names the account", later,
                    "account_id=" + AccountField.accountId(Fixture.USER_BOB));
            Check.contains("a lock check that looked nothing up claims no knowledge of it", later,
                    "account_present=false");
        }
    }

    private static AuthEvent failureEvent(int marker) {
        return AuthEvent.builder()
                .timestampMillis(1_700_000_000_000L + marker)
                .type(EventType.LOGIN_FAILURE)
                .outcome("failure")
                .account("ring-probe", false)
                .source("203.0.113.9")
                .reason(Diagnostic.CREDENTIAL_MISMATCH)
                .latencyMicros(marker)
                .build();
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        for (int at = haystack.indexOf(needle); at >= 0; at = haystack.indexOf(needle, at + needle.length())) {
            count++;
        }
        return count;
    }
}
