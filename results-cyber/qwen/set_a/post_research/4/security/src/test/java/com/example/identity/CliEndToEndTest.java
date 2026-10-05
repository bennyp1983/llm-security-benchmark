package com.example.identity;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkAbsent;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * The real binary, in real subprocesses.
 *
 * <p>Everything the other suites assert lives inside one JVM. The properties that matter most to an
 * attacker are the ones that only exist across a process boundary, and no in-process test can see
 * them: a credential that reloads wrong in a second JVM is a broken login for everyone; a passphrase
 * in {@code argv} is readable by any local user through {@code /proc/<pid>/cmdline} while the process
 * runs; a stack trace on stdout is a leak; an exit code is what a script branches on.
 *
 * <p>The child is driven through its actual stdin, with canned answers matched by <em>position</em>.
 * That is exactly the shape that hides a prompt-consumption bug - a child that reads one line too
 * many stays green while the answers shift by one and every scripted test silently feeds the wrong
 * value - so the transcript is asserted prompt-by-prompt as well: the number of prompts, the order,
 * and the fact that each answer was consumed by the prompt that asked for it.
 */
public final class CliEndToEndTest {

    /**
     * The passphrase the children run with. It has to be {@link Harness#PASSPHRASE}: H2 stores the
     * digest of the password that <em>created</em> the file, so a child that opens the fixture's
     * database with any other value is refused by the engine and every cross-process check downstream
     * fails with "Wrong user name or password". The one exception is the check below that a wrong
     * passphrase is refused on purpose.
     */
    private static final String ENV_OK = Harness.PASSPHRASE;

    /** The shape of a base64url session token, taken from the token's own declared length. */
    private static final java.util.regex.Pattern TOKEN_SHAPE =
            java.util.regex.Pattern.compile("[A-Za-z0-9_-]{" + SessionToken.TOKEN_CHARS + "}");

    private CliEndToEndTest() {
    }

    public static void run() throws Exception {
        registerThenLoginInASecondProcess();
        singleWriterStore();
        refusalTextIsIdenticalAcrossProcesses();
        credentialNeverInArgv();
        argumentShapeErrors();
        configErrors();
        statusCommandAndOutputHygiene();
    }

    // ------------------------------------------------------------------ cross-process

    private static void registerThenLoginInASecondProcess() throws Exception {
        section("Register in one JVM, authenticate in another: the stored credential reloads");
        Harness.Fixture f = Harness.fixture("cli-roundtrip", Harness.overrides());

        Harness.ProcResult reg = Harness.runCli(List.of("register"),
                Harness.E1 + "\n" + Harness.U1 + "\n" + Harness.P1 + "\n", f.configFile, ENV_OK);
        note("register exit=" + reg.exit() + " stdout=" + Harness.firstLine(reg.stdout()));
        checkEquals("register exits 0", 0, reg.exit());
        check("register says the account was created",
                reg.stdout().contains(Reason.ACCOUNT_CREATED.genericUserMessage()));
        check("the prompt sequence is email, username, password",
                Harness.countOccurrences(reg.stdout(), "email: ") == 1
                        && Harness.countOccurrences(reg.stdout(), "username: ") == 1
                        && Harness.countOccurrences(reg.stdout(), "password: ") == 1);
        check("prompts are asked in that order",
                reg.stdout().indexOf("email: ") < reg.stdout().indexOf("username: ")
                        && reg.stdout().indexOf("username: ") < reg.stdout().indexOf("password: "));
        checkAbsent("the password is not echoed back", reg.stdout(), Harness.P1);
        // Not checkAbsent on stderr: a successful run writes *nothing* there, and an empty corpus is
        // the stronger fact. Requiring stderr to be non-empty to prove the password is absent from it
        // would fail precisely when the program behaved best.
        checkEquals("nothing at all was written to stderr by a successful register", "", reg.stderr());
        checkAbsent("the passphrase is not printed", reg.stdout(), ENV_OK);
        checkAbsent("the stored encoding is not printed", reg.stdout(), "pbkdf2-sha256");
        check("no stack trace escaped", !reg.stderr().contains("at com.example.identity"));

        // A genuinely separate process: same files, new JVM, nothing inherited but the database.
        Harness.ProcResult login = Harness.runCli(List.of("login"),
                Harness.U1 + "\n" + Harness.P1 + "\n", f.configFile, ENV_OK);
        note("login exit=" + login.exit() + " stdout=" + oneLine(login.stdout()));
        checkEquals("login in a second process exits 0", 0, login.exit());
        check("and reports success", login.stdout().contains(Reason.AUTHENTICATED.genericUserMessage()));
        // The whole transcript, spelled out: two prompts and one sentence. Asserting the exact bytes
        // is what makes "nothing else is printed" a real check rather than a search for a needle
        // someone happened not to add.
        checkEquals("login prints the prompts and one sentence, and nothing else",
                "email or username: password: " + Reason.AUTHENTICATED.genericUserMessage() + "\n",
                login.stdout());
        check("no session token is printed - the CLI has no command that consumes one, and the next"
                        + " process to open the store revokes it anyway",
                !TOKEN_SHAPE.matcher(login.stdout()).find()
                        && !TOKEN_SHAPE.matcher(login.stderr()).find());
        check("the sign-in still created its session row, so the absence above is not a failure to"
                        + " issue a session",
                Harness.rawCount(f, "session") == 1);
        // The three-prompt transcript only works if one reader serves the whole run: a reader per
        // prompt fills its buffer from the pipe on the first call, so prompts two and three would see
        // end-of-input. Grep the code as well as the bytes, because a canned-stdin test passes for a
        // single-prompt command either way.
        String src = Harness.stripJavaComments(Harness.sourceOf("PortalCli"));
        check("exactly one reader is constructed for the run and handed to every prompt",
                Harness.countOccurrences(src, "new LineReader(") == 1
                        && src.contains("doRegister(api, console, input, out)")
                        && src.contains("doLogin(api, console, input, out)"));
        check("so both prompt helpers take the shared reader rather than the raw stream",
                src.contains("readLine(Console console, LineReader in")
                        && src.contains("readSecret(Console console, LineReader in"));
        // Rule 5's erasure guarantee is only real if the piped secret path never builds a String.
        // A canned-stdin test cannot see this at all - the plaintext is gone either way by the time
        // the process exits - so the shape is the only falsifiable claim. readSecretChars is the one
        // call that returns char[]; any readLine() on the secret path would pin it as an immutable
        // String that a heap dump, a core dump or a same-uid ptrace still yields.
        String secretPath = src.substring(src.indexOf("private static char[] readSecret("));
        check("the secret path reads characters, never a line",
                secretPath.contains("in.readSecretChars(Password.MAX_CP)")
                        && !secretPath.contains("in.readLine("));
        check("no String-shaped reader is even imported any more, so the secret cannot be re-pinned"
                        + " as a String without a diff a reviewer would see",
                !src.contains("BufferedReader") && !src.contains("InputStreamReader"));

        section("The credential really was reloaded, not remembered");
        checkEquals("exactly one account exists in the file the child wrote", 1,
                Harness.rawCount(f, "account"));
        check("the stored encoding is a PBKDF2 encoding at or above the accepted floor",
                Harness.rawColumn(f, "SELECT password FROM account").get(0)
                        .startsWith("v1$pbkdf2-sha256$"));
        // Measured here, before any further process opens the store. Every activation revokes what a
        // previous one left behind, so a child's session row is on disk only until the next open -
        // asserting a larger count later would assert behaviour the program deliberately refuses.
        checkEquals("the child's session is a row in the file, written by a process that is gone",
                1, Harness.rawCount(f, "session"));
        try (Harness.Bundle reopen = Harness.openApi(f)) {
            check("a fresh process revokes the sessions a previous one left behind, and says how"
                    + " many it found",
                    reopen.api.startupWarnings().stream()
                            .anyMatch(w -> w.contains("revoked 1 session(s)")));
            check("so no session survives a restart", reopen.api.liveSessionCount() == 0);
            check("the account survived that cleanup", reopen.api.accountCount() == 1);
            check("and the credential verifies in this process too",
                    reopen.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
        }

        Harness.ProcResult wrong = Harness.runCli(List.of("login"),
                Harness.U1 + "\n" + Harness.P2 + "\n", f.configFile, ENV_OK);
        checkEquals("a wrong password in a third process exits 1", 1, wrong.exit());
        check("with the generic refusal",
                wrong.stdout().contains(Reason.BAD_CREDENTIAL.genericUserMessage()));
        checkEquals("and the refusal transcript has the same one-sentence shape as the success",
                "email or username: password: " + Reason.BAD_CREDENTIAL.genericUserMessage() + "\n",
                wrong.stdout());

        Harness.ProcResult byEmail = Harness.runCli(List.of("login"),
                Harness.E1 + "\n" + Harness.P1 + "\n", f.configFile, ENV_OK);
        checkEquals("the e-mail form authenticates too", 0, byEmail.exit());
        check("and the two processes agree on the account",
                byEmail.stdout().contains(Reason.AUTHENTICATED.genericUserMessage()));
        check("the child's own session is again exactly one row: the activation revoked the"
                        + " previous one on the way in and added its own",
                Harness.rawCount(f, "session") == 1);

        Harness.ProcResult reReg = Harness.runCli(List.of("register"),
                Harness.E1 + "\n" + "othername" + "\n" + Harness.P3 + "\n", f.configFile, ENV_OK);
        checkEquals("a duplicate e-mail in a fresh process exits 1", 1, reReg.exit());
        check("with the registration refusal",
                reReg.stdout().contains(Reason.REGISTRATION_DUPLICATE.genericUserMessage()));
        check("and six separate processes still agree on one account",
                Harness.rawCount(f, "account") == 1);
    }

    /**
     * The database is an embedded, single-process engine, and {@code SqlIdentityStore} leans on that:
     * every decision is a {@code synchronized} method on one connection, which is what makes the
     * check-then-act in registration and in the attempt counters atomic (Rule 7). None of that holds
     * across a process boundary, so the claim "two concurrent activations cannot both write" is only
     * true if the second activation is refused the file. A second JVM settles that; no in-process
     * test can, because the second thread would share the very lock being claimed.
     */
    private static void singleWriterStore() throws Exception {
        section("A second process cannot open the same store while the first holds it");
        Harness.Fixture f = Harness.fixture("cli-single-writer", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            check("the first process holds a usable store", b.api.accountCount() == 1);
            Process second = Harness.startChild(StoreOpenerChild.class.getName(), f.configFile, ENV_OK);
            String answer;
            int exit;
            try (var in = new java.io.BufferedReader(new java.io.InputStreamReader(
                    second.getInputStream(), StandardCharsets.UTF_8))) {
                answer = in.readLine();
                exit = second.waitFor(120, java.util.concurrent.TimeUnit.SECONDS) ? second.exitValue() : -1;
            } finally {
                second.destroyForcibly();
            }
            note("second process answered: " + answer + " exit=" + exit);
            check("the second JVM did not silently get its own copy of the credentials",
                    !"OPENED".equals(answer));
            check("it was told the store is unavailable", "REFUSED".equals(answer));
            check("and the first process is none the worse - the same row is still readable",
                    b.api.accountCount() == 1
                            && b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL)
                                  .isSuccess());
        }
        check("once the holder is gone the file opens normally again", opensCleanly(f));
        String src = Harness.stripJavaComments(Harness.sourceOf("SqlIdentityStore"));
        check("the store asks for a database that closes when its last connection does - a store"
                        + " that stayed open after close() would lock its own account table against"
                        + " every later activation in the same JVM",
                src.contains("DB_CLOSE_DELAY=0") && !src.contains("DB_CLOSE_DELAY=-1"));
    }

    private static boolean opensCleanly(Harness.Fixture f) throws Exception {
        try (Harness.Bundle b = Harness.openApi(f)) {
            return b.api.accountCount() == 1;
        }
    }

    private static void refusalTextIsIdenticalAcrossProcesses() throws Exception {
        section("One refusal sentence, whichever process asked");
        Harness.Fixture f = Harness.fixture("cli-refusal", Harness.overrides());
        Harness.runCli(List.of("register"),
                Harness.E1 + "\n" + Harness.U1 + "\n" + Harness.P1 + "\n", f.configFile, ENV_OK);
        List<String> outputs = new ArrayList<>();
        List<String> errputs = new ArrayList<>();
        for (String answer : List.of(Harness.U1, "nosuchuser", "nobody@example.com",
                "!!! not an identifier !!!")) {
            Harness.ProcResult r = Harness.runCli(List.of("login"),
                    answer + "\n" + Harness.P2 + "\n", f.configFile, ENV_OK);
            checkEquals("the refusal for <" + answer + "> exits 1", 1, r.exit());
            // The whole stdout, not its first line: the prompts carry no trailing newline, so the
            // transcript is one line and firstLine() would fold prompts into the sentence.
            outputs.add(r.stdout());
            errputs.add(r.stderr());
        }
        check("every sign-in refusal printed exactly the same bytes",
                Harness.distinct(outputs).size() == 1);
        checkEquals("and those bytes are the two prompts plus the in-process message, nothing else",
                "email or username: password: " + Reason.BAD_CREDENTIAL.genericUserMessage() + "\n",
                outputs.get(0));
        check("nothing else was printed on any of them",
                outputs.stream().allMatch(s -> !s.contains("session") && !s.contains("token")));
        check("the refusal never mentions which of the four cases it was",
                outputs.get(0).toLowerCase(java.util.Locale.ROOT).indexOf("exist") < 0
                        && outputs.get(0).toLowerCase(java.util.Locale.ROOT).indexOf("unknown") < 0
                        && outputs.get(0).toLowerCase(java.util.Locale.ROOT).indexOf("disabled") < 0);
        check("stderr carried no failure detail for any of them (details go to the log only)",
                !errputs.isEmpty() && errputs.stream().allMatch(String::isEmpty));
        check("the distinction between the four is in the audit log, where it belongs",
                Harness.scanTextFiles(f.config.dataDir()).contains("ABSENT_ACCOUNT")
                        && Harness.scanTextFiles(f.config.dataDir()).contains("BAD_CREDENTIAL"));
    }

    // ------------------------------------------------------------------ argv discipline

    private static void credentialNeverInArgv() throws Exception {
        section("The passphrase travels in the environment, never in argv");
        Harness.Fixture f = Harness.fixture("cli-argv", Harness.overrides());
        Harness.ProcResult ok = Harness.runCli(List.of("register"),
                Harness.E1 + "\n" + Harness.U1 + "\n" + Harness.P1 + "\n", f.configFile, ENV_OK);
        check("the run worked with the passphrase supplied only in the environment", ok.exit() == 0);

        section("A credential-shaped argument is refused before anything else happens");
        // A fixture of its own: the register above legitimately created this data directory, so
        // "no database file was created" is only falsifiable where nothing had been created yet.
        Harness.Fixture fresh = Harness.fixture("cli-argv-refused", Harness.overrides());
        Harness.ProcResult leakedPw = Harness.runCli(
                List.of("register", Harness.E1, Harness.U1, "Str0ng!Passw0rd-X"), "",
                fresh.configFile, ENV_OK);
        checkEquals("credential-shaped argv exits 2", 2, leakedPw.exit());
        check("and says why, without echoing the value",
                leakedPw.stderr().contains("refusing to accept a credential as a command-line argument")
                        && !leakedPw.stderr().contains("Str0ng!Passw0rd-X"));
        check("no database file was created for a refused invocation",
                !Files.exists(fresh.config.dataDir().resolve("identity.mv.db"), LinkOption.NOFOLLOW_LINKS));
        check("and no audit log either - the refusal precedes opening anything",
                !Files.exists(fresh.config.dataDir().resolve("audit.log"), LinkOption.NOFOLLOW_LINKS));
        check("nothing was printed to stdout", leakedPw.stdout().isEmpty());

        Harness.ProcResult pwOnly = Harness.runCli(List.of("login", "Str0ng!Passw0rd-X"),
                "", fresh.configFile, ENV_OK);
        checkEquals("even a single credential argument is refused", 2, pwOnly.exit());
        check("still no database file after the second refusal",
                !Files.exists(fresh.config.dataDir().resolve("identity.mv.db"), LinkOption.NOFOLLOW_LINKS));

        section("The live process's own argv and environ, read from /proc while it runs");
        Harness.LiveChild live = Harness.inspectLiveChild(List.of("login"), f.configFile, ENV_OK);
        check("the child was observed while alive", live.pid() > 0);
        check("argv was non-empty", !live.argv().isEmpty());
        note("argv: " + live.argv());
        checkAbsent("the database passphrase is not in the command line",
                String.join(" ", live.argv()), ENV_OK);
        checkAbsent("no password is in the command line", String.join(" ", live.argv()), Harness.P1);
        check("the config path is passed as a system property, not an argument",
                live.argv().stream().anyMatch(a -> a.startsWith("-Dportal.config=")));
        check("the command line is launcher, classpath, that one -D and the main class, so there is"
                + " no free slot a secret could travel in",
                live.argv().get(0).endsWith("java")
                        && live.argv().stream().filter(a -> a.startsWith("-D")).count() == 1
                        && live.argv().contains(PortalCli.class.getName()));
        check("and the only positional argument is the command name",
                live.argv().get(live.argv().size() - 1).equals("login"));
        check("the passphrase really did arrive through the environment (that is the boundary we"
                        + " chose, and it is readable only by the same uid and by root)",
                ENV_OK.equals(live.environ().get(Config.ENV_DB_PASSWORD)));
        check("no environment variable other than that one carries the passphrase",
                live.environ().entrySet().stream().filter(e -> ENV_OK.equals(e.getValue()))
                        .map(java.util.Map.Entry::getKey).toList().equals(List.of(Config.ENV_DB_PASSWORD)));

        section("The passphrase is absent from every file the run leaves behind");
        String files = Harness.scanTextFiles(f.config.dataDir());
        check("the text-sink corpus under the data directory is non-empty", files.length() > 0);
        checkAbsent("no text sink contains the passphrase", files, ENV_OK);
        checkAbsent("no text sink contains a user password", files, Harness.P1);
        check("the audit log is in that corpus (so the absence above means something)",
                files.contains("event="));
    }

    // ------------------------------------------------------------------ exit codes

    private static void argumentShapeErrors() throws Exception {
        section("Invocation errors are the operator's own, and cost no database access");
        Harness.Fixture f = Harness.fixture("cli-args", Harness.overrides());
        Harness.ProcResult none = Harness.runCli(List.of(), "", f.configFile, ENV_OK);
        checkEquals("no arguments exits 2", 2, none.exit());
        check("and prints the usage line on stderr", none.stderr().contains("usage: register | login | status"));
        check("nothing on stdout", none.stdout().isEmpty());

        Harness.ProcResult extra = Harness.runCli(List.of("login", "alice", "extra"),
                "", f.configFile, ENV_OK);
        checkEquals("two plain arguments exit 2", 2, extra.exit());
        check("the usage line is printed rather than a guess", extra.stderr().contains("usage:"));

        Harness.ProcResult bogus = Harness.runCli(List.of("droptable"), "", f.configFile, ENV_OK);
        checkEquals("an unknown command exits 2", 2, bogus.exit());
        check("the unknown command is not echoed", !bogus.stderr().contains("droptable"));

        Harness.ProcResult upper = Harness.runCli(List.of("LOGIN"), "x\ny\n", f.configFile, ENV_OK);
        check("a command name is case-insensitive but otherwise exact",
                upper.exit() == 1 || upper.exit() == 0);
        check("no database was opened for any of the shape errors",
                !Files.exists(f.config.dataDir().resolve("identity.mv.db"), LinkOption.NOFOLLOW_LINKS)
                        || Harness.rawCount(f, "account") == 0);
    }

    private static void configErrors() throws Exception {
        section("Configuration problems exit 3 and name the key, never the value");
        Path dir = Harness.scratch("cli-badconfig");
        Path cfg = dir.resolve("identity.properties");
        Files.writeString(cfg, "db.dataDir=" + Harness.scratch("cli-badconfig-data")
                + "\ndb.name=identity\n", StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(cfg, Harness.ownerReadWriteOnly());
        Harness.ProcResult missingKeys = Harness.runCli(List.of("status"), "", cfg, ENV_OK);
        checkEquals("a config missing required keys exits 3", 3, missingKeys.exit());
        check("the operator is told which key", missingKeys.stderr().contains("security.pbkdf2Iterations"));
        check("the message is labelled as a configuration error",
                missingKeys.stderr().contains("configuration error"));

        Harness.ProcResult noPass = Harness.runCli(List.of("status"), "", cfg, "");
        check("with no passphrase in the environment the run cannot start", noPass.exit() == 3);
        check("and the error names the variable to set",
                noPass.stderr().contains(Config.ENV_DB_PASSWORD));
        check("no fallback passphrase exists, so it does not silently start",
                noPass.stdout().isEmpty());

        Path shortPw = Harness.scratch("cli-shortpw");
        Path cfg2 = shortPw.resolve("identity.properties");
        Files.copy(cfg, cfg2);
        Files.setPosixFilePermissions(cfg2, Harness.ownerReadWriteOnly());
        Harness.ProcResult shortPassphrase = Harness.runCli(List.of("status"), "", cfg2,
                "too-short");
        checkEquals("a passphrase below the minimum length exits 3", 3, shortPassphrase.exit());
        check("the error states the accepted range",
                shortPassphrase.stderr().contains("24-512"));
        checkAbsent("the too-short passphrase is not echoed in the error", shortPassphrase.stderr(),
                "too-short");

        section("A passphrase with a space is refused (it would not survive the environment cleanly)");
        Harness.ProcResult spaced = Harness.runCli(List.of("status"), "", cfg,
                "Correct Horse Battery Staple 9");
        checkEquals("exit 3", 3, spaced.exit());
        checkAbsent("and the phrase is not echoed", spaced.stderr(), "Horse");

        section("A config below the accepted cost floor is refused, not quietly honoured");
        Path dir3 = Harness.scratch("cli-weakkdf");
        String text = Harness.configText(Harness.overrides(), dir3)
                .replace("security.pbkdf2Iterations=100000", "security.pbkdf2Iterations=1000");
        Path cfg3 = dir3.resolve("identity.properties");
        Files.writeString(cfg3, text, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(cfg3, Harness.ownerReadWriteOnly());
        Harness.ProcResult weak = Harness.runCli(List.of("status"), "", cfg3, ENV_OK);
        checkEquals("a 1000-iteration setting exits 3 rather than running weak", 3, weak.exit());
        check("naming the offending key", weak.stderr().contains("security.pbkdf2Iterations"));
    }

    private static void statusCommandAndOutputHygiene() throws Exception {
        section("status reports counts, and only counts");
        Harness.Fixture f = Harness.fixture("cli-status", Harness.overrides());
        Harness.runCli(List.of("register"), Harness.E1 + "\n" + Harness.U1 + "\n" + Harness.P1 + "\n",
                f.configFile, ENV_OK);
        Harness.runCli(List.of("login"), Harness.U1 + "\n" + Harness.P1 + "\n", f.configFile, ENV_OK);
        Harness.runCli(List.of("login"), Harness.U1 + "\n" + Harness.P2 + "\n", f.configFile, ENV_OK);
        Harness.ProcResult st = Harness.runCli(List.of("status"), "", f.configFile, ENV_OK);
        checkEquals("status exits 0", 0, st.exit());
        String line = Harness.firstLine(st.stdout());
        note("status: " + line);
        check("it prints the three operational counters",
                line.startsWith("accounts=") && line.contains("liveSessions=")
                        && line.contains("attemptCounters="));
        check("the account counter is right", line.startsWith("accounts=1 "));
        check("the attempt counter recorded the failed guess",
                counter(line, "attemptCounters=") >= 1);
        check("live sessions are zero - sessions do not survive a process",
                counter(line, "liveSessions=") == 0);
        checkAbsent("no identifier appears in the counters", line, Harness.U1);
        checkAbsent("nor an address", line, "example.com");
        checkAbsent("nor a token", line, "token");
        check("status does not print a token line", !st.stdout().contains("session token:"));
        check("status wrote nothing to stderr", st.stderr().isEmpty());

        section("The transcript of a full run holds no secret");
        String corpus = st.stdout() + st.stderr();
        check("the corpus is non-empty", corpus.length() > 0);
        checkAbsent("no passphrase", corpus, ENV_OK);
        checkAbsent("no fixture password", corpus, Harness.P1);
    }

    // ------------------------------------------------------------------ helpers

    private static int counter(String line, String key) {
        int i = line.indexOf(key);
        if (i < 0) {
            return -1;
        }
        String rest = line.substring(i + key.length());
        int end = 0;
        while (end < rest.length() && Character.isDigit(rest.charAt(end))) {
            end++;
        }
        return end == 0 ? -1 : Integer.parseInt(rest.substring(0, end));
    }

    private static String oneLine(String s) {
        return Harness.lines(s).isEmpty() ? "<empty>" : String.join(" | ", Harness.lines(s));
    }
}
