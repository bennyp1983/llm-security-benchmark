package com.portal.auth;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;

/**
 * Reference front door for the portal authentication module.
 *
 * <p>Seeds a few accounts and loops on username/password until the operator quits. It doubles as the
 * demonstration of the lockout: enter five wrong passwords for {@code demo} and the sixth attempt is
 * refused without the password being looked at.
 *
 * <p>Passwords are read without echoing where a real terminal is attached ({@link Console}); with
 * piped input (tests, demos) it falls back to a line reader, which does echo. That fallback is for
 * demos only, which is why the seeded accounts below are deliberately low-value.
 */
public final class PortalAuthApp {

    private static final String DEMO_PASSWORD = "Correct-Horse-9";

    private final AuthenticationService auth;
    private final Reader reader;

    PortalAuthApp(AuthenticationService auth, Reader reader) {
        this.auth = auth;
        this.reader = reader;
    }

    public static void main(String[] args) throws IOException {
        LoginPolicy policy = LoginPolicy.DEFAULT;
        if (args.length > 0) {
            try {
                policy = new LoginPolicy(Integer.parseInt(args[0]), policy.failureWindow(),
                        policy.lockDuration(), policy.permanentLockAfterLocks());
            } catch (IllegalArgumentException e) {
                System.err.println("usage: PortalAuthApp [maxFailedAttempts >= 1]  (" + e.getMessage() + ")");
                System.exit(2);
            }
        }
        PortalAuthApp app = build(policy, new TerminalReader());
        System.out.println("Employee portal sign-in (type 'quit' to exit).");
        System.out.println("Demo account: demo / " + DEMO_PASSWORD + "  -- "
                + policy.maxFailedAttempts() + " wrong passwords lock it for "
                + policy.lockDuration().toMinutes() + " minutes.");
        app.run();
    }

    /** Wiring, exposed so the verification harness builds the identical object graph. */
    static PortalAuthApp build(LoginPolicy policy, Reader reader) {
        PasswordHasher hasher = new PasswordHasher(120_000);
        InMemoryCredentialStore store = InMemoryCredentialStore.of(
                new Credential("demo", "Demo Employee",
                        hasher.hash(PasswordHasher.toChars(DEMO_PASSWORD)), UserStatus.ACTIVE, Instant.now()),
                new Credential("jchen", "Jordan Chen",
                        hasher.hash(PasswordHasher.toChars("another-secret-passphrase")), UserStatus.ACTIVE,
                        Instant.now()),
                new Credential("terminated.user", "Ex Employee",
                        hasher.hash(PasswordHasher.toChars("left-the-company")), UserStatus.DISABLED,
                        Instant.now()));
        AuthenticationService auth = new AuthenticationService(
                store, hasher, new LoginAttemptTracker(policy), new ConsoleAuditLog());
        return new PortalAuthApp(auth, reader);
    }

    void run() throws IOException {
        while (true) {
            String username = reader.readLine("username: ");
            if (username == null) {
                System.out.println();
                return;
            }
            if (username.isBlank()) {
                continue;
            }
            if (username.strip().equalsIgnoreCase("quit")) {
                return;
            }
            char[] password = reader.readPassword("password: ");
            if (password == null) {
                System.out.println();
                return;
            }
            System.out.print(render(auth.authenticate(username, password)));
        }
    }

    /**
     * Everything a person sees after one attempt.
     *
     * <p>Derived from {@link LoginResult#outcome()} and the countdown alone, never from
     * {@code accountExists}: printing "attempts remaining" only for names that exist in the store
     * would hand back, through the terminal, the very fact the rest of the module works to hide. The
     * countdown stays identical for a real and an unknown name because both are counted the same way.
     */
    static String render(LoginResult result) {
        StringBuilder out = new StringBuilder("-> ").append(result.userMessage()).append('\n');
        if (result instanceof LoginResult.InvalidCredentials invalid && invalid.attemptsRemaining() > 0) {
            out.append("   attempts remaining before lockout: ").append(invalid.attemptsRemaining()).append('\n');
        }
        return out.toString();
    }

    /** Input boundary, so the loop can be driven by a terminal or by a scripted harness. */
    interface Reader {
        String readLine(String prompt) throws IOException;

        char[] readPassword(String prompt) throws IOException;
    }

    static final class TerminalReader implements Reader {
        private final Console console = System.console();
        private final BufferedReader lines = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));

        @Override
        public String readLine(String prompt) throws IOException {
            if (console != null) {
                return console.readLine(prompt);
            }
            return promptLine(prompt);
        }

        @Override
        public char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                return console.readPassword(prompt);
            }
            String line = promptLine(prompt);
            return line == null ? null : PasswordHasher.toChars(line);
        }

        private String promptLine(String prompt) throws IOException {
            System.out.print(prompt);
            System.out.flush();
            return lines.readLine();
        }
    }

    static {
        Locale.setDefault(Locale.ROOT);
    }
}
