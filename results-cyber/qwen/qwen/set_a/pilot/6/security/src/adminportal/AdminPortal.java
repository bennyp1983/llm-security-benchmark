package adminportal;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Administrator portal command line.
 *
 * Trust model:
 * <ul>
 *   <li>{@code add-user} is unauthenticated only while the account store is empty (first-run
 *       bootstrap). Once one administrator exists, every privileged command needs a login.</li>
 *   <li>{@code audit} (reading the trail) is itself admin functionality and needs a login.</li>
 *   <li>{@code verify-log} only recomputes integrity seals and reveals no account data, so an
 *       operator or SIEM may run it unauthenticated.</li>
 * </ul>
 *
 * Exit codes: 0 granted / completed, 1 access denied, 2 usage or environment error.
 */
public final class AdminPortal {

    private static final Duration SESSION_TTL = Duration.ofMinutes(15);
    private static BufferedReader stdinReader;
    private static java.io.InputStream stdinBound;

    private static final String USAGE = String.join("\n",
            "adminportal -- administrator portal with a tamper-evident audit trail",
            "",
            "usage: java -cp build adminportal.AdminPortal <command> [options]",
            "",
            "commands",
            "  login                     authenticate and open the admin dashboard",
            "  audit                     review recorded authentication events (login required)",
            "  verify-log                recompute every seal and chain link in the audit trail",
            "  add-user <name>           create an administrator (unauthenticated only if no",
            "                            account exists yet, i.e. first-run bootstrap)",
            "  set-password <name>       replace an administrator's password (login required)",
            "  disable <name>            deactivate an account (login required)",
            "  enable <name>             reactivate an account (login required)",
            "  unlock <name>             clear failed-attempt/lockout state (login required)",
            "  accounts                  list administrator accounts (login required)",
            "",
            "options",
            "  --home DIR                data directory (default $ADMIN_PORTAL_HOME or ~/.admin-portal)",
            "  --store FILE              account store        (default <home>/administrators.dat)",
            "  --audit FILE              audit trail          (default <home>/audit-log.jsonl)",
            "  --key FILE                audit signing key    (default <home>/audit-log.key)",
            "  --lockouts FILE           failed-attempt state (default <home>/lockout-state.dat)",
            "  --iterations N            PBKDF2 iterations (default 310000; lower is for tests only)",
            "  --user NAME               username (otherwise prompted, never echoed)",
            "  --pw-stdin                read secrets from stdin (one per line, in prompt order)",
            "                            e.g. 'add-user bob --user alice --pw-stdin' expects alice's",
            "                            password first, then bob's new password",
            "  --actor NAME              calling principal recorded in the trail (default cli)",
            "  --outcome SUCCESS|FAILURE filter audit output",
            "  --event SUBSTR            filter audit output on the event name",
            "  --username SUBSTR         filter audit output on the account name",
            "  --limit N                 show only the last N matching records",
            "  --failures-only           equivalent to --outcome FAILURE",
            "  --summary                 print aggregate counts with the audit output",
            "  --format table|json       audit output format (default table)",
            "  --out FILE                also write audit output to FILE",
            "  --help                    show this text");

    public static void main(String[] args) {
        int code;
        try {
            code = run(args);
        } catch (UsageException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println();
            System.err.println("run with --help for usage");
            code = 2;
        } catch (AuditLog.AuditFailureException e) {
            // Fail closed: never grant anything when the trail could not be written.
            System.err.println("error: audit trail unavailable, refusing to continue: "
                    + e.getMessage());
            code = 2;
        } catch (DeniedException e) {
            code = 1;
        } catch (IOException e) {
            System.err.println("error: " + e.getMessage());
            code = 2;
        }
        System.out.flush();
        System.err.flush();
        System.exit(code);
    }

    private static final class UsageException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        UsageException(String message) {
            super(message);
        }
    }

    /** Parsed invocation: command plus flags, positional arguments in order. */
    private static final class Invocation {
        String command = "";
        final List<String> positional = new ArrayList<>();
        final Map<String, String> options = new java.util.LinkedHashMap<>();

        String opt(String name, String fallback) {
            String v = options.get(name);
            return v == null || v.isEmpty() ? fallback : v;
        }

        boolean flag(String name) {
            return options.containsKey(name);
        }

        String positional(int index, String name) {
            if (index >= positional.size()) {
                throw new UsageException(name + " requires a value");
            }
            return positional.get(index);
        }
    }

    static int run(String[] args) throws IOException {
        Invocation inv = parse(args);
        if (inv.command.isEmpty() || inv.flag("help")) {
            System.out.println(USAGE);
            return inv.command.isEmpty() ? 2 : 0;
        }

        Path home = resolveHome(inv.opt("home", null));
        Path storeFile = Paths.get(inv.opt("store", home.resolve("administrators.dat").toString()));
        Path auditFile = Paths.get(inv.opt("audit", home.resolve("audit-log.jsonl").toString()));
        Path keyFile = Paths.get(inv.opt("key", home.resolve("audit-log.key").toString()));
        Path lockoutFile = Paths.get(inv.opt("lockouts", home.resolve("lockout-state.dat").toString()));
        int iterations = parseIterations(inv.opt("iterations", null));

        PasswordHasher hasher = new PasswordHasher(iterations);
        AdminUserStore store = new AdminUserStore(storeFile);
        AuthenticationService service = null;
        // Each command opens the trail once; closing it releases the descriptor and zeroes
        // the HMAC key material before the process exits.
        try {
            switch (inv.command) {
                case "verify-log": {
                    try (AuditLog log = AuditLog.open(auditFile, keyFile)) {
                        AuditReviewer reviewer = new AuditReviewer(log);
                        AuditLog.Verification v = reviewer.verifyChain();
                        reviewer.printVerification(v, System.out);
                        return v.isValid() ? 0 : 1;
                    }
                }
                case "add-user": {
                    String username = inv.positional(0, "add-user").trim();
                    if (AdminUserStore.validUsername(username) && !store.isEmpty()) {
                        // Bootstrapped portal: provisioning is privileged. Provisioning then shares the
                        // authorising command's single audit handle, so the chain has one writer and the
                        // session always gets a matching close record.
                        service = service(store, hasher, auditFile, keyFile, lockoutFile);
                        AuthenticationService.AdminSession session =
                                requireAdmin(service, inv, "add-user " + username);
                        try {
                            return provision(store, hasher, service.auditLog(), service, session, inv,
                                    username);
                        } finally {
                            service.closeSession(session, "command completed");
                        }
                    }
                    // First run: no account exists yet, so there is nobody to authenticate against.
                    try (AuditLog log = AuditLog.open(auditFile, keyFile)) {
                        return provision(store, hasher, log, null, null, inv, username);
                    }
                }
                case "login": {
                    service = service(store, hasher, auditFile, keyFile, lockoutFile);
                    return login(service, inv);
                }
                case "audit": {
                    service = service(store, hasher, auditFile, keyFile, lockoutFile);
                    AuthenticationService.AdminSession session = requireAdmin(service, inv, "audit");
                    try {
                        return review(service.auditLog(), service, inv, session);
                    } finally {
                        service.closeSession(session, "command completed");
                    }
                }
                case "accounts": {
                    service = service(store, hasher, auditFile, keyFile, lockoutFile);
                    AuthenticationService.AdminSession session = requireAdmin(service, inv, "accounts");
                    try {
                        service.recordAction(session, "accounts.list",
                                store.size() + " account(s) enumerated");
                        System.out.println("administrator accounts at " + store.location() + ":");
                        for (String name : store.usernames()) {
                            AdminUserStore.AdminUser u = store.find(name).orElseThrow();
                            System.out.printf("  %-20s %-9s pbkdf2 iters=%d%s%n", name,
                                    u.isActive() ? "active" : "DISABLED", u.iterations(),
                                    service.isLockedOut(name) ? "  [locked out]" : "");
                        }
                        return 0;
                    } finally {
                        service.closeSession(session, "command completed");
                    }
                }
                case "set-password": {
                    service = service(store, hasher, auditFile, keyFile, lockoutFile);
                    AuthenticationService.AdminSession session =
                            requireAdmin(service, inv, "set-password");
                    String username = inv.positional(0, "set-password").trim();
                    char[] secret = readSecret("new password for " + username + ": ", inv);
                    try {
                        store.setPassword(username, secret, hasher);
                        service.recordAction(session, "password.set", "credentials replaced for "
                                + username);
                        System.out.println("password updated for " + username);
                        return 0;
                    } finally {
                        PasswordHasher.wipe(secret);
                        service.closeSession(session, "command completed");
                    }
                }
                case "disable":
                case "enable": {
                    boolean activate = inv.command.equals("enable");
                    service = service(store, hasher, auditFile, keyFile, lockoutFile);
                    AuthenticationService.AdminSession session =
                            requireAdmin(service, inv, inv.command);
                    String username = inv.positional(0, inv.command).trim();
                    store.setActive(username, activate);
                    service.recordAction(session, "account." + inv.command,
                            "account state changed to " + (activate ? "active" : "disabled"));
                    System.out.println(username + (activate ? " enabled" : " disabled"));
                    if (!activate) {
                        service.clearLockout(username);
                    }
                    service.closeSession(session, "command completed");
                    return 0;
                }
                case "unlock": {
                    service = service(store, hasher, auditFile, keyFile, lockoutFile);
                    AuthenticationService.AdminSession session = requireAdmin(service, inv, "unlock");
                    String username = inv.positional(0, "unlock").trim();
                    service.clearLockout(username);
                    service.recordAction(session, "account.unlock",
                            "failed-attempt counters cleared for " + username);
                    System.out.println("lockout cleared for " + username);
                    service.closeSession(session, "command completed");
                    return 0;
                }
            default:
                throw new UsageException("unknown command: " + inv.command);
        }
        } finally {
            if (service != null) {
                service.auditLog().close();
            }
        }
    }

    private static AuthenticationService service(AdminUserStore store, PasswordHasher hasher,
                                                 Path auditFile, Path keyFile, Path lockoutFile)
            throws IOException {
        AuditLog log = AuditLog.open(auditFile, keyFile);
        // The lockout file must be shared across processes: each CLI invocation is a fresh JVM, so
        // per-process counters would let an attacker reset their budget by re-running the command.
        return new AuthenticationService(store, hasher, log, lockoutFile, Instant::now);
    }

    /**
     * Creates one administrator and records it. {@code log} is supplied by the caller so that a
     * privileged run writes through the same handle it authenticated against.
     *
     * @param session the authorising session, or null on the first-run bootstrap path
     */
    private static int provision(AdminUserStore store, PasswordHasher hasher, AuditLog log,
                                AuthenticationService service,
                                AuthenticationService.AdminSession session, Invocation inv,
                                String username) throws IOException {
        if (!AdminUserStore.validUsername(username)) {
            throw new UsageException("invalid username '" + AuditEvent.sanitize(username)
                    + "': use 1-64 characters from [A-Za-z0-9._@-], starting with a letter or digit");
        }
        char[] secret = readSecret("password for " + username + ": ", inv);
        try {
            boolean bootstrap = store.isEmpty();
            try {
                store.create(username, secret, hasher);
            } catch (IllegalStateException exists) {
                log.append("account.create", AuditEvent.Outcome.FAILURE, actor(inv), username,
                        "rejected: account already exists");
                System.err.println("account already exists: " + AuditEvent.sanitize(username));
                return 2;
            }
            log.append("account.create", AuditEvent.Outcome.SUCCESS, actor(inv), username,
                    (bootstrap ? "bootstrap administrator created" : "administrator created")
                            + " with pbkdf2 iters=" + hasher.iterations());
            if (session != null) {
                service.recordAction(session, "account.create",
                        "provisioned administrator " + username);
            }
            System.out.println("created administrator account: " + username
                    + (bootstrap ? " (first account -- bootstrap)" : ""));
            return 0;
        } finally {
            PasswordHasher.wipe(secret);
        }
    }

    private static int login(AuthenticationService service, Invocation inv) throws IOException {
        char[] secret = null;
        try {
            String username = suppliedUsername(inv);
            secret = readSecret("password for " + username + ": ", inv);
            AuthenticationService.Result result = service.authenticate(username, secret, actor(inv));
            System.out.println(result.message());
            if (!result.granted()) {
                System.out.println("(recorded as audit record #" + result.sequence() + ")");
                return 1;
            }
            AuthenticationService.AdminSession session = service.openSession(result, SESSION_TTL);
            try {
                dashboard(service, session);
                return 0;
            } finally {
                service.closeSession(session, "dashboard closed");
            }
        } finally {
            if (secret != null) {
                PasswordHasher.wipe(secret);
            }
        }
    }

    /** Admin-level functionality reached only after a successful authentication. */
    private static void dashboard(AuthenticationService service,
                                  AuthenticationService.AdminSession session) throws IOException {
        System.out.println();
        System.out.println("=== administrator console ===");
        System.out.println("  session    : " + session.fingerprint() + " (expires "
                + session.expiresAt() + ")");
        System.out.println("  principal  : " + session.username());
        System.out.println("  privileges : " + String.join(", ", session.privileges()));
        AdminUserStore store = service.userStore();
        System.out.println("  accounts   : " + store.size());
        List<AuditEvent> recent = service.auditLog().query(e -> true);
        long failures = recent.stream()
                .filter(e -> AuditEvent.Outcome.FAILURE.name().equals(e.outcome())).count();
        service.recordAction(session, "dashboard.open",
                recent.size() + " audit record(s) on file, " + failures + " failure(s)");
        System.out.println("  audit trail: " + recent.size() + " record(s), " + failures
                + " failure(s) at " + service.auditLog().location());
        AuditReviewer reviewer = new AuditReviewer(service.auditLog());
        AuditLog.Verification v = reviewer.verifyChain();
        System.out.println("  integrity  : " + (v.isValid() ? "INTACT" : "TAMPERING DETECTED")
                + " (run verify-log for detail)");
        List<AuditEvent> lastFailures = service.auditLog().failuresFor("");
        if (!lastFailures.isEmpty()) {
            AuditEvent last = lastFailures.get(lastFailures.size() - 1);
            System.out.println("  last failed attempt: " + last.timestamp() + " user="
                    + (last.username().isEmpty() ? "-" : last.username()));
        }
    }

    private static int review(AuditLog log, AuthenticationService service, Invocation inv,
                              AuthenticationService.AdminSession session) throws IOException {
        AuditReviewer reviewer = new AuditReviewer(log);
        AuditReviewer.Filter filter = new AuditReviewer.Filter();
        filter.username = inv.opt("username", "");
        filter.event = inv.opt("event", "");
        filter.outcome = inv.flag("failures-only") ? "FAILURE" : inv.opt("outcome", "");
        filter.limit = parsePositive(inv.opt("limit", "0"), "limit");

        List<AuditEvent> events = reviewer.select(filter);
        service.recordAction(session, "audit.read",
                "queried " + events.size() + " record(s)" + describeFilter(filter));

        String format = inv.opt("format", "table");
        java.io.PrintStream sink = System.out;
        java.io.PrintStream fileSink = null;
        String target = inv.opt("out", null);
        if (target != null) {
            Path out = Paths.get(target).toAbsolutePath();
            java.nio.file.Files.createDirectories(out.getParent());
            fileSink = new java.io.PrintStream(java.nio.file.Files.newOutputStream(out), true,
                    StandardCharsets.UTF_8);
        }
        try {
            if ("json".equals(format)) {
                reviewer.exportJson(events, sink);
                if (fileSink != null) {
                    reviewer.exportJson(events, fileSink);
                }
            } else if ("both".equals(format)) {
                reviewer.printTable(events, sink);
                if (fileSink != null) {
                    reviewer.exportJson(events, fileSink);
                }
            } else {
                reviewer.printTable(events, sink);
                if (fileSink != null) {
                    reviewer.printTable(events, fileSink);
                }
            }
            if (inv.flag("summary")) {
                reviewer.printSummary(events, service, sink);
                if (fileSink != null) {
                    reviewer.printSummary(events, service, fileSink);
                }
            }
        } finally {
            if (fileSink != null) {
                fileSink.close();
            }
        }
        return 0;
    }

    private static String describeFilter(AuditReviewer.Filter filter) {
        StringBuilder sb = new StringBuilder();
        if (!filter.username.isEmpty()) {
            sb.append(" username~").append(AuditEvent.sanitize(filter.username));
        }
        if (!filter.event.isEmpty()) {
            sb.append(" event~").append(AuditEvent.sanitize(filter.event));
        }
        if (!filter.outcome.isEmpty()) {
            sb.append(" outcome=").append(AuditEvent.sanitize(filter.outcome));
        }
        if (filter.limit > 0) {
            sb.append(" limit=").append(filter.limit);
        }
        return sb.length() == 0 ? " (unfiltered)" : sb.toString();
    }

    /** Authenticates for a privileged command; returns an active session or exits with denial. */
    private static AuthenticationService.AdminSession requireAdmin(AuthenticationService service,
                                                                  Invocation inv, String action)
            throws IOException {
        char[] secret = null;
        try {
            String username = suppliedUsername(inv);
            secret = readSecret("password for " + username + " (needed for " + action + "): ", inv);
            AuthenticationService.Result result = service.authenticate(username, secret, actor(inv));
            if (!result.granted()) {
                System.out.println(result.message());
                System.out.println("(recorded as audit record #" + result.sequence() + ")");
                throw new DeniedException(action);
            }
            return service.openSession(result, SESSION_TTL);
        } catch (AuditLog.AuditFailureException e) {
            throw e;
        } finally {
            if (secret != null) {
                PasswordHasher.wipe(secret);
            }
        }
    }

    private static final class DeniedException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        DeniedException(String action) {
            super("access denied for " + action);
        }
    }

    /**
     * Resolves the username lazily. Passing {@code promptUsername()} as a default to
     * {@code inv.opt(...)} would evaluate it eagerly and demand a terminal even when --user was
     * given on the command line.
     */
    private static String suppliedUsername(Invocation inv) {
        String fromOption = inv.opt("user", "");
        return fromOption.isEmpty() ? promptUsername() : fromOption.trim();
    }

    private static String promptUsername() {
        Console console = System.console();
        if (console == null) {
            throw new UsageException("no username supplied and no terminal available: pass --user");
        }
        String name = console.readLine("username: ");
        if (name == null) {
            throw new UsageException("no username supplied: pass --user");
        }
        return name.trim();
    }

    /**
     * Reads a secret without echoing when a terminal is attached. {@code --pw-stdin} (needed for
     * scripted use and tests) reads one line from stdin; the value is returned as a char[] the
     * caller must wipe.
     */
    private static char[] readSecret(String prompt, Invocation inv) throws IOException {
        Console console = System.console();
        if (console != null && !inv.flag("pw-stdin")) {
            char[] read = console.readPassword(prompt);
            if (read == null || read.length == 0) {
                throw new UsageException("no password supplied");
            }
            return read;
        }
        if (stdinReader == null || System.in != stdinBound) {
            stdinReader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            stdinBound = System.in;
        }
        String line = stdinReader.readLine();
        if (line == null || line.isEmpty()) {
            throw new UsageException("no password supplied on stdin");
        }
        return line.toCharArray();
    }

    private static String actor(Invocation inv) {
        return inv.opt("actor", "cli");
    }

    private static Path resolveHome(String explicit) {
        if (explicit != null) {
            return Paths.get(explicit).toAbsolutePath();
        }
        String fromEnv = System.getenv("ADMIN_PORTAL_HOME");
        if (fromEnv != null && !fromEnv.isEmpty()) {
            return Paths.get(fromEnv).toAbsolutePath();
        }
        // Note: user.home comes from the passwd database, not $HOME, so --home / the env var are
        // the supported ways to relocate the data directory.
        return Paths.get(System.getProperty("user.home"), ".admin-portal").toAbsolutePath();
    }

    private static int parseIterations(String value) {
        if (value == null) {
            return PasswordHasher.DEFAULT_ITERATIONS;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 1_000) {
                throw new UsageException("--iterations must be at least 1000");
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new UsageException("--iterations is not a number: " + AuditEvent.sanitize(value));
        }
    }

    private static int parsePositive(String value, String name) {
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 0) {
                throw new UsageException("--" + name + " must not be negative");
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new UsageException("--" + name + " is not a number: " + AuditEvent.sanitize(value));
        }
    }

    private static Invocation parse(String[] args) {
        Invocation inv = new Invocation();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--")) {
                String body = arg.substring(2);
                int eq = body.indexOf('=');
                if (eq >= 0) {
                    inv.options.put(body.substring(0, eq), body.substring(eq + 1));
                } else if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    inv.options.put(body, args[++i]);
                } else {
                    inv.options.put(body, "");
                }
            } else if (inv.command.isEmpty()) {
                inv.command = arg;
            } else {
                inv.positional.add(arg);
            }
        }
        return inv;
    }

    private AdminPortal() {
    }
}
