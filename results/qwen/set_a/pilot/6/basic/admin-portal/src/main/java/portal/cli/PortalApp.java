package portal.cli;

import java.nio.file.Path;
import java.nio.file.Paths;

import portal.admin.AdminGate;
import portal.admin.AdminOperations;
import portal.admin.AuditLog;
import portal.admin.AuthenticationConfig;
import portal.admin.AuthenticationService;
import portal.admin.ConsoleAuditLog;
import portal.admin.CredentialStore;
import portal.admin.InMemoryAuditLog;
import portal.admin.SessionManager;
import portal.security.Clock;
import portal.security.PasswordHasher;
import portal.security.PasswordPolicy;

/**
 * Wires the portal together in one place so the authentication path cannot be assembled
 * half-configured: a {@code PortalApp} always has a store, a hasher, a gate and an audit
 * sink, and the session manager and gate always share the same clock and configuration.
 */
public final class PortalApp {

    private final CredentialStore store;
    private final PasswordHasher hasher;
    private final PasswordPolicy policy;
    private final AuthenticationConfig config;
    private final InMemoryAuditLog audit;
    private final AuthenticationService authentication;
    private final SessionManager sessions;
    private final AdminGate gate;
    private final AdminOperations operations;
    private final Clock clock;
    private InteractiveReader defaultReader;

    public PortalApp(Path storeFile, AuthenticationConfig config, PasswordHasher hasher, Clock clock) {
        this(storeFile, config, hasher, clock, null);
    }

    /**
     * @param auditSink where security events go; {@code null} uses a console sink, and the
     *                  in-memory review window is always kept so option 8 works
     */
    public PortalApp(Path storeFile, AuthenticationConfig config, PasswordHasher hasher, Clock clock,
                     AuditLog auditSink) {
        this.clock = clock;
        this.config = config;
        this.store = new CredentialStore(storeFile).load();
        this.hasher = hasher;
        this.policy = new PasswordPolicy();
        this.audit = new InMemoryAuditLog(
                auditSink != null ? auditSink : new ConsoleAuditLog(System.out, false),
                InMemoryAuditLog.DEFAULT_CAPACITY);
        this.authentication = new AuthenticationService(store, hasher, config, audit, clock);
        this.sessions = new SessionManager(config, audit, clock);
        this.gate = new AdminGate(sessions, audit);
        this.operations = new AdminOperations(store, hasher, policy, sessions, gate, audit, clock);
    }

    /** Production wiring with the JDK clock and the shipped PBKDF2 cost. */
    public static PortalApp create(Path storeFile) {
        return new PortalApp(storeFile, AuthenticationConfig.defaults(), new PasswordHasher(), Clock.SYSTEM);
    }

    public static Path defaultStoreFile() {
        String fromEnv = System.getenv("ADMIN_PORTAL_STORE");
        if (fromEnv != null && !fromEnv.trim().isEmpty()) {
            return Paths.get(fromEnv.trim());
        }
        return Paths.get(System.getProperty("user.home", "."), ".admin-portal", "administrators.dat");
    }

    public CredentialStore store() {
        return store;
    }

    public PasswordHasher hasher() {
        return hasher;
    }

    public PasswordPolicy policy() {
        return policy;
    }

    public AuthenticationConfig config() {
        return config;
    }

    public InMemoryAuditLog audit() {
        return audit;
    }

    public AuthenticationService authentication() {
        return authentication;
    }

    public SessionManager sessions() {
        return sessions;
    }

    public AdminGate gate() {
        return gate;
    }

    public AdminOperations operations() {
        return operations;
    }

    public Clock clock() {
        return clock;
    }

    /** Console bound to the given reader. */
    public AdminConsole console(InteractiveReader reader, java.io.PrintStream out) {
        return new AdminConsole(authentication, sessions, operations, gate, reader, out);
    }

    /**
     * The reader for prompts: the installed scripted reader if one was set, otherwise the
     * controlling terminal.
     */
    public InteractiveReader reader(java.io.PrintStream out) {
        return defaultReader != null ? defaultReader : new TerminalReader(out);
    }

    /** Console using {@link #reader}. */
    public AdminConsole console(java.io.PrintStream out) {
        return console(reader(out), out);
    }

    /**
     * Installs the reader used by every prompt. Exists so a scripted run (a test, or a
     * piped provisioning session) can supply input without a tty; the production default is
     * always the terminal reader.
     */
    public PortalApp withReader(InteractiveReader reader) {
        this.defaultReader = reader;
        return this;
    }
}
