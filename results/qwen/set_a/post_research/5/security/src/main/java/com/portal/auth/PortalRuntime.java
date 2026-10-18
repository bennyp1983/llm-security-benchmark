package com.portal.auth;

import java.nio.file.Path;

/**
 * Wires the pieces together and is the only way a front end obtains them, so the startup
 * checks cannot be skipped.
 *
 * <p>Refuse-only boot: if the data directory is not private, the roster cannot be read
 * under our mode policy, a record is below the KDF floor, the ledger is corrupt, or the
 * audit log cannot be created, this throws and the process exits. There is no mode in
 * which a check fails and authentication continues.
 */
public final class PortalRuntime {

    private final EmployeeStore store;
    private final ThrottleManager throttle;
    private final SessionManager sessions;
    private final Authenticator authenticator;
    private final AuditLog audit;

    /**
     * Package-private so the HTTP suite can drive {@link PortalServer} against the
     * {@link HttpExchangeView} double with a fixture-sized roster. {@link #open} stays the
     * only public construction path, so the refuse-only startup checks cannot be skipped by
     * a real caller.
     */
    PortalRuntime(EmployeeStore store, ThrottleManager throttle, SessionManager sessions,
                  Authenticator authenticator, AuditLog audit) {
        this.store = store;
        this.throttle = throttle;
        this.sessions = sessions;
        this.authenticator = authenticator;
        this.audit = audit;
    }

    public static PortalRuntime open(PortalConfig config) {
        Path dir = PrivateFiles.requireDataDirectory(config.dataDir());
        AuditLog audit = new AuditLog(dir.resolve("audit.log"));
        PasswordHasher hasher = new PasswordHasher(config.iterations());

        EmployeeStore store = new EmployeeStore(dir.resolve("employees.dat"), hasher, audit);
        store.requireAcceptableFileMode();
        store.load();
        store.requirePolicyCompliantRecords();

        Ledger ledger = new Ledger(dir.resolve("throttle.log"));
        ThrottleManager throttle = new ThrottleManager(ledger);
        if (throttle.ledgerLossCount() > 0) {
            // Counters restart at zero, which is the strictest state, but the operator must
            // know the durable history was not usable.
            audit.event("ledger", "-", "-", "reset", "untrustworthy-ledger");
        }
        SessionManager sessions = new SessionManager();
        Authenticator authenticator =
                new Authenticator(store, hasher, throttle, sessions, audit);
        return new PortalRuntime(store, throttle, sessions, authenticator, audit);
    }

    public EmployeeStore store() {
        return store;
    }

    public ThrottleManager throttle() {
        return throttle;
    }

    public SessionManager sessions() {
        return sessions;
    }

    public Authenticator authenticator() {
        return authenticator;
    }

    public AuditLog audit() {
        return audit;
    }
}
