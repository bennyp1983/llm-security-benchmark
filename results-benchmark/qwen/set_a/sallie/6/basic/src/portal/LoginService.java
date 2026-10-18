package portal;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Verifies administrator credentials and hands out a session that admin-level
 * commands require.
 *
 * <p>Three properties are deliberate:
 * <ul>
 *   <li>Every branch that reaches the store does one full PBKDF2 derivation,
 *       including the branches that cannot possibly succeed, so response time does
 *       not reveal whether a username has an account or is locked.</li>
 *   <li>Failed attempts are counted per username and lock that username only.</li>
 *   <li>Access is granted only if the successful attempt was written to the audit
 *       log. If the log cannot be written, the login is refused.</li>
 * </ul>
 */
public final class LoginService {

    public static final int DEFAULT_MAX_FAILURES = 5;
    public static final long DEFAULT_LOCKOUT_MILLIS = 15 * 60 * 1000L;
    public static final long DEFAULT_SESSION_TTL_MILLIS = 15 * 60 * 1000L;

    public enum Status {
        GRANTED,
        DENIED,
        LOCKED,
        REJECTED,
        RECORDING_FAILED
    }

    public record AuthResult(Status status, String username, String role, String message,
                             long elapsedNanos, boolean auditBroken) {

        boolean granted() {
            return status == Status.GRANTED;
        }
    }

    public record Session(String token, String username, String role, long expiresAtMillis) {

        boolean live(long nowMillis) {
            return token != null && nowMillis < expiresAtMillis;
        }
    }

    private static final String GENERIC_FAILURE = "the username or password is not correct";

    private final CredentialStore store;
    private final AuditLog audit;
    private final int maxFailures;
    private final long lockoutMillis;
    private final long sessionTtlMillis;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Integer> failuresByName = new HashMap<>();
    private final Map<String, Long> lockedUntilByName = new HashMap<>();

    public LoginService(CredentialStore store, AuditLog audit) {
        this(store, audit, DEFAULT_MAX_FAILURES, DEFAULT_LOCKOUT_MILLIS,
                DEFAULT_SESSION_TTL_MILLIS);
    }

    public LoginService(CredentialStore store, AuditLog audit, int maxFailures,
                        long lockoutMillis, long sessionTtlMillis) {
        if (maxFailures < 1) {
            throw new IllegalArgumentException("maxFailures must be at least 1");
        }
        this.store = store;
        this.audit = audit;
        this.maxFailures = maxFailures;
        this.lockoutMillis = lockoutMillis;
        this.sessionTtlMillis = sessionTtlMillis;
    }

    public int maxFailures() {
        return maxFailures;
    }

    public boolean isLockedOut(String username) {
        Long until = lockedUntilByName.get(username);
        return until != null && System.currentTimeMillis() < until;
    }

    public int failuresFor(String username) {
        Integer seen = failuresByName.get(username);
        return seen == null ? 0 : seen;
    }

    /** Clears the lock and the failure count for one username (supervisor action). */
    public void clearLock(String username) {
        failuresByName.remove(username);
        lockedUntilByName.remove(username);
    }

    /**
     * Authenticates {@code username} with {@code password}. The password array is
     * wiped before returning, whichever branch was taken.
     */
    public AuthResult verify(String username, char[] password) {
        long started = System.nanoTime();
        try {
            String unusable = PasswordPolicy.structural(password);
            if (unusable != null) {
                return refuse(started, Status.REJECTED, "-", null, unusable,
                        "AUTH_REJECTED", "-", "the password is not usable");
            }
            String name;
            try {
                name = Names.normalize(username);
            } catch (IllegalArgumentException badName) {
                Pbkdf2.shadowWorkSafely("-", Pbkdf2.ITERATIONS);
                return refuse(started, Status.REJECTED, "-", null,
                        "that is not a valid username: " + badName.getMessage(),
                        "AUTH_REJECTED", "-", "username syntax");
            }

            CredentialStore.AdminCredential row = store.find(name);
            if (isLockedOut(name)) {
                spendWork(row, name);
                return refuse(started, Status.LOCKED, name, null,
                        "this account is temporarily locked, try again later",
                        "AUTH_LOCKED", name, "attempt while locked");
            }
            if (row == null) {
                spendWork(null, name);
                return refuse(started, Status.DENIED, name, null, GENERIC_FAILURE,
                        "AUTH_DENIED", name, "no such administrator");
            }

            byte[] derived;
            try {
                derived = Pbkdf2.derive(password, row.salt(), row.iterations());
            } catch (GeneralSecurityException | IllegalArgumentException unusableRow) {
                spendWork(null, name);
                return refuse(started, Status.DENIED, name, null,
                        "this account cannot be used, ask a supervisor to reset its password",
                        "AUTH_DENIED", name, "stored credential unusable");
            }
            boolean ok = Pbkdf2.matches(row.key(), derived);
            Arrays.fill(derived, (byte) 0);
            if (!ok) {
                registerFailure(name);
                if (isLockedOut(name)) {
                    return refuse(started, Status.LOCKED, name, null,
                            "this account is temporarily locked, try again later",
                            "AUTH_LOCKED", name, "too many failed attempts");
                }
                return refuse(started, Status.DENIED, name, null, GENERIC_FAILURE,
                        "AUTH_DENIED", name, "password mismatch");
            }

            failuresByName.remove(name);
            lockedUntilByName.remove(name);
            String role = Roles.isKnown(row.role()) ? row.role() : Roles.OPERATOR;
            boolean auditBroken = write("AUTH_GRANTED", name, "role=" + role);
            if (auditBroken) {
                return refuse(started, Status.RECORDING_FAILED, name, null,
                        "access refused: the login could not be recorded",
                        "AUTH_GRANT_WITHDRAWN", name, "the login was not recorded");
            }
            return new AuthResult(Status.GRANTED, name, role, "welcome back, " + name,
                    System.nanoTime() - started, false);
        } catch (IOException | RuntimeException unexpected) {
            return new AuthResult(Status.RECORDING_FAILED, "-", null,
                    "access refused: the portal could not complete the check",
                    System.nanoTime() - started, true);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /** Issues a fresh session for a granted authentication. */
    public Session issueSession(String username, String role) {
        byte[] raw = new byte[16];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        return new Session(token, username, role, System.currentTimeMillis() + sessionTtlMillis);
    }

    /** Confirms that an admin-level command runs inside a live session. */
    public boolean authorized(Session session) {
        return session != null && session.live(System.currentTimeMillis())
                && Roles.isKnown(session.role());
    }

    private AuthResult refuse(long started, Status status, String username, String role,
                              String message, String event, String subject, String detail)
            throws IOException {
        boolean auditBroken = write(event, subject, detail);
        Status effective = status;
        String effectiveMessage = message;
        if (auditBroken && status == Status.GRANTED) {
            effective = Status.RECORDING_FAILED;
            effectiveMessage = "access refused: the login could not be recorded";
        }
        return new AuthResult(effective, username, role, effectiveMessage,
                System.nanoTime() - started, auditBroken);
    }

    private void spendWork(CredentialStore.AdminCredential row, String name) {
        Pbkdf2.shadowWorkSafely(row == null ? name : row.username(),
                row == null ? Pbkdf2.ITERATIONS : row.iterations());
    }

    private void registerFailure(String name) {
        int seen = failuresFor(name) + 1;
        if (seen >= maxFailures) {
            failuresByName.remove(name);
            lockedUntilByName.put(name, System.currentTimeMillis() + lockoutMillis);
            return;
        }
        failuresByName.put(name, seen);
    }

    /** @return true when the record could not be written */
    private boolean write(String event, String subject, String detail) {
        try {
            audit.record(event, subject, detail);
            return false;
        } catch (IOException cannotRecord) {
            return true;
        }
    }

    static String lower(String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }
}
