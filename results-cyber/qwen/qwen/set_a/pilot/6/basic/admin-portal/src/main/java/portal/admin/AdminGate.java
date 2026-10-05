package portal.admin;

import java.util.Optional;

/**
 * The single choke point in front of every admin-level operation.
 *
 * <p>Each operation re-validates the bearer token rather than trusting a principal handed
 * to it earlier, so a session revoked or expired between menu steps cannot keep being used.
 * Denials are audited, which is the point: a refused privileged call is itself a signal.
 */
public final class AdminGate {

    private final SessionManager sessions;
    private final AuditLog audit;

    public AdminGate(SessionManager sessions, AuditLog audit) {
        this.sessions = sessions;
        this.audit = audit;
    }

    /**
     * @throws AccessDeniedException if the token is not a live session, or its role does
     *                               not grant {@code permission}
     */
    public AdminPrincipal require(AdminRole.Permission permission, String token) {
        Optional<AdminPrincipal> principal = sessions.validate(token);
        if (principal.isEmpty()) {
            audit.record(AuditResult.DENIED, "-",
                    "operation '" + permission + "' refused: session is missing, expired or revoked");
            throw new AccessDeniedException(
                    "You are not signed in, or your session has expired.", permission);
        }
        if (!principal.get().can(permission)) {
            audit.record(AuditResult.DENIED, principal.get().username(),
                    "operation '" + permission + "' refused for role " + principal.get().role());
            throw new AccessDeniedException(
                    "Role " + principal.get().role() + " is not permitted to " + permission.description() + '.',
                    permission);
        }
        return principal.get();
    }

    /** Convenience for read-only views that only need a live session. */
    public AdminPrincipal requireSignedIn(String token) {
        return sessions.validate(token).orElseThrow(() -> {
            audit.record(AuditResult.DENIED, "-", "request refused: no live session");
            return new AccessDeniedException("You are not signed in, or your session has expired.", null);
        });
    }
}
