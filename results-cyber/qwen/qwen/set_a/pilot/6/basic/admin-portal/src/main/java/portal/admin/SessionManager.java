package portal.admin;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import portal.security.Clock;
import portal.security.RandomTokens;

/**
 * Issues and validates the bearer tokens that carry an authenticated identity into the
 * admin console.
 *
 * <ul>
 *   <li>Tokens come from {@link java.security.SecureRandom} (256 bits) and are opaque:
 *       nothing about the role is encoded in them, so a client cannot escalate by editing
 *       a token.</li>
 *   <li>Tokens are held server-side keyed by their SHA-256 digest, so a leaked dump of the
 *       session table cannot be replayed.</li>
 *   <li>Sessions expire twice over: on inactivity and at an absolute deadline, whichever
 *       comes first. A privileged session cannot be kept alive forever by mouse movement.</li>
 *   <li>Newest sessions displace a user's oldest ones past a small cap, bounding how many
 *       live sessions one set of stolen credentials can hold open.</li>
 * </ul>
 */
public final class SessionManager {

    private final Map<String, AdminSession> byTokenHash = new LinkedHashMap<>();
    private final RandomTokens tokens = new RandomTokens();
    private final AuthenticationConfig config;
    private final AuditLog audit;
    private final Clock clock;

    public SessionManager(AuthenticationConfig config, AuditLog audit, Clock clock) {
        this.config = config;
        this.audit = audit;
        this.clock = clock;
    }

    public AdminSession issue(AdminPrincipal principal) {
        long now = clock.currentTimeMillis();
        String tokenId = tokens.base64Url(32);
        String tokenHash = hashToken(tokenId);

        evictOverflow(principal.username(), now);

        AdminSession session = new AdminSession(tokenId, tokenHash, principal, now,
                now + config.sessionIdleMillis(), now + config.sessionAbsoluteMillis());
        byTokenHash.put(tokenHash, session);
        audit.record(AuditResult.SUCCESS, principal.username(),
                "session " + session.tokenFingerprint() + " issued for role " + principal.role());
        return session;
    }

    /**
     * Resolves a presented token to its principal, sliding the idle window on success.
     *
     * @return the principal, or empty for an unknown, revoked or expired token; callers
     *         must treat empty as "not signed in" and re-authenticate
     */
    public Optional<AdminPrincipal> validate(String presentedToken) {
        long now = clock.currentTimeMillis();
        if (presentedToken == null || presentedToken.isEmpty()) {
            return Optional.empty();
        }
        AdminSession session = byTokenHash.get(hashToken(presentedToken));
        if (session == null || !session.matches(presentedToken)) {
            return Optional.empty();
        }
        if (session.revoked()) {
            byTokenHash.remove(session.tokenHash());
            return Optional.empty();
        }
        if (session.expiresAtMillis() <= now) {
            remove(session);
            audit.record(AuditResult.EXPIRED, session.principal().username(),
                    "session " + session.tokenFingerprint() + " idle-expired");
            return Optional.empty();
        }
        if (session.absoluteDeadlineMillis() <= now) {
            remove(session);
            audit.record(AuditResult.EXPIRED, session.principal().username(),
                    "session " + session.tokenFingerprint() + " reached its absolute lifetime");
            return Optional.empty();
        }
        session.touch(now);
        session.extendIdleExpiry(now + config.sessionIdleMillis());
        return Optional.of(session.principal());
    }

    /** @return true if the token belonged to a live session and is now dead */
    public boolean revoke(String presentedToken) {
        if (presentedToken == null) {
            return false;
        }
        AdminSession session = byTokenHash.remove(hashToken(presentedToken));
        if (session == null) {
            return false;
        }
        session.revoke("signed out");
        audit.record(AuditResult.SUCCESS, session.principal().username(),
                "session " + session.tokenFingerprint() + " closed");
        return true;
    }

    /**
     * Kills every live session for a username. Used after a password reset, a disable, or
     * any suspicion, so the action cannot be undone by an already-issued token.
     *
     * @return number of sessions revoked
     */
    public int revokeAllForUser(String username, String reason) {
        int revoked = 0;
        for (Iterator<AdminSession> it = byTokenHash.values().iterator(); it.hasNext(); ) {
            AdminSession session = it.next();
            if (namesMatch(session.principal().username(), username)) {
                session.revoke(reason);
                it.remove();
                revoked++;
            }
        }
        if (revoked > 0) {
            audit.record(AuditResult.WARNING, username,
                    "revoked " + revoked + " live session(s): " + reason);
        }
        return revoked;
    }

    public int purgeExpired() {
        long now = clock.currentTimeMillis();
        int removed = 0;
        for (Iterator<AdminSession> it = byTokenHash.values().iterator(); it.hasNext(); ) {
            AdminSession session = it.next();
            if (session.revoked() || session.expiresAtMillis() <= now
                    || session.absoluteDeadlineMillis() <= now) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    public List<AdminSession> activeSessions() {
        long now = clock.currentTimeMillis();
        List<AdminSession> live = new ArrayList<>();
        for (AdminSession session : byTokenHash.values()) {
            if (!session.revoked() && session.expiresAtMillis() > now
                    && session.absoluteDeadlineMillis() > now) {
                live.add(session);
            }
        }
        live.sort(Comparator.comparing(AdminSession::issuedAtMillis));
        return live;
    }

    public int activeSessionCount(String username) {
        int count = 0;
        for (AdminSession session : activeSessions()) {
            if (namesMatch(session.principal().username(), username)) {
                count++;
            }
        }
        return count;
    }

    private void evictOverflow(String username, long now) {
        List<AdminSession> existing = new ArrayList<>();
        for (AdminSession session : byTokenHash.values()) {
            if (namesMatch(session.principal().username(), username)
                    && !session.revoked() && session.expiresAtMillis() > now) {
                existing.add(session);
            }
        }
        existing.sort(Comparator.comparing(AdminSession::issuedAtMillis));
        int excess = existing.size() - config.maxSessionsPerUser() + 1;
        for (int i = 0; i < excess; i++) {
            AdminSession oldest = existing.get(i);
            oldest.revoke("displaced by a newer sign-in");
            byTokenHash.remove(oldest.tokenHash());
            audit.record(AuditResult.WARNING, username,
                    "session " + oldest.tokenFingerprint() + " displaced by a newer sign-in");
        }
    }

    private void remove(AdminSession session) {
        session.revoke("expired");
        byTokenHash.remove(session.tokenHash());
    }

    static String hashToken(String token) {
        return AdminSession.sha256(token);
    }

    private static boolean namesMatch(String a, String b) {
        return CredentialStore.key(a).equals(CredentialStore.key(b));
    }

    /** Total ever issued minus those removed, for operator display only. */
    public int liveSessionCount() {
        return byTokenHash.size();
    }
}
