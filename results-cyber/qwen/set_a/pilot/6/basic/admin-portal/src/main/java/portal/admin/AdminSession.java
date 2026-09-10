package portal.admin;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

/**
 * An issued session. The opaque token is the only thing a client holds; the principal,
 * role and expiry live server-side.
 *
 * <p>The object itself never carries credential material, and {@link #tokenFingerprint()}
 * is the only form in which the token may be logged.
 */
public final class AdminSession {

    private final String tokenId;
    private final String tokenHash;
    private final AdminPrincipal principal;
    private final long issuedAtMillis;
    private long expiresAtMillis;
    private final long absoluteDeadlineMillis;

    private long lastActivityMillis;
    private boolean revoked;
    private String revokeReason;

    AdminSession(String tokenId, String tokenHash, AdminPrincipal principal, long issuedAtMillis,
                 long expiresAtMillis, long absoluteDeadlineMillis) {
        this.tokenId = tokenId;
        this.tokenHash = tokenHash;
        this.principal = principal;
        this.issuedAtMillis = issuedAtMillis;
        this.expiresAtMillis = expiresAtMillis;
        this.absoluteDeadlineMillis = absoluteDeadlineMillis;
        this.lastActivityMillis = issuedAtMillis;
    }

    /** Opaque bearer token. Compare with {@link #matches(String)}, do not store raw. */
    public String tokenId() {
        return tokenId;
    }

    String tokenHash() {
        return tokenHash;
    }

    public AdminPrincipal principal() {
        return principal;
    }

    public long issuedAtMillis() {
        return issuedAtMillis;
    }

    public long lastActivityMillis() {
        return lastActivityMillis;
    }

    public long expiresAtMillis() {
        return expiresAtMillis;
    }

    public long absoluteDeadlineMillis() {
        return absoluteDeadlineMillis;
    }

    public boolean revoked() {
        return revoked;
    }

    public String revokeReason() {
        return revokeReason;
    }

    void touch(long nowMillis) {
        this.lastActivityMillis = nowMillis;
    }

    /** Slides the idle deadline forward; never moves the absolute deadline. */
    void extendIdleExpiry(long newExpiryMillis) {
        this.expiresAtMillis = Math.min(newExpiryMillis, this.absoluteDeadlineMillis);
    }

    void revoke(String reason) {
        this.revoked = true;
        this.revokeReason = reason;
    }

    /** Timing-safe check of a presented bearer token. */
    public boolean matches(String presented) {
        if (presented == null) {
            return false;
        }
        return MessageDigest.isEqual(
                tokenHash.getBytes(StandardCharsets.UTF_8),
                SessionManager.hashToken(presented).getBytes(StandardCharsets.UTF_8));
    }

    /** Short, non-secret handle for audit lines. */
    public String tokenFingerprint() {
        int len = Math.min(8, tokenHash.length());
        return tokenHash.substring(0, len);
    }

    @Override
    public String toString() {
        return "AdminSession{" + principal.username() + ", role=" + principal.role()
                + ", token=" + tokenFingerprint() + "***" + (revoked ? ", revoked" : "") + "}";
    }

    static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable on this JVM", e);
        }
    }
}
