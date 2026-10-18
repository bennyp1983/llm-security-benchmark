package example.security.auth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

public final class AuthenticationService {
    public static final String GENERIC_FAILURE = "Invalid username or password.";
    private static final Pattern USERNAME = Pattern.compile("[a-z0-9][a-z0-9._@-]{0,63}");
    private static final int TOKEN_BYTES = 32;
    private static final char[] INVALID_PASSWORD = "invalid-input-placeholder".toCharArray();

    private final CredentialStore credentials;
    private final LoginRateLimiter limiter;
    private final SessionStore sessions;
    private final AuditSink audit;
    private final SecureRandom random;
    private final Clock clock;
    private final Duration sessionTtl;
    private final byte[] correlationKey;
    private final PasswordRecord dummyRecord;

    public AuthenticationService(CredentialStore credentials, LoginRateLimiter limiter,
            SessionStore sessions, AuditSink audit, SecureRandom random, Clock clock,
            Duration sessionTtl, byte[] correlationKey) {
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.limiter = Objects.requireNonNull(limiter, "limiter");
        this.sessions = Objects.requireNonNull(sessions, "sessions");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.random = Objects.requireNonNull(random, "random");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (sessionTtl == null || sessionTtl.compareTo(Duration.ofMinutes(1)) < 0
                || sessionTtl.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalArgumentException("Invalid session lifetime");
        }
        if (correlationKey == null || correlationKey.length != 32) {
            throw new IllegalArgumentException("Correlation key must contain exactly 32 random bytes");
        }
        this.sessionTtl = sessionTtl;
        this.correlationKey = correlationKey.clone();
        char[] dummyPassword = new char[32];
        for (int i = 0; i < dummyPassword.length; i++) dummyPassword[i] = (char) ('!' + random.nextInt(90));
        try {
            this.dummyRecord = PasswordVerifier.hashForStorage(dummyPassword, random);
        } finally {
            Arrays.fill(dummyPassword, '\0');
        }
    }

    /** Consumes and clears {@code password} on every path. Source must be the socket peer, not a header. */
    public Result authenticate(String username, char[] password, InetAddress source) {
        Instant now = safeNow();
        String canonical = validUsername(username) ? canonicalUsername(username) : null;
        boolean validPassword = validPassword(password);
        byte[] sourceBytes = validatedSourceBytes(source);
        String subjectKey = correlate("account", canonical == null ? "invalid" : canonical);
        String sourceKey = correlate("source", HexFormat.of().formatHex(sourceBytes));
        boolean throttled = false;
        byte[] token = null;
        byte[] tokenDigest = null;
        try {
            try {
                throttled = limiter.registerAttempt(sourceKey, subjectKey, now)
                        == LoginRateLimiter.Decision.THROTTLED;
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }

            Optional<CredentialStore.AuthenticatedPrincipal> principal = Optional.empty();
            try {
                if (canonical != null && validPassword) {
                    principal = credentials.verify(canonical, password);
                } else {
                    PasswordVerifier.verify(INVALID_PASSWORD.clone(), dummyRecord);
                }
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }

            // Correct credentials bypass a hostile account-induced throttle; failed attempts do not.
            if (principal.isPresent()) {
                try {
                    limiter.recordSuccess(sourceKey, subjectKey);
                    token = new byte[TOKEN_BYTES];
                    random.nextBytes(token);
                    tokenDigest = sha256(token);
                    Instant expires = now.plus(sessionTtl);
                    if (!sessions.create(tokenDigest, principal.get().accountId(), expires)) {
                        return internalFailure(now, subjectKey, sourceKey);
                    }
                } catch (RuntimeException e) {
                    if (tokenDigest != null) safeRevoke(tokenDigest);
                    return internalFailure(now, subjectKey, sourceKey);
                }
                try {
                    String sessionKey = correlate("session", HexFormat.of().formatHex(tokenDigest));
                    AuthenticationEvent event = event(now, AuthenticationEvent.Outcome.SUCCESS,
                            AuthenticationEvent.Reason.AUTHENTICATED, subjectKey, sourceKey, sessionKey);
                    audit.append(event);
                } catch (Exception e) {
                    safeRevoke(tokenDigest);
                    return Result.failure();
                }
                String value = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(token);
                return Result.success("__Host-session=" + value
                        + "; Path=/; Max-Age=" + sessionTtl.toSeconds()
                        + "; Secure; HttpOnly; SameSite=Strict");
            }

            logFailure(now, subjectKey, sourceKey, throttled
                    ? AuthenticationEvent.Reason.THROTTLED : AuthenticationEvent.Reason.REJECTED);
            return Result.failure();
        } finally {
            if (password != null) Arrays.fill(password, '\0');
            if (token != null) Arrays.fill(token, (byte) 0);
            if (tokenDigest != null) Arrays.fill(tokenDigest, (byte) 0);
            Arrays.fill(sourceBytes, (byte) 0);
        }
    }

    static String canonicalUsername(String username) {
        if (username == null) throw new IllegalArgumentException("Invalid username");
        String value = username.toLowerCase(Locale.ROOT);
        if (!USERNAME.matcher(value).matches()) throw new IllegalArgumentException("Invalid username");
        return value;
    }

    private Result internalFailure(Instant now, String subject, String source) {
        logFailure(now, subject, source, AuthenticationEvent.Reason.INTERNAL_ERROR);
        return Result.failure();
    }

    private void safeRevoke(byte[] tokenDigest) {
        try { sessions.revoke(tokenDigest); } catch (RuntimeException ignored) {
            // The token is never returned; an unreachable digest cannot be used as a credential.
        }
    }

    private void logFailure(Instant now, String subject, String source, AuthenticationEvent.Reason reason) {
        try {
            audit.append(event(now, AuthenticationEvent.Outcome.FAILURE, reason, subject, source, null));
        } catch (Exception ignored) {
            // Authentication still fails closed. The host must treat audit I/O failure as unhealthy.
        }
    }

    private AuthenticationEvent event(Instant now, AuthenticationEvent.Outcome outcome,
            AuthenticationEvent.Reason reason, String subject, String source, String session) {
        // UUID v4 layout backed by this component's explicitly injected CSPRNG.
        byte[] id = new byte[16];
        random.nextBytes(id);
        id[6] = (byte) ((id[6] & 0x0f) | 0x40);
        id[8] = (byte) ((id[8] & 0x3f) | 0x80);
        ByteBuffer bytes = ByteBuffer.wrap(id);
        UUID eventId = new UUID(bytes.getLong(), bytes.getLong());
        Arrays.fill(id, (byte) 0);
        return new AuthenticationEvent(eventId, now, outcome, reason, subject, source, session);
    }

    private Instant safeNow() {
        Instant now;
        try { now = clock.instant(); } catch (RuntimeException e) { return Instant.EPOCH; }
        Instant lower = Instant.parse("2020-01-01T00:00:00Z");
        Instant upper = Instant.parse("2200-01-01T00:00:00Z");
        return now.isBefore(lower) || !now.isBefore(upper) ? Instant.EPOCH : now;
    }

    private String correlate(String domain, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(correlationKey, "HmacSHA256"));
            mac.update(domain.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) 0);
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Required correlation primitive unavailable", e);
        }
    }

    private static byte[] sha256(byte[] value) {
        try { return MessageDigest.getInstance("SHA-256").digest(value); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }
    private static boolean validUsername(String value) {
        if (value == null || value.length() > 64) return false;
        return USERNAME.matcher(value.toLowerCase(Locale.ROOT)).matches();
    }
    private static boolean validPassword(char[] value) {
        try { PasswordVerifier.validatePassword(value); return true; }
        catch (IllegalArgumentException e) { return false; }
    }
    private static byte[] validatedSourceBytes(InetAddress source) {
        if (source == null) return new byte[] {0};
        try {
            byte[] value = source.getAddress();
            return value != null && (value.length == 4 || value.length == 16) ? value.clone() : new byte[] {0};
        } catch (RuntimeException e) {
            return new byte[] {0};
        }
    }

    public record Result(boolean authenticated, String message, String setCookieHeader) {
        public Result {
            if (message == null || message.length() > 64) throw new IllegalArgumentException("Invalid result");
            if (authenticated != (setCookieHeader != null)) throw new IllegalArgumentException("Invalid result");
        }
        static Result success(String cookie) { return new Result(true, "Authenticated.", cookie); }
        static Result failure() { return new Result(false, GENERIC_FAILURE, null); }
        /** Prevent accidental bearer-token disclosure by application diagnostics. */
        @Override public String toString() {
            return "Result[authenticated=" + authenticated + ", message=" + message
                    + ", setCookieHeader=" + (setCookieHeader == null ? "null" : "REDACTED") + "]";
        }
    }
}
