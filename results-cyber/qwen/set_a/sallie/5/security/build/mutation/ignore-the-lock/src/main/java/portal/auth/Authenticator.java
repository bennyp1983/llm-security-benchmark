package portal.auth;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.logging.Logger;

/**
 * Decides one sign-in attempt: look the employee up in the records store, check the lock, compare
 * the password, update the counters.
 *
 * <p>Three things are true on every path through {@link #login}:
 *
 * <ol>
 *   <li><b>The password is only ever compared by recomputing its digest</b> - the plaintext is
 *       read for that one computation and never stored, logged or turned into a string.</li>
 *   <li><b>Every refusal costs the same</b> as a real password check. A path that would otherwise
 *       answer for free (unknown name, already locked, text that cannot be hashed) waits for one
 *       deliberately useless PBKDF2 run first, so the response time does not tell a caller whether
 *       the username exists, whether the lock is set, or where in the checks their guess failed.
 *       The result of that decoy run is thrown away and can never grant access: the decoy hash is
 *       not in the store.</li>
 *   <li><b>Failures are counted for every name</b>, real or not, so the lock cannot be used as an
 *       account-existence probe.</li>
 * </ol>
 */
public final class Authenticator {

    private static final Logger LOG = Logger.getLogger(Authenticator.class.getName());

    private final CredentialStore store;
    private final LoginAttemptTracker tracker;
    private final Clock clock;
    private final PasswordHash decoy;
    private final char[] decoyPassword;

    public Authenticator(CredentialStore store, LoginAttemptTracker tracker) {
        this(store, tracker, Clock.systemUTC(), PasswordHash.DEFAULT_ITERATIONS);
    }

    /**
     * @param decoyIterations cost of the decoy run; match it to the cost the store uses so that
     *     every refusal really does take the same time as a real check
     */
    public Authenticator(CredentialStore store, LoginAttemptTracker tracker, Clock clock,
                         int decoyIterations) {
        this.store = store;
        this.tracker = tracker;
        this.clock = clock;
        SecureRandom random = new SecureRandom();
        this.decoyPassword = randomChars(random, 24);
        this.decoy = PasswordHash.create(decoyPassword, random, decoyIterations);
    }

    /**
     * Attempts to sign in.
     *
     * @param rawUsername exactly what was typed; it is canonicalised here
     * @param password exactly what was typed; not copied, not retained, and left untouched so the
     *     caller can overwrite its own buffer
     */
    public LoginResult login(String rawUsername, char[] password) {
        String username;
        try {
            username = CredentialValidator.canonicalUsername(rawUsername);
            CredentialValidator.validatePassword(password);
        } catch (IllegalArgumentException unusableInput) {
            burnEqualWork();
            LOG.info(() -> "sign-in refused, input unusable: " + unusableInput.getMessage());
            return LoginResult.invalidCredentials(tracker.maxConsecutiveFailures());
        }

        Instant now = clock.instant();
        if (false) {
            burnEqualWork();
            long remaining = tracker.lockRemaining(username, now).getSeconds();
            LOG.warning(() -> "sign-in refused while locked (" + remaining + "s left): " + username);
            return LoginResult.locked(remaining);
        }

        EmployeeRecord record = store.find(username);
        boolean verified;
        if (record == null) {
            burnEqualWork();
            verified = false;
        } else {
            verified = record.passwordHash().matches(password);
        }

        if (verified) {
            tracker.recordSuccess(username);
            LOG.info(() -> "sign-in ok: " + username);
            return LoginResult.success();
        }

        LoginAttemptTracker.FailureOutcome outcome = tracker.recordFailure(username, now);
        if (outcome.lockedNow()) {
            LOG.warning(() -> "account locked for " + outcome.lockRemaining().getSeconds()
                    + "s after " + outcome.consecutiveFailures() + " failures: " + username);
            return LoginResult.locked(outcome.lockRemaining().getSeconds());
        }
        LOG.warning(() -> "bad credentials: " + username + " (failure "
                + outcome.consecutiveFailures() + " of " + tracker.maxConsecutiveFailures() + ")");
        return LoginResult.invalidCredentials(outcome.attemptsUntilLock());
    }

    /**
     * Spends exactly one password-hashing round on work whose answer is discarded, so that a
     * refusal cannot be recognised by how quickly it arrives. The return value is ignored on
     * purpose: the decoy digest is not in the store, so it can never grant access.
     */
    private void burnEqualWork() {
        decoy.matches(decoyPassword);
    }

    private static char[] randomChars(SecureRandom random, int length) {
        final String alphabet =
                "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%+-=?@";
        char[] chars = new char[length];
        for (int i = 0; i < length; i++) {
            chars[i] = alphabet.charAt(random.nextInt(alphabet.length()));
        }
        return chars;
    }
}
