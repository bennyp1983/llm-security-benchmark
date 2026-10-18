package com.example.auth;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Checks one credential pair and shapes the work it does so that no failure outcome is
 * distinguishable from another by timing.
 *
 * <p><b>Comparable work for every outcome.</b> Each of these paths performs one full PBKDF2
 * derivation before it returns:
 * <ul>
 *   <li>username not in the store - the derivation uses a server-generated salt with the configured
 *       iteration count, and its result is discarded;</li>
 *   <li>username present, password wrong;</li>
 *   <li>username present, password correct.</li>
 * </ul>
 * After the derivation, every remaining difference is a field read or a map probe, and the latency
 * floor absorbs the residual spread.
 *
 * <p><b>Work is capped globally, not per key.</b> A fixed number of permits, handed out in FIFO
 * order, bounds how much hashing an attacker can force regardless of how many usernames or source
 * addresses the attempts are spread across. A caller that cannot obtain a permit within
 * {@value #PERMIT_TIMEOUT_MILLIS} ms is denied; attempts are never queued without bound, because an
 * unbounded queue is the denial of service this exists to prevent. Waiting for a permit also counts
 * against the latency floor, so a saturated service is uniformly slower - it cannot be made to run
 * one outcome fast and another slow.
 *
 * <p><b>No latch.</b> Saturating the permits denies only the attempts that arrive while saturated;
 * permits are released in a {@code finally} block and the next attempt proceeds normally.
 */
final class CredentialVerifier {

    /** Longest a caller will wait for a work permit before being denied. */
    static final long PERMIT_TIMEOUT_MILLIS = 2_000L;

    private final PasswordHasher hasher;
    private final LatencyBudget budget;
    private final Semaphore workPermits;
    private final int maxConcurrentDerivations;
    private final AttemptParameters decoy;

    CredentialVerifier(PasswordHasher hasher, LatencyBudget budget, int maxConcurrentDerivations,
            AttemptParameters decoy) {
        if (maxConcurrentDerivations < 1) {
            throw new IllegalArgumentException("maxConcurrentDerivations");
        }
        this.hasher = hasher;
        this.budget = budget;
        this.workPermits = new Semaphore(maxConcurrentDerivations, true);
        this.maxConcurrentDerivations = maxConcurrentDerivations;
        this.decoy = decoy;
    }

    /**
     * Verifies a password against the record for a resolved username.
     *
     * @param passwordUtf8 validated UTF-8 bytes of the candidate password
     * @param record the record for the resolved username, or {@code null} when there is none
     * @return {@code true} only when the digest matches
     * @throws AuthException when the check could not be performed at all - no permit, no decoy
     *     parameters, or a store failure. The caller must deny the attempt and must not treat this
     *     as either a match or a distinguishable kind of failure.
     */
    boolean verify(byte[] passwordUtf8, AccountCredentials record) throws AuthException {
        if (passwordUtf8 == null || passwordUtf8.length == 0) {
            throw new AuthException(Diagnostic.PASSWORD_TOO_SHORT);
        }
        if (decoy == null) {
            throw new AuthException(Diagnostic.STORE_UNAVAILABLE);
        }
        boolean acquired;
        try {
            acquired = workPermits.tryAcquire(PERMIT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthException(Diagnostic.WORK_UNAVAILABLE);
        }
        if (!acquired) {
            throw new AuthException(Diagnostic.WORK_UNAVAILABLE);
        }
        long started = System.nanoTime();
        try {
            final boolean matched;
            if (record == null) {
                // Discarded deliberately: the purpose is that an unknown username costs exactly what
                // a known one costs.
                hasher.matches(passwordUtf8, decoy.salt(), decoy.iterations(), decoy.digest());
                matched = false;
            } else {
                matched = hasher.matches(passwordUtf8, record.salt(), record.iterations(), record.digest());
            }
            budget.padUntil(started);
            return matched;
        } finally {
            workPermits.release();
        }
    }

    /** Derivations the service will run at once. */
    int maxConcurrentDerivations() {
        return maxConcurrentDerivations;
    }

    /** Salt, iteration count and digest used to burn work for an unknown username. */
    static final class AttemptParameters {

        private final byte[] salt;
        private final int iterations;
        private final byte[] digest;

        AttemptParameters(byte[] salt, int iterations, byte[] digest) {
            this.salt = salt;
            this.iterations = iterations;
            this.digest = digest;
        }

        byte[] salt() {
            return salt.clone();
        }

        int iterations() {
            return iterations;
        }

        byte[] digest() {
            return digest.clone();
        }
    }
}
