package com.example.identity;

import java.util.HashSet;
import java.util.Set;

/**
 * Bounds how many password verifications may be in flight, globally and per account.
 *
 * <h2>The race this exists for</h2>
 * A sign-in decision is {@code check penalty -> derive (~850 ms) -> charge counter}. The penalty
 * check and the charge are serialised in the store, but the derivation between them is not, so
 * without this a caller holding K parallel connections passes the check K times before any of them
 * charges: the limit hands over {@code limit + K} guesses per window instead of {@code limit}, and
 * the limiter's other job - bounding server CPU - is defeated outright. Re-ordering the steps does
 * not fix it either: charging before the derivation would let one correct sign-in buy an attacker a
 * refund, which is how a source budget gets kept permanently empty.
 *
 * <h2>What it guarantees</h2>
 * <ul>
 *   <li><b>One in-flight decision per key.</b> The caller claims twice: by the submitted
 *     identifier's canonical form before the lookup, and by the account's primary key once the row is
 *     known. The first claim costs nothing to compute and stops the same spelling racing itself;
 *     the second is what actually matters, because one account has two spellings (username and
 *     email) and only the primary key sees them as one account. Either claim refusing is enough: a
 *     second concurrent attempt against the same account is refused cheaply, so the per-account
 *     overshoot is zero rather than {@code K - 1}. Two humans guessing the same account at the same
 *     instant is not a workload; an attacker with K sockets is, and this is what tells them apart
 *     without distinguishing them.</li>
 *   <li><b>At most {@code maxInFlight} decisions in total.</b> Beyond that, load-shed. Unbounded
 *     parallel PBKDF2 is a free denial of service, and the work is deliberately expensive, so the
 *     bound has to be explicit rather than "however many threads the transport spawns". Guesses
 *     against identifiers with no account are still bounded by this, which is why the global permit
 *     is taken on every branch that derives - the dummy derivation costs exactly as much.</li>
 * </ul>
 *
 * <h2>Refusing, never queueing</h2>
 * Both bounds refuse immediately instead of waiting. Queueing would convert a CPU bound into a
 * latency bound the attacker controls - hold K slots and everyone else's sign-in blocks - and a
 * waiting caller would then be indistinguishable from a slow one. The refusal is the same cheap
 * {@link Reason#THROTTLED} refusal an active penalty produces, so shedding is not an oracle either:
 * the caller cannot tell which bound stopped it, and cannot tell whether the account exists.
 *
 * <p>In-process state only, which is honest about its scope: it bounds one JVM. The durable limits
 * live in {@code auth_throttle} and are enforced by the database, so they hold across processes;
 * this class only closes the window the durable check cannot see.
 */
final class DecisionGuard {

    private final int maxInFlight;
    private final Set<String> inFlightAccounts = new HashSet<>();
    private int running;

    DecisionGuard(int maxInFlight) {
        if (maxInFlight < 1) {
            throw new IllegalArgumentException("at least one verification must be allowed in flight");
        }
        this.maxInFlight = maxInFlight;
    }

    /**
     * Claims the right to run a derivation for {@code accountKey}, or refuses.
     *
     * @param accountKey the bucket key of the account being verified, or {@code null} when no
     *                   account is involved (unknown identifier, policy failure) - those still cost
     *                   the full derivation, so they still consume a global slot
     */
    synchronized boolean tryBegin(String accountKey) {
        if (running >= maxInFlight) {
            return false;
        }
        if (accountKey != null && !inFlightAccounts.add(accountKey)) {
            return false;
        }
        running++;
        return true;
    }

    /** Releases whatever {@link #tryBegin} claimed; safe to call only after a successful claim. */
    synchronized void end(String accountKey) {
        running--;
        if (accountKey != null) {
            inFlightAccounts.remove(accountKey);
        }
    }

    /** For tests and the operational read: how many decisions are running right now. */
    synchronized int inFlight() {
        return running;
    }
}
