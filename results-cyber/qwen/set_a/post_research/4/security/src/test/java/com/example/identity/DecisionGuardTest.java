package com.example.identity;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The bound on concurrent verification work (Rule 3's "limit repeated attempts" under concurrency,
 * and Rule 7's check-then-act).
 *
 * <h2>Why a limiter in the database is not enough on its own</h2>
 * The durable counter is charged correctly and atomically, but the decision that consults it is
 * spread over ~850 ms of PBKDF2: {@code check penalty -> derive -> charge}. K parallel connections
 * all pass the check while all K derivations are still running, so the shipped limits hand over
 * {@code limit + K} guesses per window, and the limiter's other purpose - bounding the CPU an
 * unauthenticated caller can force - is not served at all. That window cannot be closed by
 * re-ordering the steps (charging first lets one correct sign-in refund an attacker's budget), so
 * what closes it is a bound on how many decisions may be in flight.
 *
 * <h2>Why these tests do not measure the race itself</h2>
 * Racing real {@code signIn} calls to observe the overshoot would be a test that passes for the
 * broken code as often as for the fixed code - whether K threads actually overlap depends on the
 * machine. So the guard is tested directly, with a barrier that makes the claims simultaneous by
 * construction, and the <em>wiring</em> is asserted against the source, which is the only
 * falsifiable statement available about ordering inside one method.
 */
public final class DecisionGuardTest {

    private DecisionGuardTest() {
    }

    /**
     * Runs {@code n} claims that all attempt to enter at the same instant, and reports which of them
     * were admitted - the caller has to release exactly those, since ending a claim that was refused
     * would decrement a slot that was never taken.
     */
    private static List<String> race(DecisionGuard guard, String key, int n, boolean distinctKeys)
            throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(n);
        CountDownLatch done = new CountDownLatch(n);
        List<String> admitted = java.util.Collections.synchronizedList(new ArrayList<>());
        List<Thread> pool = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final String attemptKey = key == null ? null : (distinctKeys ? key + i : key);
            Thread t = new Thread(() -> {
                try {
                    barrier.await(30, TimeUnit.SECONDS);
                } catch (Exception lost) {
                    done.countDown();
                    return;
                }
                if (guard.tryBegin(attemptKey)) {
                    admitted.add(attemptKey == null ? "<anon>" : attemptKey);
                }
                done.countDown();
            }, "claim-" + i);
            pool.add(t);
            t.start();
        }
        for (Thread t : pool) {
            t.join(60_000L);
        }
        check("all " + n + " claim attempts completed", done.await(1, TimeUnit.SECONDS));
        return new ArrayList<>(admitted);
    }

    public static void run() throws Exception {
        section("At most one decision per key, however many arrive at once");
        DecisionGuard perKey = new DecisionGuard(64);
        checkEquals("eight simultaneous claims against the same account admit exactly one",
                1, race(perKey, "acc", 8, false).size());
        checkEquals("with exactly the one slot accounted for", 1, perKey.inFlight());
        check("a second claim against the held key is refused while the winner is inside",
                !perKey.tryBegin("acc"));
        check("while a different key is unaffected by the one held",
                perKey.tryBegin("other"));
        checkEquals("and the global count counts both claims", 2, perKey.inFlight());
        perKey.end("acc");
        perKey.end("other");
        checkEquals("releasing every claim empties the guard", 0, perKey.inFlight());
        check("and the account is claimable again - a released slot is not remembered",
                perKey.tryBegin("acc"));
        perKey.end("acc");

        section("The global bound is enforced across distinct keys");
        DecisionGuard capped = new DecisionGuard(2);
        List<String> admitted = race(capped, "id", 6, true);
        checkEquals("six simultaneous claims against six different identifiers admit exactly two",
                2, admitted.size());
        checkEquals("with both slots held", 2, capped.inFlight());
        check("a third claim is refused while two run", !capped.tryBegin("idX"));
        capped.end(admitted.get(0));
        check("one release lets exactly one more in", capped.tryBegin("idX"));
        checkEquals("and the bound still holds at the cap", 2, capped.inFlight());
        capped.end(admitted.get(1));
        capped.end("idX");

        section("Shedding refuses immediately rather than queueing");
        // Queueing would trade a CPU bound for a latency bound the attacker owns: hold every slot
        // and everyone else's sign-in blocks. A refusal, by contrast, is indistinguishable from the
        // cheap refusal an active penalty already produces.
        DecisionGuard one = new DecisionGuard(1);
        check("take the only slot", one.tryBegin("acc"));
        long t0 = System.nanoTime();
        boolean second = one.tryBegin("other");
        long waitedMicros = (System.nanoTime() - t0) / 1_000L;
        check("the second claim is refused", !second);
        check("and it was refused in microseconds, not after waiting for the holder",
                waitedMicros < 50_000L);
        note("second claim returned after " + waitedMicros + " us");
        one.end("acc");

        section("A null key consumes a global slot only");
        // The branches with no account behind them (malformed identifier, candidate that fails
        // policy) still run a full derivation, so they must consume the global permit; they simply
        // have no per-account exclusion to offer.
        DecisionGuard nulls = new DecisionGuard(2);
        check("first anonymous claim", nulls.tryBegin(null));
        check("second anonymous claim", nulls.tryBegin(null));
        check("third is refused by the global bound", !nulls.tryBegin(null));
        nulls.end(null);
        nulls.end(null);
        checkEquals("and both anonymous slots came back", 0, nulls.inFlight());

        section("The bound cannot be configured away");
        List<String> rejected = new ArrayList<>();
        for (int bad : new int[]{0, -1, Integer.MIN_VALUE}) {
            try {
                new DecisionGuard(bad);
                rejected.add(bad + " was accepted");
            } catch (IllegalArgumentException expected) {
                // refusing to build a guard that would allow no work is the fail-closed direction
            }
        }
        checkEquals("a zero or negative bound is refused rather than silently allowing everything",
                "", String.join(" | ", rejected));
        check("the shipped bound is a positive constant and not configuration",
                AuthApi.MAX_IN_FLIGHT_DERIVATIONS >= 1
                        && !Harness.stripJavaComments(Harness.sourceOf("Config"))
                        .contains("inFlight"));

        section("AuthApi actually takes the permit before it does any of the work");
        // Ordering inside one method is not observable from outside, so it is asserted against the
        // source. Each position below is a distinct failure mode: claiming after the penalty check
        // would let K threads past the check; claiming after the derivation would bound nothing.
        String src = Harness.stripJavaComments(Harness.sourceOf("AuthApi"));
        String body = regionOf(src, "public AuthResult signIn(");
        int claim = body.indexOf("guard.tryBegin(guardKey)");
        int sourceCheck = body.indexOf("isPenaltyActive(SqlIdentityStore.bucketKindSource()");
        int accountCheck = body.indexOf("isPenaltyActive(SqlIdentityStore.bucketKindAccount()");
        int firstCharge = body.indexOf("chargeSource(source, now)");
        int derive = body.indexOf("chargeEqualWork()");
        check("the claim is taken before the source penalty check", claim >= 0 && claim < sourceCheck);
        check("before any charge is written", claim >= 0 && claim < firstCharge);
        check("before any derivation is paid for", claim >= 0 && claim < derive);
        check("and before the per-account penalty check", claim >= 0 && claim < accountCheck);
        check("the account's own key is claimed once the row is known, which is the claim that sees"
                        + " both spellings of one account as one account",
                body.contains("rowKey = accountKey")
                        && body.indexOf("rowClaimed = guard.tryBegin(rowKey)") > accountCheck - 400
                        && body.indexOf("rowClaimed = guard.tryBegin(rowKey)") < accountCheck);
        String finallyBlock = body.substring(body.lastIndexOf("} finally {"));
        check("both claims are released in the finally, so a thrown store error cannot leak a slot"
                        + " and permanently wedge an account",
                finallyBlock.contains("guard.end(rowKey)") && finallyBlock.contains("guard.end(guardKey)")
                        && finallyBlock.contains("if (rowClaimed)"));
        check("the release is guarded by the claim flag, so a refused claim cannot decrement a slot"
                        + " it never took", finallyBlock.indexOf("if (rowClaimed)")
                        < finallyBlock.indexOf("guard.end(rowKey)"));
        check("the shed refusal carries no new information: it audits THROTTLED and returns the same"
                        + " credential sentence every other refusal returns",
                body.contains("audit.record(Reason.THROTTLED, identifier)")
                        && body.contains("return AuthResult.of(Reason.BAD_CREDENTIAL)"));
    }

    /** One method's source, anchored on its declaration (see the note in {@code LineReaderTest}). */
    private static String regionOf(String strippedSource, String declaration) {
        int decl = strippedSource.indexOf(declaration);
        if (decl < 0) {
            return "";
        }
        int open = strippedSource.indexOf('{', decl);
        int depth = 0;
        for (int i = open; i < strippedSource.length(); i++) {
            char c = strippedSource.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return strippedSource.substring(decl, i + 1);
                }
            }
        }
        return "";
    }
}
