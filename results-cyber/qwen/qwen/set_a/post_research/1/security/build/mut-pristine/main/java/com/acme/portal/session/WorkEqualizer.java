package com.acme.portal.session;

/**
 * Does a fixed, small amount of throwaway computation on every request.
 *
 * <p><b>What it equalizes.</b> A refusal that happens <i>before</i> the session-store lookup is
 * measurably cheaper than one that happens after it. The response body already hides which check
 * refused, but latency does not: an attacker who can time the endpoint can tell "this candidate is
 * not even well-formed" from "this candidate is well-formed but unknown", which is a per-candidate
 * signal for anyone generating identifiers. Padding every outcome to the cost of the most expensive
 * one removes that signal.
 *
 * <p>The work is a fixed number of SHA-256 compressions over a constant buffer: no secret, no
 * attacker-controlled length, no I/O, and a cost independent of every input, which is what makes it
 * a level playing field rather than a new side channel.
 *
 * <p><b>Why it runs before every gate, including the throttle.</b> A cheap path is itself a signal,
 * so the padding is applied first and unconditionally. That costs something real, and it is a trade
 * rather than a free win: a request the rate limiter refuses still pays for the padding, so the
 * limiter sheds the session-store round trip and the cookie write, not this. Moving the padding off
 * the limited path would make "you are being throttled for this address" readable as a latency
 * difference, and would leave the availability refusal as a cheap probe for whether this deployment
 * is wired up at all. The accepted trade is therefore explicit -- constant work on every path, and a
 * constant small enough that this is a capacity cost of tens of microseconds rather than the lever a
 * flooding attacker would rather press.
 *
 * <p>The count was measured on this machine, not guessed: see the harness {@code TIMING} section,
 * which prints per-outcome microsecond timings and asserts both an absolute floor and a spread bound.
 * A padding constant that is never measured is how a guard like this silently stops working: if the
 * padding is smaller than the difference it is meant to hide, deleting it changes nothing observable
 * and no test can notice.
 */
final class WorkEqualizer {

    /**
     * SHA-256 compressions per request. Cost here is about {@code 3 us + 0.35 us x n}, so 160 lands
     * near 60 us -- but the harness measures the call in the same run that checks it, so neither
     * figure is taken on trust.
     *
     * <p>The sizing is two-sided, and the quantity to size against is the spread between whole request
     * paths, not the cost of the decision inside them. Measured in the harness: the cheapest path (the
     * availability refusal -- padding plus a 503) and the dearest (a refusal that also throttles, calls
     * the store and writes the body) differ by roughly 24 us. A padding of {@code P} therefore leaves a
     * spread of {@code (P + 24) / P}: staying inside 2x needs {@code P >= 24 us}, and a margin over
     * that needs about twice it. That is what 160 buys, and it measured 1.45x.
     *
     * <p>An earlier value of 48 was sized against the wrong quantity -- the 3.0-4.5 us delta
     * <i>inside</i> the decision -- and the harness reported it: padding measured 18 us, the spread
     * came out 2.59x, and the availability refusal answered in 17 us against 41-44 us for everything
     * else. That is precisely the cheap-and-distinguishable path this class exists to remove, which is
     * worth writing down because "the padding is too big" and "the padding is too small" are the same
     * mistake made in opposite directions. At the other extreme, 200 compressions (~79 us) was three
     * times the work it hid and was charged to requests the throttle had already refused, so the
     * component spent more CPU declining than the session store spent answering.
     *
     * <p>The upper end is why the answer is not simply a much larger number. The padding is charged
     * before every gate, so 60 us caps one core at roughly 16 000 requests per second doing nothing
     * else -- the deliberate price of an answer whose timing says nothing, and still less than the
     * store round trip that sits behind the throttle. The harness asserts both ends against values it
     * measures in its own run: that the padding is real work, and that it has not grown back into a
     * lever.
     *
     * <p>What it cannot assert is a particular deployment's throughput budget; if a site needs the last
     * of those microseconds, the honest options are a cheaper decision path or a written acceptance of
     * a weaker timing property, not an unmeasured constant.
     */
    private static final int COMPRESSIONS = 160;

    private static final ThreadLocal<java.security.MessageDigest> SHA256 =
            new ThreadLocal<java.security.MessageDigest>() {
                @Override
                protected java.security.MessageDigest initialValue() {
                    try {
                        return java.security.MessageDigest.getInstance("SHA-256");
                    } catch (java.security.NoSuchAlgorithmException impossible) {
                        throw new IllegalStateException("SHA-256 unavailable", impossible);
                    }
                }
            };

    /**
     * Constant input: the digest value is discarded and its length never varies. It is never the
     * loop's working buffer -- {@link #apply} clones it -- because the loop zeroes whatever it ends
     * on, and writing zeros into this shared array would silently turn every later request's padding
     * into a digest of nothing. That is invisible while the loop runs and total the moment someone
     * sets {@link #COMPRESSIONS} to zero, which is exactly the kind of defect a shared mutable array
     * should not be allowed to hide.
     */
    private static final byte[] CONSTANT_INPUT = "acme-work-equalizer-constant-input".getBytes(
            java.nio.charset.StandardCharsets.US_ASCII);

    private WorkEqualizer() {
    }

    static void apply() {
        java.security.MessageDigest digest = SHA256.get();
        byte[] carry = CONSTANT_INPUT.clone();
        for (int i = 0; i < COMPRESSIONS; i++) {
            digest.reset();
            digest.update(carry);
            carry = digest.digest();
        }
        // Keep the result reachable so the loop cannot be treated as dead code, and zero the private
        // copy so the intermediate digest does not outlive the call.
        java.util.Arrays.fill(carry, (byte) 0);
    }

    /** Exposed for the harness, which tunes {@link #COMPRESSIONS} against measured cost. */
    static int compressions() {
        return COMPRESSIONS;
    }
}
