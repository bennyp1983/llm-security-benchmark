package com.example.identity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * Equal work on every refusal branch (Rule 6: "identical messages <em>and comparable work</em> for
 * every failure").
 *
 * <p>Same messages are only half the control. If "no such account" returns in 0.1 ms and "wrong
 * password" takes 140 ms, the timing channel says exactly what the message was written not to say,
 * and a caller does not need the message at all. So every early return in {@code signIn} is timed
 * <em>separately</em>, not as a group: comparing a group average to itself hides the one branch
 * whose work went missing.
 *
 * <p>Three things make these assertions falsifiable rather than decorative, and each is the residue
 * of a timing test that went green for the wrong reason:
 * <ul>
 *   <li><b>Microseconds.</b> At 100k PBKDF2 iterations every path prints "1 ms" in milliseconds and
 *     the comparison is noise.</li>
 *   <li><b>An absolute floor, not only a ratio.</b> Delete the derivation from <em>every</em> branch
 *     and the spread stays at 1.00 while the whole property is gone. Only a floor in absolute units
 *     catches work removed uniformly.</li>
 *   <li><b>A CPU floor next to the wall-clock one.</b> A wall-clock equaliser - padding every branch
 *     up to a common floor with a park or a sleep - satisfies a stopwatch while doing no key
 *     derivation at all. PBKDF2 is CPU-bound, so the CPU time must track the wall time.</li>
 * </ul>
 *
 * <p>The budgets are set far above the number of attempts made here. A fixture that trips its own
 * limiter mid-matrix rewrites the assertions being measured (the third sample of a five-sample
 * matrix is suddenly the throttled branch), which is how a timing suite ends up measuring the wrong
 * branch and still passing.
 */
public final class EqualWorkTest {

    /** Half of the ~140 ms a 100k-iteration derivation costs here; catches its complete removal. */
    private static final double FLOOR_US = 50_000d;
    /** A branch may not cost more than this multiple of the cheapest equal-cost branch. */
    private static final double MAX_SPREAD = 3.0d;
    private static final int REPS = 3;

    private EqualWorkTest() {
    }

    public static void run() throws Exception {
        signInBranches();
        cpuWorkNotWallClock();
        throttledBranchIsCheapAndSymmetric();
        registrationBranches();
    }

    // ------------------------------------------------------------------ sign-in

    private static void signInBranches() throws Exception {
        section("Every sign-in refusal costs about one derivation (microseconds, per branch)");
        Harness.Fixture f = Harness.fixture("equalwork", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            Harness.register(b, Harness.E2, Harness.U2, Harness.P2);
            // A credential below the accepted cost floor: strictly decoded, therefore refused, and
            // the branch that must still spend a full derivation.
            Harness.rawExecute(f, "UPDATE account SET password = 'v1$pbkdf2-sha256$1$AAAAAAAAAAA"
                    + "$AAAAAAAAAAA' WHERE username_canon = 'bob'");

            Map<String, Double> medians = new LinkedHashMap<>();
            medians.put("wrong password (account exists)", measure(() ->
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL)));
            medians.put("unknown username", measure(() ->
                    b.api.signIn("nosuchaccount", Harness.chars(Harness.P2), SourceId.LOCAL)));
            medians.put("unknown e-mail", measure(() ->
                    b.api.signIn("nobody@example.com", Harness.chars(Harness.P2), SourceId.LOCAL)));
            medians.put("stored row fails strict decoding", measure(() ->
                    b.api.signIn(Harness.U2, Harness.chars(Harness.P3), SourceId.LOCAL)));
            medians.put("candidate refused by policy", measure(() ->
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P_BELOW_MIN), SourceId.LOCAL)));
            medians.put("malformed identifier", measure(() ->
                    b.api.signIn("not a legal identifier!!", Harness.chars(Harness.P1), SourceId.LOCAL)));
            medians.put("wrong password via e-mail", measure(() ->
                    b.api.signIn(Harness.E1, Harness.chars(Harness.P2), SourceId.LOCAL)));

            for (Map.Entry<String, Double> e : medians.entrySet()) {
                note(String.format("  %-34s median %8.1f ms", e.getKey(), e.getValue() / 1000d));
            }
            for (Map.Entry<String, Double> e : medians.entrySet()) {
                check("\"" + e.getKey() + "\" still costs a derivation (absolute floor)",
                        e.getValue() >= FLOOR_US);
            }
            double min = medians.values().stream().mapToDouble(Double::doubleValue).min().orElse(0d);
            double max = medians.values().stream().mapToDouble(Double::doubleValue).max().orElse(0d);
            check(String.format("the spread across all seven refusal branches is <= %sx (was %.2fx)",
                    MAX_SPREAD, max / min), max / min <= MAX_SPREAD);

            // The accepting branch must not be visibly different either, or "did I get it right"
            // becomes answerable by timing alone.
            double success = measure(() -> b.api.signIn(Harness.U1, Harness.chars(Harness.P1),
                    SourceId.LOCAL));
            note(String.format("  %-34s median %8.1f ms", "correct password (accepts)", success / 1000d));
            check("a successful sign-in costs a derivation too", success >= FLOOR_US);
            check("and is not separated from the refusals by more than the same spread",
                    success / min <= MAX_SPREAD && max / success <= MAX_SPREAD);

            check("the limiter never engaged during the matrix (the assertions above would otherwise"
                    + " have been measuring the throttled branch)",
                    Long.parseLong(Harness.rawColumn(f,
                            "SELECT MAX(until_epoch_s) FROM auth_throttle").get(0)) == 0L);
            check("the fixture's per-account budget was never approached",
                    Long.parseLong(Harness.rawColumn(f,
                            "SELECT MAX(failures) FROM auth_throttle").get(0)) < 50L);
        }
    }

    private static void cpuWorkNotWallClock() throws Exception {
        section("The equalising work is real key derivation, not a wall-clock pad");
        Harness.Fixture f = Harness.fixture("equalwork-cpu", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            double[] wrong = cpu(() -> b.api.signIn(Harness.U1,
                    Harness.chars(Harness.P2), SourceId.LOCAL));
            double[] absent = cpu(() -> b.api.signIn("nosuchaccount",
                    Harness.chars(Harness.P2), SourceId.LOCAL));
            double[] policy = cpu(() -> b.api.signIn(Harness.U1,
                    Harness.chars(Harness.P_BELOW_MIN), SourceId.LOCAL));
            check("this JVM reports thread CPU time (a -1 would make the floor vacuous)",
                    wrong[1] >= 0 && absent[1] >= 0 && policy[1] >= 0);
            Map<String, double[]> all = new LinkedHashMap<>();
            all.put("wrong password", wrong);
            all.put("unknown account", absent);
            all.put("policy-refused candidate", policy);
            for (Map.Entry<String, double[]> e : all.entrySet()) {
                double wall = e.getValue()[0];
                double cpu = e.getValue()[1];
                note(String.format("  %-24s wall %8.1f ms  cpu %8.1f ms  (%.0f%% of wall)",
                        e.getKey(), wall / 1000d, cpu / 1000d, wall <= 0 ? 0d : 100d * cpu / wall));
                check(e.getKey() + ": CPU time itself clears the floor", cpu >= FLOOR_US);
                check(e.getKey() + ": the work is CPU-bound (PBKDF2), not a sleep or a park",
                        wall > 0 && cpu / wall >= 0.6d);
            }
            check("the CPU-time spread across branches is also within the bound",
                    maxOf(all) / minCpu(all) <= MAX_SPREAD);
        }
    }

    private static void throttledBranchIsCheapAndSymmetric() throws Exception {
        section("The one deliberate exception: a throttled refusal is cheap for anybody");
        Harness.Overrides o = Harness.overrides();
        // 3, not 1: the loader requires the per-account attempt limit to be in
        // [3, Config.MAX_ATTEMPT_COUNT], so a fixture at 1 aborts at startup and the throttled
        // branch is never measured at all.
        o.authAccountMax = 3;
        o.authSourceMax = 1000;
        Harness.Fixture f = Harness.fixture("equalwork-throttle", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            // Three each, because the limit is 3: the penalty is free until the counter reaches it.
            for (int i = 0; i < 3; i++) {
                b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
                b.api.signIn("nosuchaccount", Harness.chars(Harness.P2), SourceId.LOCAL);
            }
            check("the real account is in penalty",
                    Long.parseLong(Harness.rawColumn(f, "SELECT MAX(until_epoch_s) FROM auth_throttle"
                            + " WHERE bucket LIKE 'a:%'").get(0)) > f.clock.nowEpochSeconds());
            check("so is the fictitious one - a wrong identifier gets a counter too, which is what"
                            + " makes the cheap refusal symmetric",
                    Harness.rawColumn(f, "SELECT COUNT(*) FROM auth_throttle WHERE until_epoch_s > "
                                    + f.clock.nowEpochSeconds()).get(0).equals("2"));

            double known = measure(() -> b.api.signIn(Harness.U1, Harness.chars(Harness.P1),
                    SourceId.LOCAL));
            double unknown = measure(() -> b.api.signIn("nosuchaccount", Harness.chars(Harness.P1),
                    SourceId.LOCAL));
            note(String.format("  throttled, account exists: %6.2f ms | throttled, nobody there:"
                    + " %6.2f ms", known / 1000d, unknown / 1000d));
            check("a throttled refusal is far cheaper than a derivation, so the limiter really does"
                    + " bound the cost", known < FLOOR_US / 5d && unknown < FLOOR_US / 5d);
            check("and the two cheap refusals are on the same order of magnitude, so the cheapness"
                    + " tells the caller nothing about whether the account exists",
                    Math.max(known, unknown) / Math.min(known, unknown) <= 10d);
            check("the cheap refusal is not also a success",
                    !b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());

            section("An unusable source label is cheap too, and does no work at all");
            double badSource = measure(() -> b.api.signIn(Harness.U1, Harness.chars(Harness.P1),
                    "rotating-label"));
            check("it costs no derivation", badSource < FLOOR_US / 5d);

            section("Every counter that exists is accounted for, by namespace");
            // Census rather than a bare count: the point is that the registration budgets and the
            // sign-in counters are *different rows*, so neither operation can reset or exhaust the
            // other. One shared "s" prefix used to make them the same row, which let a successful
            // sign-in hand an attacker a fresh registration budget.
            checkEquals("one global registration budget, one per-source registration budget,"
                            + " one sign-in source counter, two account counters - and no duplicates",
                    List.of("1", "1", "1", "2"),
                    List.of(
                            Harness.rawColumn(f, "SELECT COUNT(*) FROM auth_throttle"
                                    + " WHERE bucket LIKE 'g:%'").get(0),
                            Harness.rawColumn(f, "SELECT COUNT(*) FROM auth_throttle"
                                    + " WHERE bucket LIKE 'r:%'").get(0),
                            Harness.rawColumn(f, "SELECT COUNT(*) FROM auth_throttle"
                                    + " WHERE bucket LIKE 's:%'").get(0),
                            Harness.rawColumn(f, "SELECT COUNT(*) FROM auth_throttle"
                                    + " WHERE bucket LIKE 'a:%'").get(0)));
            check("the registration budgets are not in penalty, so registration still works from here",
                    Harness.rawColumn(f, "SELECT COUNT(*) FROM auth_throttle WHERE bucket LIKE 'g:%'"
                            + " OR bucket LIKE 'r:%'").get(0).equals("2")
                            && Harness.rawColumn(f, "SELECT COUNT(*) FROM auth_throttle WHERE"
                            + " (bucket LIKE 'g:%' OR bucket LIKE 'r:%') AND until_epoch_s > 0")
                            .get(0).equals("0"));
        }
    }

    // ------------------------------------------------------------------ registration

    private static void registrationBranches() throws Exception {
        section("Registration timing does not answer 'is this username taken?'");
        Harness.Fixture f = Harness.fixture("equalwork-register", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            double taken = measure(() -> b.api.register(Harness.E2, Harness.U1,
                    Harness.chars(Harness.P3), SourceId.LOCAL));
            int[] n = {0};
            double fresh = measure(() -> b.api.register("fresh" + (n[0]++) + "@example.com",
                    "fresh" + n[0], Harness.chars(Harness.P3), SourceId.LOCAL));
            double takenEmail = measure(() -> b.api.register(Harness.E1, "another" + n[0],
                    Harness.chars(Harness.P3), SourceId.LOCAL));
            note(String.format("  taken username: %6.1f ms | free username: %6.1f ms | taken e-mail:"
                    + " %6.1f ms", taken / 1000d, fresh / 1000d, takenEmail / 1000d));
            check("a duplicate username still pays for a derivation (the hash is computed before the"
                    + " insert is attempted, so the collision cannot be read off the clock)",
                    taken >= FLOOR_US);
            check("a free username pays the same", fresh >= FLOOR_US);
            check("a duplicate e-mail pays the same", takenEmail >= FLOOR_US);
            check("and the three are within the same spread",
                    Math.max(Math.max(taken, fresh), takenEmail)
                            / Math.min(Math.min(taken, fresh), takenEmail) <= MAX_SPREAD);

            int accountsBeforePolicyRefusal = Harness.rawCount(f, "account");
            double shortPassword = measure(() -> b.api.register(Harness.E3, "shortpw" + n[0],
                    Harness.chars(Harness.P_BELOW_MIN), SourceId.LOCAL));
            check("a candidate refused by policy is cheap - it is refused before any derivation, and"
                    + " the outcome describes the caller's own input rather than any server state",
                    shortPassword < FLOOR_US / 5d);
            checkEquals("and the four refused attempts created no row",
                    accountsBeforePolicyRefusal, Harness.rawCount(f, "account"));
            note("residual, stated in README 'Limitations': registration must tell the caller whether"
                    + " the account they asked for was created, so the *message* does answer 'is this"
                    + " username taken'. Timing does not, and the enumeration rate is bounded by the"
                    + " per-source and global registration budgets.");
        }
    }

    // ------------------------------------------------------------------ helpers

    /** One warm-up run (JIT), then {@value #REPS} timed runs, reported as the median. */
    private static double measure(Body body) {
        try {
            body.run();
        } catch (Exception ignored) {
            // A throwing branch is not what is being measured here; the assertions do that.
        }
        List<Double> samples = new ArrayList<>(REPS);
        for (int i = 0; i < REPS; i++) {
            samples.add(Harness.micros(() -> {
                try {
                    body.run();
                } catch (Exception ignored) {
                    // as above
                }
            }));
        }
        return Harness.median(samples);
    }

    /** Same, reporting wall and CPU microseconds for a single representative run. */
    private static double[] cpu(Body body) {
        try {
            body.run(); // warm up: a cold branch costs interpreter time, not PBKDF2 time
        } catch (Exception ignored) {
            // as above
        }
        return Harness.cpuMicros(() -> {
            try {
                body.run();
            } catch (Exception ignored) {
                // as above
            }
        });
    }

    private static double maxOf(Map<String, double[]> m) {
        double v = 0;
        for (double[] a : m.values()) {
            v = Math.max(v, a[1]);
        }
        return v;
    }

    private static double minCpu(Map<String, double[]> m) {
        double v = Double.MAX_VALUE;
        for (double[] a : m.values()) {
            v = Math.min(v, a[1]);
        }
        return v;
    }

    interface Body {
        void run() throws Exception;
    }
}
