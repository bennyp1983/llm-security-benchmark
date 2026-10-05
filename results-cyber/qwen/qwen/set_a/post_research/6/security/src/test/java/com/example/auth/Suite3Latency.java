package com.example.auth;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Suite 3: what a remote attacker learns by timing the endpoint.
 *
 * <p>Two independent properties are asserted, because either one alone is falsifiable by a defect
 * the other would catch:
 *
 * <ul>
 *   <li><b>Spread.</b> The median wall time of every credential outcome must sit within a small
 *       factor of every other, so a stopwatch cannot tell "wrong password" from "no such account"
 *       from "malformed name".</li>
 *   <li><b>Absolute floor.</b> A ratio alone stays green if the work is deleted from <em>every</em>
 *       path -- all six medians fall together and the ratio is still 1.0. So each path is also held
 *       to an absolute wall-clock floor derived from a measured derivation, and each path that is
 *       supposed to <em>do</em> the derivation is held to a CPU-time floor measured with
 *       {@link ThreadMXBean}, which padding cannot fake: parking a thread burns wall time and no
 *       CPU at all.</li>
 * </ul>
 *
 * <p>The paths that refuse on input shape (too-short password, control character) are held to the
 * wall floor only. They perform no derivation by design, and their defence is the latency floor, not
 * equal work; asserting a CPU floor on them would assert something the design never promised.
 */
public final class Suite3Latency {

    private static final int ITERATIONS = AuthConfig.MIN_PBKDF2_ITERATIONS;
    private static final int SAMPLES = 5;
    private static final String SRC = "203.0.113.77";

    /** Ratio bound on medians across paths. */
    private static final double MAX_SPREAD_RATIO = 1.45D;

    /** Ratio bound on CPU time across the paths that must derive. */
    private static final double MAX_CPU_RATIO = 1.75D;

    private static final ThreadMXBean CPU = ManagementFactory.getThreadMXBean();

    public static void main(String[] args) throws Exception {
        if (!CPU.isThreadCpuTimeSupported()) {
            Check.note("thread CPU time is unsupported here; the CPU floors below are skipped");
        }
        long derivationNanos;
        long derivationCpuNanos;
        try (Fixture fx = new Fixture("suite3")) {
            fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
            fx.withStandardAccounts(ITERATIONS);

            // Reference cost, measured on this machine with the same pepper and iteration count the
            // service will use. Every floor below is derived from these two numbers.
            PasswordHasher probe = new PasswordHasher(Fixture.PEPPER.clone(), ITERATIONS, new java.security.SecureRandom());
            byte[] probePassword = "uniform-work-probe".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            derivationNanos = measureCpuNanos(probe, probePassword, true);
            derivationCpuNanos = measureCpuNanos(probe, probePassword, false);
            probe.erase();
            Check.note("measured derivation wall_us=" + (derivationNanos / 1000L)
                    + " cpu_us=" + (derivationCpuNanos / 1000L));
            Check.ok("the reference derivation really costs measurable time",
                    derivationNanos / 1000L > 50_000L);

            try (AuthenticationService service = AuthenticationService.builder()
                    .config(fx.config(ITERATIONS).accountLockAfter(20).sourceMaxAttempts(200).build())
                    .timeSource(fx.time)
                    .build()) {
                runPaths(service, fx, derivationNanos, derivationCpuNanos);
            }
        }
        Check.summary("suite3-latency");
    }

    private static void runPaths(AuthenticationService service, Fixture fx, long derivationNanos,
            long derivationCpuNanos) throws Exception {
        String[] names = {"known-good", "known-bad", "unknown-name", "malformed-name", "short-password",
                "control-char"};
        long[][] walls = new long[names.length][SAMPLES];
        long[][] cpus = new long[names.length][SAMPLES];

        // Warm every path once: class loading and JIT on the first call are not what is being measured.
        for (int i = 0; i < names.length; i++) {
            timedAttempt(service, fx, i);
        }

        // Interleave the paths rather than run them in blocks, so drift in machine load hits each
        // path a similar number of times instead of biasing whichever ran last.
        for (int sample = 0; sample < SAMPLES; sample++) {
            for (int path = 0; path < names.length; path++) {
                long[] pair = timedAttempt(service, fx, path);
                walls[path][sample] = pair[0];
                cpus[path][sample] = pair[1];
            }
        }

        double[] medians = new double[names.length];
        double[] cpuMedians = new double[names.length];
        for (int i = 0; i < names.length; i++) {
            medians[i] = median(walls[i]);
            cpuMedians[i] = median(cpus[i]);
            // Reported in microseconds, matching the label and the derivation note above. These values
            // are read straight out of this log when the README quotes them, so a nanosecond number
            // wearing a _us suffix makes every quoted figure wrong by a factor of a thousand.
            Check.note("path=" + names[i] + " median_wall_us=" + (long) medians[i] / 1000L
                    + " median_cpu_us=" + (long) cpuMedians[i] / 1000L
                    + " min_wall_us=" + Arrays.stream(walls[i]).min().orElse(0L) / 1000L
                    + " max_wall_us=" + Arrays.stream(walls[i]).max().orElse(0L) / 1000L);
        }

        double smallest = Double.MAX_VALUE;
        double largest = 0D;
        for (double m : medians) {
            smallest = Math.min(smallest, m);
            largest = Math.max(largest, m);
        }
        double ratio = largest / Math.max(1D, smallest);
        Check.note("whole-path wall spread ratio=" + String.format(java.util.Locale.ROOT, "%.2f", ratio));
        Check.ok("every credential outcome takes comparable wall time (ratio <= " + MAX_SPREAD_RATIO + ")",
                ratio <= MAX_SPREAD_RATIO);

        // Absolute floor: a tenth of the reference derivation. Padding must hold every path there;
        // a path that returned in microseconds would show up here even with a healthy ratio.
        long absoluteFloorNanos = derivationNanos / 10L;
        for (int i = 0; i < names.length; i++) {
            Check.ok(names[i] + " respects the absolute wall floor (" + absoluteFloorNanos / 1000L + " us)",
                    medians[i] >= absoluteFloorNanos);
        }

        if (CPU.isThreadCpuTimeSupported() && CPU.isCurrentThreadCpuTimeSupported()) {
            long cpuFloor = derivationCpuNanos / 2L;
            for (int i = 0; i < 4; i++) {
                Check.ok(names[i] + " burns CPU comparable to a derivation (" + cpuFloor / 1000L
                        + " us floor)", cpuMedians[i] >= cpuFloor);
            }
            double cpuSmallest = Double.MAX_VALUE;
            double cpuLargest = 0D;
            for (int i = 0; i < 4; i++) {
                cpuSmallest = Math.min(cpuSmallest, cpuMedians[i]);
                cpuLargest = Math.max(cpuLargest, cpuMedians[i]);
            }
            double cpuRatio = cpuLargest / Math.max(1D, cpuSmallest);
            Check.note("deriving-path CPU spread ratio=" + String.format(java.util.Locale.ROOT, "%.2f", cpuRatio));
            Check.ok("the deriving paths burn comparable CPU (ratio <= " + MAX_CPU_RATIO + ")",
                    cpuRatio <= MAX_CPU_RATIO);

            // The shape-refusing paths must NOT burn derivation CPU: if they did, the wall floor
            // would be doing nothing and the design's claim would be the wrong one.
            for (int i = 4; i < names.length; i++) {
                Check.ok(names[i] + " refuses before any derivation (cpu_us=" + (long) cpuMedians[i] + ")",
                        cpuMedians[i] < cpuFloor);
            }
        }

        Check.eq("one event per timed attempt", (SAMPLES * names.length) + names.length,
                Integer.valueOf(fx.logLines().size()));
    }

    /** Runs one attempt on the given path index and returns {wallNanos, cpuNanos}. */
    private static long[] timedAttempt(AuthenticationService service, Fixture fx, int path) {
        String username;
        String password;
        switch (path) {
            case 0:
                username = Fixture.USER_ALICE;
                password = Fixture.PASSWORD_A;
                break;
            case 1:
                username = Fixture.USER_BOB;
                password = "Wrong-Password-99";
                break;
            case 2:
                username = "absent-observer-" + path;
                password = Fixture.PASSWORD_A;
                break;
            case 3:
                username = "bad name!";
                password = Fixture.PASSWORD_A;
                break;
            case 4:
                username = Fixture.USER_ALICE;
                password = "Tiny-1";
                break;
            default:
                username = Fixture.USER_ALICE;
                password = "Fresh\tIngress-21";
                break;
        }
        char[] chars = password.toCharArray();
        long start = System.nanoTime();
        long cpuStart = currentThreadCpuNanos();
        try {
            AuthResult result = service.authenticate(AuthenticationService.Attempt.of(username, chars, SRC));
            if (path == 0 && !result.isSuccess()) {
                throw new IllegalStateException("the known-good probe must succeed for this measurement");
            }
            if (path != 0 && result.isSuccess()) {
                throw new IllegalStateException("a probing path must never authenticate: " + path);
            }
            return new long[] {System.nanoTime() - start, currentThreadCpuNanos() - cpuStart};
        } finally {
            Arrays.fill(chars, (char) 0);
        }
    }

    private static long currentThreadCpuNanos() {
        if (!CPU.isThreadCpuTimeSupported() || !CPU.isCurrentThreadCpuTimeSupported()) {
            return 0L;
        }
        return CPU.getCurrentThreadCpuTime();
    }

    /** @param wall {@code true} measures wall time, {@code false} measures CPU time of the derivation. */
    private static long measureCpuNanos(PasswordHasher hasher, byte[] password, boolean wall) {
        byte[] salt = hasher.newSalt();
        long best = Long.MAX_VALUE;
        for (int i = 0; i < 2; i++) {
            long start = System.nanoTime();
            long cpu = currentThreadCpuNanos();
            try {
                hasher.derive(password, salt, ITERATIONS);
            } catch (AuthException e) {
                throw new IllegalStateException(e);
            }
            long elapsed = wall ? System.nanoTime() - start : currentThreadCpuNanos() - cpu;
            if (elapsed < best) {
                best = elapsed;
            }
        }
        return best;
    }

    private static double median(long[] values) {
        List<Long> sorted = new ArrayList<>();
        for (long v : values) {
            sorted.add(v);
        }
        sorted.sort(null);
        int n = sorted.size();
        if (n == 0) {
            return 0D;
        }
        return n % 2 == 1 ? sorted.get(n / 2) : (sorted.get(n / 2 - 1) + sorted.get(n / 2)) / 2.0D;
    }
}
