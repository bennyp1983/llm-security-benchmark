package app;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

/**
 * Credential-storage tests: hash shape, tamper rejection, memory bounds and cross-implementation
 * interoperability. Timings are reported as measurements so README prose can quote the log rather
 * than a remembered number.
 */
public final class PasswordHasherTest {

    /** Wall-clock ceiling for a refusal that must happen <em>before</em> any derivation. */
    private static final long REFUSAL_CEILING_MILLIS = 25;

    public static void main(String[] argv) throws Exception {
        PasswordHasher hasher = Harness.hasher();
        shape(hasher);
        tamperedRows(hasher);
        canonicalForm(hasher);
        upgradeDetection(hasher);
        interopWithSpring(hasher);
        measuredCost(hasher);
        System.exit(Harness.report("PasswordHasherTest"));
    }

    private static void shape(PasswordHasher hasher) {
        Harness.section("stored credential shape");
        String hash = hasher.encode(Harness.chars(Harness.PW_ONE));
        Harness.equal(hash.length(), 97, "the stored string is exactly 97 characters");
        Harness.equal(countChar(hash, '$'), 5, "the stored string has five dollar separators");
        Harness.check(hash.startsWith("$argon2id$v=19$m=" + Harness.TEST_MEMORY_KIB + ",t="
                + Harness.TEST_ITERATIONS + ",p=" + Harness.TEST_PARALLELISM + "$"),
            "the embedded parameters are the configured ones");
        String[] shapeFields = fields(hash);
        Harness.equal(shapeFields.length, 6, "the stored string has six fields");
        Harness.check(!shapeFields[4].contains("=") && !shapeFields[5].contains("="),
            "the salt and digest fields carry no padding character");
        Harness.equal(shapeFields[4].length(), 22, "the salt field is 22 unpadded base64 characters");
        Harness.equal(shapeFields[5].length(), 43, "the digest field is 43 unpadded base64 characters");
        Harness.check(!hash.contains(Harness.PW_ONE), "the password is not a substring of the credential");

        String other = hasher.encode(Harness.chars(Harness.PW_ONE));
        Harness.check(!other.equals(hash), "the same password hashes differently - a fresh salt each time");
        Harness.check(hasher.verify(Harness.chars(Harness.PW_ONE), hash), "a stored credential verifies");
        Harness.check(!hasher.verify(Harness.chars(Harness.PW_WRONG), hash),
            "a wrong password does not verify");

        PasswordHasher.Cost cost = hasher.costOf(hash);
        Harness.equal(cost.memoryKib(), Harness.TEST_MEMORY_KIB, "memory read back from the credential");
        Harness.equal(cost.iterations(), Harness.TEST_ITERATIONS, "iterations read back from the credential");
        Harness.equal(cost.parallelism(), Harness.TEST_PARALLELISM, "parallelism read back from the credential");

        try {
            hasher.costOf("$argon2i$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$" + "A".repeat(43));
            Harness.check(false, "costOf refuses a string this hasher never produced");
        } catch (IllegalArgumentException refused) {
            Harness.check(true, "costOf refuses a string this hasher never produced");
        }
    }

    /** A rewritten row must never be honoured, and must never be paid for either. */
    private static void tamperedRows(PasswordHasher hasher) {
        Harness.section("a tampered or downgraded row is refused without paying for it");
        String real = hasher.encode(Harness.chars(Harness.PW_ONE));
        Matcher parts = Pattern.compile("^\\$argon2id\\$v=19\\$m=([0-9]+),t=([0-9]+),p=([0-9]+)\\$"
            + "([A-Za-z0-9+/]{22})\\$([A-Za-z0-9+/]{43})$").matcher(real);
        Harness.check(parts.matches(), "the fixture credential parses");
        String salt = parts.group(4);
        String hash = parts.group(5);

        // Every entry below is out of the approved bounds or not a credential at all, so it must
        // be refused before any derivation happens. An in-bounds row carrying the wrong digest is
        // a different case (see refusedAfterRealWork) - it is a legitimate credential and the work
        // is genuinely performed.
        String[] tampered = {
            reparam(real, 1024, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM),
            reparam(real, 4096, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM),
            reparam(real, 19_455, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM),
            reparam(real, Harness.TEST_MEMORY_KIB, 1, Harness.TEST_PARALLELISM),
            reparam(real, Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, 0),
            reparam(real, 999_999_999, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM),
            reparam(real, 1_048_577, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM),
            reparam(real, Harness.TEST_MEMORY_KIB, 9999, Harness.TEST_PARALLELISM),
            reparam(real, Harness.TEST_MEMORY_KIB, Harness.TEST_ITERATIONS, 9),
            real.replace("$argon2id$", "$argon2i$"),
            real.replace("$v=19$", "$v=16$"),
            salt + "$" + hash,
            hash,
            "",
            real + " ",
            real + "\n",
            real + "\u0000",
            "\n" + real
        };
        for (String candidate : tampered) {
            if (candidate == null) {
                continue;
            }
            long started = System.nanoTime();
            boolean accepted = hasher.verify(Harness.chars(Harness.PW_ONE), candidate);
            long elapsedMillis = (System.nanoTime() - started) / 1_000_000L;
            Harness.check(!accepted, "refused without granting access: " + describe(candidate));
            Harness.atMost(elapsedMillis, REFUSAL_CEILING_MILLIS,
                "refused before doing key-derivation work: " + describe(candidate));
        }

        // A row rewritten to in-bounds parameters carries the wrong digest for that cost: access
        // is still refused, and the refusal legitimately costs a derivation. The point of this
        // group is that the ceiling is enforced on the value, not that odd values are skipped.
        Harness.section("an in-bounds but mismatched row costs real work and is still refused");
        String foreignDigest = fields(hasher.encode(Harness.chars(Harness.PW_TWO)))[5];
        String[] refusedAfterRealWork = {
            reparam(real, Harness.TEST_MEMORY_KIB * 2, Harness.TEST_ITERATIONS, Harness.TEST_PARALLELISM),
            "$argon2id$v=19$m=" + Harness.TEST_MEMORY_KIB + ",t=" + Harness.TEST_ITERATIONS + ",p="
                + Harness.TEST_PARALLELISM + "$" + salt + "$" + foreignDigest
        };
        for (String candidate : refusedAfterRealWork) {
            Harness.equal(candidate.length(), 97, "the mismatched-row fixture keeps the real shape");
            long started = System.nanoTime();
            boolean accepted = hasher.verify(Harness.chars(Harness.PW_ONE), candidate);
            long elapsedMillis = (System.nanoTime() - started) / 1_000_000L;
            Harness.check(!accepted, "an in-bounds mismatched row is refused: " + describe(candidate));
            Harness.check(elapsedMillis > REFUSAL_CEILING_MILLIS,
                "the refusal cost real derivation work, so no cheap row is honoured: "
                    + describe(candidate) + " took " + elapsedMillis + " ms");
        }
        Harness.check(!hasher.verify(Harness.chars(Harness.PW_ONE), null), "a null stored value is refused");
        Harness.check(!hasher.verify(new char[0], real), "an empty candidate never verifies");
        Harness.check(!hasher.verify(null, real), "a null candidate never verifies");
    }

    /** Base64 that decodes to the right bytes but is not <em>the</em> encoding must not verify. */
    private static void canonicalForm(PasswordHasher hasher) {
        Harness.section("only canonical base64 denotes a stored credential");
        String real = hasher.encode(Harness.chars(Harness.PW_ONE));
        String[] split = real.split("\\$");
        Harness.equal(split.length, 6, "the credential splits into six dollar-separated fields");
        String salt = split[4];
        String hash = split[5];

        // 16 bytes occupy 21.33 base64 characters, so the 22nd character carries four unused low
        // bits that must be zero; 32 bytes occupy 42.67, so the 43rd must have a zero low bit.
        // Flipping one of those bits yields a string that still matches the length pattern but is
        // not the encoding of any byte sequence - it must never verify.
        String nonCanonicalSalt = salt.substring(0, 21) + oddBitChar(salt.charAt(21));
        String nonCanonicalHash = hash.substring(0, 42) + oddBitChar(hash.charAt(42));
        for (String candidate : new String[] {
            split[0] + "$" + split[1] + "$" + split[2] + "$" + split[3] + "$" + nonCanonicalSalt + "$" + hash,
            split[0] + "$" + split[1] + "$" + split[2] + "$" + split[3] + "$" + salt + "$" + nonCanonicalHash,
            real + "=",
            real.substring(0, real.length() - 1)
        }) {
            Harness.check(!hasher.verify(Harness.chars(Harness.PW_ONE), candidate),
                "a non-canonical or truncated credential is refused: " + describe(candidate));
        }

        Harness.section("the credential carries no newlines and no whitespace");
        Pattern strict = Pattern.compile("\\A\\$argon2id\\$v=19\\$m=[0-9]{1,9},t=[0-9]{1,4},"
            + "p=[0-9]{1,3}\\$[A-Za-z0-9+/]{22}\\$[A-Za-z0-9+/]{43}\\z");
        Harness.check(strict.matcher(real).matches(), "the produced credential matches the strict form");
        Harness.requireNotEmpty(real, "the produced credential");
        for (String candidate : new String[] {real + "\n", "\n" + real, " " + real, real + " "}) {
            Harness.check(!hasher.verify(Harness.chars(Harness.PW_ONE), candidate),
                "surrounding whitespace is not part of a credential: " + describe(candidate));
            Harness.check(!strict.matcher(candidate).matches(),
                "the strict form rejects: " + describe(candidate));
        }
    }

    private static void upgradeDetection(PasswordHasher hasher) {
        Harness.section("an existing credential below current policy is detected");
        Harness.check(hasher.weakerThanPolicy(null), "a missing credential counts as weak");
        Harness.check(!hasher.weakerThanPolicy(hasher.encode(Harness.chars(Harness.PW_ONE))),
            "a credential at current policy is not flagged");
        PasswordHasher stronger;
        try {
            stronger = new PasswordHasher(Harness.TEST_MEMORY_KIB * 2, Harness.TEST_ITERATIONS,
                Harness.TEST_PARALLELISM);
        } catch (java.security.GeneralSecurityException impossible) {
            throw new IllegalStateException(impossible);
        }
        String weaker = hasher.encode(Harness.chars(Harness.PW_ONE));
        Harness.check(stronger.weakerThanPolicy(weaker),
            "a credential below the raised policy is flagged for upgrade");
        Harness.check(!hasher.weakerThanPolicy(stronger.encode(Harness.chars(Harness.PW_ONE))),
            "a credential above current policy is not downgraded");
        Harness.check(hasher.weakerThanPolicy("$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), "an absurd row counts as weak");
    }

    /**
     * Interoperability oracle: if this program's output cannot be verified by the mainstream
     * implementation of the same format, the format - not the reviewer's eye - is the source of
     * truth. Run in both directions.
     */
    private static void interopWithSpring(PasswordHasher hasher) {
        Harness.section("the stored format is the industry one, verified by a second implementation");
        Argon2PasswordEncoder spring = new Argon2PasswordEncoder(PasswordHasher.SALT_BYTES,
            PasswordHasher.HASH_BYTES, Harness.TEST_PARALLELISM, Harness.TEST_MEMORY_KIB,
            Harness.TEST_ITERATIONS);

        String ours = hasher.encode(Harness.chars(Harness.PW_ONE));
        Harness.check(spring.matches(Harness.PW_ONE, ours),
            "Spring Security verifies a credential produced here");
        Harness.check(!spring.matches(Harness.PW_WRONG, ours),
            "Spring Security rejects a wrong password against a credential produced here");

        String theirs = spring.encode(Harness.PW_ONE);
        Harness.equal(theirs.length(), 97, "Spring produces the same 97-character shape");
        Harness.equal(fields(theirs)[3], fields(ours)[3],
            "the two implementations emit the identical parameter field");
        Harness.check(hasher.verify(Harness.chars(Harness.PW_ONE), theirs),
            "this program verifies a credential produced by Spring Security");
        Harness.check(!hasher.verify(Harness.chars(Harness.PW_WRONG), theirs),
            "and still refuses a wrong password for it");

        Argon2PasswordEncoder springDefaults = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        String belowFloor = springDefaults.encode(Harness.PW_ONE);
        Harness.check(!hasher.verify(Harness.chars(Harness.PW_ONE), belowFloor),
            "a credential at the framework's own defaults is below the approved floor and is refused");
        Harness.note("framework default parameters are " + fields(belowFloor)[3]
            + " - refused by this program's floor of m=" + Harness.TEST_MEMORY_KIB);
    }

    /** Derives at both the fixture cost and the shipped default so prose can quote a real number. */
    private static void measuredCost(PasswordHasher hasher) {
        Harness.section("measured key-derivation cost");
        long fixture = timeDerivation(hasher);
        Harness.atLeast(fixture, 1L, "a derivation at the fixture cost took measurable time");
        Harness.note("fixture cost m=" + Harness.TEST_MEMORY_KIB + "KiB,t=" + Harness.TEST_ITERATIONS
            + ",p=" + Harness.TEST_PARALLELISM + " took " + fixture + " ms");
        Harness.atLeast(fixture, 20L,
            "even the approved floor is expensive enough to be a rate-limit multiplier");

        try {
            PasswordHasher shipped = new PasswordHasher(Config.DEFAULT_MEMORY_KIB, Config.DEFAULT_ITERATIONS,
                Config.DEFAULT_PARALLELISM);
            long cost = timeDerivation(shipped);
            Harness.note("shipped default m=" + Config.DEFAULT_MEMORY_KIB + "KiB,t="
                + Config.DEFAULT_ITERATIONS + ",p=" + Config.DEFAULT_PARALLELISM + " took " + cost + " ms");
            Harness.atLeast(cost, fixture, "the shipped default costs at least as much as the floor");
            Harness.atMost(cost, 8_000L, "the shipped default stays inside a request budget");
        } catch (java.security.GeneralSecurityException impossible) {
            Harness.check(false, "the shipped default parameters must be constructible: " + impossible);
        }
    }

    private static long timeDerivation(PasswordHasher hasher) {
        char[] password = Harness.chars(Harness.PW_ONE);
        long best = Long.MAX_VALUE;
        for (int attempt = 0; attempt < 3; attempt++) {
            long started = System.nanoTime();
            String hash = hasher.encode(password);
            boolean ok = hasher.verify(password, hash);
            long elapsed = (System.nanoTime() - started) / 1_000_000L;
            Harness.check(ok, "round-trip at the measured cost");
            best = Math.min(best, elapsed);
        }
        java.util.Arrays.fill(password, '\0');
        return best;
    }

    private static final String B64_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * A different character of the base64 alphabet whose 6-bit value differs only in the low bit,
     * so the trailing group gains a non-zero unused bit and the string stops being canonical.
     */
    private static char oddBitChar(char value) {
        int index = B64_ALPHABET.indexOf(value);
        if (index < 0) {
            throw new IllegalArgumentException("the fixture field is not base64");
        }
        return B64_ALPHABET.charAt(index % 2 == 0 ? index + 1 : index - 1);
    }

    /** Dollar-separated fields of a PHC string: ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]. */
    private static String[] fields(String hash) {
        return hash.split("\\$");
    }

    /** Replaces only the parameter field, leaving the salt and digest fields untouched. */
    private static String reparam(String hash, int memory, int iterations, int parallelism) {
        String[] parts = fields(hash);
        return "$" + parts[1] + "$" + parts[2] + "$m=" + memory + ",t=" + iterations + ",p=" + parallelism
            + "$" + parts[4] + "$" + parts[5];
    }

    private static int countChar(String value, char needle) {
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == needle) {
                count++;
            }
        }
        return count;
    }

    /** Printable, non-echoing label for a fixture: control characters are escaped, not emitted. */
    private static String describe(String value) {
        StringBuilder label = new StringBuilder(64);
        for (int i = 0; i < value.length() && i < 24; i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                label.append(String.format("\\u%04x", (int) c));
            } else {
                label.append(c);
            }
        }
        if (value.length() > 24) {
            label.append("...(").append(value.length()).append(" chars)");
        }
        return "<" + label + ">";
    }
}
