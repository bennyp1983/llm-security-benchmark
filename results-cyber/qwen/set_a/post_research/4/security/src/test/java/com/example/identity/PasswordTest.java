package com.example.identity;

import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * Password policy, erasure, and the credential encoding.
 *
 * <p>The first section is a <em>proof</em>, not a check on our own code: it derives through the raw
 * JCE, bypassing {@link Password}, to demonstrate that the collision classes {@link Password}
 * refuses are real on this JVM. Without that, the guard looks like paranoia and can be deleted
 * without anything going red. If a future JDK stops colliding, that section reports it as a note
 * rather than failing - the guard stays, because the JCE does not document the behaviour either way.
 *
 * <p>Control characters are built from numeric casts, never literals: a raw NUL in a source file is
 * invisible in a diff, defeats textual patching, and still compiles, so the assertion silently tests
 * different bytes than it appears to. {@code tools/build.sh} fails the build on one.
 *
 * <p>Each negative fixture is defective in exactly one way, so a pass can never be owed to a rule
 * other than the one under test.
 */
public final class PasswordTest {

    private static final byte[] FIXED_SALT =
            new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static final int PROOF_ITERATIONS = 1000;

    private static final char NUL = (char) 0x00;
    private static final char TAB = (char) 0x09;
    private static final char CR = (char) 0x0D;
    private static final char LF = (char) 0x0A;

    private PasswordTest() {
    }

    public static void run() throws Exception {
        section("Password: the PBEKeySpec collisions being guarded against are real");
        // These pairs are DIFFERENT passwords that the JCE derives IDENTICALLY. Each pair is a
        // mutual-impersonation bug: register with one, and the other signs you in.
        String base = "Fresh-Cafe-21";
        String trailingNul = base + NUL;
        String trailingNulNul = base + NUL + NUL;
        String interiorNul = "Fresh" + NUL + "-Cafe-21";
        // Long enough to clear the length policy, so a rejection here can only be the surrogate
        // rule. At 9 characters the same fixtures were refused for length and the check below was
        // asserting nothing about the '?' form it was meant to compare against.
        String d800 = "Fresh-quest-" + (char) 0xD800;
        String d801 = "Fresh-quest-" + (char) 0xD801;
        String literalQuestion = "Fresh-quest-?";

        String rawBase = rawJceDerive(base);
        String rawTrailingNul = rawJceDerive(trailingNul);
        String rawTrailingNulNul = rawJceDerive(trailingNulNul);
        String rawD800 = rawJceDerive(d800);
        String rawD801 = rawJceDerive(d801);
        String rawQuestion = rawJceDerive(literalQuestion);

        boolean trailingNulCollides = rawBase.equals(rawTrailingNul) && rawBase.equals(rawTrailingNulNul);
        boolean surrogateCollides = rawD800.equals(rawD801) && rawD800.equals(rawQuestion);
        if (trailingNulCollides) {
            note("raw JCE confirms the trailing-NUL collision on this JVM (register one, log in with another)");
        } else {
            note("raw JCE did NOT reproduce the trailing-NUL collision on this JVM;"
                    + " Password still refuses NUL - the behaviour is undocumented");
        }
        if (surrogateCollides) {
            note("raw JCE confirms the unpaired-surrogate -> '?' collision on this JVM");
        } else {
            note("raw JCE did NOT reproduce the unpaired-surrogate collision on this JVM;"
                    + " Password still refuses unpaired surrogates");
        }
        check("the proof harness itself derives a non-trivial digest", rawBase.length() == 64);
        check("the proof harness distinguishes two genuinely different passwords",
                !rawBase.equals(rawJceDerive("Fresh-Cafe-22")));

        // An interior NUL changes the digest, which is why the rule is "refuse any NUL" rather than
        // "strip trailing NULs": stripping would silently rename a different password, and only
        // refusing covers both shapes.
        check("interior NUL is a distinct digest under the raw JCE",
                !rawBase.equals(rawJceDerive(interiorNul)));

        section("Password: policy rejects every colliding class");
        check("trailing NUL rejected", Password.adopt(trailingNul.toCharArray()) == null);
        check("two trailing NULs rejected", Password.adopt(trailingNulNul.toCharArray()) == null);
        check("interior NUL rejected", Password.adopt(interiorNul.toCharArray()) == null);
        check("unpaired high surrogate rejected", Password.adopt(d800.toCharArray()) == null);
        check("a different unpaired high surrogate rejected", Password.adopt(d801.toCharArray()) == null);
        check("unpaired low surrogate rejected",
                Password.adopt(("Fresh-quest-" + (char) 0xDC00).toCharArray()) == null);
        check("the '?' form that collides with them is itself accepted (it is a real password)",
                Password.adopt(literalQuestion.toCharArray()) != null);

        section("Password: length bounds");
        check("exactly minimum length accepted", Password.adopt(Harness.chars(Harness.P_MIN)) != null);
        check("one below minimum rejected", Password.adopt(Harness.chars(Harness.P_BELOW_MIN)) == null);
        check("128 code points accepted",
                Password.adopt(("Ab1-" + Harness.repeat("c", 124)).toCharArray()) != null);
        check("129 code points rejected",
                Password.adopt(("Ab1-" + Harness.repeat("c", 125)).toCharArray()) == null);
        check("an all-NUL 1024-char buffer is rejected, not accepted as 1024 chars",
                Password.adopt(new char[1024]) == null);
        check("an empty buffer is rejected", Password.adopt(new char[0]) == null);
        check("null rejected", Password.adopt(null) == null);
        check("oversized input refused without a code-point scan",
                Password.adopt(new char[100_000]) == null);
        // Why this one is a code-shape assertion and not a stopwatch: the refusal path erases the
        // buffer, and the erase is itself O(n). Measured on this box, a 409k-char rejection costs
        // the same ~300-1200 us whether the length guard is present or not, so "it got slower" is
        // not observable, while "it scanned 100x more attacker-controlled characters before saying
        // no" is exactly the DoS the ceiling exists to bound. The requirement is that the ceiling
        // is a plain length comparison evaluated before the scan - which is checkable, and dies if
        // someone "tidies" it into a scan-time cap or a multiplied constant.
        String pwSrc = Harness.stripJavaComments(Harness.sourceOf("Password"));
        checkEquals("the scan ceiling is one plain array-length comparison", 1,
                Harness.countOccurrences(pwSrc, "if (chars.length > HARD_CAP_CP) {"));
        check("and it is evaluated before the loop it exists to bound",
                pwSrc.indexOf("if (chars.length > HARD_CAP_CP) {") >= 0
                        && pwSrc.indexOf("if (chars.length > HARD_CAP_CP) {")
                            < pwSrc.indexOf("while (i < chars.length)"));
        check("the ceiling is above the policy maximum but not absurdly above it",
                Password.HARD_CAP_CP > Password.MAX_CP && Password.HARD_CAP_CP <= 64 * Password.MAX_CP);
        check("newline rejected (log-line forgery)",
                Password.adopt(("Fresh-Ca" + LF + "fe-21").toCharArray()) == null);
        check("CR rejected", Password.adopt(("Fresh-Ca" + CR + "fe-21").toCharArray()) == null);
        Password astral = Password.adopt(("Abc12345" + (char) 0xD83D + (char) 0xDE00 + "!").toCharArray());
        check("a correctly paired astral character is accepted", astral != null);
        check("astral pairs count as one code point each, so two chars plus eight others is ten",
                astral != null && astral.codePointLength() == 10);
        if (astral != null) {
            astral.close();
        }

        section("Password: the array is consumed on every path");
        char[] accepted = Harness.chars(Harness.P1);
        Password ok = Password.adopt(accepted);
        check("accepted password is readable before close",
                ok != null && ok.chars().length == accepted.length);
        ok.close();
        check("chars() throws after close", throwsIllegalState(ok));
        check("guard() passes once closed", guardPasses(ok));
        ok.guard();

        char[] rejected = Harness.chars(Harness.P_BELOW_MIN);
        check("rejected password is erased, not left resident",
                Password.adopt(rejected) == null && Harness.allZero(rejected));

        char[] alsoRejected = Harness.chars("too-short");
        Password.adopt(alsoRejected);
        check("a second rejected buffer is erased too", Harness.allZero(alsoRejected));

        char[] nulRejected = (Harness.P1 + NUL).toCharArray();
        Password.adopt(nulRejected);
        check("a buffer rejected for containing NUL is erased anyway", Harness.allZero(nulRejected));

        check("a copy keeps its own buffer while the original stays alive", keepsOwnBuffer());
        check("guard() fails loudly when a live password is not closed", guardDetectsLeak());
        check("toString does not contain the secret",
                !Password.adopt(Harness.chars(Harness.CANARY)).toString().contains(Harness.CANARY));
        check("toString reports only the length",
                Password.adopt(Harness.chars(Harness.CANARY)).toString().contains("len="));

        section("PasswordHasher: stored encoding shape");
        Harness.Fixture f = Harness.fixture("pw-shape");
        PasswordHasher hasher = new PasswordHasher(f.config);
        String enc = hasher.hash(Password.adopt(Harness.chars(Harness.P1)));
        note("encoded credential length is " + enc.length() + " characters");
        check("encoding has the v1 prefix", enc.startsWith("v1$"));
        checkEquals("encoding has five dollar-separated fields", 5, enc.split("\\$", -1).length);
        check("encoding names the scheme explicitly", enc.contains("$pbkdf2-sha256$"));
        check("encoding records the iteration count", enc.contains("$" + f.config.pbkdf2Iterations() + "$"));
        check("encoding is ASCII with no whitespace", enc.chars().allMatch(c -> c > 0x20 && c < 0x7F));
        check("encoding fits the VARCHAR(256) column", enc.length() <= 256);
        check("the plaintext never appears in the encoding", !enc.contains(Harness.P1));

        String[] parts = enc.split("\\$", -1);
        byte[] salt = Base64.getDecoder().decode(parts[3]);
        byte[] digest = Base64.getDecoder().decode(parts[4]);
        checkEquals("salt is 16 bytes", 16, salt.length);
        checkEquals("digest is 32 bytes", 32, digest.length);

        String enc2 = hasher.hash(Password.adopt(Harness.chars(Harness.P1)));
        check("the same password twice yields different encodings (fresh salt)", !enc.equals(enc2));
        check("and different salts", !enc.split("\\$")[3].equals(enc2.split("\\$")[3]));
        check("both still verify", hasher.matchesStored(Harness.chars(Harness.P1), enc)
                && hasher.matchesStored(Harness.chars(Harness.P1), enc2));

        section("PasswordHasher: verification");
        check("correct password verifies", hasher.matchesStored(Harness.chars(Harness.P1), enc));
        check("wrong password does not verify", !hasher.matchesStored(Harness.chars(Harness.P2), enc));
        check("empty candidate does not verify", !hasher.matchesStored(new char[0], enc));
        check("all-NUL candidate does not verify", !hasher.matchesStored(new char[16], enc));
        check("a case-variant candidate does not verify",
                !hasher.matchesStored(Harness.chars(Harness.P1.toLowerCase()), enc));
        check("a candidate with a trailing space does not verify",
                !hasher.matchesStored((Harness.P1 + " ").toCharArray(), enc));
        check("the candidate is not erased by a verify (the caller owns the buffer)",
                candidateSurvivesVerify(hasher, enc));

        section("PasswordHasher: the equal-work charge costs real work");
        // The cheap branches are only equal-cost if this actually derives. A no-op here keeps every
        // functional test green and hands an attacker a timing oracle for account existence, so the
        // cost is asserted directly rather than inferred from behaviour elsewhere.
        double[] charged = Harness.cpuMicros(() -> {
            try {
                hasher.chargeDummy();
            } catch (IdentityStoreException e) {
                throw new IllegalStateException(e);
            }
        });
        note("chargeDummy wall=" + (long) charged[0] + "us cpu=" + (long) charged[1] + "us");
        check("the equal-work charge burns at least 20ms of CPU", charged[1] >= 20_000d);
        check("the dummy candidate is not one of the fixture passwords",
                !String.valueOf(PasswordHasher.internalDummyCandidate()).startsWith("Fresh-"));

        section("PasswordHasher: strict decoding of attacker-controlled stored text");
        // The iterations field is read from the database. An unvalidated one would let anyone who
        // can write a row make the KDF effectively free, so a low count must be refused outright.
        check("null stored value is refused as absent", refusesAbsent(hasher, null));
        check("empty stored value is refused", refusesAbsent(hasher, ""));
        check("iteration count 1 is refused as corrupt, not honoured",
                refusesCorrupt(hasher, tamper(enc, 2, "1")));
        check("non-numeric iterations refused", refusesCorrupt(hasher, tamper(enc, 2, "1e5")));
        check("negative iterations refused", refusesCorrupt(hasher, tamper(enc, 2, "-1")));
        check("overflowing iterations refused", refusesCorrupt(hasher, tamper(enc, 2, "99999999999999")));
        check("leading-zero iterations refused (forces a canonical spelling)",
                refusesCorrupt(hasher, tamper(enc, 2, "0" + f.config.pbkdf2Iterations())));
        check("empty iterations field refused", refusesCorrupt(hasher, tamper(enc, 2, "")));
        check("unknown version refused", refusesCorrupt(hasher, tamper(enc, 0, "v9")));
        check("unknown scheme refused (no downgrade to a weaker KDF)",
                refusesCorrupt(hasher, tamper(enc, 1, "md5")));
        check("missing field refused",
                refusesCorrupt(hasher, "v1$pbkdf2-sha256$" + f.config.pbkdf2Iterations() + "$AAA"));
        check("extra field refused", refusesCorrupt(hasher, enc + "$extra"));
        check("short salt refused",
                refusesCorrupt(hasher, tamper(enc, 3, Base64.getEncoder().encodeToString(new byte[8]))));
        check("long salt refused",
                refusesCorrupt(hasher, tamper(enc, 3, Base64.getEncoder().encodeToString(new byte[24]))));
        check("short digest refused",
                refusesCorrupt(hasher, tamper(enc, 4, Base64.getEncoder().encodeToString(new byte[16]))));
        check("non-base64 digest refused", refusesCorrupt(hasher, tamper(enc, 4, "not!base64!!")));
        check("embedded whitespace refused", refusesCorrupt(hasher, enc.replace("$", " $")));
        check("over-long stored value refused without parsing",
                refusesCorrupt(hasher, enc + Harness.repeat("A", 400)));
        check("a SQL fragment in the stored value is refused, not executed",
                refusesCorrupt(hasher, "v1$pbkdf2-sha256$100000$AAA'$or 1=1 --$BBB"));

        section("PasswordHasher: the cost floor is a boundary, not a coincidence");
        // The fixture's own cost equals the floor, so a boundary pair needs a hasher configured above
        // it - otherwise "at the floor is fine" is the same string as the untouched encoding.
        Harness.Overrides aboveFloor = Harness.overrides();
        aboveFloor.iterations = 200_000;
        Harness.Fixture fHi = Harness.fixture("pw-floor", aboveFloor);
        PasswordHasher hasherHi = new PasswordHasher(fHi.config);
        String encHi = hasherHi.hash(Password.adopt(Harness.chars(Harness.P1)));
        int floor = PasswordHasher.minAcceptedIterations();
        check("a row exactly at the floor is honoured (boundary is inclusive)",
                !refusesCorrupt(hasherHi, tamper(encHi, 2, String.valueOf(floor))));
        check("a row one below the floor is refused (the guard is the floor, not today's cost)",
                refusesCorrupt(hasherHi, tamper(encHi, 2, String.valueOf(floor - 1))));

        section("PasswordHasher: tampering is detected");
        // Flip one base64 character of the digest: must fail to verify, and must be a single-field
        // change so a pass would mean the digest is not actually being compared.
        String flipped = flipOneChar(enc);
        check("a one-character digest change is detected",
                !flipped.equals(enc) && !hasher.matchesStored(Harness.chars(Harness.P1), flipped));
        check("only the digest field differs after the flip",
                flipped.split("\\$")[4].length() == enc.split("\\$")[4].length()
                        && differentFieldCount(enc, flipped) == 1);
        check("and it really is one character, not a re-encoding of the whole field",
                differingCharCount(enc.split("\\$")[4], flipped.split("\\$")[4]) == 1);
        String saltFlipped = flipOneChar(enc, 3);
        check("a salt change is detected (does not verify the original password)",
                !hasher.matchesStored(Harness.chars(Harness.P1), saltFlipped));

        section("PasswordHasher: the digest comparison is the platform's constant-time one");
        // Behaviour cannot falsify this. `Arrays.equals` returns the same boolean as
        // `MessageDigest.isEqual` on every input a test can construct - it differs only in how
        // early it stops, and that difference is the side channel. A timed assertion would be the
        // wrong instrument here too: the comparison is over 32 bytes, nanoseconds, under a JVM the
        // attacker cannot keep steady. So the requirement is stated against the code, which is the
        // only place the distinction between the two calls actually lives.
        String hashSrc = Harness.stripJavaComments(Harness.sourceOf("PasswordHasher"));
        checkEquals("the verifier uses MessageDigest.isEqual exactly once", 1,
                Harness.countOccurrences(hashSrc, "MessageDigest.isEqual("));
        check("and never Arrays.equals, in either spelling (the qualified form still matches)",
                !hashSrc.contains("Arrays.equals(") && !hashSrc.contains("Arrays::equals"));
        check("the comparison is over the derived digests, not over password text",
                hashSrc.contains("MessageDigest.isEqual(expected, actual)"));
        check("SessionToken is the other constant-time comparison and keeps it",
                Harness.countOccurrences(
                        Harness.stripJavaComments(Harness.sourceOf("SessionToken")),
                        "MessageDigest.isEqual(") == 1);

        section("PasswordHasher: rehash decision");
        check("a current-parameter row does not need rehash", !hasher.needsRehash(enc));
        check("a corrupt row needs no rehash (decode refuses it; asserted above)",
                !hasher.needsRehash("garbage"));
        check("a row below today's cost but above the floor is marked for upgrade",
                needsRehashAtCost(200_000, 300_000));
        check("a row at or above today's cost is not churned",
                !needsRehashAtCost(300_000, 200_000));

        section("PasswordHasher: cross-process reload (the stored bytes must be the bytes)");
        // A stored salt built with StringBuilder.append(encode(...)) renders "[B@6f1c29d1" instead of
        // base64, compiles clean, and only shows up when a *different process* reads it back.
        Harness.Fixture reload = Harness.fixture("pw-reload");
        try (Harness.Bundle b = Harness.openApi(reload)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
        }
        try (Harness.Bundle reopened = Harness.openApi(reload)) {
            AuthResult r = reopened.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
            check("a fresh process can authenticate using only the file on disk", r.isSuccess());
            SqlIdentityStore.Account row = reopened.store.findByCanonicalIdentity(
                    Identity.parseClientUsername(Harness.U1));
            check("the reloaded row exists", row != null);
            check("the reloaded row's stored encoding is well-formed",
                    row != null && row.passwordHash().startsWith("v1$pbkdf2-sha256$"));
            check("the reloaded salt decodes to exactly 16 bytes",
                    row != null && Base64.getDecoder().decode(row.passwordHash().split("\\$")[3]).length == 16);
            check("the reloaded digest decodes to exactly 32 bytes",
                    row != null && Base64.getDecoder().decode(row.passwordHash().split("\\$")[4]).length == 32);
            check("no '[B@' array-identity artefact was ever written",
                    row != null && !row.passwordHash().contains("[B@"));
            check("the reloaded encoding still verifies", row != null
                    && reopened.hasher.matchesStored(Harness.chars(Harness.P1), row.passwordHash()));
            check("the reloaded encoding rejects a wrong password", row != null
                    && !reopened.hasher.matchesStored(Harness.chars(Harness.P2), row.passwordHash()));
        }
    }

    // ------------------------------------------------------------------ helpers

    /** Derives with no project code in the path, to prove the JCE's own behaviour. */
    private static String rawJceDerive(String password) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), FIXED_SALT, PROOF_ITERATIONS, 256);
        try {
            byte[] out = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
            StringBuilder sb = new StringBuilder();
            for (byte b : out) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } finally {
            spec.clearPassword();
        }
    }

    private static String tamper(String encoding, int field, String replacement) {
        String[] parts = encoding.split("\\$", -1);
        parts[field] = replacement;
        return String.join("$", parts);
    }

    private static int differentFieldCount(String a, String b) {
        String[] pa = a.split("\\$", -1);
        String[] pb = b.split("\\$", -1);
        int n = 0;
        for (int i = 0; i < pa.length && i < pb.length; i++) {
            if (!pa[i].equals(pb[i])) {
                n++;
            }
        }
        return n;
    }

    private static int differingCharCount(String a, String b) {
        if (a.length() != b.length()) {
            return -1;
        }
        int n = 0;
        for (int i = 0; i < a.length(); i++) {
            if (a.charAt(i) != b.charAt(i)) {
                n++;
            }
        }
        return n;
    }

    private static String flipOneChar(String encoding) {
        return flipOneChar(encoding, 4);
    }

    private static String flipOneChar(String encoding, int field) {
        String[] parts = encoding.split("\\$", -1);
        byte[] raw = Base64.getDecoder().decode(parts[field]);
        // Flip a bit the decoder actually keeps. Editing the *text* is not enough: the trailing
        // character of a padded field is padding, and the low bits of the last real character are
        // discarded on decode, so a text-only flip can yield identical bytes. Measured that way,
        // "a one-character digest change is detected" stayed green for a hasher that compared
        // nothing at all. Flipping the last byte's low bit changes exactly one base64 character and
        // provably changes the value.
        raw[raw.length - 1] ^= 0x01;
        parts[field] = Base64.getEncoder().encodeToString(raw);
        String out = String.join("$", parts);
        if (out.equals(encoding)) {
            throw new IllegalStateException("base64 field " + field + " did not change");
        }
        return out;
    }

    private static boolean refusesAbsent(PasswordHasher h, String stored) {
        try {
            h.matchesStored(Harness.chars(Harness.P1), stored);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.ABSENT_ACCOUNT || e.reason() == Reason.CORRUPT_RECORD;
        }
    }

    private static boolean refusesCorrupt(PasswordHasher h, String stored) {
        try {
            h.matchesStored(Harness.chars(Harness.P1), stored);
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CORRUPT_RECORD;
        }
    }

    /**
     * Writes a row at {@code storedCost} and asks a hasher configured at {@code todayCost} whether
     * it needs upgrading, then that the row still verifies. The upgrade must be transparent: a cost
     * bump must never lock out an existing account.
     *
     * <p>Two fixtures because the point is the <em>configuration</em> delta - the encoding is portable
     * text, so the second hasher only has to parse the first one's output.
     */
    private static boolean needsRehashAtCost(int storedCost, int todayCost) throws Exception {
        Harness.Overrides wrote = Harness.overrides();
        wrote.iterations = storedCost;
        wrote.minIterations = 100_000;
        PasswordHasher writer = new PasswordHasher(Harness.fixture("pw-rehash-w" + storedCost + todayCost, wrote).config);
        String stored = writer.hash(Password.adopt(Harness.chars(Harness.P1)));

        Harness.Overrides reads = Harness.overrides();
        reads.iterations = todayCost;
        reads.minIterations = 100_000;
        PasswordHasher stricter = new PasswordHasher(
                Harness.fixture("pw-rehash-r" + storedCost + todayCost, reads).config);

        return stricter.needsRehash(stored) && writer.matchesStored(Harness.chars(Harness.P1), stored);
    }

    private static boolean keepsOwnBuffer() {
        char[] original = Harness.chars(Harness.P3);
        Password copy = Password.copyOf(original);
        boolean originalUntouched = Harness.P3.equals(new String(original));
        boolean copyUsable = copy != null && copy.chars().length == original.length;
        copy.close();
        Password.erase(original);
        return originalUntouched && copyUsable;
    }

    private static boolean guardDetectsLeak() {
        Password leaked = Password.adopt(Harness.chars(Harness.P4));
        try {
            leaked.guard();
            return false;
        } catch (IllegalStateException expected) {
            return true;
        } finally {
            leaked.close();
        }
    }

    private static boolean candidateSurvivesVerify(PasswordHasher h, String enc) throws Exception {
        char[] candidate = Harness.chars(Harness.P2);
        boolean mismatch = !h.matchesStored(candidate, enc);
        boolean intact = Harness.P2.equals(new String(candidate));
        Password.erase(candidate);
        return mismatch && intact;
    }

    private static boolean throwsIllegalState(Password p) {
        try {
            p.chars();
            return false;
        } catch (IllegalStateException expected) {
            return true;
        }
    }

    private static boolean guardPasses(Password p) {
        try {
            p.guard();
            return true;
        } catch (IllegalStateException leaked) {
            return false;
        }
    }
}
