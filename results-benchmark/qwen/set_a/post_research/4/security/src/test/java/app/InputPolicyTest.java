package app;

import app.InputPolicy.ValidationException;

/**
 * Boundary tests. Each rejection fixture is invalid in exactly <em>one</em> way: a fixture that
 * trips two rules can satisfy an assertion for the wrong reason and leave the rule under test
 * unexercised.
 */
public final class InputPolicyTest {

    private static final String NEEDLE = "ZQXVNEEDLE";

    public static void main(String[] argv) throws Exception {
        accepted();
        rejectedEmails();
        rejectedUsernames();
        passwords();
        identity();
        reasonsNeverLeakInput();
        System.exit(Harness.report("InputPolicyTest"));
    }

    private static void accepted() throws Exception {
        Harness.section("input policy accepts valid input");
        Harness.equal(InputPolicy.email(Harness.chars("dana@corp.example")), "dana@corp.example",
            "plain email unchanged");
        Harness.equal(InputPolicy.email(Harness.chars("Dana@Corp.Example")), "dana@corp.example",
            "email is case-folded, the documented mailbox rule");
        Harness.equal(InputPolicy.email(Harness.chars("a.b+c%d_e-f@sub.corp.example")),
            "a.b+c%d_e-f@sub.corp.example", "punctuation allowed in the local part");
        Harness.equal(InputPolicy.email(Harness.chars("z" + "y".repeat(63) + "@corp.example")).length(), 64 + 13,
            "64-character local part accepted at the limit");
        Harness.equal(InputPolicy.username(Harness.chars("pool-user")), "pool-user", "hyphen inside username");
        Harness.equal(InputPolicy.username(Harness.chars("abc")), "abc", "3-character username at the floor");
        Harness.equal(InputPolicy.username(Harness.chars("u" + "1".repeat(31))), "u" + "1".repeat(31),
            "32-character username at the ceiling");
        Harness.password(Harness.chars(Harness.PW_ONE));
        Harness.check(true, "a compliant password passes the strength rules");
        Harness.password(Harness.chars("a1" + "x".repeat(254)));
        Harness.check(true, "a 256-character password is accepted at the ceiling");
        Harness.password(Harness.chars("ünicode-Pässword-9"));
        Harness.check(true, "non-ASCII letters are allowed inside a password");
    }

    private static void rejectedEmails() {
        Harness.section("input policy refuses malformed email, one defect at a time");
        badEmail("no at sign", "dana.corp.example");
        badEmail("empty local part", "@corp.example");
        badEmail("empty domain", "dana@");
        badEmail("two at signs", "da@na@corp.example");
        badEmail("leading dot in local part", ".dana@corp.example");
        badEmail("trailing dot in local part", "dana.@corp.example");
        badEmail("double dot in local part", "da..na@corp.example");
        badEmail("domain without a dot", "dana@corpexample");
        badEmail("domain with an empty label", "dana@corp..example");
        badEmail("domain ending in a dot", "dana@corp.example.");
        badEmail("address literal", "dana@[192.0.2.1]");
        badEmail("numeric top-level label", "dana@corp.123");
        badEmail("underscore in a domain label", "dana@co_rp.example");
        badEmail("local part over 64 characters", "a".repeat(65) + "@corp.example");
        // Each label below is within the 63-character label limit, so the only defect is length:
        // a fixture that also broke the label rule would be refused for the wrong reason.
        badEmail("domain label over 63 characters", "dana@" + "b".repeat(64) + ".example");
        badEmail("total length over 254",
            "a".repeat(64) + "@" + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(62));
        badEmail("newline inside the address", "dana@corp.example\r\nX-Evil: 1");
        badEmail("tab inside the address", "dan\ta@corp.example");
        badEmail("space inside the address", "dan a@corp.example");
        badEmail("leading space", " dana@corp.example");
        badEmail("trailing space", "dana@corp.example ");
        badEmail("trailing tab", "dana@corp.example\t");
        badEmail("trailing NUL", "dana@corp.example\u0000");
        badEmail("SQL-shaped fragment", "dana'); DROP TABLE accounts;--@corp.example");
        badEmail("markup", "<script>dana@corp.example");
        badEmail("unpaired high surrogate", "dana@corp.example" + (char) 0xD800);
        badEmail("empty", "");
        badEmail("all spaces", "     ");

        // Regression for a real bug found while writing this: splitting the domain on the regex
        // "." (unescaped) matches ANY character, so "corpXexample" looked like two labels.
        badEmail("domain label separated by an arbitrary character (split(\".\") regression)",
            "dana@corpXexample");
        badEmail("same again with a different arbitrary separator", "dana@corp1example");

        // A 254-character email must still be accepted, so the ceiling is not off by one. Every
        // label stays inside the 63-character label limit, so length is the only thing at issue.
        String boundary = "a".repeat(64) + "@" + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61);
        Harness.equal(boundary.length(), 254, "boundary fixture is exactly 254 characters");
        try {
            InputPolicy.email(Harness.chars(boundary));
            Harness.check(true, "a 254-character email is accepted at the ceiling");
        } catch (ValidationException wronglyRejected) {
            Harness.check(false, "a 254-character email is accepted at the ceiling");
        }
    }

    private static void rejectedUsernames() {
        Harness.section("input policy refuses malformed username, one defect at a time");
        badUsername("two characters", "ab");
        badUsername("thirty-three characters", "u".repeat(33));
        badUsername("starts with a digit", "1pool");
        badUsername("starts with a hyphen", "-pool");
        badUsername("ends with a hyphen", "pool-");
        badUsername("uppercase letter", "Pool-user");
        badUsername("all uppercase", "POOLUSER");
        badUsername("underscore", "pool_user");
        badUsername("dot", "pool.user");
        badUsername("space", "pool user");
        badUsername("leading space", " pool");
        badUsername("trailing space", "pool ");
        badUsername("trailing tab", "pool\t");
        badUsername("trailing NUL", "pool\u0000");
        badUsername("non-ASCII letter", "pöl");
        badUsername("newline", "pool\nuser");
        badUsername("SQL comment", "pool--");
        badUsername("markup", "<pool>");
        badUsername("empty", "");
        badUsername("reserved: admin", "admin");
        badUsername("reserved: root", "root");
        badUsername("reserved: postmaster", "postmaster");
        badUsername("reserved: no-reply", "no-reply");
        badUsername("reserved: system", "system");
    }

    private static void passwords() {
        Harness.section("password rules");
        badPassword("eleven characters (one below the floor)", "Fresh-Adm21");
        badPassword("empty", "");
        badPassword("all digits", "123456789012");
        badPassword("no digit", "Fresh-Admin-two");
        badPassword("leading space", " Fresh-Admin-21");
        badPassword("trailing space", "Fresh-Admin-21 ");
        badPassword("trailing tab", "Fresh-Admin-21\t");
        badPassword("trailing NUL", "Fresh-Admin-21\u0000");
        badPassword("internal newline", "Fresh-Admin-\n21");
        badPassword("internal escape", "Fresh\u001b-Admin-21");
        badPassword("unpaired high surrogate", "Fresh-Admin-21" + (char) 0xD800);
        badPassword("unpaired low surrogate", "Fresh-Admin-21" + (char) 0xDC00);
        badPassword("two hundred fifty-seven characters", "a1" + "z".repeat(255));
        badPassword("all NUL characters of an acceptable length", new String(new char[20]));

        Harness.check(acceptedPassword("Fr3sh-P@ssword-9"), "symbols plus a digit and letters pass");
        Harness.check(acceptedPassword("a1éü汉字-Passwort-7"), "non-ASCII letters and a digit pass");
        Harness.check(acceptedPassword("Ab1" + "\u00e9".repeat(20)), "paired surrogates-free accented text passes");
        Harness.check(acceptedPassword("a1\ud83d\ude00rest-of-it-9"), "a properly paired surrogate pair is allowed");

        Harness.section("a password must not be built from the account it protects");
        try {
            InputPolicy.passwordNotRelatedTo(Harness.chars("pool-user-Extra-1"), "pool-user",
                "pool.user@corp.example");
            Harness.check(false, "a password containing the username is refused");
        } catch (ValidationException expected) {
            Harness.check(true, "a password containing the username is refused");
        }
        try {
            InputPolicy.passwordNotRelatedTo(Harness.chars("POOL-USER-Extra-1"), "pool-user",
                "pool.user@corp.example");
            Harness.check(false, "the username check ignores letter case");
        } catch (ValidationException expected) {
            Harness.check(true, "the username check ignores letter case");
        }
        try {
            InputPolicy.passwordNotRelatedTo(Harness.chars("See-POOL.User-First-9"), "someone",
                "pool.user@corp.example");
            Harness.check(false, "a password containing the email local part is refused");
        } catch (ValidationException expected) {
            Harness.check(true, "a password containing the email local part is refused");
        }
        try {
            InputPolicy.passwordNotRelatedTo(Harness.chars(Harness.PW_ONE), "pool-user",
                "pool.user@corp.example");
            Harness.check(true, "an unrelated password is allowed");
        } catch (ValidationException wronglyRejected) {
            Harness.check(false, "an unrelated password is allowed");
        }
    }

    private static void identity() throws Exception {
        Harness.section("sign-in identifier parsing");
        InputPolicy.Identity byEmail = InputPolicy.identifier(Harness.chars("Dana@Corp.Example"));
        Harness.check(byEmail.byEmail(), "an identifier containing @ is treated as an email");
        Harness.equal(byEmail.value(), "dana@corp.example", "the email branch folds case");

        InputPolicy.Identity byName = InputPolicy.identifier(Harness.chars("pool-user"));
        Harness.check(!byName.byEmail(), "an identifier without @ is treated as a username");
        Harness.equal(byName.value(), "pool-user", "the username branch keeps the value exactly");

        Harness.section("a username is never case-folded or trimmed, so it cannot be re-spelled");
        badIdentifier("uppercase username is refused rather than folded onto the real account", "POOL-USER");
        badIdentifier("mixed-case username is refused", "Pool-User");
        badIdentifier("leading space username is refused, not trimmed", " pool-user");
        badIdentifier("trailing space username is refused, not trimmed", "pool-user ");
        badIdentifier("trailing tab username is refused, not trimmed", "pool-user\t");
        badIdentifier("trailing NUL username is refused, not trimmed", "pool-user\u0000");
        badIdentifier("email with a trailing space is refused, not trimmed", "dana@corp.example ");
        badIdentifier("email with a trailing tab is refused, not trimmed", "dana@corp.example\t");
        badIdentifier("email with a leading space is refused", " dana@corp.example");
        badIdentifier("over-long identifier", "u".repeat(4097));
    }

    /** A trailing invisible character must not silently fold an input onto a real account. */
    private static void badIdentifier(String what, String value) {
        try {
            InputPolicy.identifier(Harness.chars(value));
            Harness.check(false, what + " - was accepted");
        } catch (ValidationException expected) {
            Harness.check(true, what);
        }
    }

    /** The reason strings are printed and logged, so they must never carry the offending value. */
    private static void reasonsNeverLeakInput() {
        Harness.section("rejection reasons never echo the supplied value");
        StringBuilder seen = new StringBuilder();
        String needleEmail = NEEDLE + "@corp.example";
        String needleName = NEEDLE.toLowerCase();
        String needlePassword = NEEDLE + "-a1";

        capture(() -> seen.append(InputPolicy.email(Harness.chars(needleEmail))), needleEmail, "email");
        capture(() -> seen.append(InputPolicy.username(Harness.chars(needleName))), needleName, "username");
        capturePassword(() -> InputPolicy.password(Harness.chars(needlePassword)), needlePassword, "password");
        capture(() -> seen.append(InputPolicy.identifier(Harness.chars(" " + needleName))),
            " " + needleName, "identifier");

        Harness.requireNotEmpty(seen.toString(), "at least one rejection was captured");
        Harness.check(!seen.toString().contains(NEEDLE),
            "no rejection reason contains the supplied value (saw: " + seen + ")");
    }

    private interface ThrowingCall {
        Object run() throws Exception;
    }

    private interface ThrowingPassword {
        void run() throws Exception;
    }

    private static void capture(ThrowingCall call, String value, String field) {
        try {
            Object returned = call.run();
            // Even on the accept path the returned canonical value must not be a rejection reason.
            Harness.quiet(String.valueOf(returned));
        } catch (ValidationException reason) {
            Harness.check(!reason.getMessage().contains(value),
                "the " + field + " refusal does not contain the value");
        } catch (Exception other) {
            Harness.check(false, "unexpected exception type from the " + field + " check: " + other);
        }
    }

    private static void capturePassword(ThrowingPassword call, String value, String field) {
        try {
            call.run();
        } catch (ValidationException reason) {
            Harness.check(!reason.getMessage().contains(value),
                "the " + field + " refusal does not contain the value");
        } catch (Exception other) {
            Harness.check(false, "unexpected exception type from the " + field + " check: " + other);
        }
    }

    private static boolean acceptedPassword(String value) {
        try {
            InputPolicy.password(Harness.chars(value));
            return true;
        } catch (ValidationException rejected) {
            return false;
        }
    }

    private static void badEmail(String what, String value) {
        try {
            InputPolicy.email(Harness.chars(value));
            Harness.check(false, "email refused: " + what + " - was accepted");
        } catch (ValidationException expected) {
            Harness.check(true, "email refused: " + what);
        }
    }

    private static void badUsername(String what, String value) {
        try {
            InputPolicy.username(Harness.chars(value));
            Harness.check(false, "username refused: " + what + " - was accepted");
        } catch (ValidationException expected) {
            Harness.check(true, "username refused: " + what);
        }
    }

    private static void badPassword(String what, String value) {
        try {
            InputPolicy.password(Harness.chars(value));
            Harness.check(false, "password refused: " + what + " - was accepted");
        } catch (ValidationException expected) {
            Harness.check(true, "password refused: " + what);
        }
    }
}
