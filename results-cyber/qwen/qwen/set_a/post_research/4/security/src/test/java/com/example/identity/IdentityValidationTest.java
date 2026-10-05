package com.example.identity;

import java.util.List;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.section;

/**
 * Input validation at the trust boundary.
 *
 * <p>Every control character below is written as a Java escape, never embedded literally: a raw
 * NUL or DEL inside a string literal is invisible in an editor and in a diff, breaks the
 * {@code edit} tool's matching, and still compiles - so the test can look like it checks something
 * else entirely.
 *
 * <p>Each negative fixture is defective in exactly <em>one</em> way. A fixture that violates two
 * rules at once can satisfy the assertion because of the rule that is not under test, which is how a
 * guard ends up untested while its test passes. Where a case could be rejected for two reasons, the
 * fixture is built so only one applies (valid length, valid character class everywhere except the
 * one defect).
 */
public final class IdentityValidationTest {

    /** NUL, TAB, CR, LF, DEL - the characters String.trim()/strip() silently deletes. */
    static final char NUL = (char) 0x00;
    static final char TAB = (char) 0x09;
    static final char CR = (char) 0x0D;
    static final char LF = (char) 0x0A;
    static final char DEL = (char) 0x7F;
    /** Latin small letter e with acute. */
    static final char E_ACUTE = (char) 0x00E9;
    /** Fullwidth latin small letter a. */
    static final char FULLWIDTH_A = (char) 0xFF41;

    private IdentityValidationTest() {
    }

    public static void run() {
        section("Identity: usernames");

        check("valid username accepted", Identity.parseClientUsername("alice") != null);
        check("3-char username accepted (minimum)", Identity.parseClientUsername("abc") != null);
        check("32-char username accepted (maximum)",
                Identity.parseClientUsername("a" + Harness.repeat("b", 30) + "c") != null);
        check("2-char username rejected", Identity.parseClientUsername("ab") == null);
        check("33-char username rejected",
                Identity.parseClientUsername("a" + Harness.repeat("b", 32)) == null);

        check("uppercase folds to lowercase",
                "alice".equals(Identity.parseClientUsername("ALICE").canonical()));
        check("surrounding spaces are stripped",
                "alice".equals(Identity.parseClientUsername("  alice  ").canonical()));

        // Control characters. Each is the fixture's only defect, and each is exactly what
        // trim()/strip() would delete - folding the value onto the real account.
        check("trailing TAB rejected (trim would have folded it onto 'alice')",
                Identity.parseClientUsername("alice" + TAB) == null);
        check("trailing NUL rejected (trim would have folded it onto 'alice')",
                Identity.parseClientUsername("alice" + NUL) == null);
        check("leading TAB rejected", Identity.parseClientUsername("" + TAB + "alice") == null);
        check("interior space rejected", Identity.parseClientUsername("al ice") == null);
        check("trailing LF rejected", Identity.parseClientUsername("alice" + LF) == null);
        check("interior CR rejected", Identity.parseClientUsername("ali" + CR + "ce") == null);
        check("trailing DEL rejected", Identity.parseClientUsername("alice" + DEL) == null);

        check("leading dot rejected", Identity.parseClientUsername(".alice") == null);
        check("trailing dot rejected", Identity.parseClientUsername("alice.") == null);
        check("leading hyphen rejected", Identity.parseClientUsername("-alice") == null);
        check("trailing hyphen rejected", Identity.parseClientUsername("alice-") == null);
        check("double dot rejected", Identity.parseClientUsername("al..ice") == null);
        check("at-sign rejected", Identity.parseClientUsername("al@ice") == null);
        check("slash rejected", Identity.parseClientUsername("al/ice") == null);
        check("semicolon rejected", Identity.parseClientUsername("ali;ce") == null);
        check("SQL comment sequence rejected", Identity.parseClientUsername("ali--") == null);
        check("single quote rejected", Identity.parseClientUsername("ali'ce") == null);
        check("angle bracket rejected", Identity.parseClientUsername("ali<ce") == null);
        check("empty rejected", Identity.parseClientUsername("") == null);
        check("null rejected", Identity.parseClientUsername(null) == null);
        check("all-spaces rejected", Identity.parseClientUsername("     ") == null);
        check("oversized junk rejected without scanning",
                Identity.parseClientUsername(Harness.repeat("a", 5000)) == null);

        // Non-ASCII is refused outright, which is what removes homoglyph impersonation.
        check("non-ASCII username rejected", Identity.parseClientUsername("alic" + E_ACUTE) == null);
        check("full-width lookalike rejected",
                Identity.parseClientUsername("" + FULLWIDTH_A + "lice") == null);

        section("Identity: emails");
        check("valid email accepted", Identity.parseClientEmail("alice@example.com") != null);
        check("email folds to lowercase",
                "alice@example.com".equals(Identity.parseClientEmail("Alice@Example.COM").canonical()));
        check("plus-tag accepted (real-world addressing)",
                "alice+news@example.com".equals(Identity.parseClientEmail("Alice+News@example.com").canonical()));
        check("subdomain accepted", Identity.parseClientEmail("a@mail.corp.example.org") != null);
        check("underscore in local part accepted", Identity.parseClientEmail("a_b@example.com") != null);

        check("no @ rejected", Identity.parseClientEmail("aliceexample.com") == null);
        check("empty local part rejected", Identity.parseClientEmail("@example.com") == null);
        check("empty domain rejected", Identity.parseClientEmail("alice@") == null);
        check("two @ rejected (must not be read as alice@corp)",
                Identity.parseClientEmail("alice@corp@evil.example") == null);
        check("leading dot rejected", Identity.parseClientEmail(".alice@example.com") == null);
        check("trailing dot in local rejected", Identity.parseClientEmail("alice.@example.com") == null);
        check("double dot in local rejected", Identity.parseClientEmail("al..ice@example.com") == null);
        check("space in local rejected", Identity.parseClientEmail("ali ce@example.com") == null);
        check("trailing TAB rejected (would fold onto the real address)",
                Identity.parseClientEmail("alice@example.com" + TAB) == null);
        check("trailing NUL rejected (would fold onto the real address)",
                Identity.parseClientEmail("alice@example.com" + NUL) == null);
        check("TLD-less domain rejected", Identity.parseClientEmail("alice@localhost") == null);
        check("numeric TLD rejected", Identity.parseClientEmail("alice@example.123") == null);
        check("single-char TLD rejected", Identity.parseClientEmail("alice@example.c") == null);
        check("bracketed IP literal rejected", Identity.parseClientEmail("alice@[192.0.2.1]") == null);
        check("path traversal in domain rejected",
                Identity.parseClientEmail("alice@corp.example/../../etc") == null);
        check("colon in domain rejected", Identity.parseClientEmail("alice@corp:80.example") == null);
        check("backslash in domain rejected", Identity.parseClientEmail("alice\\@corp.example") == null);
        check("domain label with leading hyphen rejected",
                Identity.parseClientEmail("alice@-corp.example") == null);
        check("legal-but-unwanted local char rejected", Identity.parseClientEmail("al!ce@example.com") == null);
        check("comma in local rejected", Identity.parseClientEmail("al,ce@example.com") == null);
        check("angle bracket in local rejected", Identity.parseClientEmail("al<ce@example.com") == null);
        check("local part over 64 rejected",
                Identity.parseClientEmail(Harness.repeat("a", 65) + "@example.com") == null);
        check("local part at 64 accepted",
                Identity.parseClientEmail(Harness.repeat("a", 64) + "@example.com") != null);
        check("overall length over 254 rejected",
                Identity.parseClientEmail(Harness.repeat("a", 200) + "@" + Harness.repeat("b", 54) + ".com") == null);
        check("non-ASCII domain rejected", Identity.parseClientEmail("alice@" + E_ACUTE + "xample.com") == null);

        section("Identity: stored values are re-validated, not repaired");
        check("stored canonical username accepted", Identity.fromStoredUsername("alice") != null);
        // Anything our own writer would never produce is refused, with no normalisation.
        check("stored uppercase username rejected (not folded)", Identity.fromStoredUsername("Alice") == null);
        check("stored username with trailing space rejected (not trimmed)",
                Identity.fromStoredUsername("alice ") == null);
        check("stored username with TAB rejected", Identity.fromStoredUsername("alice" + TAB) == null);
        check("stored username with NUL rejected", Identity.fromStoredUsername("alice" + NUL) == null);
        check("stored empty username rejected", Identity.fromStoredUsername("") == null);
        check("stored null username rejected", Identity.fromStoredUsername(null) == null);
        check("stored email with uppercase rejected", Identity.fromStoredEmail("Alice@Example.com") == null);
        check("stored email with two @ rejected", Identity.fromStoredEmail("a@b@c.com") == null);

        section("Identity: values cannot reach a log in the clear");
        Identity id = Identity.parseClientEmail("alice@example.com");
        String rendered = id.toString();
        check("toString does not contain the address", !rendered.contains("alice@example.com"));
        check("toString does not even contain the local part", !rendered.contains("alice"));
        check("toString still identifies kind and length",
                rendered.contains("EMAIL") && rendered.contains("len=17"));
        check("display-only helper refuses a newline (log-line forgery)",
                Identity.displayForm("alice@example.com" + LF + "INJECTED") == null);
        check("display-only helper bounds length", Identity.displayForm(Harness.repeat("a", 5000)) == null);

        section("Identity: domain grammar is real, not a regex typo");
        // Regression guard for split("."): as a regex "." matches every character, so the label
        // loop would validate nothing and any domain would pass.
        check("two one-char labels still need a >=2-char TLD", Identity.parseClientEmail("a@a.com") != null);
        check("domain 'a.b' (single-char TLD) rejected", Identity.parseClientEmail("alice@a.b") == null);
        check("domain with an empty label rejected", Identity.parseClientEmail("alice@corp..example") == null);
        check("domain label of 63 accepted",
                Identity.parseClientEmail("a@" + Harness.repeat("b", 63) + ".com") != null);
        check("domain label of 64 rejected",
                Identity.parseClientEmail("a@" + Harness.repeat("b", 64) + ".com") == null);

        section("Identity: separator and metacharacter handling");
        // The canonical form is what we index, compare, and sometimes interpolate into a fixed SQL
        // shape, so it must never contain the credential encoding's field separator or a shell/SQL
        // metacharacter.
        List<String> mustNeverAppear = List.of("$", ";", "|", "&", "`", "\\", "\"", "'", "%", "*", "(", ")");
        for (String bad : mustNeverAppear) {
            check("username with '" + bad + "' rejected",
                    Identity.parseClientUsername("ali" + bad + "ce") == null);
            check("email local part with '" + bad + "' rejected",
                    Identity.parseClientEmail("ali" + bad + "ce@example.com") == null);
        }
        checkEquals("canonical username alphabet is exactly [a-z0-9._-]",
                true, Identity.parseClientUsername("a.b_c-d9").canonical().matches("[a-z0-9._-]+"));
    }
}
