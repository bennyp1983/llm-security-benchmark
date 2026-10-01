package com.example.accounts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class InputValidatorTest {

    @Test
    void canonicalisesEmailCaseAndWhitespace() throws Exception {
        assertEquals("alice@example.com", InputValidator.canonicalEmail("  Alice@Example.COM "));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "", "   ", "no-at-sign", "two@at@signs.com", "@example.com", "alice@",
        "alice@example", "alice@example.c", "alice@-example.com", "alice@example-.com",
        "alice@exam ple.com", "alice@example..com", ".alice@example.com", "alice.@example.com",
        "al..ice@example.com", "alice@example.123", "alice<script>@example.com",
        "ali ce@example.com",
        "\u0430lice@example.com",      // Cyrillic 'a' look-alike
        "alice\n@example.com",         // embedded newline (log injection attempt)
        "alice@example.com\u0000x"     // embedded NUL
    })
    void rejectsMalformedEmail(String candidate) {
        assertThrows(ValidationException.class, () -> InputValidator.canonicalEmail(candidate));
    }

    @Test
    void rejectsOverlongEmail() {
        String local = "a".repeat(64);
        String domain = ("b".repeat(60) + ".").repeat(4) + "com";
        assertThrows(ValidationException.class,
                () -> InputValidator.canonicalEmail(local + "@" + domain));
    }

    @Test
    void foldsConfusableUsernamesTogether() throws Exception {
        // Full-width characters normalise to ASCII, so they cannot create a look-alike twin.
        assertEquals("alice99",
                InputValidator.canonicalUsername("\uff41\uff4c\uff49\uff43\uff45\uff19\uff19"));
        assertEquals("alice99", InputValidator.canonicalUsername("Alice99"));
    }

    @Test
    void rejectsReservedUsernameEvenWhenDisguised() {
        // Full-width 'A' + "dmin" folds to the reserved name "admin".
        assertThrows(ValidationException.class,
                () -> InputValidator.canonicalUsername("\uff21dmin"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "ab", "-alice", "alice-", ".alice", "alice.", "al..ice", "al--ice",
        "ali ce", "alice!", "alice@example.com", "admin", "ADMIN", "root", "support"
    })
    void rejectsBadUsername(String candidate) {
        assertThrows(ValidationException.class, () -> InputValidator.canonicalUsername(candidate));
    }

    @Test
    void rejectsOverlongUsername() {
        assertThrows(ValidationException.class,
                () -> InputValidator.canonicalUsername("a".repeat(33)));
        assertThrows(ValidationException.class,
                () -> InputValidator.canonicalUsername("a".repeat(5000)));
    }

    @Test
    void acceptsReasonableUsername() throws Exception {
        assertEquals("alice.b_99-x", InputValidator.canonicalUsername("Alice.B_99-X"));
    }

    @Test
    void rejectsShortPassword() throws Exception {
        char[] prepared = InputValidator.preparePassword("short1!A".toCharArray());
        assertThrows(ValidationException.class,
                () -> InputValidator.checkPasswordPolicy(prepared, "alice", "alice@example.com"));
    }

    @Test
    void rejectsPasswordContainingUsernameOrEmail() throws Exception {
        char[] withUsername = InputValidator.preparePassword("xx-alice-river-99".toCharArray());
        assertThrows(ValidationException.class,
                () -> InputValidator.checkPasswordPolicy(withUsername, "alice", "bob@example.com"));
        char[] withEmail = InputValidator.preparePassword("zz-bobby-stone-77".toCharArray());
        assertThrows(ValidationException.class,
                () -> InputValidator.checkPasswordPolicy(withEmail, "alice", "bobby@example.com"));
    }

    @Test
    void rejectsPredictablePasswords() throws Exception {
        for (String candidate : new String[] {
            "aaaaaaaaaaaaaa", "abcdefghijklmn", "password1234", "111111111111"
        }) {
            char[] prepared = InputValidator.preparePassword(candidate.toCharArray());
            assertThrows(ValidationException.class,
                    () -> InputValidator.checkPasswordPolicy(prepared, "alice", "alice@example.com"),
                    candidate);
        }
    }

    @Test
    void rejectsControlAndFormatCharactersInPassword() {
        assertThrows(ValidationException.class,
                () -> InputValidator.preparePassword("bell\u0007separated".toCharArray()));
        assertThrows(ValidationException.class,
                () -> InputValidator.preparePassword("tab\tseparated-pass".toCharArray()));
        assertThrows(ValidationException.class,
                () -> InputValidator.preparePassword("zero\u200dwidth-join".toCharArray()));
        assertThrows(ValidationException.class,
                () -> InputValidator.preparePassword("nul\u0000inside-pass".toCharArray()));
    }

    @Test
    void rejectsOverlongPassword() {
        char[] tooLong = new char[InputValidator.PASSWORD_MAX_LENGTH + 1];
        Arrays.fill(tooLong, 'x');
        assertThrows(ValidationException.class, () -> InputValidator.preparePassword(tooLong));
    }

    @Test
    void mapsUnicodeSpaceSeparatorsToAsciiSpace() throws Exception {
        // U+00A0 NO-BREAK SPACE is a space separator and must become U+0020 (RFC 8265).
        char[] prepared =
                InputValidator.preparePassword("correct\u00a0horse\u00a0battery".toCharArray());
        assertEquals("correct horse battery", new String(prepared));
    }

    @Test
    void acceptsAStrongPassphrase() throws Exception {
        char[] prepared = InputValidator.preparePassword("pewter-rhubarb-glacier-7".toCharArray());
        InputValidator.checkPasswordPolicy(prepared, "alice", "alice@example.com");
    }

    @Test
    void preparePasswordLeavesCallerArrayAlone() throws Exception {
        char[] raw = "pewter-rhubarb-glacier-7".toCharArray();
        char[] prepared = InputValidator.preparePassword(raw);
        assertEquals("pewter-rhubarb-glacier-7", new String(raw));
        assertEquals("pewter-rhubarb-glacier-7", new String(prepared));
    }
}
