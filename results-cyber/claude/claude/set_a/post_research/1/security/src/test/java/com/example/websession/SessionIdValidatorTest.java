package com.example.websession;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SessionIdValidatorTest {

    @Test
    void acceptsBase64UrlIdentifiersWithinBounds() {
        assertTrue(SessionIdValidator.isValid("abcdefghijklmnopqrstuv"));
        assertTrue(SessionIdValidator.isValid("A-_9".repeat(8)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "tooshort",
            "abcdefghijklmnopqrstu\r\nSet-Cookie: x=y",
            "abcdefghijklmnopqrstuv;Path=/",
            "abcdefghijklmnopqrstuv value",
            "abcdefghijklmnopqrstuv\"",
            "abcdefghijklmnopqrstuv,extra",
            "abcdefghijklmnopqrstuv=",
            "abcdefghijklmnopqrstu\u00e9"
    })
    void rejectsEverythingElse(String candidate) {
        assertFalse(SessionIdValidator.isValid(candidate), candidate);
    }

    @Test
    void rejectsNullAndOversizedValues() {
        assertFalse(SessionIdValidator.isValid(null));
        assertFalse(SessionIdValidator.isValid("a".repeat(SessionIdValidator.MAX_LENGTH + 1)));
        assertTrue(SessionIdValidator.isValid("a".repeat(SessionIdValidator.MAX_LENGTH)));
    }
}
