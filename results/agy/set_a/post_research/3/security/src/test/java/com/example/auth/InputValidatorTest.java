package com.example.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class InputValidatorTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "user@example.com",
            "first.last@sub.example.com",
            "user+tag@domain.co.uk",
            "12345@domain.org",
            "test_user-name@domain-name.com"
    })
    void testValidEmails(String email) {
        assertTrue(InputValidator.isValidEmail(email));
        assertEquals(email.toLowerCase(), InputValidator.canonicalizeEmail(email));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "   ",
            "notanemail",
            "@domain.com",
            "user@",
            "user@.com",
            "user@domain",
            "user@domain..com",
            "user space@domain.com",
            "user@domain.c", // TLD too short (<2)
            "user@domain." // missing TLD
    })
    void testInvalidEmails(String email) {
        assertFalse(InputValidator.isValidEmail(email));
    }

    @Test
    void testEmailNullAndLengthBounds() {
        assertFalse(InputValidator.isValidEmail(null));
        assertFalse(InputValidator.isValidEmail("a@")); // length 2 (< 3)

        // RFC 5321: 254 characters max
        String prefix = "a".repeat(240);
        String validMax = prefix + "@domain.com";
        assertTrue(InputValidator.isValidEmail(validMax));

        String tooLong = "a".repeat(245) + "@domain.com"; // > 254 chars
        assertFalse(InputValidator.isValidEmail(tooLong));
    }

    @Test
    void testEmailDisallowsControlCharactersAndCrlf() {
        assertFalse(InputValidator.isValidEmail("user\n@domain.com"));
        assertFalse(InputValidator.isValidEmail("user\r@domain.com"));
        assertFalse(InputValidator.isValidEmail("user\t@domain.com"));
        assertFalse(InputValidator.isValidEmail("user\0@domain.com"));
    }

    @Test
    void testEmailReDosSafety() {
        // Test that linear regex evaluation completes instantaneously on malicious payload
        assertTimeoutPreemptively(Duration.ofMillis(200), () -> {
            String attackPayload = "a".repeat(250) + "!";
            assertFalse(InputValidator.isValidEmail(attackPayload));
        });
    }

    @Test
    void testPasswordLengthBounds() {
        assertFalse(InputValidator.isValidPasswordForAuth(null));
        assertFalse(InputValidator.isValidPasswordForAuth(new char[0]));
        assertTrue(InputValidator.isValidPasswordForAuth(new char[1]));
        assertTrue(InputValidator.isValidPasswordForAuth(new char[128]));
        assertFalse(InputValidator.isValidPasswordForAuth(new char[129])); // Prevents CPU DoS

        // Password for creation requires min 8 chars
        assertFalse(InputValidator.isValidPasswordForCreation("1234567".toCharArray()));
        assertTrue(InputValidator.isValidPasswordForCreation("12345678".toCharArray()));
        assertTrue(InputValidator.isValidPasswordForCreation(new char[128]));
        assertFalse(InputValidator.isValidPasswordForCreation(new char[129]));
    }

    @Test
    void testSourceIdSanitization() {
        assertEquals("192.168.1.1", InputValidator.sanitizeSourceId("192.168.1.1"));
        assertEquals("2001:db8::1", InputValidator.sanitizeSourceId("2001:db8::1"));
        assertEquals("client-abc_123", InputValidator.sanitizeSourceId("client-abc_123"));
        assertEquals("unknown-source", InputValidator.sanitizeSourceId(null));
        assertEquals("unknown-source", InputValidator.sanitizeSourceId("   "));

        // Format containing invalid characters or newlines
        assertEquals("invalid-source-format", InputValidator.sanitizeSourceId("user\n123"));
        assertEquals("invalid-source-format", InputValidator.sanitizeSourceId("ip;DROP TABLE"));
    }

    @Test
    void testDatabaseHashParametersValidation() {
        byte[] validSalt = new byte[16];
        byte[] validHash = new byte[32];

        assertTrue(InputValidator.isValidDatabaseHashParameters(
                PasswordHasher.ALGORITHM, 210_000, validSalt, validHash));

        // Wrong algorithm
        assertFalse(InputValidator.isValidDatabaseHashParameters(
                "MD5", 210_000, validSalt, validHash));

        // Iterations too low (<100,000)
        assertFalse(InputValidator.isValidDatabaseHashParameters(
                PasswordHasher.ALGORITHM, 1000, validSalt, validHash));

        // Iterations too high (>10,000,000)
        assertFalse(InputValidator.isValidDatabaseHashParameters(
                PasswordHasher.ALGORITHM, 20_000_000, validSalt, validHash));

        // Salt too short (<16 bytes)
        assertFalse(InputValidator.isValidDatabaseHashParameters(
                PasswordHasher.ALGORITHM, 210_000, new byte[8], validHash));

        // Hash length wrong (!= 32 bytes)
        assertFalse(InputValidator.isValidDatabaseHashParameters(
                PasswordHasher.ALGORITHM, 210_000, validSalt, new byte[16]));
    }
}
