package com.security.auth.validation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("Rule 1 & Rule 5: Input Validation Tests")
class InputValidatorTest {

    @Test
    @DisplayName("Valid email normalization and structure")
    void testValidEmail() {
        String normalized = InputValidator.validateAndNormalizeEmail("User.Name+Tag@Example.Com");
        assertEquals("user.name+tag@example.com", normalized);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "   ",
            "not-an-email",
            "@example.com",
            "user@",
            "user@.com",
            "user@domain..com",
            "user\n@domain.com",
            "user\r\n@domain.com",
            "user\0@domain.com",
            "user' OR '1'='1@domain.com",
            "<script>alert(1)</script>@domain.com"
    })
    @DisplayName("Invalid emails must be strictly rejected")
    void testInvalidEmail(String email) {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateAndNormalizeEmail(email));
    }

    @Test
    @DisplayName("Email exceeding 254 octets is rejected (RFC 5321 limit)")
    void testOversizedEmail() {
        String longLocal = "a".repeat(250);
        String email = longLocal + "@example.com";
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateAndNormalizeEmail(email));
    }

    @ParameterizedTest
    @ValueSource(strings = {"john_doe", "alice-123", "SuperUser99", "admin_user", "sec-ops_01"})
    @DisplayName("Valid usernames are accepted")
    void testValidUsername(String username) {
        assertEquals(username, InputValidator.validateUsername(username));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "ab", // Too short (< 3)
            "this_username_is_way_too_long_to_be_allowed_in_the_system", // Too long (> 32)
            "admin", // Reserved
            "administrator", // Reserved
            "root", // Reserved
            "system", // Reserved
            "guest", // Reserved
            "null", // Reserved
            "john doe", // Space
            "user;DROP TABLE users;--", // SQL injection
            "user<script>", // XSS
            "user\n123" // Control char
    })
    @DisplayName("Invalid and reserved usernames must be rejected")
    void testInvalidUsername(String username) {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUsername(username));
    }

    @Test
    @DisplayName("Valid complex passwords pass validation")
    void testValidPassword() {
        char[] pwd = "Correct-Horse-Battery-Staple-2026!".toCharArray();
        assertDoesNotThrow(() -> InputValidator.validatePassword(pwd));
    }

    @Test
    @DisplayName("Passwords too short (< 12 chars) are rejected")
    void testPasswordTooShort() {
        char[] pwd = "Short1!a".toCharArray();
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validatePassword(pwd));
    }

    @Test
    @DisplayName("Passwords exceeding 128 characters are rejected to prevent Hash DoS")
    void testPasswordTooLong() {
        char[] pwd = "A1!a".repeat(40).toCharArray(); // 160 chars
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validatePassword(pwd));
    }

    @Test
    @DisplayName("Passwords missing required character classes are rejected")
    void testPasswordMissingClasses() {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validatePassword("lowercaseonly1234!".toCharArray())); // No uppercase
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validatePassword("UPPERCASEONLY1234!".toCharArray())); // No lowercase
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validatePassword("NoDigitsAtAllHere!!".toCharArray())); // No digit
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validatePassword("NoSpecialChars1234".toCharArray())); // No special char
    }

    @Test
    @DisplayName("Valid IP formats accepted and sanitized")
    void testValidIp() {
        assertEquals("192.168.1.1", InputValidator.validateSourceIp("192.168.1.1"));
        assertEquals("::1", InputValidator.validateSourceIp("::1"));
        assertEquals("127.0.0.1", InputValidator.validateSourceIp(""));
        assertEquals("127.0.0.1", InputValidator.validateSourceIp(null));
    }

    @Test
    @DisplayName("Invalid IP formats rejected")
    void testInvalidIp() {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateSourceIp("999.999.999.999"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateSourceIp("192.168.1.1; rm -rf /"));
    }
}
