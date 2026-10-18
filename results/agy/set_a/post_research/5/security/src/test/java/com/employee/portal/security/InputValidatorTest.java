package com.employee.portal.security;

import com.employee.portal.security.validation.InputValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Rule 1 & 6: Input Validation and Sanitization Tests")
class InputValidatorTest {

    @ParameterizedTest
    @ValueSource(strings = {"alice", "bob.smith", "charlie_123", "user-name", "admin_01"})
    void testValidUsernames(String username) {
        assertTrue(InputValidator.isValidUsername(username));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "", "a", "ab", // too short
        "this_username_is_way_too_long_and_exceeds_thirty_two_chars", // too long
        "user!name", "user@domain", "user#1", "user$name", // invalid characters
        "../admin", "admin/../../etc/passwd", "..", // path traversal
        "user\nname", "user\rname", "user\0name" // control characters
    })
    void testInvalidUsernames(String username) {
        assertFalse(InputValidator.isValidUsername(username));
    }

    @Test
    void testNullUsername() {
        assertFalse(InputValidator.isValidUsername(null));
    }

    @Test
    void testValidPassword() {
        assertTrue(InputValidator.isValidPassword("P@ssw0rd1234!".toCharArray()));
        assertTrue(InputValidator.isValidPassword("12345678".toCharArray()));
    }

    @Test
    void testInvalidPassword() {
        assertFalse(InputValidator.isValidPassword(null));
        assertFalse(InputValidator.isValidPassword("short".toCharArray())); // < 8 chars
        char[] hugePassword = new char[129];
        assertFalse(InputValidator.isValidPassword(hugePassword)); // > 128 chars (DoS prevention)
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "192.168.1.10", "10.0.0.1", "::1", "localhost"})
    void testValidSourceIps(String ip) {
        assertTrue(InputValidator.isValidSourceIp(ip));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "999.999.999.999", "127.0.0.1\r\nINJECTION", "not an ip", "1.2.3.4.5"})
    void testInvalidSourceIps(String ip) {
        assertFalse(InputValidator.isValidSourceIp(ip));
    }

    @Test
    void testLogSanitizationPreventsCrlfInjection() {
        String malicious = "alice\r\n[SECURITY_AUDIT] event=LOGIN_SUCCESS user=admin";
        String sanitized = InputValidator.sanitizeForLog(malicious);
        assertFalse(sanitized.contains("\r"));
        assertFalse(sanitized.contains("\n"));
        assertEquals("alice__[SECURITY_AUDIT] event=LOGIN_SUCCESS user=admin", sanitized);
    }

    @Test
    void testHtmlEscapingPreventsXss() {
        String xss = "<script>alert('xss')</script>&\"'";
        String escaped = InputValidator.escapeHtml(xss);
        assertFalse(escaped.contains("<script>"));
        assertTrue(escaped.contains("&lt;script&gt;"));
        assertTrue(escaped.contains("&amp;"));
        assertTrue(escaped.contains("&quot;"));
        assertTrue(escaped.contains("&#x27;"));
    }
}
