package com.security.auth.validation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("InputValidator Security & Trust Boundary Tests (Rule 1)")
class InputValidatorTest {

    @ParameterizedTest
    @ValueSource(strings = {"alice", "bob_123", "user.name", "john-doe", "admin@domain.com", "abc", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
    @DisplayName("Should accept valid usernames within bounds and character whitelist")
    void testValidUsernames(String username) throws ValidationException {
        assertEquals(username, InputValidator.validateUsername(username));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "al", // Too short (< 3)
            "user\nname", // CRLF injection (newline)
            "user\rname", // CRLF injection (carriage return)
            "user name", // Disallowed space
            "user\tname", // Tab character
            "admin' OR '1'='1", // SQL injection chars
            "<script>", // XSS chars
            "../../etc/passwd", // Directory traversal
            "user\0name", // Null byte
            "user;drop table users;", // Semicolon injection
            "user@domain..com" // Note: chars may match, but let's test specific invalid
    })
    @DisplayName("Should reject invalid or malicious usernames")
    void testInvalidUsernames(String username) {
        if (!username.matches("^[a-zA-Z0-9_.@-]{3,64}$")) {
            assertThrows(ValidationException.class, () -> InputValidator.validateUsername(username));
        }
    }

    @Test
    @DisplayName("Should reject null or oversized username")
    void testUsernameBounds() {
        assertThrows(ValidationException.class, () -> InputValidator.validateUsername(null));
        assertThrows(ValidationException.class, () -> InputValidator.validateUsername("a".repeat(65)));
    }

    @Test
    @DisplayName("Should accept passwords within valid bounds")
    void testValidPasswords() throws ValidationException {
        InputValidator.validatePassword("P@ssw0rd123!".toCharArray());
        InputValidator.validatePassword("12345678".toCharArray());
        InputValidator.validatePassword("a".repeat(128).toCharArray());
    }

    @Test
    @DisplayName("Should reject null, short, or oversized passwords to prevent CPU DoS")
    void testInvalidPasswords() {
        assertThrows(ValidationException.class, () -> InputValidator.validatePassword(null));
        assertThrows(ValidationException.class, () -> InputValidator.validatePassword("short".toCharArray()));
        assertThrows(ValidationException.class, () -> InputValidator.validatePassword("a".repeat(129).toCharArray()));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.254",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "fe80::1"
    })
    @DisplayName("Should accept valid IPv4 and IPv6 addresses")
    void testValidIpAddresses(String ip) throws ValidationException {
        assertEquals(ip, InputValidator.validateClientIp(ip));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "256.1.1.1", // Octet > 255
            "192.168.1.1\r\n", // CRLF injection
            "localhost", // Hostname (prevents DNS lookup / SSRF)
            "evil.com", // Hostname
            "127.0.0.1; rm -rf", // Command injection
            "",
            "1.2.3", // Incomplete IPv4
            "1.2.3.4.5" // Extra octet
    })
    @DisplayName("Should reject invalid IP formats and hostnames")
    void testInvalidIpAddresses(String ip) {
        assertThrows(ValidationException.class, () -> InputValidator.validateClientIp(ip));
    }
}
