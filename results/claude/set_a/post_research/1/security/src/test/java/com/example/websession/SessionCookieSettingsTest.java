package com.example.websession;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class SessionCookieSettingsTest {

    @Test
    void defaultsAreTheStrictChoice() {
        SessionCookieSettings settings = SessionCookieSettings.secureDefaults();
        assertEquals("__Host-SID", settings.cookieName());
        assertEquals("/", settings.path());
        assertEquals("Strict", settings.sameSite());
        assertTrue(settings.secure());
        assertEquals(0, settings.maxAgeSeconds());
        assertEquals(0, settings.trustedProxyCount());
    }

    @Test
    void unknownValuesAreRejectedRatherThanDefaulted() {
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieSettings.fromMap(Map.of("SESSION_COOKIE_SAMESITE", "Lacks")));
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieSettings.fromMap(Map.of("SESSION_COOKIE_SECURE", "yes")));
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieSettings.fromMap(Map.of("SESSION_COOKIE_MAX_AGE_SECONDS", "-1")));
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieSettings.fromMap(Map.of("SESSION_COOKIE_MAX_AGE_SECONDS", "99999999")));
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieSettings.fromMap(Map.of("SESSION_COOKIE_NAME", "")));
    }

    @Test
    void inconsistentCookieCombinationsCannotBeDeployed() {
        assertThrows(IllegalArgumentException.class, () -> SessionCookieSettings.fromMap(
                Map.of("SESSION_COOKIE_SECURE", "false")));
        assertThrows(IllegalArgumentException.class, () -> SessionCookieSettings.fromMap(
                Map.of("SESSION_COOKIE_PATH", "/app")));
        assertThrows(IllegalArgumentException.class, () -> SessionCookieSettings.fromMap(
                Map.of("SESSION_COOKIE_NAME", "SID",
                        "SESSION_COOKIE_SECURE", "false",
                        "SESSION_COOKIE_SAMESITE", "None")));
    }

    @Test
    void cookieNameAndPathCannotCarryHeaderDelimiters() {
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieSettings.fromMap(Map.of("SESSION_COOKIE_NAME", "SID\r\nX: y")));
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieSettings.fromMap(Map.of(
                        "SESSION_COOKIE_NAME", "SID", "SESSION_COOKIE_PATH", "/a; Secure")));
    }

    @Test
    void errorMessagesNameTheKeyButNeverTheValue() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SessionCookieSettings.fromMap(Map.of("SESSION_COOKIE_SAMESITE", "s3cr3t-looking-value")));
        assertTrue(e.getMessage().contains("SESSION_COOKIE_SAMESITE"));
        assertTrue(!e.getMessage().contains("s3cr3t"), e.getMessage());
    }
}
