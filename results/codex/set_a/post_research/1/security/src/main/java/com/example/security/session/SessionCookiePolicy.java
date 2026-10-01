package com.example.security.session;

import jakarta.servlet.http.Cookie;

final class SessionCookiePolicy {
    static final String COOKIE_NAME = "__Host-session";
    static final String REQUEST_ATTRIBUTE =
            "com.example.security.session.authenticatedSessionId";
    static final int TOKEN_LENGTH = 43; // unpadded base64url encoding of 256 random bits
    static final int SOURCE_KEY_MAX_LENGTH = 64;
    static final String DUMMY_SESSION_ID = "___________________________________________";
    static final String DUMMY_SOURCE_KEY = "invalid-source";

    private SessionCookiePolicy() {}

    static boolean isValidSessionId(String value) {
        if (value == null || value.length() != TOKEN_LENGTH || DUMMY_SESSION_ID.equals(value)) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
                return false;
            }
        }
        return true;
    }

    static boolean isValidSourceKey(String value) {
        if (value == null || value.isEmpty() || value.length() > SOURCE_KEY_MAX_LENGTH) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')
                    || (c >= 'a' && c <= 'f') || c == ':' || c == '.')) {
                return false;
            }
        }
        return true;
    }

    static Cookie sessionCookie(String sessionId) {
        Cookie cookie = baseCookie(sessionId);
        cookie.setMaxAge(-1); // browser-session cookie; no persistent expiry
        return cookie;
    }

    static Cookie deletionCookie() {
        Cookie cookie = baseCookie("");
        cookie.setMaxAge(0);
        return cookie;
    }

    private static Cookie baseCookie(String value) {
        Cookie cookie = new Cookie(COOKIE_NAME, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        // No Domain attribute: required by the __Host- prefix.
        cookie.setAttribute("SameSite", "Strict");
        return cookie;
    }
}
