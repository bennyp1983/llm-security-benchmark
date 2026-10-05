package com.example.auth;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Produces unguessable session identifiers for applications that do not already have their own
 * identifier store.
 *
 * <p>Output is 256 bits from {@link SecureRandom}, Base64-URL encoded without padding (43
 * characters), which stays inside the character set {@link SessionCookieFactory} accepts.
 */
public final class SessionIdGenerator {

    private static final int ENTROPY_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private SessionIdGenerator() {
    }

    public static String generate() {
        byte[] bytes = new byte[ENTROPY_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
