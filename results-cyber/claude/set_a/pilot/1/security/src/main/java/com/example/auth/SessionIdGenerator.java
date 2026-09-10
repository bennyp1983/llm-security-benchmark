package com.example.auth;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates opaque session identifiers.
 *
 * <p>Identifiers come from a CSPRNG and carry 256 bits of entropy, so they
 * cannot be guessed or enumerated. They are meaningless on their own: all
 * authorization state lives server-side, keyed by this value.
 */
public final class SessionIdGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int ENTROPY_BYTES = 32; // 256 bits

    private SessionIdGenerator() {
    }

    public static String newSessionId() {
        byte[] bytes = new byte[ENTROPY_BYTES];
        RANDOM.nextBytes(bytes);
        // URL-safe, unpadded -> always a legal cookie-octet sequence.
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
