package com.example.auth.session;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Mints opaque session identifiers.
 *
 * <p>Authentication normally hands an already-issued identifier over to
 * {@link com.example.auth.web.LoginServlet}; this class is what a session store should use to
 * produce one. Identifiers are the only thing a client gets to hold, so they carry no claims and are
 * unpredictable: 256 bits from the platform CSPRNG, encoded base64url without padding so the result
 * survives the cookie-value character set untouched.
 */
public final class SessionIdentifiers {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int RANDOM_BYTES = 32;

    private SessionIdentifiers() {
    }

    public static String newSessionId() {
        byte[] bytes = new byte[RANDOM_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
