package com.example.auth;

import java.nio.charset.StandardCharsets;

/**
 * Turns sensitive values into log-safe stand-ins. Log lines must be able to correlate
 * repeated attempts without recording the address itself, so an email becomes its
 * first character plus a short SHA-256 fingerprint.
 */
public final class LogMasker {

    private LogMasker() {
    }

    public static String maskEmail(String email) {
        if (email == null || email.isEmpty()) {
            return "<none>";
        }
        return email.charAt(0) + "***@*** (eid:" + fingerprint(email) + ")";
    }

    /** Short, non-reversible correlation id for any sensitive string. */
    public static String fingerprint(String value) {
        byte[] digest = Hashing.sha256(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(12);
        for (int i = 0; i < 6; i++) {
            sb.append(Character.forDigit((digest[i] >> 4) & 0xF, 16));
            sb.append(Character.forDigit(digest[i] & 0xF, 16));
        }
        return sb.toString();
    }

    /** Secrets such as session tokens are never logged; use this if one must be shown. */
    public static String maskSecret(String secret) {
        if (secret == null || secret.isEmpty()) {
            return "<none>";
        }
        // No character of the secret is reproduced; only its length.
        return "*** (" + secret.length() + " chars)";
    }
}
