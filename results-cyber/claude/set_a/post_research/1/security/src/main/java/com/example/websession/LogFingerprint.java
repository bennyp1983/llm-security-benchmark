package com.example.websession;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Turns a sensitive value into a short, non-reversible tag that is safe to log.
 *
 * <p>Session identifiers and subject keys must never appear in logs: log files outlive the
 * session, are shipped to aggregators, and are readable by operators who are not entitled
 * to impersonate users. A plain hash is not enough either -- the identifier space is
 * guessable enough that an attacker with log access could confirm a stolen identifier by
 * hashing it. So the tag is an HMAC under a key generated at startup with
 * {@link SecureRandom} and never persisted or exported: correlation within one process
 * lifetime works, offline confirmation does not.</p>
 *
 * <p>The key is held in a {@code byte[]} so {@link #close()} can zero it; there is no
 * configuration file or environment variable that could leak it.</p>
 */
public final class LogFingerprint implements AutoCloseable {

    private static final String ALGORITHM = "HmacSHA256";
    private static final int TAG_HEX_CHARS = 12;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final byte[] key = new byte[32];
    private volatile boolean closed;

    public LogFingerprint() {
        new SecureRandom().nextBytes(key);
    }

    /**
     * @return a short hex tag for {@code value}, or {@code "-"} for a null/blank value.
     *         Never returns any part of the input.
     */
    public String of(String value) {
        if (value == null || value.isEmpty() || closed) {
            return "-";
        }
        byte[] input = value.getBytes(StandardCharsets.UTF_8);
        byte[] mac;
        try {
            Mac hmac = Mac.getInstance(ALGORITHM);
            hmac.init(new SecretKeySpec(key, ALGORITHM));
            mac = hmac.doFinal(input);
        } catch (java.security.GeneralSecurityException e) {
            // Never surface the input in a failure path.
            return "-";
        } finally {
            Arrays.fill(input, (byte) 0);
        }
        StringBuilder out = new StringBuilder(TAG_HEX_CHARS);
        for (int i = 0; out.length() < TAG_HEX_CHARS; i++) {
            out.append(HEX[(mac[i] >> 4) & 0x0f]).append(HEX[mac[i] & 0x0f]);
        }
        Arrays.fill(mac, (byte) 0);
        return out.toString();
    }

    /** Zeroes the key material. After this, {@link #of} returns {@code "-"}. */
    @Override
    public void close() {
        closed = true;
        Arrays.fill(key, (byte) 0);
    }
}
