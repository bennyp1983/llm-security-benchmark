package com.example.websession;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class LogFingerprintTest {

    @Test
    void isStableWithinAProcessAndRevealsNothing() {
        try (LogFingerprint fingerprint = new LogFingerprint()) {
            String secret = "k7QwErTyUiOpAsDfGhJkL-_1234567890";
            String tag = fingerprint.of(secret);
            assertEquals(tag, fingerprint.of(secret));
            assertEquals(12, tag.length());
            assertFalse(secret.contains(tag));
            assertNotEquals(tag, fingerprint.of(secret + "x"));
        }
    }

    @Test
    void differsAcrossProcessesSoLogsCannotConfirmAnIdentifier() {
        try (LogFingerprint a = new LogFingerprint(); LogFingerprint b = new LogFingerprint()) {
            assertNotEquals(a.of("same-input"), b.of("same-input"));
        }
    }

    @Test
    void handlesNullAndClosedState() {
        LogFingerprint fingerprint = new LogFingerprint();
        assertEquals("-", fingerprint.of(null));
        fingerprint.close();
        assertEquals("-", fingerprint.of("anything"));
    }
}
