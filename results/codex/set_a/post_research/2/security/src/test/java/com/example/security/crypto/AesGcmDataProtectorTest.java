package com.example.security.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Dependency-free verification harness; it is not part of the library API. */
public final class AesGcmDataProtectorTest {
    private AesGcmDataProtectorTest() {}

    public static void main(String[] args) throws Exception {
        roundTripAndRandomNonce();
        tamperingAndContextMismatchFailGenerically();
        keyRotationWorksAndUnknownKeyFails();
        boundsAndLifecycleFailClosed();
        invalidConfigurationIsRejected();
    }

    private static void roundTripAndRandomNonce() throws Exception {
        byte[] key = AesGcmDataProtector.generateKey();
        byte[] plaintext = "private value".getBytes(StandardCharsets.UTF_8);
        byte[] context = "tenant/7/record/42".getBytes(StandardCharsets.UTF_8);
        try (AesGcmDataProtector protector = AesGcmDataProtector.create(
                Map.of("key-2026-01", key), "key-2026-01", "customer-profile", 1024)) {
            byte[] first = protector.encrypt(plaintext, context);
            byte[] second = protector.encrypt(plaintext, context);
            check(!Arrays.equals(first, second), "fresh nonces must change ciphertext");
            byte[] recovered = protector.decrypt(first, context);
            try {
                check(Arrays.equals(plaintext, recovered), "round trip failed");
            } finally {
                Arrays.fill(recovered, (byte) 0);
            }
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static void tamperingAndContextMismatchFailGenerically() throws Exception {
        byte[] key = AesGcmDataProtector.generateKey();
        byte[] plaintext = {1, 2, 3};
        byte[] context = {4, 5, 6};
        try (AesGcmDataProtector protector = AesGcmDataProtector.create(
                Map.of("primary", key), "primary", "test-data", 32)) {
            byte[] envelope = protector.encrypt(plaintext, context);
            for (int position : new int[] {0, 7, envelope.length - 1}) {
                byte[] changed = envelope.clone();
                changed[position] ^= 1;
                expectGenericFailure(() -> protector.decrypt(changed, context));
            }
            expectGenericFailure(() -> protector.decrypt(envelope, new byte[] {4, 5, 7}));
            expectGenericFailure(() -> protector.decrypt(null, context));
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static void keyRotationWorksAndUnknownKeyFails() throws Exception {
        byte[] oldKey = AesGcmDataProtector.generateKey();
        byte[] newKey = AesGcmDataProtector.generateKey();
        byte[] context = new byte[0];
        Map<String, byte[]> keys = new LinkedHashMap<>();
        keys.put("old-key", oldKey);
        keys.put("new-key", newKey);
        try (AesGcmDataProtector oldProtector = AesGcmDataProtector.create(
                    keys, "old-key", "rotation-test", 64);
             AesGcmDataProtector newProtector = AesGcmDataProtector.create(
                    keys, "new-key", "rotation-test", 64)) {
            byte[] oldEnvelope = oldProtector.encrypt(new byte[] {9}, context);
            byte[] recovered = newProtector.decrypt(oldEnvelope, context);
            check(recovered[0] == 9, "old key could not decrypt during rotation");
            Arrays.fill(recovered, (byte) 0);

            byte[] unknownId = oldEnvelope.clone();
            // Same-length valid identifier, but absent from trusted server-side state.
            byte[] replacement = "bad-key".getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(replacement, 0, unknownId, 7, replacement.length);
            expectGenericFailure(() -> newProtector.decrypt(unknownId, context));
        } finally {
            Arrays.fill(oldKey, (byte) 0);
            Arrays.fill(newKey, (byte) 0);
        }
    }

    private static void boundsAndLifecycleFailClosed() throws Exception {
        byte[] key = AesGcmDataProtector.generateKey();
        AesGcmDataProtector protector = AesGcmDataProtector.create(
                Map.of("key", key), "key", "bounds", 2);
        try {
            expectGenericFailure(() -> protector.encrypt(new byte[3], new byte[0]));
            protector.close();
            expectGenericFailure(() -> protector.encrypt(new byte[1], new byte[0]));
            expectGenericFailure(() -> protector.decrypt(new byte[36], new byte[0]));
        } finally {
            protector.close();
            Arrays.fill(key, (byte) 0);
        }
    }

    private static void invalidConfigurationIsRejected() {
        byte[] shortKey = new byte[16];
        try {
            expectIllegalArgument(() -> AesGcmDataProtector.create(
                    Map.of("key", shortKey), "key", "purpose", 10));
            expectIllegalArgument(() -> AesGcmDataProtector.create(
                    Map.of("invalid key id", new byte[32]), "invalid key id", "purpose", 10));
        } finally {
            Arrays.fill(shortKey, (byte) 0);
        }
    }

    private static void expectGenericFailure(CheckedRunnable operation) throws Exception {
        try {
            operation.run();
            throw new AssertionError("operation unexpectedly succeeded");
        } catch (DataProtectionException expected) {
            check("Data protection operation failed".equals(expected.getMessage()),
                    "failure message disclosed details");
            check(expected.getCause() == null, "failure disclosed a cause");
        }
    }

    private static void expectIllegalArgument(Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("configuration unexpectedly succeeded");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }
}
