package com.example.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Core engine behaviour, judged as if the reader is trying to make it lie. */
class CipherBehaviourTest {

    private final SymmetricCrypto crypto = new SymmetricCrypto();

    private KeyMaterial key(int version) throws CryptoException {
        return crypto.generateKey(version);
    }

    @Test
    void roundTripsBytesAndText() throws Exception {
        try (KeyMaterial k = key(1)) {
            byte[] secret = "card=4111111111111111".getBytes(StandardCharsets.UTF_8);
            EncryptedBlob b = crypto.encrypt(k, secret, "payment-ref");
            assertArrayEquals(secret, crypto.decrypt(k, b, "payment-ref"));
            assertArrayEquals(secret, crypto.decrypt(k, EncryptedBlob.fromEncoded(b.toBase64Url()), "payment-ref"));
            assertArrayEquals(secret, crypto.decrypt(k, b.toBase64Url(), "payment-ref"));
        }
        try (KeyMaterial k = key(1)) {
            EncryptedBlob b = crypto.encrypt(k, "caf\u00e9 \u2615 \uD83D\uDE00", "note");
            assertEquals("caf\u00e9 \u2615 \uD83D\uDE00", crypto.decryptToString(k, b, "note"));
            assertEquals("caf\u00e9 \u2615 \uD83D\uDE00", crypto.decryptToString(k, b.toBase64Url(), "note"));
        }
    }

    @Test
    void emptyPlaintextIsAllowedAndRoundTrips() throws Exception {
        try (KeyMaterial k = key(1)) {
            EncryptedBlob b = crypto.encrypt(k, new byte[0], null);
            assertEquals(0, crypto.decrypt(k, b, null).length);
        }
    }

    @Test
    void samePlaintextTwiceYieldsDifferentRecords() throws Exception {
        try (KeyMaterial k = key(1)) {
            byte[] pt = "same".getBytes(StandardCharsets.UTF_8);
            EncryptedBlob a = crypto.encrypt(k, pt, "ctx");
            EncryptedBlob b = crypto.encrypt(k, pt, "ctx");
            assertNotEquals(a, b, "nonce reuse would make these identical");
            assertFalse(Arrays.equals(a.toBytes(), b.toBytes()));
            assertArrayEquals(pt, crypto.decrypt(k, a, "ctx"));
            assertArrayEquals(pt, crypto.decrypt(k, b, "ctx"));
        }
    }

    @Test
    void noncesNeverRepeatAcrossManyRecords() throws Exception {
        try (KeyMaterial k = key(1)) {
            Set<String> nonces = new HashSet<>();
            for (int i = 0; i < 500; i++) {
                EncryptedBlob b = crypto.encrypt(k, new byte[]{(byte) i}, null);
                byte[] n = Arrays.copyOfRange(b.toBytes(), 3, 15);
                assertEquals(12, n.length, "the record nonce must be 96 bits");
                assertTrue(nonces.add(Arrays.toString(n)), "nonce repeated at i=" + i);
            }
            assertEquals(500, nonces.size());
        }
    }

    @Test
    void flippingAnyCiphertextOrTagByteFailsAuthentication() throws Exception {
        try (KeyMaterial k = key(1)) {
            EncryptedBlob b = crypto.encrypt(k, "attack at dawn".getBytes(StandardCharsets.UTF_8), "ops");
            byte[] base = b.toBytes();
            int checked = 0;
            for (int i = EncryptedBlob.HEADER_BYTES; i < base.length; i++) {
                byte[] tampered = base.clone();
                tampered[i] ^= 0x01;
                CryptoException e;
                try {
                    crypto.decrypt(k, EncryptedBlob.wrap(tampered, true, "ops"), "ops");
                    fail("byte " + i + " flip was accepted");
                    return;
                } catch (CryptoException ce) {
                    e = ce;
                }
                assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, e.code(),
                        "byte " + i + " failed with the wrong code");
                checked++;
            }
            /* Ciphertext plus the 16-byte tag, every one of them covered. */
            assertEquals(base.length - EncryptedBlob.HEADER_BYTES, checked);
            assertTrue(checked > 16, "the fixture must be longer than the tag itself");
        }
    }

    @Test
    void everyAuthenticationFailureIsIndistinguishable() throws Exception {
        try (KeyMaterial k = key(1); KeyMaterial wrong = key(2)) {
            EncryptedBlob b = crypto.encrypt(k, "payload".getBytes(StandardCharsets.UTF_8), "ctx");
            byte[] flipTag = b.toBytes();
            flipTag[flipTag.length - 1] ^= 0x40;
            byte[] flipNonce = b.toBytes();
            flipNonce[3] ^= 0x01;
            byte[] borrowVersion = b.toBytes();
            borrowVersion[2] = 2;

            Set<String> messages = new HashSet<>();
            messages.add(userOf(() -> crypto.decrypt(wrong, b, "ctx")));                     // wrong key
            messages.add(userOf(() -> crypto.decrypt(k, EncryptedBlob.wrap(flipTag, true, "ctx"), "ctx")));
            messages.add(userOf(() -> crypto.decrypt(k, EncryptedBlob.wrap(flipNonce, true, "ctx"), "ctx")));
            messages.add(userOf(() -> crypto.decrypt(k, EncryptedBlob.wrap(borrowVersion, true, "ctx"), "ctx")));
            messages.add(userOf(() -> crypto.decrypt(k, b, "other-ctx")));                    // wrong context
            messages.add(userOf(() -> crypto.decrypt(k, b, null)));                           // missing context

            /*
             * Equality is necessary but not sufficient: a change that makes every path leak the same
             * detail keeps them equal. So assert the shared text's own properties too.
             */
            assertEquals(1, messages.size(), "authentication refusals differ by kind: " + messages);
            String shared = messages.iterator().next();
            String lower = shared.toLowerCase();
            assertFalse(lower.contains("key"), "the refusal names 'key': " + shared);
            assertFalse(lower.contains("password"), "the refusal names 'password': " + shared);
            assertFalse(lower.contains("context"), "the refusal names 'context': " + shared);
            assertFalse(lower.contains("tamper"), "the refusal admits tampering: " + shared);
            assertFalse(lower.contains("version"), "the refusal admits a version mismatch: " + shared);
            assertFalse(shared.contains("ctx"), "the refusal echoes the caller's context: " + shared);
            assertFalse(shared.isEmpty(), "an empty refusal tells the caller nothing was checked");
        }
    }

    @Test
    void everyFormatFailureIsAlsoIndistinguishableAndGeneric() throws Exception {
        try (KeyMaterial k = key(1)) {
            EncryptedBlob b = crypto.encrypt(k, "payload".getBytes(StandardCharsets.UTF_8), null);
            byte[] badFlag = b.toBytes();
            badFlag[1] = 7;
            byte[] badVersion = b.toBytes();
            badVersion[0] = 9;
            byte[] keyVersionZero = b.toBytes();
            keyVersionZero[2] = 0;

            Set<String> messages = new HashSet<>();
            messages.add(userOf(() -> EncryptedBlob.fromBytes(new byte[20])));
            messages.add(userOf(() -> EncryptedBlob.fromBytes(new byte[0])));
            messages.add(userOf(() -> EncryptedBlob.fromBytes(badFlag)));
            messages.add(userOf(() -> EncryptedBlob.fromBytes(badVersion)));
            messages.add(userOf(() -> EncryptedBlob.fromBytes(keyVersionZero)));

            assertEquals(1, messages.size(), "format refusals differ by reason: " + messages);
            String shared = messages.iterator().next();
            String lower = shared.toLowerCase();
            for (String tip : new String[]{"version", "flag", "length", "byte", "key", "decrypt"}) {
                assertFalse(lower.contains(tip), "the format refusal reveals which check failed ("
                        + tip + "): " + shared);
            }
            /*
             * The technical detail is where the reason belongs - it must differ where the user
             * message deliberately does not, or the log is useless.
             */
            Set<String> details = new HashSet<>();
            details.add(detailOf(() -> EncryptedBlob.fromBytes(badFlag)));
            details.add(detailOf(() -> EncryptedBlob.fromBytes(badVersion)));
            assertEquals(2, details.size(), "the log detail lost the distinction the operator needs");
        }
    }

    @Test
    void aRecordCannotBorrowAnotherKeysVersion() throws Exception {
        try (KeyMaterial v1 = key(1); KeyMaterial v2 = key(2)) {
            EncryptedBlob real = crypto.encrypt(v2, "secret".getBytes(StandardCharsets.UTF_8), "ctx");
            byte[] restamped = real.toBytes();
            restamped[2] = 1; // claim "I was written with key version 1"
            CryptoException e = assertThrows(CryptoException.class,
                    () -> crypto.decrypt(v1, EncryptedBlob.wrap(restamped, true, "ctx"), "ctx"));
            assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, e.code());
        }
    }

    @Test
    void aRecordCannotBeRelabelledAsContextFree() throws Exception {
        /*
         * The context flag sits outside the ciphertext, so the parser cannot tell a cleared flag from a
         * record that never had a context - what protects here is that the flag is inside the AAD. The
         * property to assert is therefore "no plaintext comes out", by every route an attacker has.
         */
        try (KeyMaterial k = key(1)) {
            byte[] pt = "secret".getBytes(StandardCharsets.UTF_8);
            EncryptedBlob bound = crypto.encrypt(k, pt, "owner:42");
            byte[] stripped = bound.toBytes();
            stripped[1] = 0; // clear the context flag

            // Route 1: present it as an unbound record with no context.
            CryptoException a = assertThrows(CryptoException.class,
                    () -> crypto.decrypt(k, EncryptedBlob.fromBytes(stripped), null));
            assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, a.code());

            // Route 2: present the cleared-flag record while still supplying the real context.
            CryptoException b = assertThrows(CryptoException.class,
                    () -> crypto.decrypt(k, EncryptedBlob.wrap(stripped, false, null), "owner:42"));
            assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, b.code());

            // Route 3: encode form with a context field attached to a flag-0 record.
            String forged = "v1." + canonical(stripped) + ".owner:42";
            assertThrows(CryptoException.class, () -> EncryptedBlob.fromEncoded(forged),
                    "a flag-0 record must not carry a context field");
        }
    }

    @Test
    void aRecordCannotBeRetargetedAtAnotherKeyVersionThroughThePublicApi() throws Exception {
        /*
         * The key-version byte is attacker-writable text in a stored string. Re-stamping it must not
         * let a record claim a different key: the version is inside the AAD, and the single-key path
         * additionally requires the key's own tag to equal it.
         */
        try (KeyMaterial v1 = key(1); KeyMaterial v2 = key(2)) {
            EncryptedBlob real = crypto.encrypt(v1, "secret".getBytes(StandardCharsets.UTF_8), "ctx");
            byte[] restamped = real.toBytes();
            restamped[2] = 2; // "I was written with key version 2"
            String forged = "v1." + canonical(restamped) + ".ctx";

            EncryptedBlob parsed = EncryptedBlob.fromEncoded(forged); // parses: the byte is in range
            assertEquals(2, parsed.keyVersion(), "the parser should surface the claimed version");

            // The v2 key cannot open it: the AAD still says 1.
            assertThrows(CryptoException.class, () -> crypto.decrypt(v2, parsed, "ctx"));
            // The v1 key can, but only because it IS the key that wrote it - and the claimed version
            // no longer matches, so the engine refuses rather than let the claim stand.
            CryptoException e = assertThrows(CryptoException.class, () -> crypto.decrypt(v1, parsed, "ctx"));
            assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, e.code());
        }
    }

    @Test
    void truncationNeverYieldsAPlaintext() throws Exception {
        try (KeyMaterial k = key(1)) {
            EncryptedBlob b = crypto.encrypt(k, "0123456789abcdefghij".getBytes(StandardCharsets.UTF_8), null);
            byte[] base = b.toBytes();
            for (int cut = 1; cut <= 24; cut++) {
                byte[] truncated = Arrays.copyOf(base, base.length - cut);
                if (truncated.length < EncryptedBlob.HEADER_BYTES) {
                    break;
                }
                CryptoException e = assertThrows(CryptoException.class,
                        () -> crypto.decrypt(k, EncryptedBlob.wrap(truncated, false, null), null),
                        "a record truncated by " + cut + " bytes was accepted");
                assertNotNull(e.getMessage());
            }
        }
    }

    @Test
    void editingTheHeaderCostsTheSameAsEditingTheCiphertext() throws Exception {
        /*
         * A version or flag check placed in front of the cipher makes "the header was tampered with" a
         * measurably cheaper refusal than "the payload was tampered with", which tells an attacker with
         * write access which bytes they may probe. Every route below must pay for a full AES-GCM
         * attempt, so their median costs have to sit within noise of each other.
         *
         * The base record carries no context: that way nothing is refused by the parser (a flag-0 record
         * may not carry a context field) and every one of these edits really does reach the tag.
         */
        KeyMaterial key = key(1);
        KeyMaterial sameVersionDifferentBytes = key(1);
        EncryptedBlob blob = crypto.encrypt(key, "timing sensitive payload".getBytes(StandardCharsets.UTF_8), null);

        byte[] badVersion = blob.toBytes();
        badVersion[2] = 2;
        byte[] raisedFlag = blob.toBytes();
        raisedFlag[1] = 1;
        byte[] badNonce = blob.toBytes();
        badNonce[3] ^= 1;
        byte[] badBody = blob.toBytes();
        badBody[EncryptedBlob.HEADER_BYTES] ^= 1;
        byte[] badTag = blob.toBytes();
        badTag[badTag.length - 1] ^= 1;

        Map<String, java.util.concurrent.Callable<String>> routes = new LinkedHashMap<>();
        routes.put("versionByte", () -> authCodeOf(
                () -> crypto.decrypt(key, EncryptedBlob.fromBytes(badVersion), null)));
        /*
         * A flag-0 record whose flag was set to 1 cannot be built with fromBytes (that combination is
         * refused by the parser), so it goes in through the package-internal constructor - which is how
         * a record already at rest, whose stored byte was edited, really does arrive.
         */
        routes.put("contextFlag", () -> authCodeOf(
                () -> crypto.decrypt(key, EncryptedBlob.wrap(raisedFlag, false, null), null)));
        routes.put("nonceByte", () -> authCodeOf(
                () -> crypto.decrypt(key, EncryptedBlob.fromBytes(badNonce), null)));
        routes.put("firstBodyByte", () -> authCodeOf(
                () -> crypto.decrypt(key, EncryptedBlob.fromBytes(badBody), null)));
        routes.put("lastTagByte", () -> authCodeOf(
                () -> crypto.decrypt(key, EncryptedBlob.fromBytes(badTag), null)));
        /* Caller supplies a context the record never claimed: a disagreement for the tag to settle. */
        routes.put("extraContext", () -> authCodeOf(() -> crypto.decrypt(key, blob, "unexpected")));
        /* Same version, different bytes: the only disagreement is the key itself. */
        routes.put("otherKey", () -> authCodeOf(
                () -> crypto.decrypt(sameVersionDifferentBytes, blob, null)));

        double fastest = Double.MAX_VALUE;
        double slowest = 0;
        StringBuilder report = new StringBuilder();
        for (Map.Entry<String, java.util.concurrent.Callable<String>> e : routes.entrySet()) {
            double us = medianUs(e.getValue());
            report.append(String.format(java.util.Locale.ROOT, "%s=%.1fus ", e.getKey(), us));
            fastest = Math.min(fastest, us);
            slowest = Math.max(slowest, us);
        }
        /* Microseconds, not nanoseconds: the resolution that matters for an oracle a client can observe. */
        System.out.println("tamper-cost " + report
                + String.format(java.util.Locale.ROOT, "| spread=%.2fx", slowest / fastest));
        assertTrue(slowest / fastest < 4.0, "refusal cost spread too wide: " + report);
        /* A guard that refused before doing any work would also have a tight spread: require real work. */
        assertTrue(fastest > 40, "refusals implausibly cheap, so the AEAD is not attempted: " + report);
    }

    /**
     * The failure code of a refusal, asserting it is an authentication failure. Timing a route that
     * quietly succeeded - or refused for a validation reason and so skipped the cipher - would prove
     * nothing, so each measured route is required to reach the tag check.
     */
    private static String authCodeOf(ThrowingRunnable r) {
        try {
            r.run();
        } catch (CryptoException e) {
            assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, e.code(),
                    "route refused for the wrong reason");
            return e.code().name();
        }
        throw new AssertionError("route unexpectedly decrypted");
    }

    @Test
    void oversizedPlaintextIsRefusedBeforeAnyWork() throws Exception {
        try (KeyMaterial k = key(1)) {
            CryptoException e = assertThrows(CryptoException.class,
                    () -> crypto.encrypt(k, new byte[Limits.MAX_PLAINTEXT_BYTES + 1], null));
            assertEquals(CryptoException.CryptoFailureCode.TOO_LARGE, e.code());
            assertNotNull(crypto.encrypt(k, new byte[Limits.MAX_PLAINTEXT_BYTES], null),
                    "the bound must be inclusive, not one byte short");
        }
    }

    @Test
    void onlyAes256KeyLengthsAreAccepted() {
        for (int len : new int[]{0, 1, 15, 16, 24, 31, 33, 64}) {
            byte[] bad = new byte[len];
            CryptoException e = assertThrows(CryptoException.class, () -> KeyMaterial.fromBytes(bad),
                    "a " + len + "-byte key was accepted");
            assertEquals(CryptoException.CryptoFailureCode.INVALID_KEY, e.code());
        }
        try {
            assertNotNull(KeyMaterial.fromBytes(new byte[32]));
        } catch (CryptoException e) {
            fail("a 32-byte key was rejected: " + e.getMessage(), e);
        }
    }

    @Test
    void keyVersionOutOfRangeIsRefused() {
        byte[] k = new byte[32];
        for (int v : new int[]{0, -1, 256, Integer.MAX_VALUE}) {
            CryptoException e = assertThrows(CryptoException.class, () -> KeyMaterial.fromBytes(k, v));
            assertEquals(CryptoException.CryptoFailureCode.INVALID_INPUT, e.code());
        }
    }

    @Test
    void contextValidationRefusesInjectionAndOversize() throws Exception {
        try (KeyMaterial k = key(1)) {
            byte[] pt = "x".getBytes(StandardCharsets.UTF_8);
            for (String bad : new String[]{"", " ", "has space", "line\nbreak", "tab\tsep", "nul\u0000char",
                    "nbsp\u00a0here", "\u001b[31mred\u001b[0m", "\uD83D\uDE00emoji",
                    "a".repeat(Limits.MAX_CONTEXT_CHARS + 1)}) {
                CryptoException e = assertThrows(CryptoException.class, () -> crypto.encrypt(k, pt, bad),
                        "context was accepted: <" + bad + ">");
                assertEquals(CryptoException.CryptoFailureCode.INVALID_INPUT, e.code());
            }
            assertNotNull(crypto.encrypt(k, pt, "a".repeat(Limits.MAX_CONTEXT_CHARS)),
                    "the maximum legal context must be accepted");
            assertNotNull(crypto.encrypt(k, pt, "user:42/profile"));
        }
    }

    @Test
    void nullInputsFailClosedRatherThanSubstituting() throws Exception {
        try (KeyMaterial k = key(1)) {
            assertThrows(CryptoException.class, () -> crypto.encrypt(k, (byte[]) null, null));
            assertThrows(CryptoException.class, () -> crypto.encrypt(k, (String) null, null));
            assertThrows(CryptoException.class, () -> crypto.decrypt(k, (EncryptedBlob) null, null));
            assertThrows(CryptoException.class,
                    () -> crypto.decrypt(null, crypto.encrypt(k, new byte[]{1}, null), null));
        }
        assertThrows(CryptoException.class, () -> new SymmetricCrypto((SecureRandom) null));
    }

    @Test
    void malformedUtf8IsRefusedNotReplaced() throws Exception {
        try (KeyMaterial k = key(1)) {
            EncryptedBlob b = crypto.encrypt(k, new byte[]{(byte) 0xFF, (byte) 0xFE, 'a'}, null);
            CryptoException e = assertThrows(CryptoException.class, () -> crypto.decryptToString(k, b, null));
            assertEquals(CryptoException.CryptoFailureCode.INVALID_INPUT, e.code());
            /* The bytes remain available: the text view is refused, not the record. */
            assertArrayEquals(new byte[]{(byte) 0xFF, (byte) 0xFE, 'a'}, crypto.decrypt(k, b, null));
        }
    }

    @Test
    void failureCostDoesNotDependOnWhichCheckFailed() throws Exception {
        /*
         * Timing parity measured in microseconds with an absolute floor as well as a ratio: a change
         * that removes work from every branch keeps a ratio-only assertion at 1.0.
         */
        try (KeyMaterial k = key(1); KeyMaterial wrong = key(2)) {
            EncryptedBlob b = crypto.encrypt(k, "0123456789abcdef".getBytes(StandardCharsets.UTF_8), "ctx");
            long wrongKey = medianUs(() -> userOf(() -> crypto.decrypt(wrong, b, "ctx")));
            long wrongCtx = medianUs(() -> userOf(() -> crypto.decrypt(k, b, "nope")));
            long tampered = medianUs(() -> {
                byte[] t = b.toBytes();
                t[t.length - 1] ^= 0x01;
                return userOf(() -> crypto.decrypt(k, EncryptedBlob.wrap(t, true, "ctx"), "ctx"));
            });
            long floor = Math.min(wrongKey, Math.min(wrongCtx, tampered));
            long ceiling = Math.max(wrongKey, Math.max(wrongCtx, tampered));
            assertTrue(floor > 0, "measured 0 us - the timer is too coarse, the assertion would be vacuous");
            assertTrue(ceiling < floor * 4,
                    "authentication failures differ by more than 4x: floor=" + floor + "us ceiling=" + ceiling + "us");
            /* And the work really happens: an empty stub would be under 50 us. */
            assertTrue(floor >= 50, "authentication failures are suspiciously cheap (" + floor + " us) - "
                    + "is any AES-GCM work being done at all?");
        }
    }

    @Test
    void exceptionSurfaceCarriesNoInternals() throws Exception {
        try (KeyMaterial k = key(1)) {
            EncryptedBlob b = crypto.encrypt(k, "x".getBytes(StandardCharsets.UTF_8), "ctx");
            CryptoException e = assertThrows(CryptoException.class, () -> crypto.decrypt(k, b, "other"));
            assertFalse(e.toString().contains(e.getTechnicalDetail()),
                    "toString() exposes the technical detail: " + e);
            assertFalse(e.getMessage().contains(e.getTechnicalDetail()),
                    "getMessage() exposes the technical detail: " + e.getMessage());
            assertEquals(e.code().userMessage(), e.getMessage());
            assertNotNull(e.getStackTrace());
            /* The underlying AEADBadTagException must not ride along in the rendered form. */
            assertFalse(String.valueOf(e.getCause()).contains("AEADBadTag"),
                    "the provider's tag exception is exposed through getCause(): " + e.getCause());
        }
    }

    @Test
    void blobToStringNeverContainsTheRecord() throws Exception {
        try (KeyMaterial k = key(1)) {
            EncryptedBlob b = crypto.encrypt(k, "top-secret".getBytes(StandardCharsets.UTF_8), "owner:7");
            String s = b.toString();
            assertFalse(s.contains(b.toBase64Url()), "toString() prints the whole record: " + s);
            assertFalse(s.contains(java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(b.toBytes())), "toString() prints the payload: " + s);
            assertTrue(s.contains("owner") == false || !s.contains("owner:7"),
                    "toString() prints the context value: " + s);
        }
    }

    @Test
    void keyMaterialToStringAndEqualityNeverPrintKeys() throws Exception {
        try (KeyMaterial k = key(1)) {
            byte[] raw = k.copyForWrite();
            String encoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
            assertFalse(k.toString().contains(encoded), "toString() leaks the key: " + k);
            assertFalse(Integer.toHexString(System.identityHashCode(k)).isEmpty());
            assertEquals(k, k);
            assertNotEquals(k, key(1), "two distinct key objects must not compare equal");
        }
    }

    @Test
    void concurrencyProducesNoCorruptionAndNoSharedState() throws Exception {
        try (KeyMaterial k = key(1)) {
            int threads = 8;
            int perThread = 40;
            java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
            java.util.List<java.util.concurrent.Future<String>> futures = new java.util.ArrayList<>();
            for (int t = 0; t < threads; t++) {
                final int id = t;
                futures.add(pool.submit(() -> {
                    for (int i = 0; i < perThread; i++) {
                        String value = "t" + id + "-" + i;
                        EncryptedBlob b = crypto.encrypt(k, value.getBytes(StandardCharsets.UTF_8), "shared");
                        if (!value.equals(crypto.decryptToString(k, b, "shared"))) {
                            return "round trip broke under concurrency";
                        }
                    }
                    return null;
                }));
            }
            pool.shutdown();
            assertTrue(pool.awaitTermination(120, java.util.concurrent.TimeUnit.SECONDS));
            for (var f : futures) {
                assertNull(f.get(), String.valueOf(f.get()));
            }
        }
    }

    /**
     * The provider accepts a 96-bit tag without complaining, so nothing about the code proves the tag
     * was not quietly downgraded: only the measured record can. A 96-bit tag is a quarter of the forgery
     * cost, and a reader who only checks "does it round-trip" would never notice.
     */
    @Test
    void theAuthenticationTagIsTheFullWidthTheFormatPromises() throws Exception {
        try (KeyMaterial k = key(1)) {
            final int tagBytes = 16;
            assertEquals(128, Limits.TAG_BITS, "the declared tag width moved away from 128 bits");
            for (int n : new int[]{0, 1, 1000}) {
                byte[] raw = crypto.encrypt(k, new byte[n], null).toBytes();
                assertEquals(EncryptedBlob.HEADER_BYTES + n + tagBytes, raw.length,
                        "record is not body + a full-width tag at n=" + n);
            }
            /*
             * The width must also be what the parser demands: a record shorter than header + a whole tag
             * cannot exist, and one byte short of that is the downgraded format arriving in disguise.
             */
            byte[] justEnough = crypto.encrypt(k, new byte[0], null).toBytes();
            assertEquals(EncryptedBlob.HEADER_BYTES + tagBytes, justEnough.length);
            assertThrows(CryptoException.class,
                    () -> EncryptedBlob.fromBytes(Arrays.copyOf(justEnough, justEnough.length - 1)),
                    "a record with no room for a full tag parsed anyway");

            /* And a record whose tag lost a byte must never hand back plaintext. */
            byte[] clipped = crypto.encrypt(k, "do-not-return-this".getBytes(StandardCharsets.UTF_8), null)
                    .toBytes();
            byte[] chopped = Arrays.copyOf(clipped, clipped.length - 1);
            CryptoException cut = assertThrows(CryptoException.class,
                    () -> crypto.decrypt(k, EncryptedBlob.fromBytes(chopped), null));
            assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, cut.code());
        }
    }

    /**
     * Every record has exactly one textual spelling. Accepting a second spelling gives one record two
     * identities, which is enough to slip a value past a cache, a replay list or a dedupe index.
     * Non-canonical base64 spellings only exist when the byte count is not a multiple of three, so the
     * fixture uses a one-byte payload: 32 packed bytes leave two unused bits in the last character.
     */
    @Test
    void aRecordHasExactlyOneTextualSpelling() throws Exception {
        try (KeyMaterial k = key(1)) {
            EncryptedBlob b = crypto.encrypt(k, new byte[]{42}, "ctx");
            byte[] packed = b.toBytes();
            assertNotEquals(0, packed.length % 3, "the fixture must not be a whole number of base64 groups");
            String text = b.toBase64Url();
            String payload = text.substring(3, text.lastIndexOf('.'));
            assertEquals(canonical(packed), payload, "the record text is not the unpadded canonical form");

            Base64.Decoder lenient = Base64.getUrlDecoder();
            int acceptedDuplicates = 0;
            int candidates = 0;

            /* The padded spelling: the same bytes, written with the padding this format never uses. */
            String padded = java.util.Base64.getUrlEncoder().encodeToString(packed);
            if (!padded.equals(payload) && Arrays.equals(lenient.decode(padded), packed)) {
                candidates++;
                if (parsesToSameRecord("v1." + padded + ".ctx", packed)) {
                    acceptedDuplicates++;
                }
            }
            /* Every spelling that decodes to the same bytes, by sweeping the final character. */
            String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            for (int i = 0; i < alphabet.length(); i++) {
                String alt = payload.substring(0, payload.length() - 1) + alphabet.charAt(i);
                byte[] decoded;
                try {
                    decoded = lenient.decode(alt);
                } catch (IllegalArgumentException cannotDecode) {
                    continue;
                }
                if (Arrays.equals(decoded, packed) && !alt.equals(payload)) {
                    candidates++;
                    if (parsesToSameRecord("v1." + alt + ".ctx", packed)) {
                        acceptedDuplicates++;
                    }
                }
            }
            assertTrue(candidates > 0, "the fixture found no alternative spelling, so it proved nothing");
            assertEquals(0, acceptedDuplicates, acceptedDuplicates
                    + " alternative spellings of one record were accepted as valid records");
        }
    }

    /**
     * {@code peekKeyVersion} is the one method that looks at an unauthenticated record and returns
     * something a caller might act on, so it must be both correct on real records and cheap on junk -
     * it runs before any length bound has been applied anywhere else.
     */
    @Test
    void peekingTheKeyVersionIsCorrectOnRealRecordsAndBoundedOnJunk() throws Exception {
        try (KeyMaterial k1 = key(1); KeyMaterial k9 = key(9); KeyMaterial k255 = key(255)) {
            for (KeyMaterial k : List.of(k1, k9, k255)) {
                EncryptedBlob b = crypto.encrypt(k, new byte[]{1, 2, 3}, null);
                assertEquals(k.version(), EncryptedBlob.peekKeyVersion(b.toBase64Url()),
                        "peek disagreed with the record it was given");
            }
        }

        /* Everything that is not a supported record reports -1 rather than a guess. */
        assertEquals(-1, EncryptedBlob.peekKeyVersion(null));
        assertEquals(-1, EncryptedBlob.peekKeyVersion(""));
        assertEquals(-1, EncryptedBlob.peekKeyVersion("v2.AAAA"), "an unsupported prefix was read");
        assertEquals(-1, EncryptedBlob.peekKeyVersion("AAA"), "a payload too short for a header was read");
        assertEquals(-1, EncryptedBlob.peekKeyVersion("v1.!!!!.ctx"), "non-alphabet text was read");
        try (KeyMaterial k = key(1)) {
            byte[] real = crypto.encrypt(k, new byte[]{7}, null).toBytes();

            /*
             * A well-formed *header* over a payload that cannot be a record: three bytes, no room for a
             * tag. Reading a version here would mean peek answered for a string fromEncoded refuses, and
             * a caller that routed a key lookup on the difference would be consulting a field nothing
             * else in the system ever agreed was a record.
             */
            String headerOnly = Base64.getUrlEncoder().encodeToString(Arrays.copyOf(real, 3));
            assertEquals(4, headerOnly.length(), "the fixture is not one base64 group");
            assertEquals(-1, EncryptedBlob.peekKeyVersion("v1." + headerOnly),
                    "a three-byte payload was read as a record");

            byte[] zeroVersion = real.clone();
            zeroVersion[2] = 0;
            assertEquals(-1, EncryptedBlob.peekKeyVersion("v1." + canonical(zeroVersion)),
                    "the reserved key version 0 was reported as usable");
            byte[] otherFormat = real.clone();
            otherFormat[0] = 4;
            assertEquals(-1, EncryptedBlob.peekKeyVersion("v1." + canonical(otherFormat)),
                    "a foreign format version was reported");

            /*
             * Same property at the other end of the length bound: a valid header followed by eight
             * megabytes of junk must report -1, because the record is oversized and nothing else in the
             * system will accept it. This is also the only observable form of the bound - decoding is
             * already capped at four characters, so cost alone cannot tell a bounded peek from an
             * unbounded one, and a test that timed instead of compared answers would pass either way.
             */
            String oversized = "v1." + headerOnly + "A".repeat(8 * 1024 * 1024);
            assertThrows(CryptoException.class, () -> EncryptedBlob.fromEncoded(oversized),
                    "the parser accepted the oversized record, so there was nothing to disagree about");
            assertEquals(-1, EncryptedBlob.peekKeyVersion(oversized),
                    "peek reported a version for a record the parser refuses");

            long us = medianUs(() -> {
                assertEquals(-1, EncryptedBlob.peekKeyVersion(oversized));
                return "x";
            });
            System.out.println("peek-oversized " + us + "us");
            assertTrue(us < 2000, "peeking a rejected record cost " + us + "us, so it scales with the input");
        }
    }

    /**
     * The length bound on a raw record must be applied to the caller's array, not to a copy of it.
     * Outcome-wise the two orderings are identical - both refuse with the same words - so the only
     * thing that distinguishes them is who gets to decide how much heap is allocated, and the only way
     * to see that is to measure. The fixture is valid in every field except its length, so a parser
     * whose length check went away altogether would accept it, which is the second thing under test.
     */
    @Test
    void anOversizedRecordIsRefusedWithoutBeingCopiedFirst() throws Exception {
        byte[] huge = new byte[64 * 1024 * 1024];
        huge[0] = EncryptedBlob.FORMAT_VERSION;
        huge[1] = 0;
        huge[2] = EncryptedBlob.MIN_KEY_VERSION;

        CryptoException e = assertThrows(CryptoException.class, () -> EncryptedBlob.fromBytes(huge),
                "a record far longer than the format allows was accepted");
        assertEquals(CryptoException.CryptoFailureCode.INVALID_INPUT, e.code());
        assertTrue(e.getTechnicalDetail().contains("impossible length"), e.getTechnicalDetail());

        long us = medianUs(() -> {
            for (int i = 0; i < 20; i++) {
                assertThrows(CryptoException.class, () -> EncryptedBlob.fromBytes(huge));
            }
            return "x";
        });
        System.out.println("oversized-refusal " + us + "us for 20 refusals of 64 MiB");
        assertTrue(us < 20_000,
                "20 refusals of a 64 MiB record cost " + us + "us, which is copying, not checking");
    }

    /** True if {@code text} parses and yields the very same record bytes. */
    private static boolean parsesToSameRecord(String text, byte[] packed) {
        try {
            return Arrays.equals(EncryptedBlob.fromEncoded(text).toBytes(), packed);
        } catch (CryptoException refused) {
            return false;
        }
    }

    private static void assertNull(Object o, String msg) {
        org.junit.jupiter.api.Assertions.assertTrue(o == null, msg);
    }

    private static String canonical(byte[] bytes) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String userOf(ThrowingRunnable r) {
        try {
            r.run();
        } catch (CryptoException e) {
            return e.getMessage();
        }
        throw new AssertionError("expected a CryptoException, none was thrown");
    }

    private static String detailOf(ThrowingRunnable r) {
        try {
            r.run();
        } catch (CryptoException e) {
            return e.getTechnicalDetail();
        }
        throw new AssertionError("expected a CryptoException, none was thrown");
    }

    private static long medianUs(java.util.concurrent.Callable<String> body) throws Exception {
        long[] samples = new long[7];
        for (int i = 0; i < samples.length; i++) {
            long start = System.nanoTime();
            body.call();
            samples[i] = (System.nanoTime() - start) / 1000;
        }
        Arrays.sort(samples);
        return samples[samples.length / 2];
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws CryptoException;
    }
}
