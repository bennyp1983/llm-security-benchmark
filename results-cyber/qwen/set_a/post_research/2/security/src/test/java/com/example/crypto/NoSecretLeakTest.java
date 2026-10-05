package com.example.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * What a failure is allowed to say.
 *
 * <p>Rule 2 and rule 5 of the brief forbid a secret in a message, a log line, a stack trace or an error
 * response; rule 6 forbids telling a caller <em>why</em> a decryption failed when the why is itself
 * information ("that record exists", "that version is disabled", "the file is world-readable"). Both
 * are checked here the only way they can be checked: by rendering the exception every way a caller
 * could render it, and searching the result for material that must not appear.
 *
 * <p>The asserts are deliberately content-based. "All failure messages are equal" is a comparison that
 * stays green when a change makes every failure leak the same secret - so each message is also checked
 * against its own wording, and each refusal is checked to be one of the fixed small set.
 */
class NoSecretLeakTest {

    /** Chosen so a leak is unmistakable: each is distinctive and appears in exactly one role. */
    private static final String PLAINTEXT = "ssn-042-11-9999";
    private static final String CONTEXT = "tenant:acme:acct:4242";
    private static final String PASSPHRASE = "correct-horse-battery-staple-please-rotate-7731";
    private static final String STORE_PASSWORD = "a-store-password-long-enough-to-pass-the-floor-1c4d";

    /** The fixed set of caller-facing messages. Anything outside it was composed at the failure site. */
    private static final Set<String> ALLOWED_MESSAGES = Set.of(
            "No data was supplied",
            "The supplied data is not in a supported format",
            "The data could not be decrypted",
            "The data could not be processed");

    @Test
    void everyFailurePathRendersNothingAnAttackerWants() throws Exception {
        Path dir = Fixtures.dir("leak");
        SymmetricCrypto crypto = new SymmetricCrypto();
        KeyMaterial key = crypto.generateKey(7);
        byte[] plaintext = PLAINTEXT.getBytes(StandardCharsets.UTF_8);
        EncryptedBlob blob = crypto.encrypt(key, plaintext, CONTEXT);
        String encoded = blob.toBase64Url();

        /* Material that must never surface, in each form it could plausibly take. */
        byte[] rawKey = key.copyForWrite();
        List<String> forbidden = new ArrayList<>();
        forbidden.add(PLAINTEXT);
        forbidden.add(CONTEXT);
        forbidden.add(PASSPHRASE);
        forbidden.add(STORE_PASSWORD);
        forbidden.add(java.util.HexFormat.of().formatHex(rawKey));
        forbidden.add(Base64.getEncoder().encodeToString(rawKey));
        forbidden.add(Base64.getUrlEncoder().withoutPadding().encodeToString(rawKey));
        forbidden.add(Base64.getEncoder().encodeToString(plaintext));

        List<String> surfaces = new ArrayList<>();
        List<String> labels = new ArrayList<>();
        /* Every route below must actually fail; the helper asserts that, so a silent success cannot
           hide a hole by contributing no surface at all. */
        collect(labels, surfaces, "wrongKey", () -> {
            try (KeyMaterial other = crypto.generateKey(7)) {
                crypto.decrypt(other, blob, CONTEXT);
            }
        });
        collect(labels, surfaces, "wrongContext", () -> crypto.decrypt(key, blob, "tenant:other"));
        collect(labels, surfaces, "missingContext", () -> crypto.decrypt(key, blob, null));
        collect(labels, surfaces, "tamperedBody", () -> {
            byte[] t = blob.toBytes();
            t[EncryptedBlob.HEADER_BYTES] ^= 1;
            crypto.decrypt(key, EncryptedBlob.fromBytes(t), CONTEXT);
        });
        collect(labels, surfaces, "tamperedHeader", () -> {
            byte[] t = blob.toBytes();
            t[2] = 8;
            crypto.decrypt(key, EncryptedBlob.fromBytes(t), CONTEXT);
        });
        collect(labels, surfaces, "unknownFormat",
                () -> EncryptedBlob.fromBytes(new byte[]{9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}));
        collect(labels, surfaces, "garbageEncoded", () -> EncryptedBlob.fromEncoded("v1.%%%"));
        collect(labels, surfaces, "nullPlaintext", () -> crypto.encrypt(key, (byte[]) null, CONTEXT));
        collect(labels, surfaces, "nullKey", () -> crypto.decrypt(null, blob, CONTEXT));
        collect(labels, surfaces, "oversizePlaintext",
                () -> crypto.encrypt(key, new byte[Limits.MAX_PLAINTEXT_BYTES + 1], null));
        collect(labels, surfaces, "oversizeBlob", () -> {
            byte[] big = new byte[EncryptedBlob.MAX_PACKED_BYTES + 1];
            big[0] = EncryptedBlob.FORMAT_VERSION;
            big[2] = 1;
            EncryptedBlob.fromBytes(big);
        });
        collect(labels, surfaces, "badContextChars", () -> crypto.encrypt(key, plaintext, "has space"));
        collect(labels, surfaces, "badKeyLength", () -> KeyMaterial.fromBytes(new byte[16]));
        collect(labels, surfaces, "destroyedKey", () -> {
            KeyMaterial dead = crypto.generateKey(1);
            dead.destroy();
            crypto.encrypt(dead, plaintext, null);
        });
        collect(labels, surfaces, "absentKeyFile",
                () -> new KeyFileKeySource(dir.resolve("nope.key")).load());
        collect(labels, surfaces, "loosenedKeyFile", () -> {
            Path f = dir.resolve("loose.key");
            Files.write(f, rawKey);
            Fixtures.setMode(f, "644");
            new KeyFileKeySource(f).load();
        });
        collect(labels, surfaces, "symlinkedKeyFile", () -> {
            Path real = dir.resolve("leak-real.key");
            Files.write(real, rawKey);
            Fixtures.setMode(real, "600");
            Path link = dir.resolve("leak-link.key");
            Files.createSymbolicLink(link, real);
            new KeyFileKeySource(link).load();
        });
        collect(labels, surfaces, "wrongPassphrase", () -> {
            Path container = dir.resolve("leak.spkb1");
            PasswordKeySource.create(container, 1, PASSPHRASE.toCharArray(), Fixtures.fastIterations());
            try (PasswordKeySource src = new PasswordKeySource(container, 1,
                    "a-completely-different-passphrase-of-length-44e2".toCharArray())) {
                src.load();
            }
        });
        collect(labels, surfaces, "wrongStorePassword", () -> {
            Path store = dir.resolve("leak.p12");
            KeystoreKeySource.create(store, "data-key", 1, STORE_PASSWORD.toCharArray(),
                    STORE_PASSWORD.toCharArray());
            try (KeystoreKeySource src = new KeystoreKeySource(store, "data-key", 1,
                    "a-wrong-store-password-that-is-long-enough-9b2a".toCharArray(),
                    STORE_PASSWORD.toCharArray())) {
                src.load();
            }
        });
        collect(labels, surfaces, "vaultAfterClose", () -> {
            KeyVault vault = KeyVault.of(new KeyFileKeySource(dir.resolve("loose.key")));
            vault.close();
            vault.encryptString("x", null);
        });

        /* A refusal must have been produced for every route: an empty surface list proves nothing. */
        assertEquals(labels.size(), surfaces.size(), labels.toString());
        assertTrue(labels.size() >= 18, "only " + labels.size() + " failure routes were exercised");
        for (int i = 0; i < surfaces.size(); i++) {
            String rendered = surfaces.get(i);
            for (String secret : forbidden) {
                assertFalse(rendered.contains(secret),
                        labels.get(i) + " leaked [" + secret + "] as: " + abbreviate(rendered));
            }
        }

        /* The caller-facing message is always one of four fixed strings, never a composed sentence. */
        Set<String> messages = new LinkedHashSet<>();
        collectMessages(messages, labels);
        assertTrue(ALLOWED_MESSAGES.containsAll(messages),
                "a message outside the fixed set appeared: " + messages);
        /* And none of them happens to name a sensitive concept in passing. */
        for (String m : messages) {
            String lower = m.toLowerCase(java.util.Locale.ROOT);
            for (String word : List.of("key", "password", "passphrase", "secret", "tenant", "context",
                    "version", "permission", "file", "environment", "keystore", "tamper")) {
                assertFalse(lower.contains(word), "the caller-facing message names " + word + ": " + m);
            }
        }
        key.destroy();
    }

    @Test
    void aRefusalNeverConfirmsThatTheRecordOrItsAccountExists() throws Exception {
        /*
         * Rule 6: an oracle over "is this a real record" is enough to enumerate identifiers. The point of
         * one shared message for the whole secret-related family is that a caller cannot tell a wrong key
         * from a wrong context from a disabled version from a missing key file.
         */
        SymmetricCrypto crypto = new SymmetricCrypto();
        KeyMaterial k1 = crypto.generateKey(1);
        KeyMaterial k2 = crypto.generateKey(2);
        EncryptedBlob blob = crypto.encrypt(k1, PLAINTEXT.getBytes(StandardCharsets.UTF_8), CONTEXT);
        byte[] raw1 = k1.copyForWrite();

        KeyVault vault = new KeyVault(v -> new FixedSource(raw1, v), 1);
        try {
            /*
             * These records all carry a context, so they travel as encoded strings: fromBytes refuses a
             * context-bound record, and a route that died on the parser would be reporting a format
             * problem instead of the authentication question this test is about.
             */
            String encoded = blob.toBase64Url();
            String unknownRecord = userMessageOf(
                    () -> vault.decryptStringEncoded(restamp(encoded, 9), CONTEXT));
            String wrongContext = userMessageOf(() -> vault.decryptStringEncoded(encoded, "tenant:nope"));
            String tampered = userMessageOf(() -> vault.decryptStringEncoded(flipLastByte(encoded), CONTEXT));
            /*
             * rotate() is what stops reads through the superseded version, so this is the ordinary way a
             * record becomes unreadable-by-policy rather than by tampering. disable(1) directly would be
             * refused: the active version cannot be disabled.
             */
            vault.rotate();
            String disabledKey = userMessageOf(() -> vault.decryptStringEncoded(encoded, CONTEXT));
            vault.enable(1);
            String wrongVersion = userMessageOf(() -> crypto.decrypt(k2, blob, CONTEXT));

            /* All five answers identical, and identical to the shared text - not just to each other. */
            List<String> answers = List.of(unknownRecord, wrongContext, tampered, disabledKey, wrongVersion);
            assertEquals(1, distinct(answers).size(), answers.toString());
            String shared = answers.get(0);
            assertEquals("The data could not be decrypted", shared);
            assertFalse(shared.contains("9"), "the refusal names the missing version: " + shared);
            assertFalse(shared.toLowerCase(java.util.Locale.ROOT).contains("disabl"), shared);

            /*
             * The three authentication routes must share a technical detail too, and for a different
             * reason than the user message: a re-stamped version, a flipped ciphertext byte and a wrong
             * context are all resolved by one AES-GCM tag check, so the engine cannot honestly tell them
             * apart. A detail that claimed to know which one it was would be fabricated diagnostics - and
             * if it were ever routed to a caller, it would be the existence oracle this whole class is
             * about. What the two channels must differ on is the *kind* of failure, checked next.
             */
            List<String> details = List.of(
                    detailOf(() -> vault.decryptStringEncoded(restamp(encoded, 9), CONTEXT)),
                    detailOf(() -> vault.decryptStringEncoded(encoded, "tenant:nope")),
                    detailOf(() -> vault.decryptStringEncoded(flipLastByte(encoded), CONTEXT)));
            assertEquals(1, distinct(details).size(),
                    "these three are one tag check and must be reported identically: " + details);
            String authDetail = details.get(0);
            assertFalse(authDetail.contains(PLAINTEXT) || authDetail.contains(CONTEXT), authDetail);

            /*
             * But the log channel is not a copy of the user channel: two different kinds of failure do
             * get different details, which is the only reason to keep both strings. If this ever regresses
             * to one constant, the operator has been left with nothing and the split is theatre.
             */
            String formatDetail = expectFailure("badFormat", () -> EncryptedBlob.fromBytes(
                    new byte[]{9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})).getTechnicalDetail();
            String missingDetail = expectFailure("missing",
                    () -> crypto.encrypt(k1, (byte[]) null, CONTEXT)).getTechnicalDetail();
            assertTrue(distinct(List.of(authDetail, formatDetail, missingDetail)).size() == 3,
                    "details do not distinguish failure kinds: " + List.of(authDetail, formatDetail, missingDetail));
        } finally {
            vault.close();
        }
    }

    /** Rewrites the key-version byte of an encoded record, leaving the context field alone. */
    private static String restamp(String encoded, int version) {
        int secondDot = encoded.indexOf('.', 3);
        byte[] raw = Base64.getUrlDecoder().decode(encoded.substring(3, secondDot));
        raw[2] = (byte) version;
        return "v1." + Base64.getUrlEncoder().withoutPadding().encodeToString(raw) + encoded.substring(secondDot);
    }

    private static String flipLastByte(String encoded) {
        int secondDot = encoded.indexOf('.', 3);
        byte[] raw = Base64.getUrlDecoder().decode(encoded.substring(3, secondDot));
        raw[raw.length - 1] ^= 1;
        return "v1." + Base64.getUrlEncoder().withoutPadding().encodeToString(raw) + encoded.substring(secondDot);
    }

    /** Set.of rejects duplicates loudly, which is the wrong failure for a test that expects them. */
    private static List<String> distinct(List<String> in) {
        return new ArrayList<>(new LinkedHashSet<>(in));
    }

    /** A source over a fixed key, for the vault routes above. */
    private record FixedSource(byte[] key, int version) implements KeySource {
        @Override
        public KeyMaterial load() throws CryptoException {
            return KeyMaterial.fromBytes(key, version);
        }

        @Override
        public String describe() {
            return "test:v" + version;
        }
    }

    @Test
    void renderingAnExceptionCannotBringOutAnInternalsDump() throws Exception {
        SymmetricCrypto crypto = new SymmetricCrypto();
        KeyMaterial key = crypto.generateKey(1);
        EncryptedBlob blob = crypto.encrypt(key, PLAINTEXT.getBytes(StandardCharsets.UTF_8), null);
        CryptoException e = null;
        try (KeyMaterial other = crypto.generateKey(1)) {
            crypto.decrypt(other, blob, null);
        } catch (CryptoException ce) {
            e = ce;
        }
        assertNotNull(e);

        /* printStackTrace is what lands in a log file when a framework handles the exception. */
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(buf, true, StandardCharsets.UTF_8)) {
            e.printStackTrace(ps);
        }
        String printed = buf.toString(StandardCharsets.UTF_8);
        assertFalse(printed.contains("javax.crypto"), printed);
        assertFalse(printed.contains("AEADBadTag"), printed);
        assertFalse(printed.contains(PLAINTEXT), printed);
        assertFalse(printed.contains("\tat "),
                "a stack frame was emitted, which names internal classes: " + abbreviate(printed));
        assertTrue(printed.contains(CryptoException.class.getName()),
                "the exception type should still be identifiable for log routing: " + printed);

        /* A cause chain is where a provider's own message (which may quote input) would ride in. */
        assertFalse(String.valueOf(e.getCause()).contains("AEADBadTag"), String.valueOf(e.getCause()));
        assertFalse(printed.contains(String.valueOf(PLAINTEXT)));
        /* Suppression and the stack were disabled at construction; getStackTrace must be empty. */
        assertEquals(0, e.getStackTrace().length, "stack trace suppression is off: " + printed);
        assertEquals(0, e.getSuppressed().length);
        /* getMessage is the caller's message and nothing else. */
        assertEquals("The data could not be decrypted", e.getMessage());
        assertEquals(e.getMessage(), e.getLocalizedMessage());
    }

    @Test
    void nothingThatLooksLikeAKeyIsEverDerivedFromAConstantOrADefault() throws Exception {
        /*
         * The quiet failure mode for a key source is to "helpfully" return something when the real key is
         * missing: a zero key, or a hash of the app name. Everything encrypts, nothing is secret. Every
         * absent source must refuse instead.
         */
        SymmetricCrypto crypto = new SymmetricCrypto();
        List<KeySource> absent = List.of(
                new EnvKeySource("SECURE_DATA_CRYPTO_DEFINITELY_NOT_SET_" + ProcessHandle.current().pid()),
                new KeyFileKeySource(Fixtures.dir("absent").resolve("nothing.key")));
        for (KeySource s : absent) {
            CryptoException e = expectFailure(s.describe(), s::load);
            assertEquals(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE, e.code());
        }

        /* The keys that do exist are distinct and high-entropy: 200 generated keys, no repeats. */
        Set<String> seen = new LinkedHashSet<>();
        for (int i = 0; i < 64; i++) {
            KeyMaterial k = crypto.generateKey(1);
            byte[] raw = k.copyForWrite();
            k.destroy();
            seen.add(java.util.HexFormat.of().formatHex(raw));
            java.util.Arrays.fill(raw, (byte) 0);
        }
        assertEquals(64, seen.size(), "a generated key repeated, so the generator is not CSPRNG-backed");
        /* Not the all-zero key, and not any other constant, in any of them. */
        String zeros = java.util.HexFormat.of().formatHex(new byte[32]);
        assertFalse(seen.contains(zeros), "an all-zero key was generated");
        /* Every byte position varies across samples: a fixed prefix would show up immediately. */
        for (int position = 0; position < 32; position++) {
            Set<Character> at = new LinkedHashSet<>();
            for (String hex : seen) {
                at.add(hex.charAt(position * 2));
            }
            assertTrue(at.size() > 8, "byte " + position + " barely varies: " + at);
        }
    }

    private static byte[] withVersion(byte[] packed, int version) {
        byte[] copy = packed.clone();
        copy[2] = (byte) version;
        return copy;
    }

    private static String abbreviate(String s) {
        String flat = s.replace('\n', ' ');
        return flat.length() <= 160 ? flat : flat.substring(0, 160) + "...";
    }

    private static void collect(List<String> labels, List<String> surfaces, String label,
            ThrowingRunnable body) {
        CryptoException e = expectFailure(label, body);
        labels.add(label);
        surfaces.add(render(e));
    }

    /** Everything a caller could print, in one string to search. */
    private static String render(CryptoException e) {
        StringBuilder sb = new StringBuilder();
        sb.append(e.getMessage()).append('|')
                .append(e.getLocalizedMessage()).append('|')
                .append(e.getTechnicalDetail()).append('|')
                .append(e).append('|')
                .append(e.code()).append('|')
                .append(e.getCause()).append('|')
                .append(java.util.Arrays.toString(e.getSuppressed())).append('|');
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(buf, true, StandardCharsets.UTF_8)) {
            e.printStackTrace(ps);
        }
        sb.append(buf.toString(StandardCharsets.UTF_8));
        return sb.toString();
    }

    private static CryptoException expectFailure(String label, ThrowingRunnable body) {
        try {
            body.run();
        } catch (CryptoException e) {
            return e;
        } catch (Exception e) {
            throw new AssertionError(label + " failed with the wrong type: " + e, e);
        }
        throw new AssertionError(label + " unexpectedly succeeded, so it contributed no surface to check");
    }

    private static void collectMessages(Set<String> out, List<String> labels) throws Exception {
        /*
         * Re-running the routes is cheaper than threading messages out of the loop above, and keeps this
         * check honest: it reads the same code paths rather than a hand-typed list.
         */
        SymmetricCrypto crypto = new SymmetricCrypto();
        KeyMaterial key = crypto.generateKey(1);
        EncryptedBlob blob = crypto.encrypt(key, PLAINTEXT.getBytes(StandardCharsets.UTF_8), CONTEXT);
        out.add(expectFailure("wrongKey", () -> {
            try (KeyMaterial other = crypto.generateKey(1)) {
                crypto.decrypt(other, blob, CONTEXT);
            }
        }).getMessage());
        out.add(expectFailure("badFormat",
                () -> EncryptedBlob.fromBytes(new byte[]{9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))
                .getMessage());
        out.add(expectFailure("nullInput", () -> crypto.encrypt(key, (byte[]) null, CONTEXT)).getMessage());
        out.add(expectFailure("oversize",
                () -> crypto.encrypt(key, new byte[Limits.MAX_PLAINTEXT_BYTES + 1], null)).getMessage());
    }

    private static String userMessageOf(ThrowingRunnable body) {
        return expectFailure("oracle", body).getMessage();
    }

    private static String detailOf(ThrowingRunnable body) {
        return expectFailure("oracle", body).getTechnicalDetail();
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
