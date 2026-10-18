package com.example.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Key routing and lifetime: which version decrypts a record, what rotation does to old records, and
 * what happens to a vault that has been closed.
 */
class KeyVaultTest {

    private static final SecureRandom RNG = new SecureRandom();

    /** A source that hands out a fresh {@link KeyMaterial} per call, as {@link KeySource} requires. */
    private static final class FixedSource implements KeySource {
        private final int version;
        private final byte[] key;
        private final AtomicInteger loads = new AtomicInteger();

        FixedSource(int version) {
            this.version = version;
            this.key = new byte[KeyMaterial.KEY_BYTES];
            RNG.nextBytes(this.key);
        }

        @Override
        public KeyMaterial load() throws CryptoException {
            loads.incrementAndGet();
            return KeyMaterial.fromBytes(key, version);
        }

        @Override
        public String describe() {
            return "test:v" + version;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof FixedSource f && f.version == version && Arrays.equals(f.key, key);
        }

        @Override
        public int hashCode() {
            return version * 31 + Arrays.hashCode(key);
        }
    }

    /** A source whose key version deliberately disagrees with the one it is registered under. */
    private static final class LyingSource implements KeySource {
        private final int claims;

        LyingSource(int claims) {
            this.claims = claims;
        }

        @Override
        public KeyMaterial load() throws CryptoException {
            return new SymmetricCrypto().generateKey(claims);
        }

        @Override
        public String describe() {
            return "test:liarsource";
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof LyingSource l && l.claims == claims;
        }

        @Override
        public int hashCode() {
            return claims;
        }
    }

    @Test
    void aRecordIsOpenedOnlyByTheVersionItNames() throws Exception {
        FixedSource v1 = new FixedSource(1);
        try (KeyVault vault = KeyVault.of(v1)) {
            EncryptedBlob blob = vault.encryptString("balance:100", "acct:7");
            assertEquals(1, blob.keyVersion());
            assertEquals("balance:100", vault.decryptStringEncoded(blob.toBase64Url(), "acct:7"));
            /* The same record under the wrong context is refused, and the refusal is generic. */
            CryptoException e = assertThrows(CryptoException.class,
                    () -> vault.decryptStringEncoded(blob.toBase64Url(), "acct:8"));
            assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, e.code());
        }
    }

    @Test
    void rotationIsStrictlyIncreasingAndStopsReadsThroughTheOldKey() throws Exception {
        List<Integer> issued = new ArrayList<>();
        AtomicInteger created = new AtomicInteger();
        KeyVault.KeySourceFactory factory = version -> {
            created.incrementAndGet();
            issued.add(version);
            return new FixedSource(version);
        };
        try (KeyVault vault = new KeyVault(factory, 1)) {
            EncryptedBlob underOne = vault.encryptString("old record", null);
            assertEquals(1, vault.activeVersion());

            int two = vault.rotate();
            assertEquals(2, two);
            assertEquals(2, vault.activeVersion());
            /* New writes use the new key. */
            EncryptedBlob underTwo = vault.encryptString("new record", null);
            assertEquals(2, underTwo.keyVersion());

            /*
             * The old key is still registered but not readable: that is the deliberate default after a
             * rotation performed because a key may have leaked. Reading history must be a decision.
             */
            assertTrue(vault.isDisabled(1), "the superseded version should be disabled by rotate()");
            CryptoException refused = assertThrows(CryptoException.class, () -> vault.decrypt(underOne, null));
            assertEquals(CryptoException.CryptoFailureCode.KEY_UNAVAILABLE, refused.code());
            /* One generic message for every key-side refusal: "disabled" and "missing" must not be
               distinguishable by the caller's client, and the version number stays in the log detail. */
            assertEquals("The data could not be decrypted", refused.getMessage());
            assertTrue(refused.getTechnicalDetail().contains("1"),
                    "the log detail should name the version for the operator: " + refused.getTechnicalDetail());

            /* Once the operator opts in, old records read again - unchanged, and still authenticated. */
            vault.enable(1);
            assertFalse(vault.isDisabled(1));
            assertEquals("old record", vault.decryptToString(underOne, null));
            assertThrows(CryptoException.class, () -> vault.decryptToString(underOne, "someone elses context"));

            /* Monotonic: versions never repeat or go backwards, even across many rotations. */
            int previous = two;
            for (int i = 0; i < 5; i++) {
                int next = vault.rotate();
                assertTrue(next > previous, "version went backwards: " + next + " after " + previous);
                previous = next;
            }
            assertEquals(List.of(1, 2, 3, 4, 5, 6, 7), List.copyOf(issued).subList(0, 7), issued.toString());
            assertEquals(7, vault.activeVersion());
        }
    }

    @Test
    void theVaultRefusesToTrackUnboundedVersions() throws Exception {
        /* A caller that rotates in a loop must hit a wall, not grow the vault forever. */
        AtomicInteger created = new AtomicInteger();
        KeyVault.KeySourceFactory factory = version -> {
            created.incrementAndGet();
            return new FixedSource(version);
        };
        KeyVault vault = new KeyVault(factory, 1);
        int rotations = 0;
        CryptoException stopped = null;
        try {
            for (int i = 0; i < KeyVault.MAX_VERSIONS + 20; i++) {
                vault.rotate();
                rotations++;
            }
        } catch (CryptoException e) {
            stopped = e;
        }
        vault.close();
        assertNotNull(stopped, "rotating past MAX_VERSIONS was never refused");
        assertEquals(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, stopped.code());
        assertEquals(KeyVault.MAX_VERSIONS, rotations,
                "expected to stop exactly at the tracked-version cap: " + rotations);
        assertEquals(KeyVault.MAX_VERSIONS, created.get(),
                "more key sources were created than the cap allows: " + created.get());
        assertTrue(stopped.getMessage() != null && !stopped.getMessage().isBlank());
    }

    @Test
    void aSourceThatClaimsTheWrongVersionIsRejected() throws Exception {
        /*
         * Registering a source under a version it does not itself use would let a record claim a version
         * it was not written under, which is the retargeting attack with help from configuration.
         */
        try (KeyVault vault = new KeyVault(v -> new FixedSource(v), 5)) {
            CryptoException e = assertThrows(CryptoException.class,
                    () -> vault.addReadableKey(3, new LyingSource(4)));
            assertEquals(CryptoException.CryptoFailureCode.INVALID_KEY, e.code());
            /* And the honest case works, so the refusal above is about the mismatch and not the API. */
            vault.addReadableKey(3, new FixedSource(3));
            assertTrue(vault.knownVersions().contains(3), vault.knownVersions().toString());
        }
    }

    @Test
    void aFactoryThatMislabelsItsKeyIsRefusedOnBothSides() throws Exception {
        /*
         * addReadableKey probes a source a caller registers, but sources the vault creates itself come
         * from the factory and are only checked at use time. A mislabelled key must be reported as the
         * configuration fault it is rather than surfacing as an authentication failure - and, critically,
         * a record must never be decrypted with a key that is not the version the record names.
         */
        SymmetricCrypto engine = new SymmetricCrypto();
        try (KeyVault vault = new KeyVault(v -> new LyingSource(v + 1), 4)) {
            CryptoException writing = assertThrows(CryptoException.class,
                    () -> vault.encryptString("secret", null));
            assertEquals(CryptoException.CryptoFailureCode.INVALID_KEY, writing.code(),
                    "encrypt silently used a key that was not the active version");

            /* A record that exists anyway must not open with the mislabelled key either. */
            try (KeyMaterial real = engine.generateKey(4)) {
                EncryptedBlob blob = engine.encrypt(real, "payload".getBytes(StandardCharsets.UTF_8), null);
                CryptoException reading = assertThrows(CryptoException.class, () -> vault.decrypt(blob, null));
                assertEquals(CryptoException.CryptoFailureCode.INVALID_KEY, reading.code(),
                        "decrypt used a key that was not the version the record names");
                /* The refusal must be the mismatch, never an authentication failure or a plaintext. */
                assertFalse(reading.getTechnicalDetail().toLowerCase().contains("tag"),
                        reading.getTechnicalDetail());
            }
        }
    }

    @Test
    void theActiveVersionCannotBeDisabledAndUnknownVersionsCannotBeEnabled() throws Exception {
        try (KeyVault vault = new KeyVault(v -> new FixedSource(v), 1)) {
            vault.rotate();
            CryptoException refuseActive = assertThrows(CryptoException.class, () -> vault.disable(2));
            assertEquals(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, refuseActive.code());
            /* Disabling a version that was never registered is a typo, not a control: say so. */
            CryptoException unknown = assertThrows(CryptoException.class, () -> vault.enable(9));
            assertEquals(CryptoException.CryptoFailureCode.KEY_UNAVAILABLE, unknown.code());
            CryptoException range = assertThrows(CryptoException.class, () -> vault.addReadableKey(0, new FixedSource(0)));
            assertNotNull(range.getMessage());
        }
    }

    @Test
    void closingTheVaultMakesItFailClosedRatherThanRecreateAKey() throws Exception {
        /*
         * close() promises the vault is unusable afterwards. A vault that simply re-runs the factory
         * would hand the caller a fresh key while appearing to have been shut down, so the teardown has
         * to be sticky.
         */
        AtomicInteger created = new AtomicInteger();
        KeyVault vault = new KeyVault(v -> {
            created.incrementAndGet();
            return new FixedSource(v);
        }, 1);
        EncryptedBlob blob = vault.encryptString("still secret", null);
        int before = created.get();
        vault.close();

        CryptoException encrypt = assertThrows(CryptoException.class, () -> vault.encryptString("nope", null));
        CryptoException decrypt = assertThrows(CryptoException.class, () -> vault.decrypt(blob, null));
        CryptoException rotate = assertThrows(CryptoException.class, vault::rotate);
        for (CryptoException e : List.of(encrypt, decrypt, rotate)) {
            assertEquals(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, e.code(), e.code().name());
            /* Generic to the caller, explicit in the log: a client must not learn the vault is closed. */
            assertEquals("The data could not be decrypted", e.getMessage());
            assertTrue(e.getTechnicalDetail().toLowerCase(java.util.Locale.ROOT).contains("clos"),
                    "the log detail should say the vault is closed: " + e.getTechnicalDetail());
        }
        assertEquals(before, created.get(),
                "the factory was called again after close(), so the key was resurrected");
    }

    @Test
    void concurrentUseRoutesEveryRecordToItsOwnVersion() throws Exception {
        /*
         * Key sources are created lazily and cached. Check-then-act on that cache must be atomic: a
         * torn read would mean two different key objects for one version, i.e. records that cannot be
         * read back by the process that wrote them.
         */
        AtomicInteger created = new AtomicInteger();
        ConcurrentLinkedQueue<Integer> createdVersions = new ConcurrentLinkedQueue<>();
        KeyVault.KeySourceFactory factory = version -> {
            created.incrementAndGet();
            createdVersions.add(version);
            /* Widen the window any race would need, so a non-atomic cache shows up. */
            try {
                Thread.sleep(2);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
            return new FixedSource(version);
        };
        int threads = 8;
        int ops = 25;
        try (KeyVault vault = new KeyVault(factory, 1)) {
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch go = new CountDownLatch(1);
            List<Future<String>> futures = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int id = t;
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    go.await();
                    int roundTrips = 0;
                    int unavailable = 0;
                    for (int i = 0; i < ops; i++) {
                        String plain = "t" + id + "-" + i;
                        /*
                         * Either half of the round trip can be refused when another thread rotates in
                         * between: rotate() disables the version it supersedes, and a write that read
                         * that version moments earlier must fail rather than encrypt under a key that has
                         * just been retired. Refusing is the right direction. What must never happen is
                         * an authentication failure on a record this vault wrote seconds ago - that would
                         * mean the source cache handed two callers different keys for one version - or a
                         * record that reads back as someone else's plaintext.
                         */
                        try {
                            EncryptedBlob rec = vault.encryptString(plain, "ctx:" + id);
                            String back = vault.decryptToString(rec, "ctx:" + id);
                            assertEquals(plain, back, "record came back as another thread's text");
                            roundTrips++;
                        } catch (CryptoException e) {
                            assertEquals(CryptoException.CryptoFailureCode.KEY_UNAVAILABLE, e.code(),
                                    "concurrent rotation produced " + e.code() + " instead of a refusal");
                            unavailable++;
                        }
                        if (i % 5 == 0) {
                            vault.rotate();
                        }
                    }
                    /* Each thread does its own count of both outcomes: no operation may be lost. */
                    assertEquals(ops, roundTrips + unavailable);
                    assertTrue(roundTrips > 0, "a vault under rotation never completed one round trip");
                    return roundTrips + " " + unavailable;
                }));
            }
            ready.await(10, TimeUnit.SECONDS);
            go.countDown();
            for (Future<String> f : futures) {
                String[] counts = f.get(60, TimeUnit.SECONDS).split(" ");
                assertEquals(ops, Integer.parseInt(counts[0]) + Integer.parseInt(counts[1]),
                        "a thread lost or duplicated an operation");
            }
            pool.shutdownNow();

            /* Exactly one source per tracked version: no duplicate key material in the cache. */
            List<Integer> sorted = new ArrayList<>(createdVersions);
            java.util.Collections.sort(sorted);
            for (int i = 1; i < sorted.size(); i++) {
                assertFalse(sorted.get(i).equals(sorted.get(i - 1)),
                        "version " + sorted.get(i) + " was created twice: " + sorted);
            }
            assertEquals(sorted.size(), created.get());
            assertEquals(vault.knownVersions().size(), sorted.size(),
                    "cached versions " + vault.knownVersions() + " vs created " + sorted);
        }
    }

    /**
     * The estate description is what an operator reads while working out which key encrypted something,
     * so its three numbers have to describe one instant. Read outside {@code rotationLock} they can
     * straddle a {@code rotate()} and render a vault that never existed - {@code active=3} beside
     * {@code versions=[1,2]} - which is exactly the misdirection an incident cannot afford.
     *
     * <p>No behavioural test can observe this: catching a torn read needs a render to land inside a
     * rotation's window, so a test that bets on the timing either flakes or passes the broken
     * implementation, and a test that fails for want of a tear is the unfalsifiable kind. The invariant
     * is therefore checked where it lives - in the source - and the mutant that deletes the lock is what
     * proves the check is capable of failing.
     */
    @Test
    void theEstateDescriptionSnapshotsEveryNumberUnderTheRotationLock() throws Exception {
        String body = Fixtures.methodBody("KeyVault.java", "String toString()", -1);
        assertTrue(body.contains("KeyVault[active="),
                "the body read is not the vault's own description, so the check below would guard the "
                        + "wrong code: " + body);
        int lock = body.indexOf("synchronized (rotationLock)");
        assertTrue(lock >= 0, "the estate description no longer takes the rotation lock: " + body);
        for (String read : List.of("highestIssued", "knownVersions()", "disabled.size()")) {
            int at = body.indexOf(read);
            assertTrue(at >= 0, "the description stopped reporting " + read + ", so there is nothing to "
                    + "keep consistent: " + body);
            assertTrue(at > lock, read + " is read before the lock is taken, so the three numbers can "
                    + "describe different instants: " + body);
        }
    }

    @Test
    void theVaultToStringNamesNoSecret() throws Exception {
        FixedSource v1 = new FixedSource(1);
        String encoded;
        try (KeyVault vault = KeyVault.of(v1)) {
            EncryptedBlob blob = vault.encryptString("card number 4111111111111111", "acct:7");
            encoded = blob.toBase64Url();
            String rendered = vault + " " + blob + " " + v1.describe() + " " + v1;
            for (String secret : List.of("4111111111111111", "card number", encoded,
                    java.util.Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(v1.key))) {
                assertFalse(rendered.contains(secret), "rendered as " + rendered + " hid nothing: " + secret);
            }
        }
    }

    @Test
    void aRecordNamingAVersionThatWasNeverIssuedIsAnsweredLikeATamperedRecord() throws Exception {
        AtomicInteger created = new AtomicInteger();
        List<Integer> askedFor = Collections.synchronizedList(new ArrayList<>());
        KeyVault.KeySourceFactory factory = version -> {
            created.incrementAndGet();
            askedFor.add(version);
            return new FixedSource(version);
        };
        try (KeyVault vault = new KeyVault(factory, 2)) {
            EncryptedBlob real = vault.encryptString("balance:100", null);
            String genuine = canonical(real.toBytes());
            String forgedVersion = canonical(restamp(real.toBytes(), 200));
            String tamperedBody = canonical(flipLastByte(real.toBytes()));

            /*
             * Non-vacuity first: a table lazily filled by the encrypt above must already hold the version
             * the record names, or "it did not grow" would be comparing zero with zero.
             */
            int cachedBefore = vault.knownVersions().size();
            assertEquals(1, cachedBefore, "the fixture cached " + cachedBefore + " versions: "
                    + vault.knownVersions());

            int creationsBefore = created.get();
            CryptoException versionForged = assertThrows(CryptoException.class,
                    () -> vault.decryptStringEncoded("v1." + forgedVersion, null));
            CryptoException bodyForged = assertThrows(CryptoException.class,
                    () -> vault.decryptStringEncoded("v1." + tamperedBody, null));

            /*
             * One AES-GCM tag check settles both forgeries, so both the code and the log detail must
             * match. A distinct refusal here would tell the caller - and anyone they show it to - which
             * key versions this vault has never heard of, and would cost less than a real tag check.
             */
            assertEquals(versionForged.code(), bodyForged.code(),
                    "codes differ: " + versionForged.code() + " vs " + bodyForged.code());
            assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, versionForged.code());
            assertEquals(bodyForged.getTechnicalDetail(), versionForged.getTechnicalDetail(),
                    "details differ, so one of the two routes leaks which byte was forged");
            assertFalse(versionForged.getTechnicalDetail().contains("200"),
                    "the detail names the probed version, which is the vault's estate: "
                            + versionForged.getTechnicalDetail());
            assertTrue(genuine.length() > 0);

            /* Nothing was provisioned for the probed version: no factory call, no cache entry, no KDF. */
            assertEquals(creationsBefore, created.get(),
                    "the factory ran for a version that cannot exist: " + askedFor);
            assertFalse(askedFor.contains(200), "the factory was asked for version 200: " + askedFor);
            assertEquals(cachedBefore, vault.knownVersions().size(),
                    "the cache grew for a forged record: " + vault.knownVersions());

            /* A burst of distinct impossible versions must not fill the table either. */
            for (int v : new int[] {3, 4, 17, 100, 201, 255}) {
                assertThrows(CryptoException.class,
                        () -> vault.decryptStringEncoded("v1." + canonical(restamp(real.toBytes(), v)), null));
            }
            assertEquals(cachedBefore, vault.knownVersions().size(),
                    "a burst of forged versions grew the table: " + vault.knownVersions());
            assertEquals(creationsBefore, created.get(),
                    "the factory ran during the burst: " + askedFor);
        }
    }

    @Test
    void theStandInForKeyItWillNotProvisionIsNotAPredictableOne() throws Exception {
        /*
         * The refusal to provision an impossible version answers with a random key so that the caller
         * sees an ordinary tag failure. That is only safe while the stand-in is unpredictable: if it were
         * a fixed key - all zeroes, or anything derived from the version - an attacker could encrypt
         * under it for a version this vault has no key for, and this vault would accept his record as
         * authenticated. That is a forgery path, so it is tested directly against keys an attacker would
         * plausibly guess, rather than left to "it's random so don't worry".
         */
        AtomicInteger created = new AtomicInteger();
        try (KeyVault vault = new KeyVault(v -> {
            created.incrementAndGet();
            return new FixedSource(v);
        }, 1)) {
            byte[][] guessed = {new byte[KeyMaterial.KEY_BYTES], ones(), seq(), ascii("all-zero-stand-in-key-aaaaaaaaaaa")};
            for (byte[] guess : guessed) {
                try (KeyMaterial attacker = KeyMaterial.fromBytes(guess, 200)) {
                    EncryptedBlob forged = new SymmetricCrypto().encrypt(attacker, "not authenticated".getBytes(
                            StandardCharsets.UTF_8), null);
                    assertThrows(CryptoException.class,
                            () -> vault.decryptStringEncoded("v1." + canonical(forged.toBytes()), null),
                            "the vault accepted a record written under a guessed stand-in key");
                }
            }
            assertEquals(0, created.get(), "a real source was built while probing stand-in behaviour");
        }
    }

    private static byte[] ones() {
        byte[] b = new byte[KeyMaterial.KEY_BYTES];
        Arrays.fill(b, (byte) 1);
        return b;
    }

    private static byte[] seq() {
        byte[] b = new byte[KeyMaterial.KEY_BYTES];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) i;
        }
        return b;
    }

    private static byte[] ascii(String s) {
        byte[] out = new byte[KeyMaterial.KEY_BYTES];
        byte[] src = s.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(src, 0, out, 0, Math.min(src.length, out.length));
        return out;
    }

    @Test
    void neitherInsertionPathCanGrowTheVersionTablePastTheCeiling() throws Exception {
        /*
         * A high initial version leaves the table empty, so rotate() - which needs a previous version to
         * displace - is not the only way in. addReadableKey is, and it is the path a deployment uses to
         * import history, so the ceiling has to hold there too or MAX_VERSIONS is not a property of the
         * object, only of one method.
         */
        AtomicInteger created = new AtomicInteger();
        KeyVault.KeySourceFactory factory = version -> {
            created.incrementAndGet();
            return new FixedSource(version);
        };
        try (KeyVault vault = new KeyVault(factory, 255)) {
            int filled = 0;
            CryptoException refused = null;
            for (int v = 1; v < 255 && refused == null; v++) {
                try {
                    vault.addReadableKey(v, new FixedSource(v));
                    filled++;
                } catch (CryptoException e) {
                    refused = e;
                }
            }
            assertNotNull(refused, "addReadableKey filled the table past its ceiling");
            assertEquals(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, refused.code());
            assertEquals("The data could not be decrypted", refused.getMessage());
            assertEquals(filled, vault.knownVersions().size(), "the table holds more than it counted");
            assertTrue(filled <= 64, "ceiling is not enforced: " + filled + " entries");
            /* The refusal left the vault usable, not half-updated. */
            assertEquals(255, vault.activeVersion());
            assertTrue(created.get() <= filled + 1,
                    "sources were built after the table was full: " + created.get() + " for " + filled);

            /*
             * And the read path has to respect the same ceiling from the other side. A record naming a
             * version inside the range but absent from a full table is the case the size bound exists
             * for: the version bound alone would let it through, because it is a perfectly plausible
             * version number - it just has no key and can never get one.
             */
            int missing = 0;
            for (int v = 1; v < 255; v++) {
                if (!vault.knownVersions().contains(v)) {
                    missing = v;
                    break;
                }
            }
            assertTrue(missing > 0, "the fixture registered every version, so nothing was absent");
            assertTrue(missing < 255,
                    "the absent version is above the issued ceiling, so this would exercise the wrong bound");
            int built = created.get();
            int cached = vault.knownVersions().size();
            /* The record comes from a standalone key: the vault itself can no longer issue keys. */
            EncryptedBlob real;
            try (KeyMaterial outside = new SymmetricCrypto().generateKey(200)) {
                real = new SymmetricCrypto().encrypt(outside, "balance:100".getBytes(StandardCharsets.UTF_8), null);
            }
            final int probed = missing;
            CryptoException e = assertThrows(CryptoException.class,
                    () -> vault.decryptStringEncoded("v1." + canonical(restamp(real.toBytes(), probed)), null));
            assertEquals(CryptoException.CryptoFailureCode.AUTHENTICATION_FAILED, e.code(),
                    "a full vault reported the missing version differently: " + e.getTechnicalDetail());
            assertEquals(built, created.get(), "the factory filled a table that was already full");
            assertEquals(cached, vault.knownVersions().size(),
                    "the table grew past its ceiling through the read path: " + vault.knownVersions());
        }
    }

    @Test
    void aSourceStillCachedUnderAnotherVersionIsNotErasedWhenItsSlotIsReplaced() throws Exception {
        /*
         * KeyVault.of builds its vault with the factory `v -> source`, so rotate() caches that one object
         * under version 2 as well as version 1. release() destroys a keystore or passphrase source
         * outright, so "the slot was overwritten, therefore destroy what was in it" would erase an object
         * the cache still holds and still hands to a later decrypt. Displacement is not the same fact as
         * "nobody references this any more", and only the second one licenses destroying it.
         */
        Path dir = Fixtures.dir("shared-source");
        Path store = dir.resolve("keys.p12");
        char[] password = Fixtures.machinePassword();
        KeystoreKeySource.create(store, "data-key", 1, password, password.clone());
        KeystoreKeySource shared =
                new KeystoreKeySource(store, "data-key", 1, password.clone(), password.clone());
        try (KeyVault vault = KeyVault.of(shared)) {
            EncryptedBlob underOne = vault.encryptString("history", null);
            assertEquals(1, underOne.keyVersion());
            assertFalse(shared.isDestroyed(), "the source should start alive");

            vault.rotate();
            assertEquals(2, vault.activeVersion());
            /* The construction the guard exists for: the same object occupies two slots. */
            assertEquals(List.of(1, 2), vault.knownVersions());

            vault.addReadableKey(1, new FixedSource(1));

            assertFalse(shared.isDestroyed(),
                    "replacing version 1 destroyed a source the cache still holds under version 2");
            /* Not merely un-erased: the source still yields the key that opened the record above. */
            try (KeyMaterial reloaded = shared.load()) {
                assertEquals(1, reloaded.version());
                assertArrayEquals("history".getBytes(StandardCharsets.UTF_8),
                        new SymmetricCrypto().decrypt(reloaded, underOne, null),
                        "the surviving source no longer yields the key it was created with");
            }
        }
    }

    @Test
    void aVersionThatCannotExistIsRefusedRatherThanRememberedAsDisabled() throws Exception {
        FixedSource v1 = new FixedSource(1);
        try (KeyVault vault = KeyVault.of(v1)) {
            vault.rotate();
            for (int impossible : new int[] {0, -1, 256, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
                CryptoException e = assertThrows(CryptoException.class, () -> vault.disable(impossible),
                        "disable(" + impossible + ") was accepted");
                assertEquals(CryptoException.CryptoFailureCode.INVALID_INPUT, e.code());
                assertFalse(vault.isDisabled(impossible),
                        "an impossible version is now remembered as disabled: " + impossible);
            }
            /* Nothing to clean up, so a real version still behaves normally afterwards. */
            vault.disable(1);
            assertTrue(vault.isDisabled(1));
            vault.enable(1);
            assertFalse(vault.isDisabled(1));
        }
    }

    /** Rewrites the key-version byte of a raw record. */
    private static byte[] restamp(byte[] packed, int version) {
        byte[] copy = packed.clone();
        copy[2] = (byte) version;
        return copy;
    }

    private static byte[] flipLastByte(byte[] packed) {
        byte[] copy = packed.clone();
        copy[copy.length - 1] ^= 1;
        return copy;
    }

    private static String canonical(byte[] packed) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(packed);
    }

    private static void assertNotNull(Object o) {
        org.junit.jupiter.api.Assertions.assertTrue(o != null, "expected non-null");
    }

    private static void assertNotNull(Object o, String msg) {
        org.junit.jupiter.api.Assertions.assertTrue(o != null, msg);
    }
}
