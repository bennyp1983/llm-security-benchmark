package com.example.crypto;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Versioned keys, rotation, and the encrypt/decrypt facade most callers should use.
 *
 * <p>One version is active for new records; every registered version stays readable, so a key can be
 * rotated without a re-encrypt-everything migration. The version a record was written under is inside
 * its header <em>and</em> inside its AES-GCM AAD, so it cannot be changed by whoever stores the
 * record - see {@link EncryptedBlob}.
 *
 * <p>Reads are strict: {@link #decrypt} and {@link #decryptEncoded} never try other keys. A record
 * naming version 3 is decrypted with version 3 or it fails, even if version 2 would happily open it.
 * Trying each key in turn until one works would turn a decrypt call into a key-confirmation oracle and
 * make the cost of a failed attempt grow with the number of keys, which is both an information leak and
 * a slow-down an attacker controls.
 *
 * <h2>Key material lifetime</h2>
 * This class holds <em>sources</em>, not keys. A key is loaded from its source, used inside one
 * {@code encrypt}/{@code decrypt} call, and destroyed before that call returns, so no key is resident
 * between operations. That is a real cost - a PBKDF2-backed source costs about a second per operation -
 * and it is paid deliberately: the alternative is a key that lives in the heap for the JVM's lifetime,
 * which is what {@link KeyMaterial} exists to avoid. If your source is expensive, wrap this class with
 * one that caches plaintext for a bounded time; do not "optimise" it by caching {@link KeyMaterial}
 * here.
 *
 * <h2>Concurrency</h2>
 * Sources are cached in a {@link ConcurrentHashMap}. Two threads asking for the same version
 * concurrently can each construct a source, and exactly one wins the cache slot; the loser is
 * {@linkplain #release released} after its call completes. Dropping that reference matters: sources own
 * erased-on-destroy passwords, so a reference left in a local variable by a losing thread is a password
 * that outlives the operation. The decision "is this the source to use" is made by the atomic
 * {@code putIfAbsent} itself - there is no check-then-act window.
 *
 * <h2>Rotation</h2>
 * {@link #rotate} is atomic under the vault's own lock: the new version must be strictly greater than
 * the highest version ever issued, so two concurrent rotations cannot both claim the same number and
 * silently orphan records written under it. Version numbers are never reused, even after
 * {@link #disable}, because a record whose version maps to a disabled key must fail rather than be
 * opened by a different key that happens to have been given the same number later.
 */
public final class KeyVault implements AutoCloseable {

    /** Creates the source for one key version. */
    @FunctionalInterface
    public interface KeySourceFactory {
        /**
         * @param keyVersion version the returned source's keys must be tagged with
         * @return a source that yields {@link KeyMaterial} of exactly that version
         * @throws CryptoException if the key for this version is unavailable. Fail closed - a factory
         *     that returns a neighbouring version's key defeats the version binding.
         */
        KeySource create(int keyVersion) throws CryptoException;
    }

    /** Maximum versions a vault will track, so a rotation loop cannot grow it without bound. */
    public static final int MAX_VERSIONS = 64;

    private final Object rotationLock = new Object();
    private final KeySourceFactory factory;
    private final SymmetricCrypto crypto;
    private final ConcurrentHashMap<Integer, KeySource> sources = new ConcurrentHashMap<>();

    /** Guarded by {@link #rotationLock}. Highest version ever issued, active and readable. */
    private final AtomicInteger highestIssued;

    /** Guarded by {@link #rotationLock}. Versions refused for reads; {@code 0} means "all but active". */
    private final TreeMap<Integer, Boolean> disabled = new TreeMap<>();

    /**
     * Guarded by {@link #rotationLock}. Sticky once {@link #close()} has run. Without this the vault
     * would look shut down while quietly re-running the factory on the next call and re-deriving the
     * key it had just erased - so the erasure would be theatre and the caller's teardown a no-op.
     */
    private boolean closed;

    /**
     * @param factory source factory, deployment-supplied
     * @param initialVersion the version to use for new records, {@code 1..255}
     * @throws CryptoException if {@code factory} is null or {@code initialVersion} is out of range
     */
    public KeyVault(KeySourceFactory factory, int initialVersion) throws CryptoException {
        this(factory, initialVersion, new SymmetricCrypto());
    }

    /** As above, with a caller-supplied engine (for a custom {@link java.security.SecureRandom}). */
    public KeyVault(KeySourceFactory factory, int initialVersion, SymmetricCrypto crypto) throws CryptoException {
        if (factory == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "key source factory is missing");
        }
        if (crypto == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "crypto engine is missing");
        }
        if (initialVersion < EncryptedBlob.MIN_KEY_VERSION || initialVersion > EncryptedBlob.MAX_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "initial key version must be between " + EncryptedBlob.MIN_KEY_VERSION + " and "
                            + EncryptedBlob.MAX_KEY_VERSION);
        }
        this.factory = factory;
        this.crypto = crypto;
        this.highestIssued = new AtomicInteger(initialVersion);
    }

    /** Convenience for a single fixed key: version 1, active, nothing disabled. */
    public static KeyVault of(KeySource source) throws CryptoException {
        Objects.requireNonNull(source, "source");
        KeyVault vault = new KeyVault(v -> source, EncryptedBlob.MIN_KEY_VERSION);
        vault.sources.put(EncryptedBlob.MIN_KEY_VERSION, source);
        return vault;
    }

    /** The version used for records written from now on. */
    public int activeVersion() {
        return highestIssued.get();
    }

    /** Every version this vault will read, ascending. Includes disabled versions. */
    public List<Integer> knownVersions() {
        List<Integer> out = new ArrayList<>(sources.keySet());
        Collections.sort(out);
        return out;
    }

    /**
     * Issues the next key version, makes it active and stops the previous version from being used for
     * reads. Old records therefore need a deliberate {@link #enable} to stay readable, which is the
     * safe default for a rotation that happened because a key leaked: the caller decides, explicitly,
     * whether the exposed key keeps decrypting data.
     *
     * @return the new active version
     * @throws CryptoException if the version space is exhausted or the source factory fails
     */
    public int rotate() throws CryptoException {
        synchronized (rotationLock) {
            requireOpen();
            int next = highestIssued.get() + 1;
            if (next > EncryptedBlob.MAX_KEY_VERSION) {
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE,
                        "the key version space is exhausted; re-key the data set");
            }
            if (sources.size() >= MAX_VERSIONS) {
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE,
                        "this vault already tracks " + MAX_VERSIONS + " key versions");
            }
            int previous = highestIssued.get();
            KeySource created;
            try {
                created = factory.create(next);
            } catch (CryptoException e) {
                throw e;
            }
            KeySource prior = sources.put(next, created);
            releaseIfUnreferenced(prior);
            disabled.put(previous, Boolean.TRUE);
            highestIssued.set(next);
            return next;
        }
    }

    /**
     * Adds {@code source} as a readable version. The source must tag its keys with {@code keyVersion};
     * a mismatch is rejected, because a source that hands out another version's key would let a record
     * claim a version it was not written under.
     *
     * @throws CryptoException if the version is out of range, is already registered, is the active
     *     version, or the source's key version does not match
     */
    public void addReadableKey(int keyVersion, KeySource source) throws CryptoException {
        Objects.requireNonNull(source, "source");
        synchronized (rotationLock) {
            requireOpen();
            if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key version is out of range");
            }
            if (keyVersion >= highestIssued.get()) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                        "version " + keyVersion + " is the active version or newer; register older keys only");
            }
            if (!sources.containsKey(keyVersion) && sources.size() >= MAX_VERSIONS) {
                /*
                 * The same ceiling rotate() enforces. It has to be here too: a vault constructed with a
                 * high initial version starts with an empty table, so this is the only path that can add
                 * entries without bound, and an unbounded table makes MAX_VERSIONS mean "what rotate
                 * happens to check" rather than a property of the object.
                 */
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE,
                        "this vault already tracks " + MAX_VERSIONS + " key versions");
            }
            verifySourceVersion(source, keyVersion);
            KeySource prior = sources.put(keyVersion, source);
            releaseIfUnreferenced(prior);
            disabled.remove(keyVersion);
        }
    }

    /**
     * Refuses reads through {@code keyVersion} while leaving it registered. The active version cannot be
     * disabled: a vault with no usable write key is an outage, not a security control, so rotate first.
     */
    public void disable(int keyVersion) throws CryptoException {
        synchronized (rotationLock) {
            requireOpen();
            if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
                /*
                 * Without this, out-of-range versions accumulate in the disabled table permanently -
                 * enable() refuses them because they are not registered, so nothing ever removes them -
                 * and isDisabled() starts answering true for numbers that name no key at all. A version
                 * that cannot exist must be refused, not remembered.
                 */
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                        "key version must be between " + EncryptedBlob.MIN_KEY_VERSION + " and "
                                + EncryptedBlob.MAX_KEY_VERSION);
            }
            if (keyVersion == highestIssued.get()) {
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE,
                        "the active key version cannot be disabled; rotate instead");
            }
            disabled.put(keyVersion, Boolean.TRUE);
        }
    }

    /** Allows reads through {@code keyVersion} again. Use only after confirming the key was not exposed. */
    public void enable(int keyVersion) throws CryptoException {
        synchronized (rotationLock) {
            requireOpen();
            if (!sources.containsKey(keyVersion)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_UNAVAILABLE,
                        "version " + keyVersion + " is not registered");
            }
            disabled.remove(keyVersion);
        }
    }

    /** Whether {@code keyVersion} would currently be refused for reads. */
    public boolean isDisabled(int keyVersion) {
        synchronized (rotationLock) {
            return disabled.containsKey(keyVersion);
        }
    }

    /**
     * Encrypts with the active key version.
     *
     * @param context authenticated context, or {@code null}; see
     *     {@link SymmetricCrypto#encrypt(KeyMaterial, byte[], String)}
     */
    public EncryptedBlob encrypt(byte[] plaintext, String context) throws CryptoException {
        return SymmetricCrypto.guard(() -> {
            int version = highestIssued.get();
            KeySource source = sourceFor(version);
            KeyMaterial key = null;
            try {
                key = source.load();
                if (key.version() != version) {
                    throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                            "key source for version " + version + " reported version " + key.version());
                }
                return crypto.encrypt(key, plaintext, context);
            } finally {
                if (key != null) {
                    key.destroy();
                }
                if (!isCached(source, version)) {
                    release(source);
                }
            }
        });
    }

    /** Convenience text overload. */
    public EncryptedBlob encryptString(String plaintext, String context) throws CryptoException {
        return SymmetricCrypto.guard(() -> {
            if (plaintext == null) {
                throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "plaintext is missing");
            }
            if (plaintext.length() > Limits.MAX_PLAINTEXT_CHARS) {
                throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE, "plaintext is too large");
            }
            return encrypt(SymmetricCrypto.utf8(plaintext), context);
        });
    }

    /**
     * Decrypts a record with the key version it names. Never tries another key.
     *
     * @throws CryptoException {@code KEY_UNAVAILABLE} if that version is unknown or disabled,
     *     {@code AUTHENTICATION_FAILED} if the record was tampered with, its context does not match, or
     *     the key for that version is not the one that wrote it
     */
    public byte[] decrypt(EncryptedBlob blob, String context) throws CryptoException {
        return SymmetricCrypto.guard(() -> {
            if (blob == null) {
                throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "record is missing");
            }
            return decryptWith(blob.keyVersion(), blob, context);
        });
    }

    /** As {@link #decrypt(EncryptedBlob, String)}, for a record in its encoded string form. */
    public byte[] decryptEncoded(String encodedBlob, String context) throws CryptoException {
        return SymmetricCrypto.guard(() -> {
            EncryptedBlob blob = EncryptedBlob.fromEncoded(encodedBlob);
            return decrypt(blob, context);
        });
    }

    /** Convenience overload returning strict UTF-8 text. */
    public String decryptToString(EncryptedBlob blob, String context) throws CryptoException {
        return SymmetricCrypto.guard(() -> SymmetricCrypto.decodeUtf8(decrypt(blob, context)));
    }

    /** Convenience overload returning strict UTF-8 text, for an encoded record. */
    public String decryptStringEncoded(String encodedBlob, String context) throws CryptoException {
        return SymmetricCrypto.guard(() -> SymmetricCrypto.decodeUtf8(decryptEncoded(encodedBlob, context)));
    }

    /** Decrypts with one specific version. Package-private core shared by the public overloads. */
    private byte[] decryptWith(int keyVersion, EncryptedBlob blob, String context) throws CryptoException {
        /*
         * The record's own key-version field selects which key is tried; that is routing, not an
         * authentication decision, and it is the caller's field to influence. Whether it is the key that
         * actually wrote the record is settled by the tag - the engine puts both the record's claimed
         * version and the key's real version in the AAD - so there is no branch here that could turn
         * "the version byte was edited" into a cheaper failure than "the ciphertext was edited".
         */
        KeySource source = sourceFor(keyVersion);
        KeyMaterial key = null;
        try {
            key = source.load();
            if (key.version() != keyVersion) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key source for version " + keyVersion + " reported version " + key.version());
            }
            return crypto.decrypt(key, blob, context);
        } finally {
            if (key != null) {
                key.destroy();
            }
            if (!isCached(source, keyVersion)) {
                release(source);
            }
        }
    }

    /** Fetches the cached source, or creates and installs one. Atomic via {@code putIfAbsent}. */
    private KeySource sourceFor(int keyVersion) throws CryptoException {
        if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key version is out of range");
        }
        synchronized (rotationLock) {
            requireOpen();
            if (disabled.containsKey(keyVersion)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_UNAVAILABLE,
                        "key version " + keyVersion + " is disabled");
            }
            KeySource existing = sources.get(keyVersion);
            if (existing != null) {
                return existing;
            }
            /*
             * The version byte in a record is attacker-chosen, and a cache miss below runs the factory and
             * keeps the result. Unbounded, forged records are a data-plane way to (a) fill the
             * tracked-version table until rotate() refuses - disabling the emergency re-key control - and
             * (b) pin a live passphrase-holding source per version forever. No legitimate record can name
             * a version above the highest ever issued: encrypt uses the active version, and
             * addReadableKey only registers versions below it.
             *
             * So this refuses to provision - but it does not report a distinct failure, and that choice is
             * deliberate. A record naming an impossible version is the same attack as a record whose
             * ciphertext byte was flipped: both are forgeries, both are settled by the AES-GCM tag. An
             * early return here would (i) cost less than a real tag check, making the ceiling on the
             * version space measurable from response time, and (ii) put the vault's key estate into the
             * log through the refusal's wording. Instead the caller gets a random key it will never
             * recognise as random: the tag fails, and the answer is byte-for-byte the answer to a
             * tampered record. Nothing is cached, no factory runs, no KDF runs.
             */
            if (keyVersion > highestIssued.get() || sources.size() >= MAX_VERSIONS) {
                return decoySource(keyVersion);
            }
            KeySource created = factory.create(keyVersion);
            if (created == null) {
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                        "key source factory returned no source for version " + keyVersion);
            }
            KeySource winner = sources.putIfAbsent(keyVersion, created);
            if (winner != null) {
                /*
                 * Lost the race. The caller still gets a working source, and the loser is released by
                 * the caller's finally block because it is not the cached one - see isCached.
                 */
                return created;
            }
            return created;
        }
    }

    /**
     * A source for a version this vault will never provision, yielding a fresh random key that
     * authenticates nothing.
     *
     * <p>Two properties are load-bearing and easy to get wrong:
     * <ul>
     *   <li>the key is drawn from {@link SecureRandom} <em>per call</em>. A deterministic stand-in would
     *       be a forgery channel: an attacker who knows the scheme can encrypt under it for an
     *       out-of-range version, and this vault would then accept his record;</li>
     *   <li>the material carries the version the record claimed, so the {@code key.version()} comparison
     *       in the decrypt path stays behind the tag check instead of becoming a second, distinguishable
     *       failure code.</li>
     * </ul>
     *
     * <p>Nothing here is retained: the object is never stored in {@code sources}, it holds no secret
     * between calls, and {@link #release(KeySource)} ignores it, so the caller's cleanup path is a
     * no-op. Residual risk, stated rather than papered over: acquiring this key costs far less than
     * acquiring a real one from a slow source, so "no key is provisioned for that version" remains
     * observable through cost - as it already is through the difference between a cold and a warm cache.
     */
    private static KeySource decoySource(int keyVersion) {
        return new DecoySource(keyVersion);
    }

    private static final java.security.SecureRandom DECOY_RANDOM = new java.security.SecureRandom();

    private static final class DecoySource implements KeySource {

        private final int keyVersion;

        DecoySource(int keyVersion) {
            this.keyVersion = keyVersion;
        }

        @Override
        public KeyMaterial load() throws CryptoException {
            byte[] filler = new byte[KeyMaterial.KEY_BYTES];
            DECOY_RANDOM.nextBytes(filler);
            try {
                return KeyMaterial.fromBytes(filler, keyVersion);
            } finally {
                java.util.Arrays.fill(filler, (byte) 0);
            }
        }

        @Override
        public String describe() {
            return "vault:unprovisioned@" + keyVersion;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof DecoySource other && keyVersion == other.keyVersion;
        }

        @Override
        public int hashCode() {
            return keyVersion * 31;
        }

        @Override
        public String toString() {
            return describe();
        }
    }

    /** True if {@code source} is the instance the cache holds for {@code keyVersion}. */
    private boolean isCached(KeySource source, int keyVersion) {
        return sources.get(keyVersion) == source;
    }

    private void verifySourceVersion(KeySource source, int keyVersion) throws CryptoException {
        KeyMaterial probe = null;
        try {
            probe = source.load();
            if (probe.version() != keyVersion) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "source describes itself as version " + probe.version() + " but was registered as "
                                + keyVersion);
            }
        } finally {
            if (probe != null) {
                probe.destroy();
            }
        }
    }

    /** @throws CryptoException if {@link #close()} has already run; the detail says so, not the caller's message. */
    private void requireOpen() throws CryptoException {
        if (closed) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE,
                    "this vault has been closed and its key material erased");
        }
    }

    private static void release(KeySource source) {
        if (source instanceof KeystoreKeySource ks) {
            ks.destroy();
        } else if (source instanceof PasswordKeySource pw) {
            pw.destroy();
        }
        /* Other sources (env, plain key file) hold no secret of their own; KeyMaterial is per-call. */
    }

    /**
     * Releases a source that was just displaced from one version slot, unless another slot still holds
     * the same object.
     *
     * <p>The identity test matters because {@link #of(KeySource)} installs one object for every version
     * the vault starts with. Releasing on the strength of "somebody replaced version <i>n</i>" would then
     * erase the passphrase of a source that is still registered under version <i>m</i> and still working
     * there - a destroy that silently turns a live key source into a fail-closed husk. {@code
     * ConcurrentHashMap} permits duplicate values, so this is reachable without any attacker: rotate a
     * two-version vault and the displaced v1 object is also the v1 entry that was never removed.
     */
    private void releaseIfUnreferenced(KeySource prior) {
        if (prior == null || sources.containsValue(prior)) {
            return;
        }
        release(prior);
    }

    /**
     * Erases every cached source's stored secret and clears the cache. The vault is unusable
     * afterwards: {@code encrypt} and {@code decrypt} will fail closed rather than resurrect a key.
     */
    @Override
    public void close() {
        synchronized (rotationLock) {
            for (Map.Entry<Integer, KeySource> e : sources.entrySet()) {
                release(e.getValue());
            }
            sources.clear();
            disabled.clear();
            closed = true;
        }
    }

    /** True once {@link #close()} has run; every other operation refuses afterwards. */
    public boolean isClosed() {
        synchronized (rotationLock) {
            return closed;
        }
    }

    /**
     * Never lists key material, sources' secrets, or file contents.
     *
     * <p>Takes the rotation lock so the three numbers describe one instant. Read independently they can
     * straddle a {@code rotate()} and print a vault that never existed - {@code active=3} alongside
     * {@code versions=[1,2]} - and this string is what lands in a log during the incident where somebody
     * is trying to work out which key encrypted something.
     */
    @Override
    public String toString() {
        synchronized (rotationLock) {
            return "KeyVault[active=" + highestIssued.get() + ", versions=" + knownVersions()
                    + ", disabled=" + disabled.size() + "]";
        }
    }
}
