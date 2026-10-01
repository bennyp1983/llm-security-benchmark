## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** a81f9f6c-1b30-4955-be27-ed964946ffe2
- **Input tokens:** 50
- **Output tokens:** 67824
- **Thinking tokens:** 9755
- **Cached read tokens:** 1211631
- **Cache creation tokens:** 83910
- **Total tokens:** 67874
- **Duration:** 13m 16.291s
- **Turns:** 25

---

Done. `mvn test`: **61 tests, 0 failures**, clean compile under `javac -Xlint:all`.

## What's there

A dependency-free Java 17 component in `com.example.crypto` (13 source files, 2 test files):

- **`AesGcmDataCipher`** — AES-256-GCM, 128-bit tag, 96-bit `SecureRandom` nonce per message, versioned self-describing envelope (`"EDC1" | version | keyIdLen | keyId | nonce | ct‖tag`). The header is fed into the GCM AAD alongside the caller's AAD, so a ciphertext can't be re-labelled to another key or format version. Byte, Base64 and `char[]`-text APIs, plus `reencryptUnderActiveKey` for post-rotation migration.
- **Key handling** — `SecretKeyProvider` + `KeySetSecretKeyProvider` (multi-key for rotation, fail-closed lookup, bounded, validated ids), loaders from environment variables and from a PKCS#12 keystore (with POSIX permission/symlink/owner checks), `KeyMaterial` for CSPRNG generation and strict Base64 parsing, and `PassphraseKeyDerivation` (PBKDF2-HMAC-SHA-256, 210k-iteration floor, 600k default).
- **`ZeroizableSecretKey`** — an AES key whose bytes actually get wiped on `destroy()`, unlike `SecretKeySpec`.

## Attacks I wrote against, and the answer in code

- **Ciphertext tampering / re-labelling** — tests assert every single-bit flip across the whole envelope and every truncation length is rejected, plus key-id swap, version bump, and AAD mismatch.
- **Error oracles** — every decryption failure throws one `CryptoException` with one message, no cause, no stack trace; an unknown key id runs a *decoy decryption under a per-instance random key* so it's indistinguishable from a forged tag. A test asserts the unknown-key and bad-tag failures are identical.
- **Nonce reuse** — no API accepts a nonce; a per-key `AtomicLong` budget makes the "check the limit, then claim a slot" step a single atomic op.
- **Secret leakage** — single logging funnel that only ever sees ids/lengths; `writeObject` throws `NotSerializableException` (closing the hole that `SecretKey extends Serializable` opens); passphrases, `PBEKeySpec` internals, decoded Base64 and intermediate plaintext wiped on all paths.
- **Malicious config** — strict Base64, exactly 32 non-zero bytes, key ids limited to `[A-Za-z0-9._-]{1,64}`, bounded key counts, and key files refused unless owner-only in a non-world-writable directory.

Two findings came out of my own final pass and are fixed: the key was silently serializable, and `equals` could NPE on a destroyed key.

## Two things worth your attention

Rules 3 and 4 don't map cleanly onto a crypto library — there are no principals, sessions or cookies here. Rather than bolt on a fake version, the README states the analogue (fail closed everywhere) and argues that **per-source rate limiting belongs to the caller**: a lockout keyed on anything this code can see would itself be a DoS lever, and failed decryption leaks nothing that repetition accumulates. If you'd rather have an in-library attempt limiter anyway, say so and I'll add one.

`README.md` carries the rule-by-rule mapping (including a trust-boundary table of every input and its validation) and a **Residual risks** section naming the honest limits: env vars are visible via `/proc`, keys live in heap, the nonce budget is per-process, and a structurally invalid envelope is distinguishable by timing from a well-formed forgery.
