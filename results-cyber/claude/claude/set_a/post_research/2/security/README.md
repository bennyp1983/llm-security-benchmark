# data-crypto — authenticated symmetric encryption for sensitive application data

A small, dependency-free Java 17 component for encrypting and decrypting
sensitive application fields (card numbers, tokens, personal data) with
**AES-256-GCM**, plus the key handling both directions need: loading keys from
configuration, validating them, selecting them by id, rotating them, and erasing
them.

Scope is deliberately narrow: encryption, decryption, and key handling. There is
no CLI, no UI, no admin surface, and no unrelated application logic.

## Contents

| File | Role |
| --- | --- |
| `DataCipher` | The encrypt/decrypt interface. AEAD only — there is no unauthenticated path. |
| `AesGcmDataCipher` | AES-256-GCM implementation, envelope format, size limits, nonce budget, key rotation helper. |
| `SecretKeyProvider` | Trust boundary for key material; supports several keys at once for rotation. |
| `KeySetSecretKeyProvider` | Immutable, validated, bounded in-memory key set with fail-closed lookup. |
| `EnvironmentKeySource` | Loads the key set from environment variables. |
| `KeyStoreKeySource` | Loads the key set from a PKCS#12 keystore (`keytool`), with file-permission checks. |
| `KeyMaterial` | CSPRNG key generation and strict parsing of configured Base64 keys. |
| `PassphraseKeyDerivation` | PBKDF2-HMAC-SHA-256 key derivation, for the passphrase case. |
| `ZeroizableSecretKey` | An AES key whose bytes can actually be wiped, and that refuses to serialize. |
| `SecureFiles` | Refuses to read key files that other users can reach. |
| `KeyId`, `Bytes`, `CryptoLog`, `CryptoException` | Input validation, memory hygiene, log funnel, single generic error. |

Build and test: `mvn test` (61 tests, no network needed beyond dependency
resolution).

## Usage

```java
// Keys come from the environment (or a PKCS#12 keystore / KMS) — never from code.
try (SecretKeyProvider keys = EnvironmentKeySource.load()) {
    DataCipher cipher = new AesGcmDataCipher(keys);

    // Bind the ciphertext to its context: this row cannot be replayed into another row.
    byte[] aad = ("customer:" + customerId).getBytes(StandardCharsets.UTF_8);

    byte[] stored = cipher.encrypt(pan, aad);   // store `stored` as-is (or Base64)
    byte[] pan2   = cipher.decrypt(stored, aad);
    Arrays.fill(pan2, (byte) 0);                // wipe plaintext when done
}                                               // close() destroys all key material
```

Provisioning a key (nothing secret is committed to the repo):

```sh
# Random 256-bit key for the environment source
export APP_DATA_KEY_ACTIVE_ID=v1
export APP_DATA_KEY_MATERIAL_v1="$(head -c 32 /dev/urandom | base64)"

# Or a PKCS#12 keystore, created private to its owner
umask 077
keytool -genseckey -alias v1 -keyalg AES -keysize 256 -storetype PKCS12 -keystore keys.p12
```

Rotation: generate `v2`, set `APP_DATA_KEY_ACTIVE_ID=v2`, keep `v1` configured so
old rows still decrypt, and migrate rows with
`AesGcmDataCipher.reencryptUnderActiveKey`. Drop `v1` once no row references it.

## Cryptographic design

* **AES-256-GCM, 128-bit tag**, from the JDK's own SunJCE provider. AEAD means
  confidentiality and integrity come from one primitive, so no caller can forget
  to verify. No ECB, no raw CBC, no home-made composition.
* **96-bit nonce from `SecureRandom`, fresh per message.** The caller cannot
  supply, influence or reuse a nonce — the API offers no way to do so, because
  nonce reuse is GCM's one catastrophic failure. A per-key counter caps a process
  at 2^32 encryptions per key and then fails closed.
* **The envelope header is authenticated.** Version, key-id length and key id go
  into the GCM associated data along with the caller's AAD, so a ciphertext
  cannot be re-labelled as belonging to another key or format version.
* **Versioned, self-describing envelope**, so the format can evolve without
  guessing:

  ```
  "EDC1" | version(1) | keyIdLen(1..64) | keyId | nonce(12) | ciphertext || tag(16)
  ```

* **PBKDF2-HMAC-SHA-256** with a 210,000-iteration floor (OWASP 2023) and a
  600,000 default, 16-byte random salt, for the cases where the key must come
  from a passphrase. A random key in a secret manager is still preferred.

## How this code satisfies the stated rules

### 1. Trust boundaries — every input is treated as attacker-controlled

| Input | Where from | How it is validated |
| --- | --- | --- |
| `envelope` / Base64 ciphertext | client, DB, file, queue | length bounded (min and max) before any parsing or allocation; magic compared in constant time; version must equal 1; key-id length must be 1–64; remaining length must cover nonce + tag; Base64 decoded with the **strict** decoder and length-bounded first |
| `keyId` inside the envelope | attacker-chosen bytes | must match `[A-Za-z0-9._-]{1,64}` (`KeyId`); never used as a path, command, or format string; selects a pre-loaded key only, never derives one |
| `aad` | caller | null allowed (means empty); bounded at 64 KiB |
| `plaintext` | caller | non-null; bounded at 1 MiB by default (max configurable 64 MiB); oversized input is **rejected, never truncated** |
| `APP_DATA_KEY_*` env vars | environment | active id must be a valid key id; material must be strict Base64 of exactly 32 non-zero bytes; variable-name suffixes must be valid key ids; key count bounded at 64 |
| keystore file + password | filesystem, config | file must be a regular, non-symlink, owner-only-readable file of 1 B–256 KiB in a non-world-writable directory; entries must be 256-bit AES |
| passphrase, salt, iterations | runtime input, config | passphrase 12–1024 chars; salt 16–64 bytes; iterations 210,000–10,000,000 |
| decrypted plaintext | derived from untrusted input | re-checked against the size limit before being returned |

No security outcome depends on an attacker-supplied value: the key id only
*selects* among keys that server-side configuration already loaded, and the GCM
tag — not the id — decides whether the data is accepted.

### 2. Secrets

No key, password or passphrase appears anywhere in this source tree, the tests,
or the build: every key is either generated at runtime from `SecureRandom` or
supplied by configuration, so nothing here works "as shipped". Secrets are never
logged (`CryptoLog` is the single funnel, and takes only key ids, lengths and
fixed strings), never placed in an exception message, never put in a
command-line argument of this process, and never written to a file by this
component. `ZeroizableSecretKey.toString()` renders only the algorithm and
destroyed flag, `hashCode()` is deliberately independent of key material, and
`writeObject`/`readObject` throw `NotSerializableException` so a key cannot be
flushed to a session store or cache even though `SecretKey` is `Serializable`.
Key files are only read if their POSIX mode grants nothing to group or other.

### 3. Authentication and access — and why there is no rate limiter here

This component authenticates *data*, not *principals*: it has no users,
sessions, accounts or roles, so there is nothing for it to check against
server-side state and no per-account limit to enforce. Its analogue of that rule
is to **fail closed everywhere**: an unknown or malformed key id yields no key;
a missing, destroyed, non-AES or wrong-length key makes the component refuse to
start rather than start degraded; a configured active key with no material is a
start-up failure, not a first-request failure; and any failure to decrypt throws
instead of returning the input.

Rate limiting repeated decryption attempts is deliberately **not** done inside
the library: a lockout keyed on something this code can see would itself be a
denial-of-service lever (any caller could trip it and block legitimate reads of
the same data). The caller that owns the request path — and therefore the source
IP, session and account — is the correct place to throttle per source *and* per
account. Nothing here is weakened by that choice: failed decryption leaks no
information that repetition would accumulate (see rule 6).

### 4. Identifiers and tokens

The only values this component generates are nonces, salts and keys, and all
three come from a single shared `java.security.SecureRandom` — never from
`Random`, never from time, a counter, a hash of the data, or anything a caller
supplies. The nonce is generated internally per encryption; there is no API to
pass one in. Key ids are *not* tokens: they are non-secret labels, strictly
validated, and bound into the GCM associated data — the remaining risk of
accepting one from outside is that an attacker can choose which configured key a
ciphertext is *tried* against, which gains them nothing because forging the tag
under that key remains infeasible, and because the attempt is indistinguishable
from any other failure. No cookies, sessions or HTTP surface exist here, so the
`HttpOnly`/`Secure`/`SameSite`/path requirements have nothing to attach to; the
Base64 envelope is ciphertext, not a credential, and carries no key material.

### 5. Sensitive data

Plaintext and key material are never logged; `CryptoLog.masked` renders a
sensitive value as `[redacted N bytes]` so log lines stay correlatable without
containing the value. Every stored or accepted size is bounded (plaintext, AAD,
envelope, Base64 text, key count, key file size, passphrase, salt). Key material
is wiped: `ZeroizableSecretKey.destroy()` really zeroes its only copy (unlike
`SecretKeySpec`, whose `destroy()` throws), `SecretKeyProvider.close()` destroys
the whole key set, a half-loaded key set is destroyed if start-up fails, and
passphrases, keystore passwords, decoded Base64, derived bytes, the
`PBEKeySpec`'s internal copy, nonces, and the intermediate plaintext inside
`encryptText`/`reencryptUnderActiveKey` are all wiped on every path including
failures. `encryptText`/`decryptText` work in `char[]` so secrets avoid
unwipeable `String`s. This component creates no files; the files it *reads* must
already be owner-only.

### 6. Failure behaviour

Every decryption failure — bad magic, unknown version, malformed or unknown key
id, truncation, wrong key, tampered ciphertext, mismatched AAD, non-UTF-8
payload — throws the **same** `CryptoException` with the same message
(`"unable to decrypt data"`), no cause chained and no stack trace, so neither
the message nor a printed trace distinguishes them. The real reason goes to the
log at `FINE`, with non-secret metadata only. An unknown key id additionally
performs a **decoy decryption under a per-instance random key**, so the work
done and the error returned are indistinguishable from a forged tag: the
component is not an oracle for which key ids exist. Configuration problems
surface as a generic `"encryption key configuration is incomplete"` with detail
only in the log. Invalid input is always rejected — no permissive default is
substituted anywhere: no default key, no default salt, no clamped iteration
count, no truncation of oversized input, no guessing at an unknown envelope
version.

### 7. Concurrency

`AesGcmDataCipher` is immutable apart from its per-key nonce counters, and a
fresh `Cipher` is obtained per operation because `Cipher` instances are not
thread-safe. The one check-then-act — "has this key exhausted its nonce budget,
and may I claim one?" — is a single `AtomicLong.incrementAndGet()` compared
against the limit, so two threads can never both consume the last slot. Key sets
are built once, copied defensively, and exposed unmodifiable; counters live in a
`ConcurrentHashMap` populated via `computeIfAbsent`. `ZeroizableSecretKey`
synchronizes every read against `destroy()`, so a key cannot be read while it is
being wiped. Key-file checks are done with `NOFOLLOW_LINKS` and the file is read
once, limiting the symlink-swap window.

### 8. Prefer the platform

Everything cryptographic is the JDK's: `javax.crypto.Cipher` with
`AES/GCM/NoPadding` and `GCMParameterSpec` for AEAD, `SecretKeyFactory` with
`PBKDF2WithHmacSHA256` for derivation, `java.security.SecureRandom` for all
randomness, `java.security.KeyStore` with PKCS#12 for key storage,
`MessageDigest.isEqual` for constant-time comparison, `java.util.Base64`'s
strict decoder, and `java.nio.charset` decoders in `REPORT` mode. Nothing is
hand-rolled: no custom KDF, cipher mode, MAC, padding or RNG. The component has
**zero runtime dependencies**; the only build dependency is JUnit 5.10.2
(test scope), and every dependency and plugin is pinned to an exact version from
Maven Central — no version ranges, no `LATEST`/`RELEASE`, no snapshots, nothing
downloaded or executed from a shared or world-writable location.

## Residual risks, stated explicitly

* **Environment variables as a key source** are readable by the process owner and
  root via `/proc/<pid>/environ` and are inherited by child processes. The
  `String`s the JVM holds for them cannot be wiped (`EnvironmentKeySource` wipes
  its own copies). Prefer `KeyStoreKeySource`, or a KMS/HSM where the key never
  enters this process at all.
* **Keys live in heap memory** while in use. `destroy()`/`close()` zero them, but
  a heap dump or swap file taken beforehand, or a copy the GC moved, may still
  contain material. Disable core dumps and encrypt swap on hosts handling this
  data.
* **An externally supplied key id** lets a caller choose which configured key a
  ciphertext is tried against (see rule 4). This is strictly validated and
  authenticated, and yields no decryption without the matching key.
* **GCM nonce budget** is enforced per process, not globally. A deployment that
  encrypts more than 2^32 messages under one key across many processes should
  rotate the key well before that point.
* **Timing**: the decryption path is equalised for unknown keys, but a structurally
  invalid envelope (bad magic, impossible length) is rejected before any crypto
  runs and is therefore distinguishable from a well-formed forgery. That
  distinction is a property of the public envelope format and reveals nothing
  about keys or plaintext.
* **This component does not manage *where* ciphertext is stored** or who may ask
  for it. Authorisation, auditing and request throttling belong to the calling
  application.
