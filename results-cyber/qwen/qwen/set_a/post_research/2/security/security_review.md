# Security Review: secure-data-crypto 1.0.0 (`com.example.crypto`)

## 1. Executive Summary

This is a Java 17 / Maven library that provides authenticated encryption with AES-256-GCM plus the key
handling around it: versioned key estates, four key sources (raw file, PBKDF2 container, PKCS#12
keystore, environment variable), POSIX permission enforcement for key material, and an exception type
engineered to stop secrets leaking through error paths.

The cryptographic core is sound. There are no weak or deprecated algorithms, no ECB, no static or reused
IVs, no hardcoded, default or fallback keys, keys are a fixed 256 bits, the PBKDF2 default (600,000
iterations) is at or above the current recommended floor, and the record format binds its own header into
the GCM AAD twice — once as the record claims it and once as the key/caller really has it — with no early
return that could act as a cheaper oracle than the tag check. The permission work in `PrivateFiles` is
unusually thorough for code of this kind.

Ten findings are reported. The most serious is **not** a math error but a gap in an otherwise careful
local-threat model: `KeystoreKeySource` performs the *pre-read* privacy validation for its keystore file
but skips the *post-read* inode/mode/owner re-validation that the library's own shared helper performs for
every other key file, so a local attacker who may write the keystore's parent directory can swap the file
between validation and `KeyStore.load()` (SEC-01). Second, the ownership decision that the whole
"this key file is mine" model rests on is a comparison of the `user.name` **system property** against the
file owner's name — a property any JVM launcher can set, rather than the process's real UID (SEC-02). The
remaining findings are design-level: raw key bytes are accepted with no entropy check (SEC-03), the
documented nonce-capacity limit is advice rather than an enforced ceiling (SEC-04), key material is
materialised into un-erasable `String`s in a class whose own javadoc forbids exactly that (SEC-05), and a
set of Low/informational items around lock scope, a self-documented cost oracle, RNG injection, password
length, and provider-name disclosure.

Nothing here is remotely exploitable on its own. Every finding needs either local write access to the key
storage path, a misconfigured deployment, or a caller that misuses a deliberately open extension point —
but several of them defeat controls the code claims to provide, which is the standard this review applied.

## 2. Scope

Reviewed in place, read-only, from `/data/results/qwen/set_a/post_research/2/security/`. All 14 main
sources under `src/main/java/com/example/crypto/` were read in full, together with `pom.xml` and
`README.md`; the test suite was read by targeted search. `target/` (prebuilt `secure-data-crypto-1.0.0.jar`
and compiled classes) is build output and was not opened, executed, imported or built.

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SymmetricCrypto.java` | AES-256-GCM AEAD engine: `generateKey`, `encrypt`, `decrypt`, `decryptToString` | `AES/GCM/NoPadding`, 128-bit tag, 96-bit random nonce per record, header bound into AAD twice, `SecureRandom` injection point, documented (unenforced) nonce-capacity ceiling |
| `KeyVault.java` | Versioned key estate: active/readable/disabled versions, `rotate()`, `addReadableKey()`, per-version source cache | Routes decrypt by the record's attacker-influenceable version byte, `MAX_VERSIONS = 64` ceiling, decoy random key for unprovisioned versions so every forgery costs the same, single `rotationLock` guarding all estate mutation and cache fill |
| `PrivateFiles.java` | POSIX privacy enforcement for key material on disk | `CREATE_NEW` + `0600` at creation (no create-then-chmod window), rejects symlinks/non-regular files, owner and mode checks, ancestor-directory ownership and world-writable/sticky checks, post-read inode/mode/owner re-check when the parent is group/world-writable |
| `PasswordKeySource.java` | Passphrase-derived key from an `SPKB1` PBKDF2 container | PBKDF2-HMAC-SHA256, iteration count drawn from a whitelist checked *before* any KDF work, 16-byte salt, container header as AAD, `DEFAULT_ITERATIONS = 600_000`, `char[]`/`PBEKeySpec` zeroisation, reads via the guarded `readOwnerOnlyFile` |
| `EncryptedBlob.java` | Record format and parsing | `[format][ctxFlag][keyVer][12B nonce][ct+tag]`; strict bounds before allocation; text form `v1.<base64url>[.<context>]` rejected unless it re-encodes canonically |
| `KeystoreKeySource.java` | Key from a PKCS#12 keystore entry | Store password + alias, `MAX_STORE_BYTES` and entry caps, generic failure mapping so a wrong store password is not distinguishable, `MIN_PASSPHRASE_CHARS = 32` for the entry passphrase |
| `KeyMaterial.java` | Owned 32-byte key holder with a version tag | `KEY_BYTES = 32`, zeroises on `destroy()`, `use()` zeroises its own clone, no `String` rendering |
| `CryptoException.java` | Failure type safe to hand to an untrusted audience | Four fixed user messages only, `transient` technical detail, `getCause()` returns a message-stripped stand-in, both `printStackTrace` overloads print the generic message |
| `EnvKeySource.java` | Key from a named environment variable | Variable *name* validated against a strict regex before `getenv` is called; value must decode through `KeyEncoding` |
| `KeyEncoding.java` | The two accepted key forms | Accepts exactly 32 raw bytes or canonical base64url text, `MAX_INPUT_BYTES = 4096`, canonical re-encode equality check, documented "no `String` renderer" doctrine (partly contradicted in code — SEC-05) |
| `RandomPasswords.java` | CSPRNG generation of store passphrases | `SecureRandom` over 94 printable ASCII characters, returns eraseable `char[]`, rejects out-of-range length rather than clamping |
| `KeyFileKeySource.java` | Key from a raw key file | Delegates to `PrivateFiles.readOwnerOnlyFile` (the guarded read) and `KeyEncoding.decodeKeyBytes` |
| `Limits.java` | Shared ceilings and bounds-first helper | `IV_BYTES = 12`, payload/context caps, `requirePayload` checks size before any copy or allocation |
| `KeySource.java` | Key-source SPI | `load()` / `describe()` / `release()` contract that all four sources implement |
| `pom.xml` | Build definition | JDK 17 `release` pin, single `junit-jupiter` test-scoped dependency; no runtime dependencies, no artifact checksum/verification configuration |

## 3. Skills Applied

The router skill `review-code-for-security-vulnerabilities` was loaded first and its workflow followed:
establish what the component actually does, search the sibling skill library for skills matching that
behaviour, apply the matches one at a time, then cover the residue against general OWASP Top 10 / CWE
knowledge.

* **`performing-cryptographic-audit-of-application`** — applied to `SymmetricCrypto.java`,
  `KeyEncoding.java`, `PasswordKeySource.java`, `RandomPasswords.java`, `KeyMaterial.java` and
  `KeystoreKeySource.java`: algorithm and mode selection, padding behaviour, key size, hardcoded or
  fallback keys, weak KDF parameters (iteration counts), entropy sources, and predictable IVs/nonces. This
  skill produced SEC-03 (no strength check on supplied key material), SEC-04 (nonce uniqueness guarantee),
  SEC-08 (RNG trust) and SEC-09 (generated-secret entropy), and cleared the weak-algorithm, weak-mode,
  static-IV and hardcoded-key classes entirely.
* **`implementing-aes-encryption-for-data-at-rest`** — applied to `SymmetricCrypto.encrypt/decrypt` and
  `EncryptedBlob`: never reuse a 96-bit GCM nonce under one key, generate nonces from a CSPRNG, store the
  nonce with ciphertext and tag, use ≥256-bit keys, wipe key material after use, rotate keys, and use
  ≥600,000 PBKDF2 iterations. This skill produced SEC-04 (the reuse ceiling is documented, not enforced)
  and SEC-05 (key bytes left in un-erasable heap objects), and validated the 600,000-iteration default.
* **Considered and not applicable** (matched on description, then excluded on content): envelope encryption
  with AWS KMS, secrets management with Vault, HSM/PKCS#11 key storage, RSA key-pair management, hardware
  security key authentication, API key security, Wi-Fi and hash-cat password cracking. This component has no
  KMS, no vault client, no PKCS#11, no asymmetric keys, no API keys and no cracking workflow; PKCS#12 is a
  file format, not a KMS.
* **General OWASP Top 10 / CWE knowledge** was applied to the areas the specialised skills do not cover,
  because a crypto library's real risk here is in its filesystem, concurrency and error paths: insecure
  direct object reference and path/permission handling in `PrivateFiles.java` and
  `KeystoreKeySource.java` (CWE-22, CWE-367, CWE-276, CWE-287 — SEC-01, SEC-02); error handling and
  information exposure in `CryptoException.java` (CWE-203, CWE-208, CWE-209, CWE-532 — SEC-07, SEC-10);
  concurrency and lock discipline in `KeyVault.java` (CWE-362, CWE-667, CWE-400 — SEC-06); resource
  limits and allocation-before-work ordering in `Limits.java`, `EncryptedBlob.java` and `KeyVault.java`
  (CWE-400, CWE-770 — no finding, see section 6); and secrets hygiene / clear-on-use across all key
  holders (CWE-226, CWE-316 — SEC-05).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Keystore file is not re-validated after reading, so it can be swapped in the read window | High | CWE-367 | `KeystoreKeySource.java:217` |
| SEC-02 | File ownership is decided by the spoofable `user.name` property, not the process UID | Medium-High | CWE-287, CWE-806 | `PrivateFiles.java:202` |
| SEC-03 | Raw 32-byte key accepted with no entropy or strength check | Medium | CWE-326, CWE-331 | `KeyEncoding.java:56` |
| SEC-04 | Nonce-capacity limit is documented advice, not enforced state | Medium | CWE-323 | `SymmetricCrypto.java:121` |
| SEC-05 | Key material is rendered into un-erasable `String`s, contradicting the class's own doctrine | Medium-Low | CWE-226, CWE-316 | `KeyEncoding.java:70` |
| SEC-06 | Deployment-supplied factory code runs while holding `rotationLock` | Low-Medium | CWE-667, CWE-400 | `KeyVault.java:388` |
| SEC-07 | Decoy path is cheaper than a real key load, leaving "version not provisioned" observable | Low | CWE-203, CWE-208 | `KeyVault.java:440` |
| SEC-08 | Injected `SecureRandom` is trusted without constraint, so config can select a weak RNG | Low | CWE-338, CWE-499 | `SymmetricCrypto.java:65` |
| SEC-09 | `RandomPasswords.generate` accepts a 1-character secret; cap documented inconsistently | Low | CWE-331, CWE-521 | `RandomPasswords.java:77` |
| SEC-10 | Provider class names and the serialized cause chain can disclose internal detail | Low | CWE-209, CWE-532 | `CryptoException.java:137` |

## 5. Detailed Findings

### SEC-01: Keystore file is not re-validated after reading, so it can be swapped in the read window

**Severity:** High

**CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition

**Location:** `KeystoreKeySource.java:217`

**Vulnerable code:**

```java
// KeystoreKeySource.java:217-228
        try (InputStream in = Files.newInputStream(file)) {
            /*
             * Both types together: on PKCS#12 a wrong store password surfaces as an IOException
             * wrapping an integrity failure, not as a GeneralSecurityException, and a handler that
             * catches only the latter would let it escape unclassified.
             */
            ks.load(in, storePassword);
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "key store could not be opened: wrong store password, tampered file, or unreadable ("
                            + e.getClass().getSimpleName() + ")", e);
        }
```

**Why it is a problem:**

`load()` validates the keystore file *before* opening it — `PrivateFiles.requirePrivateKeyFile(file)` at
`KeystoreKeySource.java:201` and the size cap at `KeystoreKeySource.java:210` — and then opens the path a
second time at line 217 and hands the bytes straight to the PKCS#12 parser. Between those two path
resolutions there is an unrestricted window, and the check applies to a *path*, not to the file the read
actually consumed.

Every other key file in this library is read through `PrivateFiles.readOwnerOnlyFile`, which snapshots the
target's `(st_dev, st_ino)`, mode and ownership, performs the read, and then re-checks all three when the
parent directory is group- or world-writable:

```java
// PrivateFiles.java:160-174
        if (parentShared) {
            if (unixMode(parent) != parentModeBefore) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file directory changed during the read");
            }
            long[] inodeAfter = identity(file);
            if (inodeAfter[0] != inodeBefore[0] || inodeAfter[1] != inodeBefore[1]) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file was replaced during the read");
            }
            if (unixMode(file) != modeBefore || !stillOwnedByMe(file)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file permissions or ownership changed during the read");
            }
        }
```

That re-check exists because the code's own comment at `PrivateFiles.java:136-141` states the attack
correctly: "an attacker who may write the directory does not chmod it to swap a key out, he unlinks the
entry and creates another one". `PasswordKeySource.load()` gets this protection
(`PasswordKeySource.java:213`); `KeystoreKeySource` is the only key source that reads a file on its own,
and it silently opts out of the protection the library designed for exactly this threat. `README.md` lists
`inode-recheck-dropped` among the defects its own adversarial pass found and that survived into the shipped
code, and the test suite contains keystore tests for world-readable refusal and wrong-store-password
genericity but none that swaps the keystore file during a read.

Exploitation needs local write permission on the keystore's parent directory — a world-writable deploy or
config directory, a shared `/tmp`-style path, a second service account in the same group, or a CI runner.
The pre-read check is then satisfied by the *original* file, and the bytes the parser receives are the
attacker's. A substituted store that carries a MAC over the real store password will be rejected, but a
PKCS#12 file with no MAC at all (`openssl pkcs12 -nomac`) is loadable by the JDK parser without any
password match, so an attacker who can plant such a file at the expected alias gets an **attacker-chosen
key** into the AEAD path rather than merely a denial of service. That is a total loss of the protection the
component exists to provide: the attacker can decrypt records the application later encrypts under the
substituted key and forge records the application will accept. Even where substitution fails, the race
still defeats the library's stated guarantee that a key file it validated is the file it used.

**Fix:**

Read the keystore through the same guarded helper every other source uses, so the inode/mode/owner
re-validation happens before any bytes reach the parser, and erase the buffer afterwards. This also removes
the now-redundant `Files.size` cap and pre-check, since the helper enforces both:

```java
        // KeystoreKeySource.load() — replace lines 201 and 209-228 with:
        // PrivateFiles.requirePrivateKeyFile(file);  // subsumed by readOwnerOnlyFile
        byte[] storeBytes = PrivateFiles.readOwnerOnlyFile(file, MAX_STORE_BYTES);
        try {
            try (InputStream in = new ByteArrayInputStream(storeBytes)) {
                /*
                 * Both types together: on PKCS#12 a wrong store password surfaces as an IOException
                 * wrapping an integrity failure, not as a GeneralSecurityException, and a handler that
                 * catches only the latter would let it escape unclassified.
                 */
                ks.load(in, storePassword);
            } catch (GeneralSecurityException | IOException e) {
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                        "key store could not be opened: wrong store password, tampered file, or unreadable ("
                                + e.getClass().getSimpleName() + ")", e);
            }
        } finally {
            java.util.Arrays.fill(storeBytes, (byte) 0);
        }
```

`import java.io.ByteArrayInputStream;` is required. If the file must be streamed rather than buffered, the
alternative is to open a `FileChannel` once, read through that single already-open descriptor, and compare
`identity()` / `unixMode` / ownership taken from the descriptor against the pre-read snapshot — the
principle is the same: validate the object the read actually consumed, not a path resolved earlier. Add a
regression test that replaces the keystore entry between validation and load and asserts
`INSECURE_KEY_STORAGE`.

### SEC-02: File ownership is decided by the spoofable `user.name` property, not the process UID

**Severity:** Medium-High

**CWE:** CWE-287: Improper Authentication (with CWE-806: Using a Proxy or Intermediate Value for a Security Decision)

**Location:** `PrivateFiles.java:202`

**Vulnerable code:**

```java
// PrivateFiles.java:200-204
    /** Ownership re-check that reports rather than throws, for use after the read. */
    private static boolean stillOwnedByMe(Path p) {
        String me = System.getProperty("user.name");
        try {
            return me != null && me.equals(Files.getOwner(p, LinkOption.NOFOLLOW_LINKS).getName());
```

**Why it is a problem:**

The library's central claim about a key file is "this file belongs to the user running this process, in a
directory no one else may write". Both places that decide that question compare the file owner's name
against `System.getProperty("user.name")` — here at `PrivateFiles.java:202-204` and again in the enforcing
path, `requireOwns` at `PrivateFiles.java:390-394`, whose decision is
`if (me == null || !me.equals(owner)) {` at `PrivateFiles.java:402`.

`user.name` is not a security-relevant value on the JVM. It is initialised from the environment but can be
overridden by any launcher with `-Duser.name=<anything>`, and by `System.setProperty` at runtime, and it is
not required to correspond to the process's real or effective UID. So the comparison is a name match
between an attacker-influenceable string and the owner string the filesystem reports. A local attacker who
runs a service as their own account, or who can influence the JVM command line of a deployment (wrapper
script, `JAVA_OPTS`, unit-file drop-in, container `ENV`/`JAVA_TOOL_OPTIONS`), launches the process with
`-Duser.name=victim`, points it at a key file they created and `chown`ed to `victim` in a directory they
also control, and every ownership assertion in `PrivateFiles` passes. The design comment at
`PrivateFiles.java:403-408` reasons only about "an attacker who can set file ownership is already root",
which is true — but the property makes the check pass for an attacker who can set a *system property*,
which is a far lower bar than `chown`.

The consequence is that the shared-directory defence degrades to "the file's owner name string looks like
what the process says it is", which is precisely the case the mode and ancestor checks are meant to
supplement. It is also silent: no log line distinguishes a real UID match from a property match.

**Fix:**

Compare numeric identity — the file's `unix:uid` against the process's real UID, which is not settable as a
property — and fail closed when the real UID cannot be determined instead of falling back to a name:

```java
    /** Real (not property-derived) UID of this process. Fails closed when unavailable. */
    private static long currentUid() throws CryptoException {
        try {
            long uid = new com.sun.security.auth.module.UnixSystem().getUid();
            if (uid < 0) {
                throw new UnsupportedOperationException("no uid");
            }
            return uid;
        } catch | Exception e {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "the real user id is unavailable, so key-file ownership cannot be verified");
        }
    }

    private static long fileUid(Path p) throws CryptoException {
        try {
            Object uid = Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS);
            if (!(uid instanceof Long u)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "filesystem does not report a numeric owner for " + p);
            }
            return u;
        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "numeric ownership is unavailable on this filesystem for " + p, e);
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "ownership could not be read for " + p, e);
        }
    }

    private static boolean stillOwnedByMe(Path p) {
        try {
            return fileUid(p) == currentUid();
        } catch (CryptoException e) {
            return false; // report-not-throw site: an unverifiable owner is not "mine"
        }
    }
```

`requireOwns` should then be rewritten as `if (fileUid(p) != currentUid()) { throw ... }`, keeping its
existing error code and message shape. `com.sun.security.auth.module.UnixSystem` lives in the
`jdk.security.auth` module; if that is unacceptable in the target module graph, the equivalent portable
route is a small JNI/JNA `geteuid()` binding, or — for a containerised deployment — running the JVM as a
UID whose private volume is the only place key files may live, and documenting that the name check is not a
security boundary. Do not "fix" this by also consulting `System.getenv("USER")`: it is spoofable by the
same attacker with the same ease.

### SEC-03: Raw 32-byte key accepted with no entropy or strength check

**Severity:** Medium

**CWE:** CWE-326: Inadequate Encryption Strength (with CWE-331: Insufficient Entropy in Random Numbers)

**Location:** `KeyEncoding.java:56`

**Vulnerable code:**

```java
// KeyEncoding.java:54-58
    public static byte[] decodeKeyBytes(byte[] raw) throws CryptoException {
        byte[] in = Limits.requirePayload(raw, MAX_INPUT_BYTES, "key material");
        if (in.length == KeyMaterial.KEY_BYTES) {
            return in.clone();
        }
```

**Why it is a problem:**

`decodeKeyBytes` is the single gate through which key material enters from `KeyFileKeySource`,
`EnvKeySource` and any caller-supplied bytes. Its first branch accepts anything exactly 32 bytes long and
returns it as an AES-256 key, without any assessment of what is in those bytes. Every other key form gets
scrutinised — the text branch rejects control characters, invalid base64url and non-canonical encodings,
`PasswordKeySource` refuses iteration counts outside a whitelist and enforces a 32-character passphrase
floor (`KeystoreKeySource.java:56`) — but the raw branch is unconditional on length alone.

Because `KeyMaterial.KEY_BYTES` is 32, the raw branch is exactly the shape of a 32-character ASCII secret.
An operator who stores a 32-character passphrase, a UUID-with-dashes-plus-suffix, a truncated SHA-256 of a
service name, or a repeated 16-byte block as the "raw key file" is silently granted an "AES-256 key" whose
real strength is the entropy of that string — potentially far below 40 bits — while the library reports
success and the deployment believes it holds a 256-bit key. There is no counter-signal anywhere: no
warning, no metric, no optional strict mode. `KeyEncoding`'s own javadoc is opinionated about hygiene
elsewhere ("There is deliberately no counterpart that renders key material as a `String`"), so the absence
of a strength floor is an inconsistency in the component's own threat model, not a deliberate trade it
documents.

This is not a defect in AES; it is a missing validation at a system boundary (operator-supplied key
material), and it is the classic way an AEAD library ends up protecting data with a guessable key while
every technical control reads green.

**Fix:**

Reject raw buffers that cannot plausibly carry 256 bits of entropy, and route passphrases to the source
that is built for them:

```java
    public static byte[] decodeKeyBytes(byte[] raw) throws CryptoException {
        byte[] in = Limits.requirePayload(raw, MAX_INPUT_BYTES, "key material");
        if (in.length == KeyMaterial.KEY_BYTES) {
            if (isAllPrintableAscii(in)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "32 bytes of printable ASCII is a passphrase, not a key: use PasswordKeySource");
            }
            if (minEntropyBits(in) < MIN_RAW_KEY_ENTROPY_BITS) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "raw key material is too predictable to be treated as a 256-bit key");
            }
            return in.clone();
        }
        // ...unchanged text branch...
    }

    /** Ceiling on how little entropy a "256-bit" raw key may show. */
    private static final double MIN_RAW_KEY_ENTROPY_BITS = 180.0;

    private static boolean isAllPrintableAscii(byte[] in) {
        for (byte b : in) {
            int v = b & 0xFF;
            if (v < 0x21 || v > 0x7E) {
                return false;
            }
        }
        return true;
    }

    /** Conservative lower bound: distinct-value count plus a byte-frequency Shannon estimate. */
    private static double minEntropyBits(byte[] in) {
        int[] hist = new int[256];
        for (byte b : in) {
            hist[b & 0xFF]++;
        }
        double shannon = 0.0;
        int distinct = 0;
        for (int c : hist) {
            if (c > 0) {
                distinct++;
                double p = (double) c / in.length;
                shannon -= p * (Math.log(p) / Math.log(2));
            }
        }
        return Math.min(in.length * shannon, 8.0 * distinct);
    }
```

The printable-ASCII refusal is the load-bearing part: it converts the silent downgrade into a message that
names the correct source. The entropy floor is heuristic and should be documented as such — its purpose is
to refuse the obviously weak shapes (repeated blocks, low-alphabet data, zero-padded values), not to
certify quality. If strict validation would break existing deployments, put it behind an explicit
`KeyEncoding.decodeKeyBytes(raw, Validation.STRICT)` overload, default it to strict, and make the lenient
call site an auditable one. Better still: have `KeyVault` refuse to activate a vault whose active key was
loaded leniently.

### SEC-04: Nonce-capacity limit is documented advice, not enforced state

**Severity:** Medium

**CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption

**Location:** `SymmetricCrypto.java:121`

**Vulnerable code:**

```java
// SymmetricCrypto.java:121-122
        byte[] nonce = new byte[Limits.IV_BYTES];
        random.nextBytes(nonce);
```

**Why it is a problem:**

Nonces are random 96-bit values (`Limits.IV_BYTES == 12`), so uniqueness under a key is probabilistic. The
class is candid about this in its own javadoc (`SymmetricCrypto.java:23-28`): "after roughly 2^32 records
under one key a collision becomes likely… This component cannot observe how many records a key has produced
across processes, so it cannot stop you crossing the line — `KeyVault#rotate()` is the control… Treat well
over a hundred million records under one key as the point to rotate."

The problem is that the control it defers to does not count either. `KeyVault.rotate()` rotates when
someone calls it; it holds no per-version record counter and nothing refuses to encrypt past the ceiling.
So the one failure mode that is unrecoverable in GCM — two records under one key sharing a nonce, which the
same javadoc correctly calls "a total loss of confidentiality for those two plus a forgery capability"
because the XOR of the two keystreams and the GHASH relation hand the attacker both plaintexts and an
authentication-key recovery — is left entirely to operational memory across an unbounded number of
processes and restarts. The AES-at-rest guidance applied in section 3 states the requirement as a hard
rule, not a target: a 96-bit nonce must never be reused under a key, and where uniqueness cannot be
guaranteed the volume must be bounded by an enforced counter.

This is realistic rather than theoretical for exactly the deployments a library like this attracts: a
service that encrypts one field per transaction against a long-lived key version, where `rotate()` is run
quarterly and nobody counts records. At a few hundred million records the collision probability is already
non-negligible, and the failure is silent — the two colliding records are simply broken for everyone
forever, with no error at the time and no way to find them afterwards.

**Fix:**

Make the ceiling a refusal inside the component instead of a paragraph, keyed to the key version that is
about to be used:

```java
    // KeyVault: enforce the capacity ceiling the engine documents.
    private static final int MAX_RECORDS_PER_KEY = 1 << 26; // 67,108,864; ~2^-37 collision odds

    private final AtomicLong recordsUnderActive = new AtomicLong();

    public EncryptedBlob encrypt(String plaintext, String context) throws CryptoException {
        long issued = recordsUnderActive.incrementAndGet();
        if (issued > MAX_RECORDS_PER_KEY) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE,
                    "the active key version has reached its record ceiling; rotate() before encrypting");
        }
        return encryptWith(activeVersion(), plaintext, context);
    }

    public int rotate() throws CryptoException {
        // ...existing body...
        highestIssued.set(next);
        recordsUnderActive.set(0);
        return next;
    }
```

The counter is per-process, so a fleet still needs either shared state (a counter in the datastore, or
versioned keys per shard) or a deliberately conservative ceiling; that limitation must be stated in the
javadoc rather than replaced with optimism. The strictly stronger alternative is to stop drawing nonces at
random and derive them deterministically from a persisted per-version counter — `nonce = first 96 bits of
HMAC-SHA256(key, counter)`, counter incremented and persisted in the vault record — which makes uniqueness
an invariant rather than a probability, at the cost of making counter persistence part of the caller's
correctness contract. Either way, the ceiling must be *enforced somewhere*; a javadoc sentence is not a
control for an unrecoverable failure mode.

### SEC-05: Key material is rendered into un-erasable `String`s, contradicting the class's own doctrine

**Severity:** Medium-Low

**CWE:** CWE-226: Sensitive Information in Resource Not Removed Before Reuse (with CWE-316: Cleartext Storage in Memory)

**Location:** `KeyEncoding.java:70`

**Vulnerable code:**

```java
// KeyEncoding.java:70-81
        String text = new String(in, StandardCharsets.US_ASCII);
        byte[] decoded;
        try {
            decoded = DECODER.decode(text);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material is not valid base64url text", e);
        }
        if (!CANON.encodeToString(decoded).equals(text)) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material is not canonically encoded base64url text");
        }
```

**Why it is a problem:**

This class documents the correct rule for key-bearing text — "There is deliberately no counterpart that
renders key material as a `String`: a `String` cannot be zeroed" — and `RandomPasswords` repeats it ("Handing
back a `String` would leave the secret in the interned string heap, un-erasable, for the life of the JVM").
The code above then creates three key-derived `String`s on the ordinary decode path: `text` (line 70) is the
encoded key itself, `decoded`'s re-encoding at line 78 (`CANON.encodeToString(decoded)`) is a second full
rendering of it, and each is immutable, unpinnable, and can be copied by the GC, paged, or captured in a
heap dump or core dump with no way to erase it. `toBase64Url` at `KeyEncoding.java:104` adds a third,
though there the `String` is at least the documented return value of an operator-facing export.

The component otherwise treats this as worth real work: `KeyMaterial` owns and zeroes its array,
`use()` zeroes its own clone, `PasswordKeySource` demands `char[]` and calls `clearPassword()` in a
`finally`, `RandomPasswords` returns `char[]` specifically so callers can erase it, and the `finally`
blocks in `SymmetricCrypto` zero the nonce buffer. The `String`s above are therefore not an accepted
platform limitation being worked around — they are avoidable work that undermines the surrounding
design, and they are on the path every text-encoded key takes. `README.md` acknowledges the residue
("un-erasable copies inside the JDK cannot be wiped", with `no-erase-of-working-copy` listed as a surviving
defect), which is honest, but the JDK's unavoidable copies are not the ones here: `Base64.Decoder` and
`Base64.Encoder` both have `byte[]` overloads precisely so the text never has to become a `String`.

**Fix:**

Keep the byte path all the way through. Both overloads exist, so the canonical check needs no `String` at
all:

```java
    public static byte[] decodeKeyBytes(byte[] raw) throws CryptoException {
        byte[] in = Limits.requirePayload(raw, MAX_INPUT_BYTES, "key material");
        if (in.length == KeyMaterial.KEY_BYTES) {
            return in.clone();
        }
        if (in.length == 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY, "key material is empty");
        }
        for (byte b : in) {
            int v = b & 0xFF;
            /* Control characters, including NUL and newline, are not part of the text form. */
            if (v <= 0x20 || v > 0x7E) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key material is neither " + KeyMaterial.KEY_BYTES + " raw bytes nor printable base64url text");
            }
        }
        byte[] decoded;
        try {
            decoded = DECODER.decode(in); // byte[] overload: no String is created
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material is not valid base64url text", e);
        }
        byte[] canonical = CANON.encode(decoded); // byte[] overload
        try {
            if (!java.util.Arrays.equals(canonical, in)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key material is not canonically encoded base64url text");
            }
            if (decoded.length != KeyMaterial.KEY_BYTES) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key material decodes to " + decoded.length + " bytes, expected " + KeyMaterial.KEY_BYTES);
            }
            return decoded;
        } finally {
            java.util.Arrays.fill(canonical, (byte) 0);
            if (decoded != null) {
                java.util.Arrays.fill(decoded, (byte) 0);
            }
        }
    }
```

(The `decoded` fill must be dropped on the success path, or the returned array zeroed — the cleanest shape
is to copy to the caller's result before the `finally` runs; shown as-is only to keep the erasure visible.)
For `toBase64Url`, keep the method — an operator export to a secret manager genuinely needs text — but
narrow it: return `char[]` if the consuming API can take it, and document the returned `String` as
single-use, never-loggable, and to be dropped out of scope immediately, as its javadoc already requires.
Adding a test that asserts `decodeKeyBytes` allocates no `String` larger than the input would lock the
property in.

### SEC-06: Deployment-supplied factory code runs while holding `rotationLock`

**Severity:** Low-Medium

**CWE:** CWE-667: Improper Locking (with CWE-400: Uncontrolled Resource Consumption)

**Location:** `KeyVault.java:388`

**Vulnerable code:**

```java
// KeyVault.java:385-392
            if (keyVersion > highestIssued.get() || sources.size() >= MAX_VERSIONS) {
                return decoySource(keyVersion);
            }
            KeySource created = factory.create(keyVersion);
            if (created == null) {
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                        "key source factory returned no source for version " + keyVersion);
            }
```

**Why it is a problem:**

`factory.create(keyVersion)` is arbitrary code supplied by the deployment: `KeySourceFactory` is a public
`@FunctionalInterface` (`KeyVault.java:54-61`) whose contract tells the implementer to do whatever is
needed to obtain the key for a version, including "fail closed" remote calls. In a normal deployment that
means fetching from a secret manager or KMS over the network. Here it executes inside
`synchronized (rotationLock) {`, which began at `KeyVault.java:358` — and the same lock is held by
`rotate()` (`KeyVault.java:142`, which itself calls `factory.create` at `KeyVault.java:156`),
`addReadableKey()`, `disable()` and `enable()`.

Two consequences follow. First, availability: one cold-miss decrypt whose factory call blocks on a slow or
hanging secret-manager endpoint holds `rotationLock`, so every other vault operation — including
`rotate()`, which `README.md` positions as the emergency re-key control and which this component itself
calls the mitigation for SEC-04 — queues behind it. A single unprovisioned version number in a submitted
record is enough to trigger the cold path, and an attacker who can name versions in forged records can
keep selecting versions whose source is not yet cached, converting a per-request key lookup into a
serialisation point across the whole vault. The bound on *created* sources (`MAX_VERSIONS`, plus the
`highestIssued` ceiling at line 385) limits how many factory calls ever happen, but it does not limit the
damage of one call that blocks: while it is stuck, the estate is frozen.

Second, reentrancy: `synchronized` is reentrant, so a factory implementation that calls back into the
vault — to check `isActive()`, consult the current version, or lazily register a readable key — runs while
the invariants the lock exists to protect are mid-update, seeing a `sources` map that has not yet received
`created` and a `highestIssued` that has not yet advanced. Nothing documents that factories must not call
back, and the javadoc gives no hint of the lock the caller is standing in.

**Fix:**

Do the unbounded work outside the lock and keep only the state transition inside it:

```java
    private KeySource sourceFor(int keyVersion) throws CryptoException {
        if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key version is out of range");
        }
        KeySource cached = sources.get(keyVersion);
        if (cached != null) {
            return cached;
        }
        boolean provisioned;
        boolean disabledVersion;
        synchronized (rotationLock) {
            requireOpen();
            disabledVersion = disabled.containsKey(keyVersion);
            provisioned = !disabledVersion
                    && keyVersion <= highestIssued.get()
                    && sources.size() < MAX_VERSIONS;
        }
        if (disabledVersion) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_UNAVAILABLE,
                    "key version " + keyVersion + " is disabled");
        }
        if (!provisioned) {
            return decoySource(keyVersion);
        }
        KeySource created = factory.create(keyVersion); // no lock held: may block on the KMS
        if (created == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "key source factory returned no source for version " + keyVersion);
        }
        synchronized (rotationLock) {
            requireOpen();
            if (disabled.containsKey(keyVersion)
                    || keyVersion > highestIssued.get()
                    || sources.size() >= MAX_VERSIONS) {
                release(created); // lost a race or the estate moved: nothing is cached
                return decoySource(keyVersion);
            }
            KeySource winner = sources.putIfAbsent(keyVersion, created);
            if (winner != null) {
                release(created);
                return winner;
            }
            return created;
        }
    }
```

The trade is that two concurrent cold misses for the same version may each run the factory and one result
is discarded — acceptable, and already the shape of the existing `putIfAbsent` race handling;
`rotate()` should likewise move its `factory.create` before taking the lock and apply only the map/
version/`disabled` updates inside it. Independently, the javadoc of `KeySourceFactory` should state that
implementations must not call back into the `KeyVault` that owns them, since even a narrow lock is not a
substitute for that contract.

### SEC-07: Decoy path is cheaper than a real key load, leaving "version not provisioned" observable

**Severity:** Low

**CWE:** CWE-203: Observable Discrepancy (with CWE-208: Observable Timing Discrepancy)

**Location:** `KeyVault.java:440`

**Vulnerable code:**

```java
// KeyVault.java:438-447
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
```

**Why it is a problem:**

The decoy design is, on the whole, a strong piece of work: returning a fresh random key for an
unprovisioned version means the caller's forgery is settled by the GCM tag and produces a byte-for-byte
identical answer to a tampered record, with no distinguishable failure code and no early return. But the
*cost* of getting that key is not matched. `DECOY_RANDOM.nextBytes` on 32 bytes is microseconds, while the
real path for an issued-but-not-yet-cached version runs `factory.create` plus `source.load()` — which for
`PasswordKeySource` is a 600,000-iteration PBKDF2, i.e. hundreds of milliseconds. So response time still
answers the question "is a source provisioned for this version, and is it warm?", even though the failure
code does not. The code says so itself at `KeyVault.java:418-422`: "acquiring this key costs far less than
acquiring a real one from a slow source, so 'no key is provisioned for that version' remains observable
through cost — as it already is through the difference between a cold and a warm cache."

Reporting a self-documented residual risk is not padding: the leak discloses the size and shape of the
key estate (how many versions are provisioned and live), which is useful reconnaissance before a Kerberos-
style offline attack or simply for targeting, and the *asymmetry* is the part worth fixing — the cheaper
side is the one an attacker controls the input to. The counter-consideration is real and is why this is Low
rather than Medium: padding the decoy to match a real KDF costs CPU on every forged record, which trades an
information leak for a DoS amplifier, and `README.md` states that rate limiting is deliberately delegated
to the caller ("Rate limiting is explicitly not implemented and cannot be" done correctly here).

**Fix:**

Close the gap by removing the decoy path from the version space an attacker can legitimately name, rather
than by buying cost parity with CPU — and say plainly that the remaining difference is bounded by
caller-side rate limiting:

```java
    private static KeySource decoySource(int keyVersion) {
        // Cost parity for the unprovisioned path: the point is that learning "not provisioned"
        // must not be cheaper than learning "wrong key". Bounded by the caller's rate limit.
        return new DecoySource(keyVersion, DECOY_KDF_PAD_BYTES);
    }

    private static final class DecoySource implements KeySource {

        private final int keyVersion;
        private final byte[] pad;

        DecoySource(int keyVersion, byte[] pad) {
            this.keyVersion = keyVersion;
            this.pad = pad;
        }

        @Override
        public KeyMaterial load() throws CryptoException {
            byte[] filler = new byte[KeyMaterial.KEY_BYTES];
            DECOY_RANDOM.nextBytes(filler);
            try {
                // Same KDF, same iteration count the configured sources are allowed to use.
                return PasswordKeySource.deriveFixedCost(filler, pad, PasswordKeySource.DEFAULT_ITERATIONS,
                        keyVersion);
            } finally {
                java.util.Arrays.fill(filler, (byte) 0);
            }
        }
    }
```

and pre-provision sources for every version in `1..highestIssued` at vault start-up (or on first use under
a bounded warm-up) so the decoy path only ever answers for version numbers that are provably unissued —
where a timing difference reveals nothing the ciphertext header does not already disclose. If the CPU cost
is unacceptable, the alternative is to keep the current behaviour and require callers to rate-limit
`decrypt*` per principal, documented as a security precondition of the vault rather than a general
suggestion.

### SEC-08: Injected `SecureRandom` is trusted without constraint, so config can select a weak RNG

**Severity:** Low

**CWE:** CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (with CWE-499: Serializable Class Containing Sensitive Data — a trust-injection analogue)

**Location:** `SymmetricCrypto.java:65`

**Vulnerable code:**

```java
// SymmetricCrypto.java:65-71
    public SymmetricCrypto(SecureRandom random) throws CryptoException {
        if (random == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                    "no cryptographic random source supplied");
        }
        this.random = random;
    }
```

**Why it is a problem:**

The class javadoc is emphatic that this component must never let an attacker-controlled input select a
weaker path — "a config file, a database row, a blob header, an HTTP body — can select a weaker path. The
only inputs this class takes are key material, data and a context string" — and the same paragraph claims
"The only inputs this class takes" while the public constructor at line 65 takes a *random source*, which
is the single most consequential input the class can receive: `random.nextBytes(nonce)` at line 121 is the
nonce-uniqueness guarantee of every record ever encrypted through that instance.

The constructor validates only for null and stores whatever it is given. `SecureRandom` is subclassable and
selectable by name and provider, so `new SecureRandom(SecureRandom.getInstance("SomeWeakOrSeeded", provider))`,
an instance seeded from a fixed value via `setSeed`, or a shim from a config-driven factory all pass. The
javadoc warns against `Random` and `ThreadLocalRandom`, but those cannot even be passed here — the
parameter type rules them out — so the warning guards the impossible case and leaves the reachable one
(a degenerate `SecureRandom`) unconstrained. In a deployment where the RNG is chosen by configuration,
which is exactly the pattern the vault's own `KeySourceFactory` normalises elsewhere, this becomes a
configuration-controlled total break of confidentiality and authenticity, silent at startup and visible
only as broken plaintext later.

This is Low because it requires a caller or deployment to do the wrong thing, not because the impact is
small.

**Fix:**

Keep the extension point but constrain what it accepts, and make the choice observable:

```java
    /** RNG algorithms this build will mint record nonces from. */
    private static final Set<String> APPROVED_RANDOM_ALGORITHMS = Set.of(
            "NativePRNG", "NativePRNGBlocking", "NativePRNGNonBlocking", "Windows-PRNG", "PK11");

    public SymmetricCrypto(SecureRandom random) throws CryptoException {
        if (random == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                    "no cryptographic random source supplied");
        }
        String alg = random.getAlgorithm();
        if (alg == null || !APPROVED_RANDOM_ALGORITHMS.contains(alg)) {
            throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                    "random source is not an approved algorithm for nonce generation");
        }
        SymmetricCrypto.logNonceSource(alg, random.getProvider().getName());
        this.random = random;
    }
```

The allowlist is a pragmatic control, not proof — a `SecureRandom` cannot attest to its own entropy source,
and a FIPS-certified module with an unlisted algorithm name would be rejected, so the set must be
deployment-configurable (configurable by the *operator*, at class-init time, never per call). A stronger
complement is a startup self-test, reusing the provider probe already present at `SymmetricCrypto.java:377`:
draw two consecutive nonce-width blocks from the supplied source and refuse the instance if they are equal
or if the block repeats a previously issued nonce, which at least catches the seeded-and-frozen case the
javadoc cannot. Default-construction (`SymmetricCrypto.java:55-57`) already avoids all of this and should
remain the recommended path.

### SEC-09: `RandomPasswords.generate` accepts a 1-character secret; cap documented inconsistently

**Severity:** Low

**CWE:** CWE-331: Insufficient Entropy in Random Numbers (with CWE-521: Weak Password Requirements)

**Location:** `RandomPasswords.java:77`

**Vulnerable code:**

```java
// RandomPasswords.java:76-80
    public static char[] generate(int length) throws CryptoException {
        if (length < 1 || length > MAX_LENGTH) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "length must be between 1 and " + MAX_LENGTH);
        }
        char[] out = new char[length];
```

**Why it is a problem:**

The lower bound is 1. `RandomPasswords.generate(1)` returns a single printable-ASCII character — roughly
6.5 bits of entropy — from a generator whose entire purpose is producing the passphrase that protects a
PKCS#12 store or a PBKDF2 container. The method's javadoc explains that out-of-range values are "rejected
rather than clamped, so a typo cannot quietly produce a 1-character password", but the guard makes exactly
that typo legal: the realistic failure is a config value or loop variable arriving as `1` or `length`
resolved from an unset default, and nothing refuses it. The consumer side proves a floor is expected —
`KeystoreKeySource.MIN_PASSPHRASE_CHARS = 32` (`KeystoreKeySource.java:56`) refuses short passphrases —
so a caller can generate a secret that the very next line of their own code will reject, or use it against
a source with no such floor.

The upper bound is documented inconsistently, which matters for a different reason: the field comment at
`RandomPasswords.java:45` states "4 KiB is the maximum any key source accepts", but `MAX_LENGTH` is
1024 **characters**, and the accepting bound elsewhere is `KeyEncoding.MAX_INPUT_BYTES = 4096`
(`KeyEncoding.java:41`) — bytes, and applied to a different input (key material, not passphrases). The
class also notes its alphabet contains shell and YAML metacharacters as "a quoting obligation on the
caller", so a legal 1,024-character secret may need escaping to survive a deployment path at all. The
number itself is generous and fine; the stated justification is wrong, and a reader who trusts "4 KiB"
will mis-size their storage or logging assumptions.

**Fix:**

Enforce the floor the consumers already assume, and state the cap in the units it is actually measured in:

```java
    /** Floor implied by the strictest consumer: KeystoreKeySource.MIN_PASSPHRASE_CHARS. */
    public static final int MIN_LENGTH = 32;

    /** Rejected rather than silently clamped; well under the 4096-byte ceiling KeyEncoding applies. */
    public static final int MAX_LENGTH = 1024;

    public static char[] generate(int length) throws CryptoException {
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "length must be between " + MIN_LENGTH + " and " + MAX_LENGTH
                            + " characters; shorter secrets are not supported by any key source");
        }
        char[] out = new char[length];
```

If a genuinely shorter value is ever legitimate (a one-time bootstrap string, say), expose it as a
separately named method rather than as the low end of the security-critical generator, so that
`RandomPasswords.generate(int)` cannot be called with an argument that no configured key source would
accept. The same javadoc should give the effective strength explicitly — `length * log2(94)` bits — since
`ALPHABET_SIZE` is already published for exactly that calculation.

### SEC-10: Provider class names and the serialized cause chain can disclose internal detail

**Severity:** Low

**CWE:** CWE-209: Generation of Error Message Containing Sensitive Information (with CWE-532: Insertion of Sensitive Information into Log)

**Location:** `CryptoException.java:137`

**Vulnerable code:**

```java
// CryptoException.java:132-138
    public synchronized Throwable getCause() {
        Throwable t = super.getCause();
        if (t == null) {
            return null;
        }
        return new ProviderFailure(t.getClass().getName());
    }
```

**Why it is a problem:**

The class goes to real lengths to keep provider detail off untrusted channels — `getMessage()` returns one
of four fixed strings, `technicalDetail` is `transient` (`CryptoException.java:73`), and both
`printStackTrace` overloads (`CryptoException.java:117`, `CryptoException.java:122`) print only the generic
message so `log.error("...", e)` cannot leak. That care is justified by the class's own reasoning:
"provider messages can quote key lengths, algorithm parameters and file paths."

Two paths still let information out. First, `ProviderFailure` renders the wrapped exception's fully
qualified class name into a message that is designed to be renderable —
`super("provider failure: " + causeClassName, null, false, false);` at `CryptoException.java:154` — so any
generic renderer reveals which JCA provider and internal class failed, which is exactly the kind of
implementation fingerprint the rest of the design declines to give out (and which tells an attacker
whether a FIPS module, a HSM shim, or a specific JDK build is in play). Second, and less obvious: the
*real* cause stays installed in the `Throwable` slot via the constructor at `CryptoException.java:84`, and
`Throwable`'s `cause` field is not transient — `technicalDetail` is, but the cause chain is serialized
with it. A `CryptoException` that crosses a serialization boundary (RPC, JMS, session replication, a cache)
therefore ships the original provider exception, message included, to the other side, where
`getUnderlyingCause()` — public, documented for "internal diagnostics", no capability check — hands it over
in plaintext. The mask is in-process only.

**Fix:**

Keep the real cause in a field that cannot be serialized, and stop putting the class name in a renderable
message — keep it in the technical detail, which is `transient` and log-side by contract:

```java
    private final CryptoFailureCode code;
    private final transient String technicalDetail;
    private final transient Throwable underlying; // never serialized, unlike Throwable.cause

    CryptoException(CryptoFailureCode code, String detail, Throwable cause) {
        super(code.userMessage(), null, /*enableSuppression*/ false, /*writableStackTrace*/ false);
        this.code = code;
        this.technicalDetail = cause == null
                ? detail
                : detail + " [" + cause.getClass().getName() + "]"; // names stay on the log side
        this.underlying = cause;
    }

    @Override
    public synchronized Throwable getCause() {
        return underlying == null ? null : new ProviderFailure();
    }

    /** Real cause, for internal diagnostics only. Never render this to an untrusted audience. */
    public synchronized Throwable getUnderlyingCause() {
        return underlying;
    }

    private static final class ProviderFailure extends Exception {
        private static final long serialVersionUID = 1L;

        ProviderFailure() {
            super("provider failure", null, false, false); // no class name in a renderable message
        }
    }
```

This preserves everything the design intended — in-process diagnostics via `getUnderlyingCause()`, generic
messages everywhere else, a deserializable `code` — while making the secret-bearing object unreachable
across a serialization hop. If exceptions from this library are in fact never serialized, delete the risk
instead of documenting it: `readObject`/`writeObject` that throw `NotSerializableException` makes the
boundary explicit and is a stronger statement than a `serialVersionUID`.

## 6. Verified Controls and Checks With No Finding

Checked and found correctly implemented, or explicitly out of scope with the reasoning stated:

* **Header binding and the absence of a cheap-failure oracle.** `SymmetricCrypto` puts both the record's
  claimed format/context-flag/key-version fields *and* the key's and caller's real values into the GCM AAD,
  so a record cannot be made to disagree with its key without breaking the tag, and `KeyVault.decryptWith`
  (`KeyVault.java:326-349`) has no branch that turns "the version byte was edited" into a cheaper failure
  than "the ciphertext was edited". `KeyVault.sourceFor` deliberately routes impossible versions to the
  decoy rather than returning early — the reasoning at `KeyVault.java:367-383` is correct, and the residual
  cost difference is SEC-07 rather than a second finding.
* **Forgery handling in the provisioned space.** A valid-format record under the wrong key yields the same
  equal-work `AUTHENTICATION_FAILED` outcome and the same generic message as a tampered one; the version
  byte is documented and implemented as routing, not an authentication decision.
* **Canonical encoding.** Both `EncryptedBlob`'s text form (`v1.<base64url>[.<context>]`) and
  `KeyEncoding.decodeKeyBytes` (`KeyEncoding.java:78-81`) reject input that does not re-encode identically,
  closing the multi-encoding-identity class of bug (duplicate records with distinct byte forms, and
  key-material ambiguity).
* **Bounds before allocation.** `Limits.requirePayload` and `EncryptedBlob`'s parser check size before
  copying or allocating; `KeystoreKeySource` caps the store at `MAX_STORE_BYTES` and entry count at
  `MAX_ENTRIES`; `KeyVault` caps tracked versions at `MAX_VERSIONS = 64` and refuses versions above
  `highestIssued`, so attacker-chosen version bytes cannot grow the estate or pin live passphrase-holding
  sources — the ceiling check at `KeyVault.java:385` is correct.
* **KDF parameter validation.** `PasswordKeySource` accepts only iteration counts drawn from a published
  whitelist and validates the container header as AAD *before* performing any KDF work, so a hostile
  container cannot force an unbounded-iteration KDF run; the default `DEFAULT_ITERATIONS = 600_000`
  (`PasswordKeySource.java:72`) meets the floor the AES-at-rest skill sets as of 2024, and
  `PBEKeySpec.clearPassword()` is called in a `finally`.
* **Algorithm inventory.** Only `AES/GCM/NoPadding` with a 128-bit tag and a fixed 256-bit key
  (`KeyMaterial.java:38`), plus `PBKDF2WithHmacSHA256`. No ECB, no CBC without a separate MAC, no RC4/DES/
  3DES/MD5/SHA-1 in a security role, no hand-rolled MAC, no padding-oracle surface (AEAD, `NoPadding`), no
  compression of plaintext.
* **No static or reused IVs, no hardcoded keys.** The nonce is drawn fresh per record; the sole exception
  noted in `pom.xml`-adjacent review is that no default, sample, fallback or test key is reachable from
  `src/main`, and `generateKey` is the only in-component key origin. Env-var and file sources fail closed
  rather than substituting a fallback key.
* **Permission enforcement at creation, not after.** `PrivateFiles` creates key files with
  `FileChannel.open(..., CREATE_NEW, PosixFilePermissions.asFileAttribute(0600))`, so there is no
  create-then-chmod window; it rejects symlinks and non-regular files, requires the file and every ancestor
  directory to be owned by the running user and not group/world-writable (allowing world-writable only with
  the sticky bit), and `EnvKeySource` validates the variable *name* against a strict regex before calling
  `getenv`, so a config value cannot name an arbitrary environment entry.
* **Zeroisation discipline (as far as the JVM permits).** `KeyMaterial` owns and zeroes its array;
  `use()` zeroes its own clone; `PasswordKeySource` requires `char[]` passphrases; `RandomPasswords`
  returns `char[]` for the same reason; nonce buffers are zeroed in `SymmetricCrypto`'s `finally` blocks;
  `EncryptedBlob` never retains plaintext. The unavoidable JDK-internal copies are documented as residual
  risk; the *avoidable* ones are SEC-05.
* **Fixed user-facing failure vocabulary.** `CryptoException.getMessage()` returns one of four fixed
  strings, so no response can distinguish a wrong key from a tampered record or an unavailable source;
  `code` is deliberately non-`transient` for a correct reason (a null `code` would make the safe message
  throw on the error path), which the comment at `CryptoException.java:65-71` justifies.
* **DoS posture within the component.** Per-operation work is bounded, every parser bound is checked before
  allocation, and the decoy path is the *cheapest* path, so forged records naming unissued versions cost
  the attacker less than they cost the defender — the right way round. Rate limiting is explicitly
  delegated to the caller, and `README.md` states plainly that it "cannot be" implemented correctly inside
  a stateless library; this is a correct scoping decision, not a gap, though it is the precondition for
  SEC-07's residual risk being acceptable.
* **Platform self-test.** `SymmetricCrypto` probes the JCA provider at class-initialisation
  (`SymmetricCrypto.java:377`) rather than failing on first use, and null/absent collaborators are rejected
  at construction with no weaker fallback substituted.
* **Build and supply-chain surface.** `pom.xml` pins the JDK `release`, has no runtime dependencies at all,
  and its only dependency is `junit-jupiter` at test scope — so the library's shipped dependency graph is
  empty. `README.md` notes that pinned versions ship without artifact checksums; with no runtime
  dependencies this is not a finding, but it is worth a checksum/`dependencyVerification` step if any
  runtime dependency is ever added.
* **Out of scope by inspection.** No SQL, LDAP or shell construction (no injection surface); no template
  rendering (no SSTI/XSS); no Java deserialization of untrusted data; no network client, TLS endpoint or
  certificate handling; no authentication, session or authorisation logic of its own; no cloud SDK.
  Consequently the injection, SSRF, deserialization, TLS-configuration and cloud-IAM skill families were
  considered and not applied.
* **Stated residual risks reviewed and accepted as stated** (`README.md`, cross-checked against code): a
  compromised root user defeats every file check; the PKCS#12 *store* KDF is weaker than the PBKDF2 path
  (mitigated only by the 32-character store-passphrase floor at `KeystoreKeySource.java:56`); un-erasable
  JDK-internal copies of key bytes; per-operation key-load CPU cost when a source is not cached;
  `RandomPasswords`' generous length; and the whole nonce-capacity question, which is SEC-04 because the
  risk is real and the component's own mitigation is not enforced.
* **Not exercised.** `target/secure-data-crypto-1.0.0.jar` and the compiled classes were not run, and no
  build or test execution was performed, per the review's static-only constraint; the 72 tests described in
  `README.md` were read as documentation of intent, not as evidence of behaviour. In particular, no test in
  the suite replaces the keystore file during a read, which is why SEC-01 has no test coverage.
