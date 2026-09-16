# Security Review: PII encryption demo (PiiCrypto / PiiApp)

## 1. Executive Summary

This project encrypts a person's name and email address with AES-256-GCM, deriving the key
from a caller-supplied passphrase with PBKDF2-HMAC-SHA256 and packing the result into a
single Base64 token (`version | salt | iv | ciphertext + tag`). The core cryptographic design
is sound: authenticated encryption with a per-record random salt and IV, strict input and
payload validation, no IV or key reuse, and a deliberate refusal to distinguish "wrong
passphrase" from "tampered token". No Critical or High findings were identified.

Nine findings are reported: **3 Medium** and **6 Low**. The Medium items are all about the
weakest link in a passphrase-based scheme rather than the cipher itself — the key-stretching
cost is set to 210,000 iterations, roughly one third of the current OWASP recommendation for
PBKDF2-HMAC-SHA256, and the entire scheme therefore reduces to guessing the passphrase; the
minimum passphrase length is enforced only in the command-line wrapper and not in the library,
so callers get no protection at all; and the documented non-interactive path expects the key
material to be passed in an environment variable, which is far more widely readable than a
key file. The Low items concern non-ASCII acceptance in the email validator, plaintext PII on
stdout, key material not being wiped, missing re-validation of decrypted payloads, JDK
exception detail leaking into user-facing messages, and a hardcoded credential literal in the
test suite.

The code is unusually well hardened for a demo, and section 6 records the many controls that
were checked and found correct, so the findings below should be read as a short list of
genuine gaps rather than a general criticism.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/PiiCrypto.java` (426 lines) | Library: AES-256-GCM encrypt/decrypt of a name + email into one Base64 token, key derived from a passphrase. | Crypto parameters (`PBKDF2_ITERATIONS`, key/tag lengths), `SecureRandom` salt/IV generation, `PBEKeySpec` key derivation and wiping, email/name/passphrase validation, token and payload framing, strict Base64 and UTF-8 decoding, error-message construction via `describe()`. |
| `src/PiiApp.java` (164 lines) | Command-line demo: reads name/email/passphrase, encrypts, decrypts, prints both. | Passphrase acquisition (`console.readPassword`, `PII_PASSPHRASE` environment variable), `MIN_PASSPHRASE_LENGTH = 10` policy, printing plaintext PII to stdout, printing exception messages, `Arrays.fill` zeroing of secret buffers. |
| `src/PiiRecord.java` (21 lines) | Value holder for a decrypted name and email. | Deliberately redacted `toString()` — the control that keeps PII out of incidental log and exception output. |
| `test/PiiCryptoTest.java` (763 lines) | Self-contained assertion suite (194 checks), no test framework. | Hardcoded passphrase fixture; asserts the advertised security constants (key size, tag size, salt/IV size, iteration floor, derivation timing lower bound); proves wrong-passphrase/tamper refusal and non-leakage of PII into tokens. |
| `build.sh` (27 lines) | Compile, run tests, run demo. | `set -e`, quoted `dirname`, `javac -Xlint:all -Werror`; optionally launches the demo with `PII_PASSPHRASE` already present in the environment. No network or filesystem mutation beyond `out/`. |
| `README.md` | Design rationale and limitations. | States "210,000 rounds … follows the current OWASP recommendation" (documentation drift, see SEC-01); recommends `PII_PASSPHRASE` for non-interactive use (see SEC-03); accurately discloses the shared-passphrase and JDK key-wiping limitations. |
| `.mutation/run_mutants.py`, `.mutation/mutants.tsv` | Mutation-testing harness: 24 deliberate defects injected to prove the suite catches them. | Writes only into throwaway copies under `.mutation/work/`; confirmed it never modifies `src/` or `test/`. Reviewed for safety of the harness itself — no finding. |

`out/*.class` are build artefacts. `prompt.txt`, `cyber_prompt.txt`, `result.md` and
`return.txt` are task scaffolding, not application code. The directory is not a git
repository, so the review covers the full current source rather than a diff.

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router — established what each file actually does, then dispatched to the specialised skills below and produced this report format.
- `performing-cryptographic-audit-of-application`: applied to all of `src/PiiCrypto.java` — primitive and mode selection (AES/GCM/NoPadding, 128-bit tag), KDF choice and cost, `SecureRandom` seeding and IV/salt lifecycle, secret handling (`PBEKeySpec.clearPassword`, key-array wiping), and information leakage through exception messages.
- `implementing-aes-encryption-for-data-at-rest`: applied to the token container format, the AEAD construction, per-record salt/IV handling and nonce-reuse reasoning, the PBKDF2 iteration-count baseline, and key rotation / envelope-encryption guidance for the single shared passphrase.
- `implementing-envelope-encryption-with-aws-kms`: applied as the key-management design check for "one shared passphrase protects every record" (`README.md:212`), i.e. whether DEK/KEK separation, rotation and separation of duties are needed here.
- `testing-for-sensitive-data-exposure`: applied to plaintext PII written to stdout, the key material held in an environment variable, the credential literal in the test file, PII residue in immutable `String`/`SecretKeySpec` objects, and the redaction behaviour of `PiiRecord.toString()`.
- `testing-api-authentication-weaknesses`: only its secret/credential-strength checklist is applicable — there is no HTTP API, JWT, OAuth or session machinery in this codebase. That checklist was applied to `requireValidPassphrase` and `MIN_PASSPHRASE_LENGTH` (entropy floor, length policy, offline brute-force resistance).

General-knowledge coverage (no library skill matched these behaviours): the decrypt-side
payload parser (`readLengthPrefixed`, `ByteBuffer` bounds arithmetic, trailing-byte and
`getShort()` sign-extension handling, `CWE-119`/`CWE-20` class), Java/JCE-specific secret
lifetime semantics such as `SecretKeySpec` cloning and `Destroyable` (`CWE-244`), Unicode
validator weaknesses — IDN homograph and bidi-control acceptance (`CWE-20`, `CWE-178`,
`CWE-1188`) — plaintext PII written to a log-consumable console (`CWE-532`, `CWE-117`),
`SecureRandom` provider semantics, and shell hygiene in `build.sh`. These were audited against
the OWASP Top 10 and CWE directly.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | PBKDF2 iteration count far below the current OWASP recommendation | Medium | CWE-916 | `src/PiiCrypto.java:59` |
| SEC-02 | Passphrase strength floor enforced only in the CLI, not in the crypto API | Medium | CWE-521 | `src/PiiCrypto.java:236-242` |
| SEC-03 | Key material accepted through an environment variable | Medium | CWE-526 | `src/PiiApp.java:122-134` |
| SEC-04 | Email validator accepts invisible, bidi and confusable non-ASCII characters | Low | CWE-20 | `src/PiiCrypto.java:225-233` |
| SEC-05 | Plaintext PII echoed to stdout by default | Low | CWE-532 | `src/PiiApp.java:52-54` |
| SEC-06 | Derived key material is never wiped or destroyed | Low | CWE-244 | `src/PiiCrypto.java:379-397` |
| SEC-07 | Decrypted payload not re-validated against the encrypt-side rules | Low | CWE-20 | `src/PiiCrypto.java:321-335` |
| SEC-08 | JDK exception detail surfaced in user-facing messages | Low | CWE-209 | `src/PiiCrypto.java:422-424` |
| SEC-09 | Hardcoded passphrase literal in the test source | Low | CWE-798 | `test/PiiCryptoTest.java:25` |

## 5. Detailed Findings

### SEC-01: PBKDF2 iteration count far below the current OWASP recommendation

- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/PiiCrypto.java:59` (related: `README.md:128`, `test/PiiCryptoTest.java:631`)

**Vulnerable code:**

```java
// src/PiiCrypto.java:55-59
    static final int SALT_LENGTH_BYTES = 16;
    static final int IV_LENGTH_BYTES = 12;
    static final int TAG_LENGTH_BITS = 128;
    static final int KEY_LENGTH_BITS = 256;
    static final int PBKDF2_ITERATIONS = 210_000;
```

**Why it is a problem:**

Because the AES key is derived from a human-chosen passphrase, the iteration count is the only
thing standing between an attacker who has stolen the stored tokens and the plaintext. OWASP's
Password Storage Cheat Sheet currently specifies **600,000** iterations for
PBKDF2-HMAC-SHA256 (220,000 is the figure for the heavier PBKDF2-HMAC-SHA512); 210,000 is
about one third of the SHA-256 target. `README.md:128` asserts that "210,000 rounds … follows
the current OWASP recommendation for PBKDF2-HMAC-SHA256", which was true of an older revision
of that guidance and is now stale — the documentation is actively reassuring operators that a
below-baseline parameter is compliant. The cost is also linear, so an attacker with GPU or
ASIC hardware parallelises it cheaply. The guard rail intended to catch exactly this drift is
too loose to help: `test/PiiCryptoTest.java:631` asserts only
`PiiCrypto.PBKDF2_ITERATIONS >= 200_000`, so lowering the constant to 200,001 — or to a fifth
of the recommended work factor — keeps the suite green.

**Fix:**

Raise the constant to the current OWASP figure, tighten the regression guard so it protects
the real target, and correct the README claim. Note that the iteration count is *not* carried
in the token, so changing it invalidates every already-stored token: either migrate
(decrypt with the old cost, re-encrypt with the new) or bump `TOKEN_VERSION` to 2 and store the
cost parameter in the container so old tokens keep opening.

```java
// src/PiiCrypto.java:59 (corrected)
    // OWASP 2024 baseline for PBKDF2-HMAC-SHA256. The count is not encoded in the
    // token, so raising it requires re-encrypting stored records (or a v2 token that
    // carries the cost parameter and still accepts v1 tokens).
    static final int PBKDF2_ITERATIONS = 600_000;

// test/PiiCryptoTest.java:631 (corrected)
        check("PBKDF2 runs at least 600000 rounds (OWASP PBKDF2-HMAC-SHA256)", true,
                PiiCrypto.PBKDF2_ITERATIONS >= 600_000);
```

### SEC-02: Passphrase strength floor enforced only in the CLI, not in the crypto API

- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/PiiCrypto.java:236-242` (related: `src/PiiApp.java:19`)

**Vulnerable code:**

```java
// src/PiiCrypto.java:236-242
    static void requireValidPassphrase(char[] passphrase) throws PiiCryptoException {
        if (passphrase == null || passphrase.length == 0) {
            throw new PiiCryptoException("a passphrase is required");
        }
        if (passphrase.length > PASSPHRASE_MAX_CHARS) {
            throw new PiiCryptoException("the passphrase is longer than " + PASSPHRASE_MAX_CHARS + " characters");
        }
```

**Why it is a problem:**

`requireValidPassphrase` checks presence, an upper bound, NUL/surrogate equivalence classes and
"not all whitespace" — it never checks that the secret is hard to guess. The only length floor
in the project is `MIN_PASSPHRASE_LENGTH = 10` in `src/PiiApp.java:19`, which lives in the
command-line demo and is invisible to anyone calling `PiiCrypto.encrypt(...)` /
`decrypt(...)` from their own code, which is precisely the documented integration path in
`README.md` ("Using it from your own code"). A library consumer can therefore encrypt regulated
PII under `"password12"`. Since this scheme's real strength is `min(KDF work factor,
passphrase entropy)`, a 10-character floor is the binding constraint: a 10-character lowercase
password sits near 2^40 guesses, which 600,000 PBKDF2 rounds does not rescue once a GPU cluster
is aimed at it. The README acknowledges the dependency ("the passphrase has to be strong,
because the 210,000 rounds only slow down a guesser") but nothing in the enforced API makes it
so — the failure is silent, and the weaker secret is indistinguishable from a strong one in the
stored token.

**Fix:**

Move the policy into the library so every caller inherits it, and keep the CLI check as a
nicer error message rather than the only gate. This is a behaviour change for existing callers
and should be called out in the release notes.

```java
// src/PiiCrypto.java:236-242 (corrected)
    static final int PASSPHRASE_MIN_CHARS = 14;   // OWASP guidance; the KDF cannot
                                                  // compensate for a short secret.

    static void requireValidPassphrase(char[] passphrase) throws PiiCryptoException {
        if (passphrase == null || passphrase.length == 0) {
            throw new PiiCryptoException("a passphrase is required");
        }
        if (passphrase.length < PASSPHRASE_MIN_CHARS) {
            throw new PiiCryptoException("the passphrase must be at least " + PASSPHRASE_MIN_CHARS + " characters");
        }
        if (passphrase.length > PASSPHRASE_MAX_CHARS) {
            throw new PiiCryptoException("the passphrase is longer than " + PASSPHRASE_MAX_CHARS + " characters");
        }
        // ... existing NUL / unpaired-surrogate / all-whitespace checks unchanged ...
    }
```

`PiiApp` should then drop its private `MIN_PASSPHRASE_LENGTH` and let
`PiiCrypto.PASSPHRASE_MIN_CHARS` be the single source of truth. For stronger assurance,
additionally reject phrases present in a breach/top-100k list; length alone does not imply
entropy.

### SEC-03: Key material accepted through an environment variable

- **Severity:** Medium
- **CWE:** CWE-526: Exposure of Sensitive Information in an Environment Variable
- **Location:** `src/PiiApp.java:122-134` (related: `README.md:30-33`, `build.sh:20`)

**Vulnerable code:**

```java
// src/PiiApp.java:122-134
    private static char[] readPassphrase() throws Exception {
        String fromEnvironment = System.getenv("PII_PASSPHRASE");
        if (fromEnvironment != null && !fromEnvironment.isEmpty()) {
            System.out.println();
            System.out.println("Using the passphrase from PII_PASSPHRASE.");
            char[] fromVar = fromEnvironment.toCharArray();
            if (fromVar.length < MIN_PASSPHRASE_LENGTH) {
                Arrays.fill(fromVar, '\0');
                throw new IllegalArgumentException(
                        "the passphrase in PII_PASSPHRASE must be at least " + MIN_PASSPHRASE_LENGTH + " characters");
            }
            return fromVar;
        }
```

**Why it is a problem:**

The class comment correctly refuses to take the passphrase as an argument ("command lines are
visible to every process on the machine and land in shell history") and correctly uses
`console.readPassword` for the interactive path, but the documented non-interactive path uses
the mechanism with nearly the same exposure surface. Environment variables are inherited by
every child process, are world-readable in `/proc/<pid>/environ` on many configurations for
the same UID and by root, are captured verbatim by `docker inspect`, container orchestration
manifests, `systemd` unit files (`Environment=`), CI pipeline logs and secret-burping debug
endpoints, and — as `README.md:33` and `build.sh:25` literally demonstrate — are typically
typed into a shell, so the secret also lands in `~/.bash_history`. It also survives for the
whole process lifetime, and `fromEnvironment` is an immutable `String`, so unlike the
`char[]` returned by `readPassword` it cannot be wiped at all. The result is that the one
credential that protects every stored PII record is routinely handled through the least private
channel the design offers.

**Fix:**

Use a key file with restrictive permissions (or a secret-manager/file-descriptor channel) for
non-interactive runs, and reserve `PII_PASSPHRASE` for local development only — or remove it.

```java
// src/PiiApp.java:122-134 (corrected)
    private static char[] readPassphrase() throws Exception {
        Console console = System.console();
        if (console != null) {
            return readPassphraseFromTerminal(console);   // unchanged console.readPassword path
        }

        // No terminal: read the key from a file the operator must have chmod 0600,
        // never from the environment (inherited by children, visible in
        // /proc/<pid>/environ, docker inspect, systemd units and CI logs).
        String configured = System.getProperty("pii.keyfile");
        if (configured == null || configured.isBlank()) {
            throw new IllegalStateException(
                    "no terminal available: set -Dpii.keyfile=/path/to/key (mode 0600), or run with a tty");
        }
        Path keyFile = Path.of(configured);
        if (Files.getPosixFilePermissions(keyFile).size() != 0
                && !Files.getPosixFilePermissions(keyFile).equals(PosixFilePermissions.fromString("rw-------"))) {
            throw new IllegalStateException("refusing to read " + keyFile + ": key file must be mode 0600");
        }
        byte[] raw = Files.readAllBytes(keyFile);
        try {
            char[] fromFile = new char[raw.length];
            for (int i = 0; i < raw.length; i++) {
                fromFile[i] = (char) (raw[i] & 0xFF);   // no intermediate String copy
            }
            return fromFile;                             // caller zeroes it in a finally block
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }
```

Correspondingly, `README.md:26-34` should stop recommending `PII_PASSPHRASE=...` as the
copy-paste non-interactive recipe, and the `PII_PASSPHRASE` branch in `build.sh:20-21` should
point at the key-file form. On Windows, replace the POSIX check with an equivalent ACL
verification. For anything regulated, prefer the envelope design the AES skill recommends: a
random per-record DEK wrapped by a KMS/HSM-held KEK, which removes the shared human secret
entirely.

### SEC-04: Email validator accepts invisible, bidi and confusable non-ASCII characters

- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation (identifier-confusion aspect: CWE-178 / CWE-1188)
- **Location:** `src/PiiCrypto.java:225-233` (also `src/PiiCrypto.java:208-214`)

**Vulnerable code:**

```java
// src/PiiCrypto.java:225-233
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '-' || c > 0x7F;
            if (!allowed) {
                throw new PiiCryptoException(
                        "the email address contains a character that host names may not use: '" + c + "'");
            }
        }
```

**Why it is a problem:**

`|| c > 0x7F` is not "also accept international addresses", it is "accept every code point
above ASCII, unconditionally". `requireNoControlCharacters` (line 265) only rejects `c < 0x20`
and `0x7F`, so the domain pass admits homoglyph labels (`micrоsoft-support.com` with a Cyrillic
`о`, or a Greek `ο`), RTL override `U+202E` and the other bidi isolates, zero-width joiner and
`U+FE0F`, fullwidth `U+FF0E`, and unpaired code points that later render as `?`. The
local-part loop at line 210 has the mirror-image hole: it rejects `c <= ' '` and seven RFC
specials, so `U+00A0`, `U+200B`, `U+202E` and `U+FE0F` all pass. The check's own error message
claims the character "may not be used in host names", so this is a validator that under-rejects
while asserting it is rejecting — the README's stated purpose is a typo filter, but anything
downstream that trusts "this address passed validation" inherits spoofable, visually
ambiguous strings, and an invisible directional override is a rendering and log-injection
vector rather than a typo.

Severity is Low because nothing in this repository resolves, displays or sends the address, so
the impact lands on the consumer of the decrypted record; it rises to Medium as soon as the
address is mailed, rendered in a UI, or compared for uniqueness (confusable variants of the
same mailbox bypass deduplication).

**Fix:**

Either restrict the validator to the ASCII LDH set it claims to enforce, or keep international
support but delegate the decision to IDNA, and close the invisible-character hole in both
parts.

```java
// src/PiiCrypto.java:225-233 (corrected) - option A: ASCII host names only
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '-';
            if (!allowed) {
                throw new PiiCryptoException(
                        "the email address contains a character that host names may not use: '" + c + "'");
            }
        }

// src/PiiCrypto.java:225-233 (corrected) - option B: keep IDN, judge it properly
        String asciiDomain;
        try {
            // IDNA2008 + STD3 rules: rejects disallowed and bidi-violating code points
            // instead of waving through everything above ASCII.
            asciiDomain = java.net.IDN.toASCII(domain, java.net.IDN.USE_STD3_ASCII_RULES);
        } catch (IllegalArgumentException e) {
            throw new PiiCryptoException("the part of the email address after the '@' is not a valid host name");
        }

// src/PiiCrypto.java:208-214 (corrected) - applies to both options: no invisible characters
        for (int i = 0; i < localPart.length(); i++) {
            char c = localPart.charAt(i);
            boolean invisible = Character.isSpaceChar(c) || Character.getType(c) == Character.FORMAT;
            if (c <= ' ' || invisible || "()<>[]:;,@\\\"".indexOf(c) >= 0) {
                throw new PiiCryptoException(
                        "the email address contains a character that plain addresses may not use: '" + c + "'");
            }
        }
```

Whichever option is chosen, update the `README.md` claim that international addresses are
accepted, and consider normalising with NFKC before storing so confusable variants collapse to
one comparable form.

### SEC-05: Plaintext PII echoed to stdout by default

- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/PiiApp.java:52-54` (also `src/PiiApp.java:75-76`)

**Vulnerable code:**

```java
// src/PiiApp.java:52-54
        System.out.println("Plain text (what you typed, this is the sensitive part)");
        System.out.println("  name : " + name);
        System.out.println("  email: " + email);
```

**Why it is a problem:**

The program goes out of its way to keep PII out of incidental output — `PiiRecord.toString()`
returns `"PiiRecord[redacted]"` specifically so a record cannot leak through a log statement or
exception message — and then unconditionally prints the name and the email address twice per
run, once as typed and again after decryption (`src/PiiApp.java:75-76`). For a CLI, stdout is
not a display; it is a stream that operators redirect into files, pipe into `tee`, capture in
CI job logs, `script`/`asciinema` recordings, terminal scrollback that is synced to support
tools, and journald. The README states plainly that the tool protects data at rest only and
that PII appearing "in a log line" is out of scope, which is a fair disclaimer for a library —
but this is the program's own default behaviour, on the demo path that `build.sh` runs, so
every user who follows the documented workflow creates an unprotected plaintext copy. It also
undercuts the redaction control's intent: the sensitive values reach the same console, so the
redacted `toString()` looks like theatre.

Severity is Low because it is a demo CLI whose whole purpose is to display the round trip, the
operator supplies the data themselves, and no log file is opened by the code.

**Fix:**

Mask by default and make plaintext display an explicit opt-in.

```java
// src/PiiApp.java:52-54 (corrected)
        System.out.println("Plain text (masked; pass --show-plaintext to print it in full)");
        System.out.println("  name : " + mask(name));
        System.out.println("  email: " + mask(email));

// new helper in PiiApp
    private static String mask(String value) {
        if (showPlaintext) {
            return value;
        }
        int keep = 2;
        return value.length() <= keep * 2
                ? "*".repeat(value.length())
                : value.substring(0, keep) + "…" + value.substring(value.length() - keep);
    }
```

Apply the same `mask(...)` at `src/PiiApp.java:75-76`; the "Round trip identical to the input"
line already proves correctness without printing the values, so no output loses its value.

### SEC-06: Derived key material is never wiped or destroyed

- **Severity:** Low
- **CWE:** CWE-244: Improper Clearing of Heap Memory Before Release ('Heap Inspection')
- **Location:** `src/PiiCrypto.java:379-397`

**Vulnerable code:**

```java
// src/PiiCrypto.java:379-397
    private static SecretKey deriveKey(char[] passphrase, byte[] salt) throws PiiCryptoException {
        byte[] keyBytes;
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
            keyBytes = factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new PiiCryptoException("could not derive a key from the passphrase: " + describe(e), e);
        } finally {
            spec.clearPassword();
        }
        // SecretKeySpec accepts any non-empty array and only fails later inside
        // Cipher.init, so the length is checked here where it can be explained.
        if (keyBytes.length != KEY_LENGTH_BITS / 8) {
            throw new PiiCryptoException(
                    "the passphrase produced a " + keyBytes.length + " byte key, expected " + KEY_LENGTH_BITS / 8);
        }
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }
```

**Why it is a problem:**

The project is careful about the passphrase — `spec.clearPassword()` runs in a `finally`, and
`PiiApp` zeroes every `char[]` it owns (lines 83, 99, 129, 145, 152, 155) — but the *derived
key*, which is exactly what an attacker wants, is never cleared. `keyBytes` is a plain
`byte[32]` returned inside a `SecretKeySpec` and left to the garbage collector, and neither
`encrypt` nor `decrypt` ever destroys the `SecretKey` they hold, so the raw AES key stays
reachable in the heap for the object's lifetime plus however long the region takes to be
reused. A long-lived process that decrypts records repeatedly therefore accumulates key
material in old generations; a heap dump (`jmap`, `jcmd`, an APM agent, a crash dump, a
swapped page) yields recoverable AES-256 keys even though the passphrase itself was wiped.
`SecretKeySpec` is `Destroyable` precisely for this, and the JDK's own advice is to call
`destroy()` when the key is no longer needed. The README discloses the *passphrase* residue
inside JDK internals, which is honest but is a different, partly unavoidable copy — the array
here is fully the code's own to erase.

Severity is Low: exploitation requires heap-read capability (debug attach, dump file, swap),
which is already a serious compromise, and the JDK does keep one unrecoverable internal copy of
the passphrase as the README notes.

**Fix:**

Zero the local copy once `SecretKeySpec` has cloned it (its constructor copies the array, so
wiping here does not break the key) and destroy the key as soon as the cipher is finished.

```java
// src/PiiCrypto.java:392-397 (corrected)
        if (keyBytes.length != KEY_LENGTH_BITS / 8) {
            Arrays.fill(keyBytes, (byte) 0);
            throw new PiiCryptoException(
                    "the passphrase produced a " + keyBytes.length + " byte key, expected " + KEY_LENGTH_BITS / 8);
        }
        SecretKeySpec key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);   // clones the array
        Arrays.fill(keyBytes, (byte) 0);                                  // drop our copy
        return key;
    }

// src/PiiCrypto.java:97-111 and 144-158 (corrected) - release the key when the cipher is done
        SecretKey key = deriveKey(passphrase, salt);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] ciphertext = cipher.doFinal(encodePayload(name, email));
            // ... pack and return the token ...
        } finally {
            if (key instanceof java.security.Destroyable destroyable && !destroyable.isDestroyed()) {
                destroyable.destroy();
            }
        }

// new helper, or inline as above (needs import java.util.Arrays;)
```

Add a test asserting `key.isDestroyed()` is unreachable from outside, and state in the README
that JDK-internal copies of the passphrase and of GCM's expanded round keys remain outside any
application's reach — the honest boundary of this control.

### SEC-07: Decrypted payload not re-validated against the encrypt-side rules

- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `src/PiiCrypto.java:321-335`

**Vulnerable code:**

```java
// src/PiiCrypto.java:321-335
    private static PiiRecord decodePayload(byte[] plaintext) throws PiiCryptoException {
        ByteBuffer buffer = ByteBuffer.wrap(plaintext);
        if (buffer.remaining() < MIN_PAYLOAD_BYTES) {
            throw new PiiCryptoException("the decrypted record is too short to hold a name and an email address");
        }
        if (buffer.get() != PAYLOAD_VERSION) {
            throw new PiiCryptoException("the decrypted record uses an unsupported layout");
        }
        byte[] nameBytes = readLengthPrefixed(buffer, "name");
        byte[] emailBytes = readLengthPrefixed(buffer, "email address");
        if (buffer.hasRemaining()) {
            throw new PiiCryptoException("the decrypted record has unexpected trailing bytes");
        }
        return new PiiRecord(decodeUtf8(nameBytes, "name"), decodeUtf8(emailBytes, "email address"));
    }
```

**Why it is a problem:**

On the encrypt side the code refuses control characters, lone surrogates, over-long values and
malformed addresses, on the documented grounds that "a newline or a NUL in PII is nearly always
a mistake or an attack, and it wrecks log and file formats". None of that is re-applied when the
record comes back out. `decodePayload` checks framing, UTF-8 validity and NUL only — a name
containing `\n`, `\r`, `U+202E` or 200 characters of emoji is accepted as soon as the AEAD tag
verifies. The tag is not a trust boundary here: by design anyone who can decrypt can also
encrypt (the README says so explicitly), so a party with encrypt-only access to a shared
passphrase — a contractor's account, a compromised writer service — can plant a record that
decrypts to `name = "Ada\n2026-09-14 09:00:00 INFO account promoted by admin"`. Whatever the
caller does with that value (log line, CSV export, HTML page, terminal) receives attacker-chosen
newlines and control characters that the library's own policy exists to prevent, i.e. log
injection (CWE-117) through a path the validation was assumed to cover.

Severity is Low because it requires possession of the passphrase and because `PiiRecord`'s
redacted `toString()` and the current call sites limit the blast radius in this repo.

**Fix:**

Re-apply the encrypt-side policy to decrypted values before returning them, so `PiiRecord`
always carries data that satisfies the same invariants regardless of who wrote the token.

```java
// src/PiiCrypto.java:321-335 (corrected)
        byte[] nameBytes = readLengthPrefixed(buffer, "name");
        byte[] emailBytes = readLengthPrefixed(buffer, "email address");
        if (buffer.hasRemaining()) {
            throw new PiiCryptoException("the decrypted record has unexpected trailing bytes");
        }
        String name = decodeUtf8(nameBytes, "name");
        String email = decodeUtf8(emailBytes, "email address");
        // The container is attacker-writable by design (any holder of the passphrase can
        // mint tokens), so re-apply the encrypt-side invariants before handing values back.
        requireValidName(name);
        requireValidEmail(email);
        return new PiiRecord(name, email);
    }
```

`requireValidName` and `requireValidEmail` already cover blank/length/control-character/
surrogate/shape checks; adding a `decodeUtf8`-level check that `nameBytes.length <=
NAME_MAX_CHARS * 4` first keeps a hostile 65 KB field from being built before rejection.
Add tests that hand-build a token whose payload contains a newline in the name and assert the
refusal, mirroring the existing tamper tests.

### SEC-08: JDK exception detail surfaced in user-facing messages

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/PiiCrypto.java:422-424` (consumer: `src/PiiApp.java:28`)

**Vulnerable code:**

```java
// src/PiiCrypto.java:422-424
    private static String describe(Exception e) {
        return e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
    }
```

**Why it is a problem:**

The class is designed so that `PiiCryptoException` messages are "fit to show a user", and the
important case is handled properly: `AEADBadTagException` is caught separately at line 150 and
replaced with a fixed message, precisely so a caller cannot tell a wrong passphrase from a
tampered token. Every *other* `GeneralSecurityException` is bypassed through `describe()`,
which concatenates the provider's exception class and message into the same
user-facing string — `encrypt` (line 114), `decrypt` (line 157) and `deriveKey` (line 386).
`PiiApp.main` then prints it verbatim at `src/PiiApp.java:28`. JCE provider messages name
algorithms, providers, key sizes, internal state and file paths (e.g. a disabled/unavailable
provider or a JCE unlimited-strength policy problem), so the error path discloses the crypto
stack configuration to whoever can trigger a failure — undermining the deliberate uniformity
built two dozen lines above. The design intent is clearly "generic message out, detail kept in
the cause"; the code just forgets that the cause is one `getCause()` away from being printed by
any caller that logs stack traces.

**Fix:**

Keep the class name only (it is stable and non-sensitive) or a fixed string, and route the real
detail to a logger rather than the message a UI shows.

```java
// src/PiiCrypto.java:422-424 (corrected)
    private static String describe(Exception e) {
        // Provider messages can name algorithms, providers and internal state. The
        // cause chain still carries them for whoever logs server-side; the message a
        // person sees stays generic, matching the AEADBadTagException handling above.
        return e.getClass().getSimpleName();
    }
```

If call-site detail is genuinely wanted, log it explicitly at the boundary
(`System.Logger.getLogger("pii").log(Level.FINE, "crypto failure", e)`) instead of embedding it
in the returned message.

### SEC-09: Hardcoded passphrase literal in the test source

- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `test/PiiCryptoTest.java:25` (also reused at `test/PiiCryptoTest.java:458`)

**Vulnerable code:**

```java
// test/PiiCryptoTest.java:25
    private static final char[] GOOD = chars("correct horse battery staple");
```

**Why it is a problem:**

This is a test fixture, not a production credential, and it has no real exposure — but it is a
hardcoded credential literal in the source tree, which means every secret scanner run over the
repository (gitleaks, trufflehog, GitHub secret scanning) fires on it and every one of those
hits has to be triaged and allowlisted by a human, which is how real findings get buried. It is
also the pattern this project otherwise avoids everywhere else, and a reviewer or a developer
copying the test harness into application code reproduces exactly the mistake SEC-02 and SEC-03
are about: a remembered phrase standing in for key material. Note the same string is reused at
line 458 to build the "wrong passphrase differs by one character" case, so the literal is load
bearing in two places.

**Fix:**

Keep a synthetic fixture but label it for humans and scanners so it stops being an unexplained
credential-shaped string, and centralise it.

```java
// test/PiiCryptoTest.java:25 (corrected)
    // gitleaks:allow  Synthetic fixture for the test suite only -- never a real
    // credential, never used outside these tests. Long enough to satisfy the
    // passphrase policy; the wrong-passphrase cases mutate it (see line 458).
    private static final char[] GOOD = chars("correct horse battery staple");
```

Add a matching entry to the repository's scanner allowlist so the exemption is auditable, and
do not extend the literal's use to any non-test source file.

## 6. Verified Controls and Checks With No Finding

- **Authenticated encryption mode:** `Cipher.getInstance("AES/GCM/NoPadding")` with `GCMParameterSpec(128, iv)` at `src/PiiCrypto.java:98` and `:147`; no ECB, no CBC, no hand-rolled MAC, no padding oracle surface; the transformation string is a private constant (`:71`) and never derived from input.
- **Key and tag sizes:** 256-bit key and 128-bit tag (`src/PiiCrypto.java:57-58`), enforced at runtime against the KDF output length (`:392-395`) rather than assumed.
- **IV and salt freshness:** a fresh 16-byte salt and 12-byte IV are drawn from a single shared `SecureRandom` (`:76`, `:94-95`, `:399-403`) for every `encrypt` call; because the salt also feeds key derivation, each record gets its own key, so GCM's nonce-reuse catastrophe cannot occur across records and the only residual bound is a 2^96 random-nonce space per derived key. The "two tokens for the same person differ" property is demonstrated by the CLI and asserted by tests.
- **No padding:** `NoPadding` with GCM is correct; there is no PKCS#7 or stream-cipher-without-MAC fallback anywhere.
- **Uniform failure for wrong key vs. tampering:** `AEADBadTagException` is mapped to a single generic message (`src/PiiCrypto.java:150-152`) and asserted not to echo the passphrase, so the decrypt endpoint gives an attacker no oracle to distinguish key failure from integrity failure.
- **Strict decoding of untrusted tokens:** `Base64.getDecoder()` (strict, not MIME) with an explicit single-line check and a `MIN_CONTAINER_BYTES` floor before any parsing (`src/PiiCrypto.java:126-128`, `:405-420`).
- **Bounds-safe payload parser:** every `ByteBuffer` read is guarded — `remaining() < MIN_PAYLOAD_BYTES` (`:323`), version byte check, `readLengthPrefixed` rejecting `length == 0` and `length > remaining()` (`:341-343`), and `hasRemaining()` rejecting trailing bytes (`:331`). No out-of-bounds read; `getShort() & 0xFFFF` avoids sign-extension of the 2-byte length. The comment at `:304-307` explains why the 2-byte lengths cannot overflow given `NAME_MAX_CHARS`/`EMAIL_MAX_CHARS`, and the suite asserts that margin.
- **Equivalence-class hardening on the passphrase:** `requireValidPassphrase` (`src/PiiCrypto.java:236-268`) rejects NUL (which `PBEKeySpec` would truncate at, making `"abc\0"` == `"abc"`) and unpaired surrogates (which the JDK would coerce to `?`), each verified against the JDK by tests — a subtle and genuinely valuable control.
- **Strict UTF-8 on both sides:** encrypt-side rejection of control characters and lone surrogates (`:270-286`), decrypt-side `CodingErrorAction.REPORT` decoding plus explicit refusal of `U+FFFD` (`:350-375`), so a mangled name is never silently returned.
- **Input caps:** 200 characters for a name, 254 for an email, 1024 for a passphrase (`:64-66`), checked before any encoding or allocation, bounding memory per call.
- **PII kept out of incidental output:** `PiiRecord.toString()` returns `"PiiRecord[redacted]"` (`src/PiiRecord.java:18-20`), and the suite asserts no recognisable part of the name or email appears in the token or its decoded bytes.
- **Secret wiping that is achievable:** `spec.clearPassword()` in a `finally` (`src/PiiCrypto.java:387-389`) and `Arrays.fill(..., '\0')` on every passphrase `char[]` the CLI owns, including the mutated `wrong` clone (`src/PiiApp.java:83`, `:99`, `:129`, `:145`, `:152`, `:155`). (The derived-key array is the exception — see SEC-06.)
- **No injection sinks:** the codebase contains no SQL, no OS-command execution, no `Runtime.exec`, no deserialization, no reflection on untrusted types, no file-path or URL construction from input, no XML/HTML output and no network client, so the command-injection, path-traversal, XXE, SSRF, XSS and insecure-deserialization skill families were checked and are genuinely inapplicable.
- **No production secrets:** grep over `src/` found no API keys, tokens, private keys or passwords; the only credential literal is the test fixture reported as SEC-09.
- **Randomness source:** one shared `SecureRandom` instance (thread-safe per its JLS contract for `nextBytes`), no `java.util.Random`, no fixed seed, no `Math.random()`, no time-derived IV.
- **Downgrade handling:** the token version byte is compared against a single expected value with no fallback branch (`src/PiiCrypto.java:131-135`), so an attacker cannot select a weaker format; the payload version is checked again after decryption (`:326`).
- **Timing behaviour:** no secret-dependent branching or short-circuit comparison in the validation paths; integrity comparison is delegated to the JCE provider; the README honestly records that no side-channel hardening was done rather than claiming constant time.
- **Build hygiene:** `build.sh` uses `set -e`, quotes `"$(dirname "$0")"`, passes `-Xlint:all -Werror` (warnings become errors, so unchecked/deprecated crypto use cannot creep in), and contains no unquoted variable expansion, `curl | sh`, or `sudo`.
- **Mutation harness safety:** `.mutation/run_mutants.py` applies the 24 defect classes from `.mutation/mutants.tsv` only to copies under `.mutation/work/` and never writes to `src/` or `test/`; the reviewed sources are pristine (confirmed by inspecting the harness logic and current source content).
- **Key-management design reviewed:** the single shared passphrase gives no separation of duties, no rotation path and no proof of origin. This is explicitly disclosed as a limitation in `README.md` ("One shared passphrase for everything is weak", "A demo, not a audited library. No formal review, no side-channel hardening.") and is a documented scoping decision rather than a defect in this codebase; the durable recommendation, per the AES and KMS skills, is a per-record DEK wrapped by a KMS/HSM-held KEK for any regulated deployment.
- **Denial-of-service balance:** encrypt-side `PASSPHRASE_MAX_CHARS = 1024` keeps the PBKDF2 cost per call bounded for legitimate use; on the decrypt side each token costs one derivation by design (the salt is per-token), which is the intended anti-guessing property, so the accepted trade-off is recorded here rather than reported as a finding.
