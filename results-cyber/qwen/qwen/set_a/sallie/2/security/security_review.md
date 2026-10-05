# Security Review: `pii` — AES-256/GCM protection for a name and an email address

## 1. Executive Summary

The component is a small, dependency-free Java 17 utility that encrypts a person's name and
email with AES-256-GCM, stores the result as a single `v1:base64` envelope, and decrypts it
again. The core cryptographic design is **correct and unusually careful for its size**:
authenticated encryption with a fresh random 96-bit IV per record, a 128-bit tag, the version
byte and IV covered as additional authenticated data, key length validated before
`SecretKeySpec` can accept a weak key, the strict Base64 decoder used deliberately to avoid
`getMimeDecoder()`'s silent character dropping, decrypted bytes re-parsed as untrusted input,
and secret buffers wiped as a matter of routine. There is no key, password or token anywhere
in the source, and none in the compiled classes.

The findings are concentrated at the **edges of the process**, not in the cipher: how the key
reaches disk, how the key and the PII reach the program, and what the program writes to its
error stream. The single most consequential issue is that `PiiKeygen` writes the master key to
disk **before** it tightens the file's permissions, so on a shared host the new AES-256 key is
briefly readable by every local user — and if the filesystem cannot apply POSIX permissions,
the tool prints a hint, keeps the permissive file, and still reports success.

**7 findings: 1 High, 2 Medium, 4 Low.** None of them is a flaw in AES-GCM usage itself; a
fix pass confined to `PiiKeygen.java` and `PiiCli.java` removes every finding except the two
informational-grade cryptographic-lifetime notes (SEC-06, SEC-07), which are hardening.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/pii/PiiCipher.java` | AES-256/GCM encrypt + decrypt of a record | AEAD mode selection, per-record random IV, AAD over version‖IV, tag verification, key length gate, `SecretKeySpec`/`GCMParameterSpec` construction, key copy + `close()` wipe |
| `src/main/java/pii/PiiRecord.java` | Holds name + email, serialises to/from length-prefixed bytes | Input validation (blank, length, control/format/unassigned chars, lone surrogates, email plausibility); treats decrypted bytes as untrusted; **rejection messages interpolate the offending email** |
| `src/main/java/pii/ProtectedPii.java` | Encrypted envelope + `v1:base64` storage format | Defensive cloning of `iv`/`ciphertext`/`tag`, strict Base64 parse, length-overhead and version gates, `toString()` that emits only lengths |
| `src/main/java/pii/KeyProvider.java` | Locates and validates the key at runtime | Key from `--key-file`/`PII_KEY_FILE`, then `--key`/`PII_KEY`; env names themselves overridable via `PII_KEY_FILE_VAR`/`PII_KEY_VAR`; strict Base64 + exact 32-byte check; raw file bytes and short keys wiped |
| `src/main/java/pii/PiiKeygen.java` | Generates a new key file | Writes Base64 key to a caller-chosen path, **then** sets `rw-------`; refuses overwrite without `--force`; `--print` echoes the key to stdout |
| `src/main/java/pii/PiiCli.java` | Command line demo | Accepts name, email and key as argv; prints plaintext PII and ciphertext to stdout; prints rejection messages and stack traces to stderr; wipes the key in `finally` |
| `src/test/java/pii/PiiSelfTest.java` | 156 self-checks, no framework | Round trip, tamper/negative tests, malformed-envelope and key-loading rejection, wipe/clone assertions, subprocess CLI runs that unset `PII_KEY`/`PII_KEY_FILE` and assert the key never appears in output |
| `out/pii/*.class` | Compiled output | Scanned for embedded key material; none present |
| `README.md` | Documentation | Documents key precedence, strict-decoder rationale, and admits the PII-on-the-command-line limitation |
| `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt` | Task-harness files, not part of the component | Not reviewed for defects; contain no key material |

## 3. Skills Applied

- **`performing-cryptographic-audit-of-application`** — the organising pass over `PiiCipher.java`, `KeyProvider.java` and `PiiKeygen.java`: primitive and mode selection (AEAD vs. unauthenticated), IV/nonce sourcing and uniqueness, key length and `SecretKeySpec` leniency, absence of hardcoded or derived keys, key storage and lifecycle (copy, wipe, rotation path), and whether the authentication tag is actually verified before plaintext is returned. Drove SEC-01, SEC-02 and SEC-07, and the checks in section 6.
- **`implementing-aes-encryption-for-data-at-rest`** — applied specifically to `PiiCipher.encrypt`/`decrypt` and the `ProtectedPii` envelope: 96-bit IV and 128-bit tag sizing, AAD binding of version and IV, ciphertext‖tag framing, per-record randomness, and the nonce-budget/rekeying expectation the standard places on random nonces. Drove SEC-06 and SEC-07.
- **`testing-for-sensitive-data-exposure`** — applied to everything that leaves the process: key material and PII in argv and environment, stdout/stderr contents, exception text, and the on-disk key file's permissions. Drove SEC-01 through SEC-05.
- Checked at description level and **deliberately not applied**, because no matching behaviour exists in this code: `implementing-secrets-management-with-vault` and `implementing-secret-scanning-with-gitleaks` (no vault client and no secrets in source — verified, so there was nothing to apply), `exploiting-insecure-deserialization` (no `ObjectInputStream`, no reflective/gadget-capable parser — the only byte-parsing is the hand-written length-prefixed reader), `implementing-rsa-key-pair-management` (symmetric key only, no key pairs), `performing-directory-traversal-testing` (no user-supplied path is joined onto a served root; the only path is the operator's own `--out`/`--key-file` argument).

**Reviewed against general OWASP Top 10 / CWE knowledge only (no specialised skill in the library matched this behaviour):** the in-memory lifetime of decrypted PII and the impossibility of erasing the `String` fields of `PiiRecord` (SEC-06's context), the hardening of the untrusted parsers in `ProtectedPii.fromBase64` and `PiiRecord.fromPlaintextBytes`, and command-line argument handling / error-surface hygiene in `PiiCli` where it did not fall under the sensitive-data-exposure skill.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Key file is created world-readable; permissions are tightened only after the write | High | CWE-276 | `src/main/java/pii/PiiKeygen.java:69` |
| SEC-02 | AES key accepted as a `--key` command-line argument | Medium | CWE-522 | `src/main/java/pii/PiiCli.java:33` |
| SEC-03 | Plaintext name and email passed as argv and echoed to stdout | Medium | CWE-359 | `src/main/java/pii/PiiCli.java:31` |
| SEC-04 | Full Java stack trace printed to stderr for unexpected errors | Low | CWE-209 | `src/main/java/pii/PiiCli.java:66` |
| SEC-05 | Email validation messages embed the entire address, which the CLI echoes | Low | CWE-209 | `src/main/java/pii/PiiRecord.java:138` |
| SEC-06 | Plaintext PII buffer in `encrypt()` is never wiped | Low | CWE-244 | `src/main/java/pii/PiiCipher.java:76` |
| SEC-07 | Random 96-bit IV with no nonce budget or rekeying control | Low | CWE-323 | `src/main/java/pii/PiiCipher.java:71` |

## 5. Detailed Findings

### SEC-01: Key file is created world-readable; permissions are tightened only after the write

- **Severity:** High
- **CWE:** CWE-276: Incorrect Default Permissions (related: CWE-732 Incorrect Permission Assignment for Critical Resource)
- **Location:** `src/main/java/pii/PiiKeygen.java:69`

**Vulnerable code:**

```java
        byte[] key = KeyProvider.newKey(new SecureRandom());
        String encoded = Base64.getEncoder().encodeToString(key);
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(file, encoded.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            restrictToOwner(file);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
```

**Why it is a problem:**

`Files.write` with no options is `CREATE + TRUNCATE_EXISTING + WRITE`: a *new* file is created
with the platform default mode `0666` masked by umask, which on most systems is **`0644` —
readable by every user on the machine**. `restrictToOwner(file)` on the next line is what makes
it `0600`, so there is an unavoidable window in which the freshly generated master key sits
world-readable on disk. On a shared host or a CI runner, another local user needs only a poll
loop on `./pii-key.bin` to capture the key. `Files.createDirectories(parent)` has the same
shape: `java pii.PiiKeygen --out /secrets/pii.key` will happily create `/secrets` as `0755`.

The window is not the whole story — the failure mode is durable. `restrictToOwner`
(`PiiKeygen.java:89-99`) catches `UnsupportedOperationException` and `IOException` and merely
prints "protect ... some other way" / "do it manually". Filesystems and mounts where
`setPosixFilePermissions` is unsupported or denied are common (FAT/exFAT media, some CIFS/SMB
and NFS mounts, volumes with ACLs managed out-of-band). In those cases the key file stays at
`0644` permanently, and `main` proceeds to print `Wrote a new AES-256 key ... to <path>` and
exits `0`, so a script or container entrypoint has no signal that the key is unprotected.
Compromise of this key is total: one 32-byte read decrypts every record ever protected.

**Fix:**

Request the restrictive mode at create time so the file is never broadly readable, and fail
closed if the resulting permissions are not owner-only instead of warning and continuing.
(Requiring `CREATE_NEW` also removes the truncation race against an existing path.)

```java
        byte[] key = KeyProvider.newKey(new SecureRandom());
        String encoded = Base64.getEncoder().encodeToString(key);
        try {
            Set<PosixFilePermission> dirMode = PosixFilePermissions.fromString("rwx------");
            Set<PosixFilePermission> fileMode = PosixFilePermissions.fromString("rw-------");
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent, PosixFilePermissions.asFileAttribute(dirMode));
            }
            byte[] material = encoded.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(
                    file,
                    Set.of(java.nio.file.StandardOpenOption.CREATE_NEW,
                           java.nio.file.StandardOpenOption.WRITE),
                    PosixFilePermissions.asFileAttribute(fileMode))) {
                channel.write(java.nio.ByteBuffer.wrap(material));
            } catch (UnsupportedOperationException notPosix) {
                // No POSIX create-time attribute available: write, then tighten, then verify.
                Files.write(file, material, java.nio.file.StandardOpenOption.CREATE_NEW,
                        java.nio.file.StandardOpenOption.WRITE);
                restrictToOwner(file);
            } finally {
                java.util.Arrays.fill(material, (byte) 0);
            }
            // Fail closed. umask can only narrow a mode, and an ACL or a remap can defeat
            // the create-time attribute, so verify the outcome rather than assume it.
            if (!fileMode.equals(Files.getPosixFilePermissions(file))) {
                Files.delete(file);
                throw new java.io.IOException("Refusing to keep a key file that is not owner-only: "
                        + file + " (deleted again - set a umask of 077 or use a POSIX filesystem)");
            }
        } finally {
            Arrays.fill(key, (byte) 0);
        }
```

### SEC-02: AES key accepted as a `--key` command-line argument

- **Severity:** Medium
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `src/main/java/pii/PiiCli.java:33`

**Vulnerable code:**

```java
                    case "--key" -> key = value(args, ++i, arg);
```

**Why it is a problem:**

Command-line arguments are not confidential. On Linux `/proc/<pid>/cmdline` is world-readable
(unless `hidepid=` is set on the mount), so any local user running `ps` or `pgrep -a java`
during the run sees the full Base64 key; the same string is also written verbatim into the
operator's shell history, into any `script`/`auditd`/EDA process-exec telemetry, and into CI
job logs that echo the command line. The README's own usage examples advertise this form:
`java -cp out pii.PiiCli --key "$(cat /secrets/pii.key)" ...`.

This is worse than the alternatives the program already supports. `PII_KEY` in the environment
is materially safer because `/proc/<pid>/environ` is owner-only (`0400`) on Linux, and
`--key-file`/`PII_KEY_FILE` never puts the key in the process table at all. The program's key
precedence (`KeyProvider.java:52-59`) therefore ends up offering the *weakest* transport as the
most discoverable option, and `--key` silently overrides nothing — it only serves the inline
case. Note this is a key-exposure issue distinct from SEC-03, which is about the PII itself.

**Fix:**

Remove the inline key path, and explain the reason rather than accepting the value silently:

```java
                    case "--key" -> {
                        System.err.println("--key puts the AES key in the process list and the shell history.");
                        System.err.println("Use --key-file PATH"
                                + " (or export " + KeyProvider.DEFAULT_KEY_FILE_VAR + " instead).");
                        System.exit(2);
                        return;
                    }
```

If an inline value must be kept for scripting, accept a *file descriptor* or read it from
standard input instead, which never appears in argv:

```java
                    case "--key-fd" -> key = readLineFromFd(Integer.parseInt(value(args, ++i, arg)));
```

### SEC-03: Plaintext name and email passed as argv and echoed to stdout

- **Severity:** Medium
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **Location:** `src/main/java/pii/PiiCli.java:31`

**Vulnerable code:**

```java
                    case "--name" -> name = value(args, ++i, arg);
                    case "--email" -> email = value(args, ++i, arg);
```

**Why it is a problem:**

The whole point of the component is that a name and email are only readable with the key, yet
both are handed to the process in cleartext through argv and then printed back in cleartext —
`PiiCli.java:80-81` (`System.out.println("   name : " + original.name());` and the matching
email line) and again after decryption at `PiiCli.java:105-106`.argv is visible to every local
user through `/proc/<pid>/cmdline`, and the values persist in shell history and in anything that
captures stdout (terminal recordings, CI logs, `tee`, log shippers). Under GDPR/UK-GDPR terms
this is personal data disclosed to an unauthorised audience; the encryption is defeated by the
delivery mechanism around it. `README.md` lists this honestly under "Honest limitations" — an
acknowledged limitation is still the finding, and the fix the README itself proposes ("read them
from standard input or an API request") is small. This is the same argv mechanism as SEC-02 but
a different secret, a different CWE and a different fix.

**Fix:**

Accept the PII on standard input by default, keeping argv only as a convenience that says so:

```java
        if (name == null || email == null) {
            System.err.println("Reading name and email from standard input (line 1 = name, line 2 = email).");
            try (java.io.BufferedReader in = new java.io.BufferedReader(new java.io.InputStreamReader(
                    System.in, java.nio.charset.StandardCharsets.UTF_8))) {
                name = in.readLine();
                email = in.readLine();
            } catch (java.io.IOException e) {
                System.err.println("Cannot read standard input: " + e.getMessage());
                System.exit(2);
                return;
            }
        }
        if (name == null || email == null) {
            System.err.println("Both a name and an email are required (--name/--email or two input lines).");
            usage(System.err);
            System.exit(2);
            return;
        }
```

In a real service, replace the demo's plaintext echo with a masked rendering
(`A*** L*******`, `a***@example.com`) behind an explicit `--show-values` flag.

### SEC-04: Full Java stack trace printed to stderr for unexpected errors

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/main/java/pii/PiiCli.java:66`

**Vulnerable code:**

```java
        } catch (Exception e) {
            System.err.println("Failed: " + e.getMessage());
            if (!(e instanceof java.security.GeneralSecurityException)) {
                e.printStackTrace(System.err);
            }
            System.exit(4);
```

**Why it is a problem:**

The guard deliberately suppresses traces for `GeneralSecurityException` — the expected,
key-related failures — but prints the full trace for everything else. A raw trace discloses
absolute filesystem paths, the JDK build and version, internal package and method names, and
argument values from the frame dump, all of which hand an attacker a map of the deployment and
its version. Worse, the "expected" filter is drawn on the wrong axis: `IllegalArgumentException`
from `PiiRecord` is caught earlier (`PiiCli.java:60`) and never reaches here, but an
`ArrayIndexOutOfBoundsException` from argument parsing or an `IOException` whose message echoes
a path does — and, unlike `GeneralSecurityException`, those messages are exactly where the
component's own input values surface (`PiiCli.java:64` already prints `e.getMessage()`
unfiltered).

**Fix:**

Keep the detail behind an opt-in switch, and surface only a stable, non-revealing message plus a
correlation reference to operators:

```java
        } catch (Exception e) {
            long reference = System.nanoTime() & 0xFFFFFFF;
            System.err.println("Failed (reference " + Long.toHexString(reference) + "): "
                    + summarise(e));   // exception class + generic cause category, never e.getMessage()
            if (Boolean.getBoolean("pii.debug")) {
                e.printStackTrace(System.err);   // opt in with -Dpii.debug=true
            } else {
                java.util.logging.Logger.getLogger(PiiCli.class.getName())
                        .log(java.util.logging.Level.SEVERE, "failure " + Long.toHexString(reference), e);
            }
            System.exit(4);
```

### SEC-05: Email validation messages embed the entire address, which the CLI echoes

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information (also CWE-359 when stderr is captured)
- **Location:** `src/main/java/pii/PiiRecord.java:138`

**Vulnerable code:**

```java
        int at = email.indexOf('@');
        if (at < 0) {
            throw new IllegalArgumentException("email must contain exactly one '@' (none found): " + email);
        }
```

**Why it is a problem:**

Every rejection inside `requirePlausibleEmail` concatenates the **whole** email value into the
message: `PiiRecord.java:138`, `141`, `146`, `149`, `152`, `156`, `163` and `171`. `PiiCli` then
prints that message verbatim — `System.err.println("Input rejected: " + e.getMessage());` at
`PiiCli.java:61` — so a rejected email lands in stderr and in any log that captures it. That is
PII written to a channel whose access controls are almost always weaker than the database that
holds the encrypted envelope, and it is the one path on which the data is guaranteed to be
malformed and therefore unexpected.

The inconsistency proves the intended rule: the sibling validator `requireText` never echoes
the value for the *name* field, reporting only an index — `what + " contains a lone surrogate at
index " + i` (`PiiRecord.java:118`, `125`) and `what + " must be at most " + maxChars +
" characters (was " + value.length() + ")"` (`PiiRecord.java:113`). An index is enough to
explain the defect; the value is not needed and is exactly what must not leak. Same weakness
class as SEC-04, different source and fix.

**Fix:**

Drop the value and report the offending position instead, matching `requireText`:

```java
        int at = email.indexOf('@');
        if (at < 0) {
            throw new IllegalArgumentException("email must contain exactly one '@' (none found)");
        }
        int second = email.indexOf('@', at + 1);
        if (second >= 0) {
            throw new IllegalArgumentException("email must contain exactly one '@' (found one at index "
                    + at + " and another at index " + second + ")");
        }
```

Apply the same change at `PiiRecord.java:146`, `149`, `152`, `156`, `163` and `171` — replacing
each `": " + email` suffix with an index, and for the forbidden-character case at line 171 with
`"... forbidden character (code point " + cp + ") at index " + i`.

### SEC-06: Plaintext PII buffer in `encrypt()` is never wiped

- **Severity:** Low
- **CWE:** CWE-244: Improper Clearing of Heap Memory Before Release ('Improper Erase of Memory')
- **Location:** `src/main/java/pii/PiiCipher.java:76`

**Vulnerable code:**

```java
        Cipher cipher = newCipher(Cipher.ENCRYPT_MODE, iv);
        cipher.updateAAD(associatedData(VERSION, iv));
        // GCM is a stream mode: doFinal returns the whole ciphertext followed by the tag.
        byte[] withTag = cipher.doFinal(pii.toPlaintextBytes());
```

**Why it is a problem:**

`pii.toPlaintextBytes()` allocates an array holding the entire plaintext record (name + email).
Because it is passed inline as an argument, nothing in this method keeps a reference to it, so
nothing can wipe it — it is left for the garbage collector to relocate and discard, potentially
copying it through generational survivors on the way. That directly contradicts the rule the
rest of the class follows for identical data: the ciphertext-and-tag buffer is wiped in a
`finally` at `PiiCipher.java:83`, the re-packed decrypt input at `PiiCipher.java:114`, and the
decrypted plaintext at `PiiCipher.java:107`. The encrypt path is the only place where a
plaintext PII buffer escapes the wiping discipline, and `PiiSelfTest` asserts the wipe behaviour
for the decrypt direction but cannot assert it here because there is no named array to check.

**Fix:**

Hoist the plaintext into a named local and wipe it in a `finally`, mirroring `decrypt`:

```java
    public ProtectedPii encrypt(PiiRecord pii) throws GeneralSecurityException {
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        byte[] plaintext = pii.toPlaintextBytes();
        try {
            Cipher cipher = newCipher(Cipher.ENCRYPT_MODE, iv);
            cipher.updateAAD(associatedData(VERSION, iv));
            // GCM is a stream mode: doFinal returns the whole ciphertext followed by the tag.
            byte[] withTag = cipher.doFinal(plaintext);
            try {
                if (withTag.length <= TAG_BYTES) {
                    throw new GeneralSecurityException("AES-GCM produced an impossibly short result of "
                            + withTag.length + " bytes");
                }
                byte[] ciphertext = Arrays.copyOfRange(withTag, 0, withTag.length - TAG_BYTES);
                byte[] tag = Arrays.copyOfRange(withTag, withTag.length - TAG_BYTES, withTag.length);
                return new ProtectedPii(VERSION, iv, ciphertext, tag);
            } finally {
                Arrays.fill(withTag, (byte) 0);
            }
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }
```

This is hardening, not a fix-all: `PiiRecord` still holds the name and email as immutable
`String`s, which cannot be erased at all, so a heap dump taken while a record is live still
shows the PII. Erasing that properly means carrying the values as `char[]`/`ByteBuffer` and
interning nothing — a larger refactor than the finding warrants.

### SEC-07: Random 96-bit IV with no nonce budget or rekeying control

- **Severity:** Low
- **CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption
- **Location:** `src/main/java/pii/PiiCipher.java:71`

**Vulnerable code:**

```java
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
```

**Why it is a problem:**

Per-record randomness is the right choice here — it is what stops two people with the same email
producing matching rows — but a random 96-bit GCM nonce is only safe within a bounded
invocation count. NIST SP 800-38D §8.3 caps a key at 2³² invocations when nonces are random,
because the birthday bound makes a nonce collision likely as that budget is approached, and a
single IV repeat under one key in GCM is catastrophic: the two messages are XORed under the same
keystream (loss of confidentiality), and the GHASH subkey can be recovered from the forgery
standing, which breaks authentication for the whole key. `PiiCipher` enforces nothing about this
— there is no per-key record counter, no exhaustion check, and nothing in the API that makes a
caller aware they must re-key. `PiiKeygen` produces one key, `README.md` mentions rotation only
as a manual procedure, and `new PiiCipher(key)` can be used to encrypt an unbounded number of
records. The class also cannot detect an IV collision with a previous record because it holds no
IV history. The trigger is high volume (a personal-data table reaching billions of rows), which
is why this is Low rather than Medium — but for a component whose stated job is protecting an
email column, the budget should be enforced by the code, not by a paragraph in a README.

**Fix:**

Track the per-key nonce budget and refuse to encrypt past it, so exhaustion fails loudly instead
of silently degrading:

```java
    /** SP 800-38D 8.3: a key whose IVs are random must not encrypt more than 2^32 records. */
    private static final long MAX_RECORDS_PER_KEY = 1L << 32;

    private final AtomicLong recordsEncrypted = new AtomicLong();

    public ProtectedPii encrypt(PiiRecord pii) throws GeneralSecurityException {
        if (recordsEncrypted.incrementAndGet() > MAX_RECORDS_PER_KEY) {
            throw new GeneralSecurityException("IV budget for this key is exhausted. Re-key with pii.PiiKeygen,"
                    + " decrypt everything with the old key and re-encrypt with the new one.");
        }
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        // ... unchanged from here
```

For deployments that will not reach 2³² records per JVM but do reuse one key across many
processes, prefer the deterministic alternative from SP 800-38D §8.2.2 (a per-key random field
plus a strictly monotonic 64-bit invocation counter persisted with the key state), which removes
the birthday bound entirely — but only if the counter genuinely survives restarts; a counter
that resets to zero in each new process is worse than the random scheme.

## 6. Verified Controls and Checks With No Finding

The following were checked and are correct as implemented. They are listed because each is a
place where this class of program typically goes wrong.

- **No key material in source or bytecode.** `KeyProvider` documents and enforces
  "no built-in key"; a scan of every `out/pii/*.class` and `src/**/*.java` file for 43–44
  character Base64 runs (the exact length of a Base64-encoded 256-bit key) returned only two
  matches, both inside `README.md`'s illustrative `v1:AZHXX…` **ciphertext** sample. There is no
  `MessageDigest`-derived, password-derived or default-key fallback anywhere.
- **Key length gate before `SecretKeySpec`.** `PiiCipher.java:54-58` rejects anything other than
  32 bytes with a message that names the `SecretKeySpec` leniency; `SecretKeySpec` is then built
  only from validated bytes (`PiiCipher.java:154`). The test at `PiiSelfTest.java:337` keeps the
  leniency visible as a positive control.
- **Strict Base64 on key material, whitespace stripped explicitly.**
  `KeyProvider.java:103-105` uses `Base64.getDecoder()` after `text.replaceAll("\\s", "")`,
  rather than tolerating junk through `getMimeDecoder()`; a short decode is wiped before the
  throw (`KeyProvider.java:113`). A URL-safe-alphabet key is rejected, not silently accepted.
- **AEAD, single transformation, no unauthenticated or block-mode fallback.**
  `Cipher.getInstance(TRANSFORMATION)` where `TRANSFORMATION = "AES/GCM/NoPadding"`
  (`PiiCipher.java:39`, `151`) with `GCMParameterSpec(TAG_BITS, iv)`; no `ECB`, no `CBC` without
  a MAC, no `DES`/`MD5`/`SHA-1` anywhere in the tree.
- **Fresh IV per record, and the IV is authenticated.** `PiiCipher.java:71-72` draws 12 bytes
  from `SecureRandom` per call; `updateAAD(associatedData(version, iv))` (`PiiCipher.java:74`,
  `104`, `143-148`) puts the version byte and IV under the tag, so IV swapping and version
  downgrades fail closed — matching the IV-swap and tamper tests.
- **Tag verified before any plaintext is returned.** `AEADBadTagException` is mapped to a
  `GeneralSecurityException` that names the failed tag check (`PiiCipher.java:110-112`);
  `decrypt` returns nothing on failure, so a wrong key never yields plausible-looking garbage.
- **KeyProvider error text never echoes key material.** `KeyProvider.java:99`, `106-107` and
  `114-116` name only the *source* (`environment variable PII_KEY`, `key file <path>`) and the
  decoded length — never the value. `PiiSelfTest` additionally asserts the CLI's printed output
  never contains the key.
- **Envelope parsing treats input as hostile.** `ProtectedPii.fromBase64`
  (`ProtectedPii.java:99-127`) enforces the `v1:` prefix, the strict alphabet, a length-overhead
  floor (`:114`) and an exact version match (`:133-139`); accessors clone
  (`ProtectedPii.java:34-47`) and `toString()` (`:68-72`) emits lengths only, so an envelope can
  be logged safely.
- **Decrypted bytes re-validated.** `PiiRecord.fromPlaintextBytes` rejects negative,
  oversized and non-matching declared field lengths, any trailing bytes, and decodes UTF-8 with
  `CodingErrorAction.REPORT` (`PiiRecord.java:94-99`) before re-running every `requireText` and
  `requirePlausibleEmail` rule — so a valid-tag envelope produced by a buggy writer cannot smuggle
  an unvalidated value into a `PiiRecord`.
- **Secret buffers wiped along every path that was checked** (except the one in SEC-06): the
  caller's key array in `PiiCli.java:69-72`, the internal copy in `PiiCipher.close()`
  (`PiiCipher.java:160-161`), raw key-file bytes in `KeyProvider.java:80-82`, and the generated
  key in `PiiKeygen.java:72-73`.
- **Key material is copied, not aliased.** `this.keyBytes = key.clone()`
  (`PiiCipher.java:60`) plus `ProtectedPii`'s cloning constructor mean a caller wiping its own
  buffers cannot silently corrupt live objects.
- **No unsafe deserialization, command execution, or script evaluation in the shipped classes.**
  No `ObjectInputStream`, no `Runtime.exec`, no `ScriptEngine`; the only `ProcessBuilder` is in
  `PiiSelfTest.java:585`, launching a fixed `java -cp out …` argument list with no shell and no
  interpolation of untrusted data.
- **Overwrite protection on the key file.** `PiiKeygen.java:54-60` refuses to clobber an existing
  key without `--force` (exit 3), which prevents silent mass data loss as well as an
  accidental-key-replacement scenario.
- **Negative-case coverage exists and is broad.** Tampering with ciphertext, IV and tag bytes,
  truncation, IV swapping between records, wrong key, malformed prefix, junk Base64, wrong-length
  components, a future format version, directory-instead-of-file key path, 16-byte key, empty
  key, and no key at all are each asserted to be refused, including subprocess-level CLI checks
  that unset `PII_KEY`/`PII_KEY_FILE` and use a `ClassNotFoundException` control so a non-zero
  exit can only mean rejection of arguments.
- **Out of scope for defects:** `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`
  and `return.txt` are task-harness artefacts, not part of the component.
