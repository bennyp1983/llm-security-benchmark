# Security Review — `com.example.crypto` (AES-256-GCM data-at-rest CLI/library)

Scope: all 8 Java sources under `src/com/example/crypto/` plus `README.md`.
Method: the `review-code-for-security-vulnerabilities` router skill — understand the code,
select matching specialised skills from the library, apply them, report with CWE + `file:line`.

## 1. What each file does (and its security-relevant behaviour)

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `SymmetricCipher.java` | AES-256-GCM encrypt/decrypt + the `SDC1` envelope format | cipher/mode selection, IV generation (`SecureRandom`), AAD binding, envelope parsing of untrusted bytes, key destruction |
| `KeyProvider.java` | Interface for key sources | contract that per-message KDF parameters travel in the clear inside the envelope |
| `KeyStoreKeyProvider.java` | PKCS#12 keystore load + `genkey` | keystore password handling, file permission checks, temp-file creation, key generation, rotation policy |
| `EnvironmentKeyProvider.java` | Base64 AES key from an env var | secret read from process environment, base64 decode, length validation, memory wiping |
| `PassphraseKeyProvider.java` | PBKDF2-HMAC-SHA256 key derivation | KDF algorithm/iterations/salt, parameters parsed from an *unauthenticated* envelope |
| `Secrets.java` | Secret reading, wiping, POSIX permission helpers | env/console secret reads, `char[]`/`byte[]` wiping, `chmod` helpers |
| `Main.java` | CLI (`genkey`/`encrypt`/`decrypt`/`selftest`) | argument parsing, plaintext via `--text`, file/stdin input, base64 I/O, error reporting, printing a raw key to stdout |
| `SelfTest.java` | Round-trip, uniqueness and tamper-rejection checks | in-memory `FixedKey` test provider; no production key handling |

Keywords derived: *cryptography, AES-GCM, IV/nonce management, key management, PBKDF2/KDF parameters,
secrets in environment, key material in memory, file permissions / temp files, parsing untrusted input,
denial of service, information exposure*.

## 2. Overall assessment

The core cryptography is well done and I could not find a break in confidentiality or integrity of the
envelope format. The findings below are in **key-material handling around the cipher** (temp file
creation, secrets in memory, secrets on the command line) and in **hardening of the untrusted-input
paths** (unbounded KDF work factor, unbounded allocation), not in the AEAD construction itself.

Highest-impact issue: **F1 — non-atomic, predictable temp file used to write the PKCS#12 keystore.**

## 3. Findings

### F1. Keystore written to a predictable temp file created before its permissions are set — MEDIUM-HIGH
- **CWE-378** (Creation of Temporary File with Insecure Permissions), with **CWE-59** (link following)
  and **CWE-367** (TOCTOU) as the exploitation paths.
- **Evidence:** `src/com/example/crypto/KeyStoreKeyProvider.java:117-124`

```java
Path tmp = storePath.resolveSibling(storePath.getFileName() + ".tmp");   // :117 predictable name
try (OutputStream out = Files.newOutputStream(
        tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE)) {                                     // :118-120 created with umask perms
    Secrets.restrictToOwner(tmp);                                        // :121 chmod happens *after* creation
    store.store(out, password);                                          // :122 key bytes written
}
```

- **Why it is a problem.** The comment on `:115-116` claims the file is created with owner-only
  permissions "before any bytes are written", but `Files.newOutputStream` is given no
  `FileAttribute`, so the file is created with the process umask (commonly `rw-r--r--`) and only
  `chmod`-ed afterwards. Two concrete attacks:
  1. *Open-then-wait (TOCTOU):* a local user opens `sdc-keystore.p12.tmp` during the window between
     `:118` and `:121`. The later `chmod` does not revoke an already-open descriptor, so they read
     the PKCS#12 blob once `store.store` writes it, and can then attack the keystore password offline.
  2. *Symlink pre-placement:* the name is fully predictable and lives in the caller-supplied
     directory (`--keystore` may point at a shared directory such as `/tmp`). `StandardOpenOption.CREATE`
     follows symlinks, so an attacker who pre-creates `sdc-keystore.p12.tmp` as a symlink has the
     keystore written to a file they control. `Secrets.restrictToOwner` cannot save this: it uses
     `LinkOption.NOFOLLOW_LINKS` (`Secrets.java:64`) and so targets the link, not the file that
     actually received the key bytes.
- **Fix.** Create the temp file atomically with restrictive permissions and refuse to reuse an
  existing path:
```java
Path tmp = Files.createTempFile(storePath.toAbsolutePath().getParent(), ".sdc", ".p12",
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
```
  (or `StandardOpenOption.CREATE_NEW` + `asFileAttribute(...)` on `newOutputStream`), and delete the
  temp file in a `catch`/`finally` so a failed `store.store` does not leave key material behind
  (currently `:118-123` leaks the `.tmp` file on error). On non-POSIX filesystems, fail closed rather
  than silently continuing, since `restrictToOwner` is a no-op there (`Secrets.java:65-67`).

### F2. PBKDF2 iteration count taken from an unauthenticated envelope with no upper bound — MEDIUM
- **CWE-1284** (Improper Validation of Specified Quantity in Input) / **CWE-400** (Uncontrolled
  Resource Consumption); enabling design issue **CWE-345** (Insufficient Verification of Data Authenticity).
- **Evidence:** `src/com/example/crypto/PassphraseKeyProvider.java:58-63`, driven by
  `src/com/example/crypto/SymmetricCipher.java:128` (`keyProvider.resolve(params)` runs *before*
  `cipher.doFinal` verifies the GCM tag).

```java
int iterations = buf.getInt();                       // :58 attacker-controlled, up to 2^31-1
if (iterations < MIN_ITERATIONS) { ... }             // :62 lower bound only
```
```java
spec = new PBEKeySpec(passphrase, salt, iterations, SymmetricCipher.KEY_BITS);   // :71
```

- **Why it is a problem.** The code comments correctly identify that a *low* iteration count is
  attacker-usable and guard against it, but the symmetric case is unguarded. An attacker who can hand
  the passphrase-provider path a crafted envelope sets `iterations = 2147483647`; the victim spends
  hours of CPU in `generateSecret` before the tag check ever runs. The header is authenticated, but
  authentication happens *after* the KDF, so the tag provides no protection here — exactly the
  asymmetry the `:59-61` comment relies on, applied in only one direction. Repeated submissions are
  a cheap CPU-exhaustion DoS against any service that decrypts caller-supplied ciphertext.
- **Fix.** Bound the count both ways, e.g. `if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS)`
  with `MAX_ITERATIONS = 10_000_000` (a few seconds of work), and reject otherwise. Same reasoning
  should be applied to any future parameter that sizes work or memory.

### F3. Keystore password and AES key are materialised as immutable `String`s that cannot be wiped — LOW-MEDIUM
- **CWE-316** (Cleartext Storage of Sensitive Information in Memory).
- **Evidence:** `src/com/example/crypto/Secrets.java:29-31`, `src/com/example/crypto/EnvironmentKeyProvider.java:42-48`

```java
String fromEnv = System.getenv(envVar);      // Secrets.java:29  password now lives in an immutable String
if (fromEnv != null && !fromEnv.isEmpty()) {
    return fromEnv.toCharArray();            // Secrets.java:31  only the *copy* is ever wiped
}
```
```java
String encoded = System.getenv(envVar);      // EnvironmentKeyProvider.java:42 base64 AES-256 key as String
raw = Base64.getDecoder().decode(encoded.trim());  // :48 .trim() makes a second copy
```

- **Why it is a problem.** `Secrets.wipe(char[])` (`Secrets.java:45-49`) zeroes only the array copy.
  The originating `String` objects — plus the `String` produced by `.trim()` and the whole
  `Map<String,String>` returned by `System.getenv()`, which the JVM caches for the process lifetime —
  remain readable in the heap until GC, and are recoverable from a heap dump or core file. This
  materially weakens the README's claim that "key material is wiped from `char[]`/`byte[]` buffers
  after use". The `char[]` discipline elsewhere (`KeyStoreKeyProvider.java:84`,
  `PassphraseKeyProvider.java:80-82`) is correct and worth keeping — this is the one hole in it.
- **Fix.** There is no way to wipe a `String`, so reduce the exposure: prefer file-based credential
  delivery (systemd `LoadCredential`, a mounted secret file, `--password-file` read into a `byte[]`)
  over `System.getenv`, and clear the decoded `byte[]`/`char[]` as the code already does. If env vars
  must be supported, document the residual `String` exposure rather than implying full wiping.
  Note also (`EnvironmentKeyProvider.java:58-60`) that wiping `raw` after `new SecretKeySpec(raw, "AES")`
  *is* correct — `SecretKeySpec` clones its input — so that part needs no change.

### F4. Plaintext accepted on the command line via `--text`, and the README demonstrates it with an SSN — LOW-MEDIUM
- **CWE-214** (Invocation of Process Using Visible Sensitive Information).
- **Evidence:** `src/com/example/crypto/Main.java:120-122`; `Main.java:172` ("testing only");
  `README.md:14` — `Main encrypt --text 'ssn=123-45-6789' --aad user-7`.
- **Why it is a problem.** The design correctly refuses to take *secrets* as arguments
  (`Secrets.java:22-27`) — but `--text` carries the very data the tool exists to protect, and argv is
  world-readable through `/proc/<pid>/cmdline` and `ps`, and lands in shell history. The README's
  headline example puts a Social Security number there, so the documented happy path leaks the
  plaintext to every local user for the lifetime of the process.
- **Fix.** Keep `--text` for tests only but gate it (e.g. require `--unsafe-text`, or drop it and use
  stdin), and change the README example to `printf 'ssn=...' | java ... encrypt --aad user-7`.

### F5. `genkey --provider env` prints a raw AES-256 key to stdout — LOW
- **CWE-532** (Insertion of Sensitive Information into Log File) / CWE-214.
- **Evidence:** `src/com/example/crypto/Main.java:60-64`
- **Why it is a problem.** The base64 key goes to stdout, which in ordinary use is captured by shell
  history (`SDC_KEY=$(...)`), terminal scrollback, CI job logs, or a redirect into a file created with
  the ambient umask. The advisory line on `:62` does not prevent any of that.
- **Fix.** Write to a file created `rw-------` (`--out PATH`), or require an explicit
  `--print-key-to-stdout` acknowledgement, and refuse to print when stdout is not a TTY.

### F6. Keystore permission check is a TOCTOU against the subsequent open — LOW
- **CWE-367** (Time-of-check Time-of-use Race Condition).
- **Evidence:** `src/com/example/crypto/KeyStoreKeyProvider.java:56-69` — `Files.exists` (`:56`),
  `Secrets.isWorldOrGroupReadable` (`:60`) and `Files.newInputStream` (`:67`) each resolve the path
  independently.
- **Why it is a problem.** The refusal on `:63-64` is good practice, but between the check and the
  open the path can be swapped (e.g. for a symlink to an attacker-controlled keystore), so the file
  actually loaded need not be the file that was vetted. Impact is limited — an attacker who can do
  this usually has write access to the keystore directory already — hence LOW.
- **Fix.** Open the file once and check permissions on the *descriptor*
  (`Files.newByteChannel(path, Set.of(READ), ...)` then `Files.readAttributes(path, PosixFileAttributes.class, NOFOLLOW_LINKS)`
  on the opened path, or verify via `/proc/self/fd`), rather than re-resolving the path three times.

### F7. Whole input is read and decoded into memory with no size limit — LOW
- **CWE-789** (Memory Allocation with Excessive Size Value) / CWE-400.
- **Evidence:** `src/com/example/crypto/Main.java:126-130` (`Files.readAllBytes` / `stdin.readAllBytes`)
  and `Main.java:87` (base64-decoding the entire input into a second array).
- **Why it is a problem.** A large `--in` file or stdin stream produces at least three full copies
  (raw bytes, `String`, decoded array) and an `OutOfMemoryError`. The README acknowledges the
  non-streaming design as a limitation; the concrete security consequence is an availability failure
  on untrusted input, and an OOM heap dump can contain plaintext and key bytes.
- **Fix.** Enforce a configurable maximum input size before reading, and treat oversized input as a
  clean error. Longer term, the chunked-and-individually-authenticated streaming format the README
  describes.

### F8. Error messages distinguish "wrong password" from other keystore failures — LOW
- **CWE-209** (Generation of Error Message Containing Sensitive Information).
- **Evidence:** `src/com/example/crypto/KeyStoreKeyProvider.java:78-79` ("wrong keystore password for
  alias 'x'"), `:70-71` ("no key with alias 'x'"), `:57-58` (full keystore path), surfaced by
  `Main.java:44-46`.
- **Why it is a problem.** Gives a local attacker a clean password-guessing oracle and confirms which
  aliases exist. The suppression of stack traces (`Main.java:44-45`) is the right call and should stay.
- **Fix.** Return one generic message ("cannot open keystore") to the user and log the distinguishing
  detail only at debug level.

### F9. Passphrase provider imposes no passphrase strength requirement, and PBKDF2 is not memory-hard — LOW (documented)
- **CWE-521** (Weak Password Requirements) / **CWE-916** (Password Hash With Insufficient Computational Effort).
- **Evidence:** `src/com/example/crypto/PassphraseKeyProvider.java:68` — whatever `Secrets.read`
  returns is used as-is; no length or entropy check. `:27-29` — PBKDF2-HMAC-SHA256, 600 000 iterations.
- **Why it is a problem.** 600k iterations matches current OWASP guidance and is *correct* for PBKDF2,
  but PBKDF2 resists only CPU-bound guessing; a 6-character passphrase is still recoverable on GPUs.
  The README's "Known limits" section already states this honestly, so this is a hardening note rather
  than a defect.
- **Fix.** Reject passphrases below a minimum length (e.g. 12 chars) at `:68`, and prefer Argon2id or
  scrypt if a dependency ever becomes acceptable.

### F10. `Secrets.toUtf8` is unused dead code — INFORMATIONAL
- **CWE-561** (Dead Code).
- **Evidence:** `src/com/example/crypto/Secrets.java:83` — no call sites anywhere in `src/`.
- **Why it matters.** It is a secret-handling helper (`char[]` → `byte[]`) that no test exercises;
  if a future caller passes it a buffer that is read-only or has a non-zero `arrayOffset`,
  `buf.array()` on `:87` misbehaves. Delete it, or add a call site and a self-test check.

## 4. What I checked and found *correct*

These were examined against the crypto skills' weakness tables and validation criteria and did not fire:

- **Algorithm and mode** — `AES/GCM/NoPadding`, 256-bit keys (`SymmetricCipher.java:33,35`). No MD5,
  SHA-1, DES/3DES, RC4, ECB or unauthenticated CBC anywhere (grepped across `src/`).
- **IV/nonce management** — fresh 12-byte IV per message from `SecureRandom`
  (`SymmetricCipher.java:38,43,47,65-66`); never derived from plaintext, never a counter in mutable
  state, never reused. 128-bit tag (`:39`). Uniqueness is regression-tested (`SelfTest.java:35-36`).
- **AEAD integrity** — the full header (magic, version, params, IV) is fed as AAD on both paths
  (`:73, :132`), so version/salt/IV substitution fails the tag check; optional caller AAD binds
  ciphertext to context. `SelfTest.java:44-64` covers modified tag, modified body, modified IV,
  wrong AAD, missing AAD, wrong key, truncation and garbage.
- **Envelope parsing of untrusted bytes** — magic, version, `paramsLen ≤ 4096`, exact `ivLen`, and a
  minimum-remaining-length check are all validated before use (`SymmetricCipher.java:99-125`), with
  `BufferUnderflowException` mapped to a clean error. No unchecked allocation from a length field
  (the `MAX_PARAMS` cap at `:109` is what prevents it), no integer overflow in `header()` (`:144-152`).
- **No hardcoded secrets** — no key, password, or salt literal in any source file; keys come only from
  a keystore, an env var, or a KDF (`KeyProvider.java:9-11`). The card number in `SelfTest.java:28` is
  a well-known test value, not a credential.
- **Key generation** — `KeyGenerator.getInstance("AES")` at 256 bits (`KeyStoreKeyProvider.java:110-112`,
  `SelfTest.java:74-78`); `SecureRandom` everywhere randomness is needed (`Main.java:61`,
  `PassphraseKeyProvider.java:33`, `SymmetricCipher.java:47`) — no `java.util.Random`, no time-based seed.
- **Rotation safety** — `genkey` refuses to overwrite an existing alias (`KeyStoreKeyProvider.java:101-105`),
  so old ciphertext stays decryptable; the keystore is never created implicitly at encryption time
  (`:24-27`, `:56-59`), which prevents "encrypted" data under a silently-invented key.
- **Memory wiping where it can work** — `char[]`/`byte[]` wiped in `finally` blocks
  (`KeyStoreKeyProvider.java:84,126-128`; `PassphraseKeyProvider.java:76-82`;
  `EnvironmentKeyProvider.java:59-61`; `Main.java:64,78-80,95-97`); `PBEKeySpec.clearPassword()` is
  called (`PassphraseKeyProvider.java:79-81`). Wiping `raw`/`derived` after `new SecretKeySpec(...)`
  is safe because `SecretKeySpec` clones its input.
- **Key length validation** — the env-supplied key must decode to exactly 32 bytes
  (`EnvironmentKeyProvider.java:53-57`), so a short/truncated key cannot silently weaken encryption.
- **KDF parameters** — PBKDF2-HMAC-SHA256, 600 000 iterations, fresh 16-byte random salt per message,
  salt and count stored in the envelope so the count can be raised later
  (`PassphraseKeyProvider.java:27-29,41-49`). Only the missing upper bound (F2) is wrong.
- **Secrets not on the command line** — passwords/passphrases come from the environment or
  `Console.readPassword` (`Secrets.java:28-42`), never from argv; `Main.parseOptions` has no password
  option. (Plaintext via `--text` is the exception — F4.)
- **Error handling** — no stack traces reach the user (`Main.java:43-47`), so no plaintext or key
  bytes leak through exception text.
- **Reviewed against general OWASP/CWE knowledge, no library skill needed, nothing found:** there is
  no SQL/ORM use (no injection surface), no OS command execution, no Java deserialization
  (`ObjectInputStream`) — the envelope is a hand-rolled length-prefixed format, no reflection, no
  network or TLS use, no XML/XXE parsing, no web/XSS surface, no authentication or session or JWT
  logic, and no user-controlled path traversal beyond the operator's own `--in`/`--keystore`
  arguments (this is a local CLI, so those are trust-equivalent to the invoking user).

## 5. Skills applied

1. `performing-cryptographic-audit-of-application` — weakness-category table (weak hashing, insecure
   encryption, bad cipher mode, key size, hardcoded secrets, weak KDF, poor entropy) and its
   validation criteria, applied to all eight files. Drove the F2 KDF finding and the §4 confirmations.
2. `implementing-aes-encryption-for-data-at-rest` — AES-GCM mode/nonce/tag rules, PBKDF2 ≥600k
   guidance, encrypted-file-format and key-wiping considerations, applied to `SymmetricCipher.java`
   and `PassphraseKeyProvider.java`.
3. `testing-for-sensitive-data-exposure` — insecure-storage and credential-leakage checks, applied to
   secret handling rather than to HTTP responses. Drove F3, F4 and F5.
4. Considered and *not* applied: `exploiting-race-condition-vulnerabilities` (Burp/web-request TOCTOU,
   not filesystem TOCTOU), `implementing-secrets-management-with-vault`, `configuring-hsm-for-key-storage`
   and `implementing-envelope-encryption-with-aws-kms` (deployment guidance for alternative
   `KeyProvider` backends, already named as future work in the README), `implementing-secret-scanning-with-gitleaks`
   (no repository history in scope). F1 and F6 were therefore assessed against general CWE knowledge
   (CWE-377/378, CWE-59, CWE-367).
