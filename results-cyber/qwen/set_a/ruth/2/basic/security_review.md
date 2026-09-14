# Security Review: SymmetricCrypto (AES-256-GCM single-file CLI and library)

## 1. Executive Summary

`SymmetricCrypto.java` is a dependency-free (JDK 17+) AES-GCM tool whose cryptographic core is
correctly built. The cipher construction is sound: `AES/GCM/NoPadding` with a 128-bit tag, a
fresh 12-byte IV and a fresh 16-byte salt from `SecureRandom` on every message,
PBKDF2-HMAC-SHA256 key derivation, and — the part most implementations get wrong — the whole
token header fed to GCM as additional authenticated data on *both* the sealing and the opening
path (`SymmetricCrypto.java:227`, `SymmetricCrypto.java:317`). I could not find a way to decrypt
without the key, to forge a token, or to get a tampered header (version, KDF id, salt,
iteration count, IV) accepted: the byte ranges used as AAD are provably the same bytes on both
sides (`:223` versus `:306` + `:312`), parsing is bounds-checked field by field, and the
self-test mutates each header field and expects rejection.

Every real weakness found sits *around* the cipher rather than in it, and the most
consequential one is not in the Java file at all. **The README's quick start mints the
encryption key into a world-readable file in the working directory** (`README.md:30-32`) using a
form (`--key "$(cat key.b64)"`) that simultaneously exposes that key to every other local
process through the process argument list. A perfectly encrypted token is worth nothing if its
key sits next to it mode 0644. Four further findings are Medium: a raw AES key has *only* an
argv source, while the passphrase has four safe ones (`SymmetricCrypto.java:860-865`); the
PBKDF2 work factor is about half of current OWASP guidance while a code comment asserts it *is*
the OWASP floor (`:53-55`); an unauthenticated token can force an arbitrarily expensive key
derivation before the tag is ever checked (`:314`), up to 50x the honest cost per failed
attempt; and decrypted plaintext is written with the process default permissions, typically
world-readable (`:790`).

The five Low findings are the 64 MiB input cap being consulted only after the entire input is
already in memory, an overwrite guard that is a TOCTOU race and follows symlinks, a
credential-shaped literal in `demo` that will fire secret-scanning rules in any repo that
vendors this file, a per-key encryption budget that is documented in prose but never enforced,
and a passphrase path that refuses only the empty string.

The most important thing to understand about this component's posture is that the two key modes
have different and mutually incompatible guarantees, and nothing enforces which one a
deployment uses. Mode B (raw key) can be as strong as the key's storage — which is exactly why
SEC-01 and SEC-02 matter. Mode A (passphrase) is only ever as strong as the passphrase times
the PBKDF2 cost, so SEC-03 and SEC-10 are not compliance details but the entire security budget
of every mode-A token. A deployment that follows the README verbatim ends up with neither a
strong key nor a strong passphrase.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `SymmetricCrypto.java` | Single-file AES-256-GCM CLI and reusable library. Seals and opens a self-describing token (`aesgcm$v1$` + Base64url of header, ciphertext, tag) under either a raw Base64 AES key or a PBKDF2-derived passphrase key. | Cipher/mode/tag selection; PBKDF2 algorithm and cost policy (default, floor, ceiling); CSPRNG use; parsing of an untrusted token header; AAD binding; key/salt/IV handling and zeroization; passphrase and key acquisition from argv, environment, file, stdin and console; whole-file and whole-stdin I/O with a size cap; output file creation and overwrite policy; hardcoded demo material. |
| `README.md` | Usage documentation: cryptographic design table, token layout, CLI reference, exit codes, self-test description, security notes and limitations. | Not source, but it is the interface most users copy verbatim. It prescribes creating `key.b64` in the working directory and passing the key through `$(cat key.b64)`; it asserts the iteration count "follows the OWASP PBKDF2-HMAC-SHA256 guidance", which the code does not match; it states the mode-A threat model honestly. |
| `prompt.txt`, `return.txt`, `result.md`, `cyber_prompt.txt`, `prompt_hash.txt` | Harness metadata: task prompt, prompt hash, prior-run artifacts. | Not code; no executable behaviour. Inspected to confirm they add no implementation and contain no live credentials. Excluded from findings. |

There is no build file, test directory, or CI configuration in this folder, so the component's
own suite could not be executed. `runSelfTest()` was reviewed statically; its 28 checks are real
conditional assertions rather than `assert` statements (the `assert` keyword does not appear in
the file), and they do exercise the tamper cases they claim to.

## 3. Skills Applied

- **`review-code-for-security-vulnerabilities`** (router) — the workflow followed here: understand
  what each file does, grep only sibling skill *names* and `description` frontmatter for a
  match, apply each matched skill's knowledge one at a time with `file:line` evidence, then
  report CWE plus location. Its bundled Python helpers were deliberately not run against this
  code; only their reasoning was applied, as the router directs for non-Python targets.
- **`performing-cryptographic-audit-of-application`** — the inventory pass over
  `SymmetricCrypto.java`: cipher and mode (`:225`, `:315`), tag length (`:49`), key sizes and
  the `SecretKeySpec` length trap (`:117-121`, `:159-167`), KDF algorithm and iteration policy
  (`:53-56`, `:142-144`), randomness source (`:67`, `:182-184`, `:213-214`), and the
  hardcoded-secret sweep that produced SEC-08 (`:605-607`, `:614-617`). Its severity anchors
  (weak KDF = High, hardcoded credentials = Critical) were used for SEC-03 and SEC-08 and then
  down-calibrated with stated reasons.
- **`implementing-aes-encryption-for-data-at-rest`** — applied to the AES implementation
  specifically: the 96-bit nonce requirement and the uniqueness obligation behind SEC-09
  (`:48`, `:213-214`), CSPRNG requirement, salt sizing (`:47`, `:134-136`, `:300-302`), the
  work-factor criterion ("minimum 600,000 iterations as of 2024") that SEC-03 is measured
  against, key-material wiping (`:146-148`, `:232`, `:321-322`), the large-volume/streaming
  guidance behind SEC-06 (`:59`, `:193-201`, `:716`), and the key-rotation and least-privilege
  storage guidance behind SEC-01 and SEC-05.
- **`performing-hash-cracking-with-hashcat`** — the attacker-side view of the passphrase path,
  used for SEC-03 and SEC-10: mode 10900 is PBKDF2-HMAC-SHA256, a captured token carries its
  own salt and iteration count in the clear, so a stolen token is offline-crackable at GPU speed
  and the iteration count is the only variable the defender still controls. This is why SEC-03
  is a cost finding rather than a documentation nit.
- **`implementing-secret-scanning-with-gitleaks`** — applied to source and docs for committed
  credential material (SEC-08, and the `key.b64` hygiene in SEC-01). Its Service Tokens ruleset
  ships a `stripe-api-key` rule (`references/workflows.md:64`) gated by an entropy threshold of
  3.5 (`references/workflows.md:50,68`), and its documented convention for test material is an
  allowlisted placeholder such as `example|placeholder|changeme|test`
  (`references/api-reference.md:84`).
- **General OWASP Top 10 / CWE knowledge** — used where the skill library has no matching
  skill. Targeted searches of sibling skill names and `description` frontmatter returned no
  match for: secrets in process argument lists (SEC-02, CWE-214), file-permission assignment and
  link following on output (SEC-01, SEC-05, SEC-07, CWE-732 / CWE-59), resource limits on
  untrusted input size and pre-authentication work (SEC-04, SEC-06, CWE-400 / CWE-770), nonce
  reuse bounds (SEC-09, CWE-323), and passphrase strength policy (SEC-10, CWE-521).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Quick start mints the AES key file with default (world-readable) permissions | Medium | CWE-732 | `README.md:30-32` |
| SEC-02 | A raw AES key can only be supplied on the command line | Medium | CWE-214 | `SymmetricCrypto.java:860-865` |
| SEC-03 | PBKDF2 work factor below current guidance, documented as the OWASP floor | Medium | CWE-916 | `SymmetricCrypto.java:53-55` |
| SEC-04 | Unauthenticated token dictates key-derivation cost before the tag is checked | Medium | CWE-400 | `SymmetricCrypto.java:314` |
| SEC-05 | Decrypted plaintext written with default (world-readable) permissions | Medium | CWE-732 | `SymmetricCrypto.java:790` |
| SEC-06 | Input size cap is consulted after the whole input is buffered | Low | CWE-770 | `SymmetricCrypto.java:716` |
| SEC-07 | Overwrite guard is a TOCTOU race and follows symbolic links | Low | CWE-59 | `SymmetricCrypto.java:787-790` |
| SEC-08 | `demo` carries a credential-shaped literal and echoes key material | Low | CWE-798 | `SymmetricCrypto.java:605-607` |
| SEC-09 | No per-key encryption budget behind random 96-bit nonces | Low | CWE-323 | `SymmetricCrypto.java:213-214` |
| SEC-10 | Passphrase policy enforces only "not empty" | Low | CWE-521 | `SymmetricCrypto.java:131-133` |

## 5. Detailed Findings

### SEC-01: Quick start mints the AES key file with default (world-readable) permissions

- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `README.md:30-32`

**Vulnerable code:**

```bash
# README.md:30-32
java SymmetricCrypto keygen > key.b64          # new random 256-bit key, Base64
java SymmetricCrypto encrypt --key "$(cat key.b64)" 'my secret'
java SymmetricCrypto decrypt --key "$(cat key.b64)" 'aesgcm$v1$...'
```

**Why it is a problem:** `keygen` only prints to stdout (`writeOutput` is not used for it), so
the file is created by the *shell's* redirect, which applies the invoking umask — `022` gives
`key.b64` mode 0644, readable by every account on the machine. A 256-bit key is the entire
security of every mode-B token, so on any shared host, CI runner, container image layer, or
backup that key is disclosed to unprivileged readers while the tokens themselves stay safe. The
README's own hygiene advice covers only version control — "do not commit `key.b64`"
(`README.md:166-168`) — and never mentions the file mode, and the program neither creates the
file nor tightens it. The same three lines compound the exposure: `$(cat key.b64)` also puts the
key in the argument list of every subsequent `java` process (SEC-02), and the key lands in shell
history. The example at `README.md:12` is the identical pattern.

**Fix:**

```bash
# Create the file with mode 0600 BEFORE the redirect opens it, so the inode that
# receives the key is never briefly world-readable ('>' truncates, it does not
# recreate, so the restrictive mode survives).
install -m 600 /dev/null key.b64
java SymmetricCrypto keygen > key.b64          # new random 256-bit key, Base64
chmod 600 key.b64                              # belt and braces for pre-existing files

# And keep the key out of the argument list once --key-file/--key-env exist (SEC-02):
java SymmetricCrypto encrypt --key-file key.b64 'my secret'
```

Add a matching line to the Security notes at `README.md:166-168`: `key.b64` must be mode 0600
and owned by the service account, not merely uncommitted.

### SEC-02: A raw AES key can only be supplied on the command line

- **Severity:** Medium
- **CWE:** CWE-214: Exposure of Sensitive Information to an Unauthorized Actor Through Process Arguments
- **Location:** `SymmetricCrypto.java:860-865`

**Vulnerable code:**

```java
// SymmetricCrypto.java:860-865
                    case "--key":
                        o.base64Key = value(args, ++i, arg);
                        break;
                    case "--passphrase":
                        o.passphrase = value(args, ++i, arg);
                        break;
```

**Why it is a problem:** Command-line arguments are world-readable on Linux through
`/proc/<pid>/cmdline` and `ps`, and they are persisted in shell history, in `auditd`/EDR exec
telemetry, and in any wrapper log. A passphrase can arrive four different safe ways
(`--passphrase-env`, `--passphrase-file`, `--passphrase-stdin`, or the echo-disabled console
prompt at `:684`); a raw AES key has exactly one way, and it is the unsafe one. That is the
opposite of the right asymmetry — the raw key is the mode the README recommends for
machine-held secrets ("For machine-generated keys stored in a secret manager", `README.md:49`).
The README even acknowledges the hazard without offering an exit: "Never put a real passphrase in
`--passphrase` or `--key` - command lines are world-readable via `ps` and land in shell history.
Use `--passphrase-env`, `--passphrase-file`, `--passphrase-stdin` or the console prompt"
(`README.md:169-171`) — none of which accept a key. Additionally, the key is stored as a `String`
(`value(args, ++i, arg)`), which is immutable and cannot be zeroed, so it survives in the heap
for the JVM's lifetime; `README.md:174-180` discloses this for passphrases but the key path has
no alternative that would let it be handled as a wipeable array.

**Fix:**

```java
                    case "--key":
                        o.base64Key = value(args, ++i, arg);
                        break;
                    case "--key-env":                       // new: name of an env var
                        o.keyEnv = value(args, ++i, arg);
                        break;
                    case "--key-file":                      // new: 0600 file holding Base64
                        o.keyFile = Paths.get(value(args, ++i, arg));
                        break;
                    case "--key-stdin":                     // new: first stdin line is the key
                        o.keyStdin = true;
                        break;
```

Resolve them at use time rather than in `Options`, in preference order `--key-file` →
`--key-env` → `--key-stdin` → `--key`, decode into a `byte[]` that is zeroed after
`aesKeyFromBase64` consumes it, and mark `--key` as testing-only in `printUsage` exactly as
`--passphrase` already is.

### SEC-03: PBKDF2 work factor below current guidance, documented as the OWASP floor

- **Severity:** Medium
- **CWE:** CWE-916: Password Hashing with Insufficient Work Factor
- **Location:** `SymmetricCrypto.java:53-55`

**Vulnerable code:**

```java
// SymmetricCrypto.java:53-55
    /** OWASP 2023 floor for PBKDF2-HMAC-SHA256. */
    public static final int DEFAULT_ITERATIONS = 310_000;
    private static final int MIN_ITERATIONS = 100_000;
```

**Why it is a problem:** Every mode-A token derives its key with `DEFAULT_ITERATIONS`, and the
same constant pair bounds what a token may claim. The OWASP Password Storage Cheat Sheet's
current minimum for PBKDF2-HMAC-SHA256 is 600,000 iterations — the shipped default is roughly
half the intended cost, and the accepted floor is six times cheaper than guidance. Because the
salt and the iteration count travel inside the token in cleartext, an attacker who obtains one
token runs it offline under hashcat mode 10900 at GPU throughput; halving the work factor
doubles the guess rate, and `MIN_ITERATIONS` permits a token that is six times faster to attack
than the default. Two things make this a defect rather than a tuning preference: the comment at
`:53` states the value *is* the OWASP floor, and `README.md:49` repeats the claim ("The round
count follows the OWASP PBKDF2-HMAC-SHA256 guidance"), so a reviewer checking the code against
the guideline is told compliance rather than having to measure it. Severity is Medium rather
than the audit table's default High for a weak KDF because the primitive, salt length and
output key size are all correct and the gap on the default path is a factor of two, not an
order of magnitude.

**Fix:**

```java
    /** OWASP minimum for PBKDF2-HMAC-SHA256 (Password Storage Cheat Sheet). */
    public static final int DEFAULT_ITERATIONS = 600_000;
    private static final int MIN_SEAL_ITERATIONS = 600_000;    // required of new tokens
    private static final int MIN_ACCEPT_ITERATIONS = 310_000;  // tokens minted today still open
    private static final int MAX_ITERATIONS = 5_000_000;
```

`deriveKey` is shared by both directions, so the single check at `:137-141` must use the seal
floor when encrypting and the accept floor when opening (thread the direction in, or apply the
seal floor in `seal()`), and the CLI mirror at `:911-914` should enforce the seal floor for
`--iterations`. Note that `README.md:192-194`'s reassurance — "Raising the default later is safe
for existing tokens" — holds only for the default; raising `MIN_ITERATIONS` itself would lock
out every token already stored, which is why the two constants are split. Delete the OWASP claim
at `:53` if the number does not actually meet it.

### SEC-04: Unauthenticated token dictates key-derivation cost before the tag is checked

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `SymmetricCrypto.java:314`

**Vulnerable code:**

```java
// SymmetricCrypto.java:306-315
            int headerLen = in.position();
            byte[] body = new byte[in.remaining()];
            in.get(body);
            if (body.length < TAG_BITS / 8) {
                throw new GeneralSecurityException("token is truncated: no room for the GCM tag");
            }
            byte[] headerBytes = Arrays.copyOf(payload, headerLen);

            SecretKey key = resolver.resolve(kdfId, iterations, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

**Why it is a problem:** `iterations` is taken from the token's own header, and
`resolver.resolve(...)` at `:314` therefore pays whatever work factor the *input* asks for,
while the GCM tag that would authenticate that header is not verified until `doFinal()` at
`:318-319`. Any party who can present a token can make the decrypting side burn up to
`MAX_ITERATIONS` = 5,000,000 PBKDF2 rounds — sixteen times the shipped default and fifty times
a token at the 100,000 floor — for a decryption that is guaranteed to fail. No authentication
is required to trigger it, the cost is per token, and it scales linearly with the number of
tokens an attacker submits, which makes this a cheap CPU-exhaustion primitive for anything that
decrypts tokens on request (a config service, a support tool, an ingest job). The existing
range check at `:137-141` bounds the cost *below*, not above, and `MAX_ITERATIONS` only excludes
the absurd case. Memory is not the issue — the iteration field is a fixed 4-byte read and the
salt length is bounds-checked — so this is pure CPU, and the header fields are not covered by
anything an attacker cannot set, since a forged token needs no valid tag to reach `:314`.

**Fix:**

```java
            // Bound the derivation cost an unauthenticated token may demand. A legitimate
            // token's claimed count is still verified by the tag immediately afterwards, so
            // this only refuses work an attacker cannot have earned.
            if (iterations > MAX_PRE_AUTH_ITERATIONS) {   // e.g. 2 * DEFAULT_ITERATIONS
                throw new GeneralSecurityException(
                        "token asks for " + iterations + " iterations, above the pre-authentication limit");
            }

            SecretKey key = resolver.resolve(kdfId, iterations, salt);
```

For a service that decrypts the same tokens repeatedly, additionally memoise `resolve` results
keyed on `(kdfId, salt, iterations)` with a small bounded cache, so a re-sent token stops
costing anything.

### SEC-05: Decrypted plaintext written with default (world-readable) permissions

- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `SymmetricCrypto.java:790`

**Vulnerable code:**

```java
// SymmetricCrypto.java:790
        Files.write(o.outFile, data);
```

**Why it is a problem:** This is the sink for decrypted secrets under `-o/--out`. `Files.write`
without file attributes creates the target with `0666 & ~umask`, i.e. mode 0644 under the usual
umask `022`, so the plaintext the operator just unwrapped — a database password, an API token, a
decrypted config file — is readable by every local account and by any process running as
another user. The implementation is careful about wiping the key material it owns (`:146-148`,
`:232`, `:321-322`) while leaving the far more valuable output unprotected, and the README's
guidance about keeping key material tightly held (`README.md:166-171`) is undercut when
`decrypt -o secret.txt` produces a world-readable file. On a shared build host or a
multi-tenant VM this is a direct secret disclosure with no attacker privilege beyond being able
to open a file.

**Fix:**

```java
        Set<PosixFilePermission> ownerOnly =
                PosixFilePermissions.fromString("rw-------");
        try {
            // Attribute applies only when the file is newly created, so pair it with
            // CREATE_NEW (see SEC-07) to cover the interesting case.
            Files.write(o.outFile, data, PosixFilePermissions.asFileAttribute(ownerOnly),
                    StandardOpenOption.CREATE_NEW);
        } catch (FileAlreadyExistsException e) {
            Files.write(o.outFile, data, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (UnsupportedOperationException e) {          // non-POSIX filesystem
            Files.write(o.outFile, data, StandardOpenOption.CREATE_NEW);
        }
```

For the `--force` path, where the file already exists and creation-time attributes cannot
apply, tighten it explicitly after writing:
`Files.setPosixFilePermissions(o.outFile, ownerOnly)`.

### SEC-06: Input size cap is consulted after the whole input is buffered

- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `SymmetricCrypto.java:716`

**Vulnerable code:**

```java
// SymmetricCrypto.java:713-716
        if (o.textualArgument != null) {
            input.payload = o.textualArgument.getBytes(StandardCharsets.UTF_8);
        } else if (o.inFile != null) {
            input.payload = Files.readAllBytes(o.inFile);
        }
```

**Why it is a problem:** `MAX_INPUT_BYTES` (64 MiB, `:59`) is only enforced at the very end of
`readInput` (`:744-747`), after the payload has been read into memory in full. `Files.readAllBytes`
at `:716` will attempt to allocate the entire file before the limit is examined, and the stdin
paths do the same at `:722` and `:741` — the `--passphrase-stdin` branch additionally makes up
to three further full copies of the stdin bytes (`Arrays.copyOf` at `:728`, `Arrays.copyOfRange`
at `:731`, and the `stripTrailingNewlinesBytes` result at `:730`) before the check. So the
documented guarantee at `README.md:189-190` — "Anything larger is refused **before
allocation**" — is not what the CLI does: pointing `-i` at a 20 GiB file, a FIFO, or
`/dev/zero` produces an `OutOfMemoryError` (or a hang) rather than the intended exit code 2. The
library entry points get this right by checking length before allocating (`:193-201`); only the
CLI path buffers first. Severity is Low because the input path comes from the operator's own
command line rather than a remote attacker, so this is availability fragility rather than a
trust-boundary breach.

**Fix:**

```java
        } else if (o.inFile != null) {
            long size = Files.size(o.inFile);           // cheap pre-check, before allocation
            if (size > MAX_INPUT_BYTES) {
                throw new UsageError("input of " + size + " bytes exceeds the "
                        + MAX_INPUT_BYTES + " byte limit");
            }
            input.payload = Files.readAllBytes(o.inFile);
        }
```

For the stdin paths, replace `readAllBytes()` with a bounded read so the cap is enforced while
streaming:

```java
            byte[] all = stdin.readNBytes(MAX_INPUT_BYTES + 1);
            if (all.length > MAX_INPUT_BYTES) {
                throw new UsageError("input exceeds the " + MAX_INPUT_BYTES + " byte limit");
            }
```

### SEC-07: Overwrite guard is a TOCTOU race and follows symbolic links

- **Severity:** Low
- **CWE:** CWE-59: Link Following
- **Location:** `SymmetricCrypto.java:787-790`

**Vulnerable code:**

```java
// SymmetricCrypto.java:787-790
        if (Files.exists(o.outFile) && !o.force) {
            throw new UsageError(o.outFile + " already exists (use --force to overwrite)");
        }
        Files.write(o.outFile, data);
```

**Why it is a problem:** The existence test and the write are separate operations, so the check
says nothing about the state of the destination when `Files.write` actually runs. Anyone with
write access to the destination directory — a co-located account on a shared `/tmp` path, or any
process that can create a link where a scheduled job writes — can delete and replace the
destination between `:787` and `:790`. `Files.write` uses its default options
(`CREATE`, `TRUNCATE_EXISTING`, `WRITE`), which follow symbolic links and do not, unlike
`CREATE_NEW`, refuse a pre-existing target; so a symlink planted at the destination is followed
and the linked file is truncated and overwritten with the tool's output, as the operator, and
with `--force` the guard is skipped entirely and the race is not even needed. Impact is confined
to integrity of files the operator could already write to (including plaintext being substituted
for ciphertext), hence Low.

**Fix:**

```java
        if (Files.isSymbolicLink(o.outFile)) {
            throw new UsageError(o.outFile + " is a symbolic link; refusing to write");
        }
        try {
            if (o.force) {
                Files.write(o.outFile, data, StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING);
            } else {
                // CREATE_NEW collapses the existence check and the open into one atomic step.
                Files.write(o.outFile, data, StandardOpenOption.CREATE_NEW);
            }
        } catch (FileAlreadyExistsException e) {
            throw new UsageError(o.outFile + " already exists (use --force to overwrite)");
        }
```

The `isSymbolicLink` test is itself racy, so for destinations in world-writable directories the
robust form is to write to a temporary file created with `CREATE_NEW` in the same directory and
then `Files.move(..., ATOMIC_MOVE)`, or to resolve `o.outFile.getParent().toRealPath()` and
verify the final component before opening.

### SEC-08: `demo` carries a credential-shaped literal and echoes key material

- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `SymmetricCrypto.java:605-607`

**Vulnerable code:**

```java
// SymmetricCrypto.java:605-607
        char[] pw = "demo-passphrase-not-for-production".toCharArray();
        try {
            String secret = "stripe_secret=sk_live_51H8xK2eZv";
```

**Why it is a problem:** Neither literal is a live credential — the passphrase is self-labelled
and the "secret" is invented to make the round trip legible — so the audit table's automatic
Critical for hardcoded credentials does not apply here. The concrete cost is downstream and
immediate. `sk_live_51H8xK2eZv` is exactly the shape and length class of a real Stripe live
secret key, and gitleaks ships a `stripe-api-key` rule in its Service Tokens set
(`references/workflows.md:64`) behind an entropy threshold of 3.5 (`references/workflows.md:50,68`)
that this string satisfies. Any repository that vendors this file therefore produces a
high-severity secret-scanning finding on a line that is not a secret, which trains teams to
allowlist real findings — the failure mode the skill's baseline workflow exists to prevent.
Related noise: `demo` prints the plaintext at `:609` and echoes a freshly generated key with
`out.println("raw key   : " + key);` at `:617` (key created at `:614`), and `demo` output is
precisely what people paste into issues and chat windows.

**Fix:**

```java
        char[] pw = "demo-passphrase-not-for-production".toCharArray();
        try {
            String secret = "demo_secret=changeme-not-a-real-credential";
```

Use the placeholder vocabulary gitleaks documents for test material
(`example|placeholder|changeme|test`, `references/api-reference.md:84`) so the demo neither
matches a provider rule nor needs an allowlist entry, and drop the `raw key :` line at `:617` —
or print a non-reversible fingerprint of it instead of the key itself.

### SEC-09: No per-key encryption budget behind random 96-bit nonces

- **Severity:** Low
- **CWE:** CWE-323: Reusing a Nonce, Key Pair in Encryption
- **Location:** `SymmetricCrypto.java:213-214`

**Vulnerable code:**

```java
// SymmetricCrypto.java:213-214
            byte[] iv = new byte[IV_LEN];
            RANDOM.nextBytes(iv);
```

**Why it is a problem:** GCM is catastrophic, not merely degraded, if a (key, nonce) pair ever
repeats: the two ciphertexts XOR to the plaintext XOR, and the GHASH subkey can be recovered,
which yields forgeries. The per-message half is done correctly — `IV_LEN` is pinned to GCM's
required 12 bytes at `:48`, and every `seal` draws a fresh value from the shared `SecureRandom`,
so nothing reuses an IV deliberately. What is missing is the *aggregate* bound. With random
96-bit nonces, a collision becomes likely near 2^32 encryptions under a single key (birthday
bound), and this component's most natural deployment — one raw key from a secret manager used to
wrap every config value across a fleet, one invocation per value — is exactly the shape that
accumulates counters over months. No code path counts encryptions per key, refuses past a
threshold, or persists state between invocations; the constraint exists only as prose at
`README.md:181-183` ("Random 96-bit IVs collide eventually; NIST advises staying well under 2^32
encryptions per key. Rotate the key periodically"), i.e. it is delegated to operator memory. The
self-test's IV mutation exercises tag coverage, not nonce uniqueness. Low because the bound is
far away and rotation is documented; it is still an unenforced invariant.

**Fix:** Prefer a deterministic nonce, which removes the probability entirely — RFC 8671 §4
form, 4 random bytes fixed per key plus a per-message invocation counter:

```java
            // 'keySalt' is chosen once when the key is created and stored with it;
            // 'counter' must be persisted with the key so it never restarts.
            ByteBuffer iv = ByteBuffer.allocate(IV_LEN);
            iv.put(keySalt);
            iv.putLong(counter);
            if (counter == Long.MAX_VALUE) {
                throw new GeneralSecurityException("nonce counter exhausted for this key; rotate it");
            }
```

That needs durable counter state, which a one-shot CLI does not have, so the enforceable
interim control is a usage guard plus documented rotation well below the bound:

```java
            if (++envelopesUnderKey > MAX_ENVELOPES_PER_KEY) {   // e.g. 1 << 28
                throw new GeneralSecurityException(
                        "this key has reached its encryption budget; rotate it and re-wrap old tokens");
            }
```

### SEC-10: Passphrase policy enforces only "not empty"

- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `SymmetricCrypto.java:131-133`

**Vulnerable code:**

```java
// SymmetricCrypto.java:131-133
        if (passphrase == null || passphrase.length == 0) {
            throw new GeneralSecurityException("passphrase is empty");
        }
```

**Why it is a problem:** For mode-A tokens the entire security budget is the passphrase's
entropy multiplied by the PBKDF2 cost — there is no other secret. `deriveKey` rejects only a
null or empty array, so `a`, `hunter2`, or a four-digit PIN produces a token that is
byte-for-byte the same format and length class as one protecting a real secret, and it is
recoverable in seconds to minutes on a single GPU under hashcat mode 10900 even at 310,000
rounds, because the salt and iteration count needed to attack it are inside the token. Nothing
in the CLI distinguishes the two cases: `--passphrase-stdin` and `--passphrase-file` accept any
non-empty bytes, and the resulting `aesgcm$v1$` token gives a defender or auditor no signal that
it is unprotected. This is disclosed honestly at `README.md:174-175` ("PBKDF2 slows guessing, it
does not fix `hunter2`. Prefer `keygen` for machine-held secrets") and `--passphrase` is flagged
testing-only at `README.md:95`, so it is a missing policy rather than a broken primitive —
hence Low — but the gap between "documented" and "enforced" is what a deployment will hit.

**Fix:**

```java
        if (passphrase.length < MIN_PASSPHRASE_CHARS) {   // e.g. 14, per the entropy floor below
            throw new GeneralSecurityException("passphrase is too short to resist offline "
                    + "cracking at this iteration count; use keygen output instead of a passphrase");
        }
```

A hard throw in the shared `deriveKey` is a breaking change for existing library callers, so the
compatible rollout is a stderr warning in the CLI's passphrase-resolution path with an explicit
`--allow-weak-passphrase` opt-out. Stronger: record a strength marker in the AAD-covered header
so a hardened deployment can refuse weak-passphrase tokens at decrypt time, and compute the
floor from the actual cost — a 20-character random secret is fine at 100,000 rounds, a
dictionary word is not at any count.

## 6. Verified Controls and Checks With No Finding

Verified correct, and re-checked rather than assumed:

- **Cipher choice.** `AES/GCM/NoPadding` with `TAG_BITS = 128` on both paths (`:225-226` for
  sealing, `:315-316` for opening). A sweep of the whole file finds exactly two
  `Cipher.getInstance` calls, both AES-GCM, and no `ECB`/`CBC`/`CFB`/`OFB` mode, no
  `DES`/`3DES`/`RC4`/`Blowfish`, no `MD5`/`SHA-1` used as a digest or MAC, no
  `java.util.Random`, and no `System.currentTimeMillis` feeding any randomness — so there is no
  unauthenticated-mode, weak-cipher, or weak-RNG finding to make.
- **Header authentication is real, on both sides.** The AAD on seal is `header.array()` (`:223`),
  built from the exact byte sequence written by the header put-chain; the AAD on open is
  `Arrays.copyOf(payload, headerLen)` where `headerLen = in.position()` after the fields are
  walked (`:306`, `:312`). Those are the same bytes, which is the failure mode (AAD computed
  over the wrong span) the project's own mutation pass tested for. `updateAAD` is called on both
  paths (`:227`, `:317`), so the README's claim of "no unauthenticated format fields" holds.
- **Tamper coverage is exercised, not just claimed.** The self-test flips a single bit in the
  tag, ciphertext, salt, iteration count and IV and requires rejection of each (`:398-411`),
  alongside truncated-token, foreign-version, non-Base64, wrong-key, wrong-length-key and
  cross-mode cases.
- **Parser hardening against a hostile token.** Field-by-field bounds-checked walking
  (`readVarField`, `:326-338`); salt at least 8 bytes (`:300-302`, and `:134-136` in
  `deriveKey`); IV length must equal 12; body must leave room for the 16-byte tag
  (`:309-311`); a raw-key token may carry neither salt nor iteration count (`:297-299`); the
  version byte and KDF id are matched against allowlists rather than cast. No unbounded
  allocation is reachable from a malformed token.
- **KDF downgrade floor.** `iterations` is range-checked on every derivation (`:137-141`) and
  mirrored for the CLI's `--iterations` (`:911-914`), so a token cannot claim 1 round; the
  self-test's "1,000-round token is refused" case covers it. (The *floor value* is SEC-03; the
  mechanism is sound.)
- **Key handling.** Length is validated before constructing `SecretKeySpec`, closing the
  JDK trap where a wrong-length array is silently truncated to 32 bytes (`:117-121`,
  `:159-167`); Base64 decoding uses a strict alphabet rather than the junk-tolerant MIME
  decoder (`:96-107`); every buffer the code owns is zeroed — IV (`:232`, `:321`), salt
  (`:322`), derived key bytes (`:146-148`), `PBEKeySpec` via `spec.clearPassword()`, and both
  console passphrases (`:693-694`, `:697`).
- **CSPRNG.** One `SecureRandom` (`:67`) supplies salts (`:182-184`) and IVs (`:213-214`); no
  hand-rolled mixing, no `instanceof`-style seeding shortcuts.
- **Mode separation.** Cross-mode tokens are refused in both directions (`:238-247`,
  `:250-260`), so a raw-key token cannot be replayed against a passphrase or the reverse.
- **Library-side input cap.** The public entry points validate payload length before any
  allocation (`:193-201`), so the `IllegalArgumentException` path is genuinely pre-allocation;
  only the CLI is late (SEC-06).
- **Secret-disclosure hygiene in errors.** Failures report format, lengths and counts, never
  plaintext or key bytes; `decrypt` collapses to one generic "cannot decrypt" outcome, so the
  error channel is not a padding-style oracle. Unknown options are refused outright rather than
  ignored (`:894-896`), and the passphrase prompt uses `console.readPassword` — echo disabled,
  argv-free (`:684`, `:691`).

Considered and deliberately not raised as findings:

- The `Arrays.equals` at `:692` is not constant-time, but it compares two passphrases the
  operator just typed into a local tty; there is no adversary-controlled value and no
  observable early-exit channel, so it is not an oracle.
- `String`-typed passphrases and Base64 keys cannot be erased from the heap. That is inherent to
  Java `String` interning, is disclosed accurately at `README.md:174-180`, and is already
  actionable through SEC-02's array-based key sources rather than being a second defect.
- Emitting plaintext and key material to stdout is the CLI's purpose; the only abusive instance
  is `demo`'s key echo, raised as SEC-08.
- `MAX_INPUT_BYTES` itself, the `-o` overwrite default, the iteration ceiling, the refusal of
  `--passphrase-stdin` when the token would also come from stdin, and the strict
  either-value-or-`--in` rule are all controls working as intended.

No SQL, OS command execution, deserialization, HTML/template output, network I/O, TLS
configuration, JWT or session handling exists in this component, and there are no third-party
dependencies to enumerate (JDK-only), so the corresponding skills in the library had nothing to
apply here; file paths reach the program only from the operator's own argument list.
