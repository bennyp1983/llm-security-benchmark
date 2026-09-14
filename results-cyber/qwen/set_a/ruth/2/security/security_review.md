# Security Review: SecureDataVault

## 1. Executive Summary

`SecureDataVault.java` is an AES-256-GCM envelope library with a `keygen`/`saltgen`/`encrypt`/`decrypt`/`rotate`/`keyinfo` command line front end, and `SelfTest.java` is a self-contained regression harness that drives it both in-process and as a subprocess. The cryptographic core is in good shape: GCM with a 128-bit tag and a fresh `SecureRandom` nonce per call, an AAD that binds the version prefix, key id and caller context so that envelope fields cannot be reinterpreted, a constant-time key-id comparison, no ECB, no weak primitive and no hardcoded key material in production code.

The weaknesses are all around the crypto, in the file and argument handling of the CLI. The most consequential is that the tool goes to real trouble to write the *keystore* owner-only (`SecureDataVault.java:781-803`) and then writes the *decrypted plaintext* with the process umask default (`SecureDataVault.java:1394`) — on a typical Linux host that is `0644`, so the secrets the tool exists to protect become readable by every local account. Related to that, the documented guarantee that "a password or key is never accepted as a command-line argument" (`SecureDataVault.java:996-997`) is enforced only through an incomplete denylist that the tool's own `--name=value` option form steps straight over (`SecureDataVault.java:1458-1464`). The remaining findings are lower grade: a PBKDF2 iteration floor six times below the documented default, an unauthenticated KDF parameter record, a 64-bit key fingerprint usable as an offline cracking oracle for passphrase-derived keys, plaintext in the process table via `--text`, permission checks that are warn-only and fail open, the caller's context string being echoed into an error message, and unbounded whole-input reads.

Nine findings are reported: four Medium and five Low. No finding indicates that ciphertext can be forged or silently mis-decrypted; every one of them is either a confidentiality leak through the filesystem or the process table, or a work-factor/robustness weakness that an attacker with local or write access can exploit.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `SecureDataVault.java` | AES-GCM envelope library plus CLI (`keygen`, `saltgen`, `encrypt`, `decrypt`, `rotate`, `keyinfo`) for protecting secrets at rest | key generation and storage in PKCS12/JCEKS keystores, PBKDF2 key derivation from a passphrase, GCM encrypt/decrypt with AAD-bound context, envelope parse and key-id fingerprinting, POSIX file-permission handling and atomic writes, command-line option parsing, plaintext input and output paths |
| `SelfTest.java` | Standalone `main()` regression harness (~250 hand-rolled assertions) that exercises the library in-process and through spawned `java SecureDataVault` and `keytool` subprocesses | passes secrets to children by environment only, writes keystores/password files/envelopes/decrypted plaintext into a temp directory it never cleans up, and asserts both refusal and acceptance cases for iteration floors, loose file permissions, argv guards and tamper detection |
| `README.md` | Design and usage documentation, including the stated threat model | documents the "never in argv" rule, 0600 + `ATOMIC_MOVE` keystore writes, the 600 000-iteration PBKDF2 default with a 100 000 floor, and the `--text` convenience option |

`cyber_prompt.txt`, `prompt.txt`, `prompt_hash.txt`, `result.md` and `return.txt` are task-runner artifacts rather than component code and were not reviewed for vulnerabilities.

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: drove the review — read every file in the folder, listed its security-relevant behaviours, matched those behaviours against the specialised skills in the library by name, then applied each matched skill's checklist to the real code one at a time.
- `performing-cryptographic-audit-of-application`: applied to every cryptographic decision in `SecureDataVault.java` — cipher mode and padding, hardcoded keys or passwords in source, KDF parameters, entropy source and IV predictability, and key custody in the keystore and in `KeyHandle`.
- `implementing-aes-encryption-for-data-at-rest`: applied to the AES-256-GCM construction itself — 96-bit nonce generation and the never-reuse rule, tag and AAD handling, the salt/nonce/ciphertext/tag storage layout, PBKDF2 parameter strength, wiping key material, and key rotation.
- `implementing-rsa-key-pair-management`: applied to key custody and lifecycle only — restrictive permissions on key material, storage format, and rotation policy. The component contains no asymmetric code, so this skill's algorithm, key-size and padding guidance had nothing to match against; it is credited solely for the permission/rotation criteria behind SEC-01 and SEC-07.
- `implementing-api-key-security-controls`: applied to the question of whether publishing the `keyId` fingerprint is itself a leak. Its own recommended pattern (store the secret hashed, publish a short id for reference) is what this code does, so no finding was raised against the fingerprint design as such; the residual exposure it creates for low-entropy derived keys is SEC-05.
- Considered and rejected as having no matching behaviour in this code: `implementing-secrets-management-with-vault`, `implementing-hashicorp-vault-dynamic-secrets` and `deploying-honeytokens-and-canarytokens` (deployment of products that are not present here), `performing-thick-client-application-penetration-test` (desktop GUI client tooling), the whole web/API family (`exploiting-sql-injection-vulnerabilities`, `testing-jwt-token-security`, `testing-for-xss-vulnerabilities`, `exploiting-server-side-request-forgery`, `testing-api-for-broken-object-level-authorization` and similar — there is no HTTP surface, no parser of untrusted documents and no authentication layer), the container/Kubernetes and cloud-posture skills, and the malware/forensics skills.
- Reviewed against general OWASP Top 10 / CWE knowledge because no skill in the library matches these behaviours: command-line argument handling and secret exposure in the process table (CWE-214/CWE-184), default filesystem permissions on generated output (CWE-276/CWE-732), content of error messages that reach stderr and therefore logs (CWE-209/CWE-532), unbounded reads of attacker-influenced input (CWE-770/CWE-400), trustworthiness of on-disk configuration (CWE-345), and non-atomic file replacement (CWE-367).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Decrypted plaintext written with umask-default file permissions | Medium | CWE-276 | `SecureDataVault.java:1394` |
| SEC-02 | Inline `--name=value` form bypasses the "no secrets in argv" denylist | Medium | CWE-184 | `SecureDataVault.java:1459` |
| SEC-03 | PBKDF2 iteration floor accepts a work factor six times below the documented default | Medium | CWE-916 | `SecureDataVault.java:102` |
| SEC-04 | KDF parameter record is unauthenticated and unprotected | Low | CWE-345 | `SecureDataVault.java:1273` |
| SEC-05 | 64-bit key fingerprint published in every envelope is an offline verification oracle | Low | CWE-203 | `SecureDataVault.java:859` |
| SEC-06 | `--text` places the plaintext secret in the process table and shell history | Low | CWE-214 | `SecureDataVault.java:1367` |
| SEC-07 | Loose key-file permissions are warn-only and the permission check fails open | Low | CWE-276 | `SecureDataVault.java:933` |
| SEC-08 | Caller-supplied context echoed verbatim into an authentication error message | Low | CWE-209 | `SecureDataVault.java:632` |
| SEC-09 | Unbounded whole-input reads allow memory exhaustion before any crypto work | Low | CWE-770 | `SecureDataVault.java:1373` |

## 5. Detailed Findings

### SEC-01: Decrypted plaintext written with umask-default file permissions

- **Severity:** Medium
- **CWE:** CWE-276: Incorrect Default Permissions (related: CWE-732)
- **Location:** `SecureDataVault.java:1382-1395` (same pattern at `SecureDataVault.java:1226` and `SecureDataVault.java:1137`)

**Vulnerable code:**

```java
// SecureDataVault.java:1382-1395
    private static void writeOutput(Opts opts, byte[] bytes) throws IOException {
        String out = opts.get("out");
        if (out == null || "-".equals(out)) {
            System.out.write(bytes);
            System.out.flush();
            return;
        }
        Path path = Paths.get(expandHome(out));
        Path dir = path.toAbsolutePath().getParent();
        if (dir != null) {
            Files.createDirectories(dir);
        }
        Files.write(path, bytes);
    }
```

**Why it is a problem:** `decrypt --out secret.txt` writes recovered plaintext through a bare `Files.write`, so the new file inherits the process umask — `0644` on a default Linux/macOS configuration, i.e. world-readable. Every other local account, and any process running as another user, can then read the secret that was just protected by AES-GCM. The contrast with the keystore writer makes this look unintended rather than a deliberate trade-off: `writeKeyStoreAtomically` creates a sibling temp file, calls `Files.setPosixFilePermissions(temp, ownerOnly)` and only then stores the key (`SecureDataVault.java:785-789`), because a keystore is sensitive. The decrypted output is strictly *more* sensitive than the keystore — it is the secret in the clear — and it gets no treatment at all. `commandRotate` (`SecureDataVault.java:1226`) and `commandSaltgen` (`SecureDataVault.java:1137`) repeat the pattern for their outputs. `SelfTest.java` never asserts anything about the permissions of `--out` files (the decrypted `blob.out` written at `SelfTest.java:757-759` is only read back), so nothing in the suite would notice if this regressed further. The exposure requires local access to the host, which is why this is Medium rather than High, but on shared build hosts, bastions and multi-tenant CI runners that condition is the normal case.

**Fix:**

```java
    private static void writeOutput(Opts opts, byte[] bytes) throws IOException {
        String out = opts.get("out");
        if (out == null || "-".equals(out)) {
            System.out.write(bytes);
            System.out.flush();
            return;
        }
        Path path = Paths.get(expandHome(out));
        Path dir = path.toAbsolutePath().getParent();
        if (dir != null) {
            Files.createDirectories(dir);
        }
        // Owner-only from the moment the inode exists, so the plaintext is never
        // briefly (or permanently) group/other-readable the way umask allows.
        // Needs: import java.nio.file.attribute.PosixFilePermissions;
        try {
            Files.write(path, bytes, PosixFilePermissions.asFileAttribute(ownerReadWrite()));
        } catch (UnsupportedOperationException nonPosix) {
            Files.write(path, bytes);
        }
        if (!opts.has("force-insecure-fileperms")) {
            try {
                // Files.write only applies attributes when *creating*; correct an
                // already-existing destination too.
                Files.setPosixFilePermissions(path, ownerReadWrite());
            } catch (UnsupportedOperationException ignored) {
                warnIfOpen(path, opts, "output");
            }
        }
    }
```

Apply the same two lines to the `rotate` output at `SecureDataVault.java:1226` and to the KDF record at `SecureDataVault.java:1137`, and add a `SelfTest` assertion that `Files.getPosixFilePermissions` on a `--out` target is owner-only.

### SEC-02: Inline `--name=value` form bypasses the "no secrets in argv" denylist

- **Severity:** Medium
- **CWE:** CWE-184: Incomplete Denylist (related: CWE-214)
- **Location:** `SecureDataVault.java:1458-1471` (guard text at `SecureDataVault.java:996-997`, dead terms at `SecureDataVault.java:1479-1483`)

**Vulnerable code:**

```java
// SecureDataVault.java:1458-1471
                String name = arg.substring(2);
                int eq = name.indexOf('=');
                if (eq >= 0) {
                    opts.values.put(name.substring(0, eq), name.substring(eq + 1));
                    continue;
                }
                if (looksLikeLiteralSecret(name)) {
                    throw new VaultException("the option --" + name + " does not exist: a secret must not be"
                            + " passed on the command line where the process table and shell history can see it."
                            + " Use --storepass-env, --storepass-file or --storepass-prompt.");
                }
                boolean nextIsValue = i + 1 < args.length && !args[i + 1].startsWith("--");
                if (nextIsValue) {
                    opts.values.put(name, args[++i]);
                } else {
```

**Why it is a problem:** The tool advertises a hard guarantee — "A password or key is never accepted as a command-line argument: argv is world readable through the process table and is kept in shell history" (`SecureDataVault.java:996-997`) — and enforces it with a denylist of option *names* checked at line 1464. The `--name=value` form is handled earlier, at lines 1459-1463, and that branch `continue`s before the denylist is ever consulted. So `--storepass=hunter2`, `--keypass=x`, `--pass=hunter2` and `--key=<base64 key>` are all accepted into `opts.values`, exactly the values the guard exists to refuse. Two consequences: the `startsWith("storepass=")` and `startsWith("password=")` terms in `looksLikeLiteralSecret` (`SecureDataVault.java:1481-1482`) are unreachable dead code — any name containing `=` has already left the loop body — which is how the authors clearly intended it to work and how it silently does not; and an operator who reaches for the inline form because the space-separated form was refused gets a *worse* outcome than one who tried the plain form, since one is refused and the other silently succeeds. `SelfTest.java` never exercises the `--opt=value` form at all (there is no occurrence of it in the file), so the harness that does cover the space-separated refusal (`SelfTest.java:768-772`) gives false assurance here. Secrets in argv are visible to any local user through `/proc/<pid>/cmdline` and `ps`, and land in shell history.

**Fix:** Run the secret check on the option name *before* splitting on `=`, and make the predicate itself insensitive to the `=` suffix:

```java
                String name = arg.substring(2);
                if (looksLikeLiteralSecret(name)) {
                    throw new VaultException("the option --" + name.split("=", 2)[0]
                            + " does not exist: a secret must not be passed on the command line where the"
                            + " process table and shell history can see it. Use --storepass-env,"
                            + " --storepass-file or --storepass-prompt.");
                }
                int eq = name.indexOf('=');
                if (eq >= 0) {
                    opts.values.put(name.substring(0, eq), name.substring(eq + 1));
                    continue;
                }
```

```java
        private static boolean looksLikeLiteralSecret(String name) {
            String key = name.split("=", 2)[0];
            return key.equals("storepass") || key.equals("keypass") || key.equals("pass")
                    || key.equals("password") || key.equals("passphrase") || key.equals("key");
        }
```

Then add `SelfTest` cases asserting `--storepass=hunter2`, `--pass=hunter2` and `--key=<b64>` all exit non-zero, in both `--opt value` and `--opt=value` forms.

### SEC-03: PBKDF2 iteration floor accepts a work factor six times below the documented default

- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `SecureDataVault.java:101-102` (enforced floor at `SecureDataVault.java:350-352`, option at `SecureDataVault.java:1130`)

**Vulnerable code:**

```java
// SecureDataVault.java:100-103
    public static final int DEFAULT_KEY_BITS = 256;
    public static final int DEFAULT_PBKDF2_ITERATIONS = 600_000;
    public static final int MIN_PBKDF2_ITERATIONS = 100_000;
    public static final int SALT_BYTES = 32;
```

**Why it is a problem:** `DEFAULT_PBKDF2_ITERATIONS` is a sound 600 000, matching the guidance in the applied skill `implementing-aes-encryption-for-data-at-rest` ("PBKDF2: NIST-approved, widely supported (minimum 600,000 iterations as of 2024)"). The floor is a different matter: `MIN_PBKDF2_ITERATIONS = 100_000` is only checked by `KdfParams`' constructor (`SecureDataVault.java:350-352`), so `saltgen --iterations 100000 --kdf x.kdf` succeeds silently and produces a record that `--kdf` will happily use. That is a 6x reduction in the offline-cracking cost of the passphrase, and PBKDF2's *only* purpose here is to make guessing the passphrase expensive — `performing-cryptographic-audit-of-application` grades "Weak KDF | Low iteration PBKDF2" as High on exactly this reasoning. Two things make the gap durable rather than theoretical: nothing ever warns when the chosen count is below the default, so the operator sees only "iterations 100000" in `saltgen` output that they may not have typed deliberately, and `SelfTest.java` codifies the weak behaviour as correct — it asserts that records with 100 000 and 200 000 iterations are *accepted* (`SelfTest.java:476`, `501`, `511`, `532`, `542`, `980`) and refuses only 1 000 and 10 (`SelfTest.java:507`, `995`); it never asserts that the default is 600 000. Anyone later "fixing" the floor upward would break the suite, which is how a weak default becomes load-bearing. Because exploitation requires the attacker to already possess an envelope *and* the KDF record, and the derived key is still PBKDF2-HMAC-SHA256 with a 32-byte salt, this is Medium rather than High.

**Fix:**

```java
    public static final int DEFAULT_KEY_BITS = 256;
    public static final int DEFAULT_PBKDF2_ITERATIONS = 600_000;
    /** Floor follows current OWASP/NIST guidance for PBKDF2-HMAC-SHA256. */
    public static final int MIN_PBKDF2_ITERATIONS = 600_000;
```

and in `commandSaltgen` (`SecureDataVault.java:1130`), make a deliberate deviation loud rather than silent:

```java
        int iterations = intOption(opts, "iterations", DEFAULT_PBKDF2_ITERATIONS);
        if (iterations < DEFAULT_PBKDF2_ITERATIONS && !opts.has("force-insecure-iterations")) {
            throw new VaultException("--iterations " + iterations + " is below the default of "
                    + DEFAULT_PBKDF2_ITERATIONS + " and weakens the derived key against offline cracking."
                    + " Raise it, or pass --force-insecure-iterations to make the choice deliberately.");
        }
```

Update the `SelfTest` fixtures that use 100 000/200 000 to `DEFAULT_PBKDF2_ITERATIONS`, and add assertions that the default is 600 000 and that a sub-default `saltgen` is refused.

### SEC-04: KDF parameter record is unauthenticated and unprotected

- **Severity:** Low
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **Location:** `SecureDataVault.java:1268-1275` (written at `SecureDataVault.java:1137`)

**Vulnerable code:**

```java
// SecureDataVault.java:1268-1275
        if (opts.has(prefix + "kdf")) {
            Path kdf = Paths.get(expandHome(opts.get(prefix + "kdf")));
            if (!Files.isRegularFile(kdf)) {
                throw new VaultException("KDF parameter file not found: " + kdf + " (create it with saltgen)");
            }
            KdfParams params = KdfParams.parseRecord(
                    new String(Files.readAllBytes(kdf), StandardCharsets.US_ASCII));
            char[] passphrase = readSecret(opts, prefix, "passphrase");
```

**Why it is a problem:** The `kdf:v1:pbkdf2-hmac-sha256:<iterations>:<salt>` record steers key derivation and is consumed as trusted input: `parseRecord` validates only the prefix, the field count and that the iteration count parses as an integer and clears the floor (`SecureDataVault.java:373-391`). Nothing binds the record to the envelopes it is supposed to unlock, and nothing detects it having changed. Two failure modes follow for anyone with write access to the file (any other user on a shared host if it sits in a world-writable location, or any process that can touch the repo it lives in). First, availability: substituting the salt changes the derived key, so every existing envelope then fails the key-id gate and the data is unrecoverable until the record is restored — with no warning that it was tampered with, and no `--force`-style recovery path. Second, a silent work-factor downgrade for *newly* encrypted data: replace the record with a legal-but-minimal iteration count and the operator's next `encrypt` runs under the weakened KDF while all prior envelopes merely error, which reads as an unrelated key mix-up rather than tampering. The AEAD key-id gate (`SecureDataVault.java:617`) is a genuine mitigating control — it prevents silent mis-decryption, which is why this is Low — but it cannot detect a downgrade that only affects data encrypted afterwards. Note also that this is the one key-source file that never gets the `warnIfOpen` treatment given to the keystore and password files (compare `SecureDataVault.java:1262` with the absence of any such call at 1268-1275), and `saltgen` creates it with umask-default permissions.

**Fix:** Treat the record as configuration that must not drift. Have `saltgen` stamp the derived key's fingerprint into the record and write it owner-only, then have the `--kdf` path verify it before use:

```java
            KdfParams params = KdfParams.parseRecord(
                    new String(Files.readAllBytes(kdf), StandardCharsets.US_ASCII));
            warnIfOpen(kdf, opts, "KDF parameter file");
            if (params.expectedKeyId() != null) {
                char[] probe = readSecret(opts, prefix, "passphrase");
                try {
                    String derived = new PassphraseKeySource(probe, params, "--" + prefix + "kdf")
                            .load().keyId();
                    if (!MessageDigest.isEqual(hexToBytes(params.expectedKeyId()), hexToBytes(derived))) {
                        throw new VaultException("KDF record " + kdf + " derives key id " + derived
                                + ", not the " + params.expectedKeyId() + " it was created for: the record has"
                                + " been replaced, edited or downgraded. Restore it from the original"
                                + " saltgen output before decrypting.");
                    }
                } finally {
                    wipe(probe);
                }
            }
```

At minimum, and independent of the above, give the record the same owner-only creation and `warnIfOpen` check the keystore already gets (see SEC-01 and SEC-07).

### SEC-05: 64-bit key fingerprint published in every envelope is an offline verification oracle

- **Severity:** Low
- **CWE:** CWE-203: Observable Discrepancy (related: CWE-916)
- **Location:** `SecureDataVault.java:858-868` (embedded at `SecureDataVault.java:159`, printed at `SecureDataVault.java:1117`)

**Vulnerable code:**

```java
// SecureDataVault.java:858-868
    /** SHA-256 fingerprint of a key, truncated to 64 bits, lowercase hex. */
    static String keyIdOf(byte[] key) {
        byte[] digest = sha256().digest(key);
        char[] hex = new char[KEY_ID_HEX_LEN];
        for (int i = 0; i < KEY_ID_HEX_LEN / 2; i++) {
            hex[2 * i] = Character.forDigit((digest[i] >> 4) & 0xF, 16);
            hex[2 * i + 1] = Character.forDigit(digest[i] & 0xF, 16);
        }
        Arrays.fill(digest, (byte) 0);
        return new String(hex);
    }
```

**Why it is a problem:** The fingerprint is unkeyed — `SHA-256(key)[:8]` — and it travels inside every envelope, is printed by `keygen` (`SecureDataVault.java:1117`) and is the first thing `rawDecrypt` compares against (`SecureDataVault.java:617`). Anyone holding an envelope can therefore test a candidate key with one SHA-256 and one 8-byte comparison, without the AES-GCM round trip. For the primary case — 256-bit keys from `keygen` — that costs nothing: 64 bits of confirmation against a 256-bit uniform key is not an attack path, and the pattern is exactly the "publish a short id, keep the secret hashed" design that `implementing-api-key-security-controls` recommends, so no finding is raised against the design as such. The exposure is specific to the `--kdf` key source, where the key is PBKDF2(passphrase) and the passphrase may be a few dozen bits of entropy. There, an attacker with an envelope and the KDF record no longer needs the AEAD to confirm a guess (a GCM tag check is the same order of work as the KDF itself, so the practical saving is modest — hence Low), but they gain something the tag cannot give them: the fingerprint is available *before* the operator is ever involved, in logs, terminal scrollback, and the plaintext envelope file, so a candidate passphrase can be screened against it offline with no need to touch the ciphertext at all. It also lets anyone read a log line and learn whether two envelopes or two keystores share a key.

**Fix:** Do not derive the published identifier with an unkeyed hash of the key. Make it depend on secret key material the attacker does not have, so it stays useful as a label but stops being a test:

```java
    /** HMAC-SHA-256 of a domain-separation label, keyed by the key itself; truncated to 64 bits. */
    static String keyIdOf(byte[] key) throws VaultException {
        Mac mac = Mac.getInstance("HmacSHA256");                 // GeneralSecurityException elided
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] digest = mac.doFinal(KDF_RECORD_PREFIX.getBytes(StandardCharsets.US_ASCII));
        char[] hex = new char[KEY_ID_HEX_LEN];
        for (int i = 0; i < KEY_ID_HEX_LEN / 2; i++) {
            hex[2 * i] = Character.forDigit((digest[i] >> 4) & 0xF, 16);
            hex[2 * i + 1] = Character.forDigit(digest[i] & 0xF, 16);
        }
        Arrays.fill(digest, (byte) 0);
        return new String(hex);
    }
```

An attacker who does not hold the key cannot compute or verify a fingerprint for a guessed key without first doing the full KDF *and* the HMAC, which removes the cheap screening path; the value remains a stable identifier for logging and rotation. Since this changes every existing envelope's key id, ship it as a `v2:` envelope header alongside a `rotate` migration rather than as an in-place fix.

### SEC-06: `--text` places the plaintext secret in the process table and shell history

- **Severity:** Low
- **CWE:** CWE-214: Invocation of Process with Sensitive Information in Arguments
- **Location:** `SecureDataVault.java:1366-1370` (advertised at `SecureDataVault.java:1000`)

**Vulnerable code:**

```java
// SecureDataVault.java:1366-1370
    private static byte[] readInput(Opts opts) throws VaultException, IOException {
        String text = opts.get("text");
        if (text != null) {
            return text.getBytes(StandardCharsets.UTF_8);
        }
```

**Why it is a problem:** The tool takes a strict, well-argued line about *keys and passwords* — they never come from argv, because "argv is world readable through the process table and is kept in shell history" (`SecureDataVault.java:996-997`) — and then accepts the *payload itself* from argv under `--text`, which is listed in `--help` among "Other options" (`SecureDataVault.java:1000`) with no caveat. The same /proc/<pid>/cmdline window that justifies the key rule applies with equal force to the secret being protected, and in one respect it is worse: the key rule protects one long-lived value, while `--text` invites a new secret into `ps` output and `~/.bash_history` on every call. `SelfTest.java:698` shows the natural usage — `--text "ssn=123-45-6789"` — so the plaintext PII in that example would be sitting in the shell history of whoever ran it. The exposure window is short (the process lifetime) for `ps`, but the shell-history residue is indefinite, and the option's presence in `--help` with a "convenience" framing is what gets it used for real values instead of the examples it was written for. Low because it is opt-in and the safe paths (`stdin`, `--in`) are the defaults and are documented.

**Fix:** Keep the option for scripting and documentation, but make the cost visible on every use and steer it towards the safe paths:

```java
    private static byte[] readInput(Opts opts) throws VaultException, IOException {
        String text = opts.get("text");
        if (text != null) {
            if (!opts.has("force-insecure-text")) {
                System.err.println("warning: --text put the plaintext in the process table and in your shell"
                        + " history; prefer piping on stdin or using --in. Suppress with"
                        + " --force-insecure-text.");
            }
            return text.getBytes(StandardCharsets.UTF_8);
        }
```

and annotate the usage line at `SecureDataVault.java:1000` accordingly ("`--text STR` Input as an argument; **the value is visible in `ps` and shell history** — for real secrets use stdin or `--in`").

### SEC-07: Loose key-file permissions are warn-only and the permission check fails open

- **Severity:** Low
- **CWE:** CWE-276: Incorrect Default Permissions (fail-open aspect: CWE-636)
- **Location:** `SecureDataVault.java:922-936` (warn-only at `SecureDataVault.java:1299-1304` and `SecureDataVault.java:1119-1121`)

**Vulnerable code:**

```java
// SecureDataVault.java:922-936
    /** True if group or other have any access at all - worth warning about. */
    static boolean permissionsAreOpen(Path path) {
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            for (PosixFilePermission p : perms) {
                String name = p.name();
                if (name.startsWith("GROUP_") || name.startsWith("OTHERS_")) {
                    return true;
                }
            }
            return false;
        } catch (UnsupportedOperationException | IOException e) {
            return false;
        }
    }
```

**Why it is a problem:** Two defects compound. First, the result is only ever used to print a warning: `warnIfOpen` (`SecureDataVault.java:1299-1304`) and the `keygen` branch (`SecureDataVault.java:1119-1121`) emit one line to stderr and carry on, so a keystore or key file at mode `0666` is used exactly as readily as one at `0600`, and the operator can silence even the warning with `--force-insecure-fileperms` (`SecureDataVault.java:1007`). `SelfTest.java` locks that behaviour in as expected: it chmods the passphrase file to `0777` and asserts `expectExit("cli still works with a loose password file", warn, 0)` (`SelfTest.java:945-947`) — the suite *requires* non-refusal. Second, and worse for detection, the `catch` returns `false` — "permissions are not open" — for `IOException` as well as `UnsupportedOperationException`. An unreadable or vanished permission set is therefore indistinguishable from a safe one, and the check silently reports all-clear on precisely the hosts where it could not see anything. The `UnsupportedOperationException` arm is a reasonable answer to a non-POSIX filesystem; the `IOException` arm is a fail-open on POSIX. Combined with SEC-01, the net effect is that the tool's permission story is advisory for everything except the keystore it writes itself. Low severity because exploiting it needs local access and, in the keystore case, still requires cracking or re-using the AEAD to learn anything — but the fail-open `catch` is the kind of bug that hides a real exposure later.

**Fix:** Separate "permissions are open" from "permissions are unknown", and make the decision a refusal rather than a warning for key material:

```java
    /** TRUE open, FALSE closed, empty if the mode could not be determined. */
    static java.util.Optional<Boolean> permissionsAreOpen(Path path) {
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            for (PosixFilePermission p : perms) {
                String name = p.name();
                if (name.startsWith("GROUP_") || name.startsWith("OTHERS_")) {
                    return java.util.Optional.of(Boolean.TRUE);
                }
            }
            return java.util.Optional.of(Boolean.FALSE);
        } catch (UnsupportedOperationException nonPosix) {
            return java.util.Optional.of(Boolean.FALSE);   // no POSIX ACLs to expose
        } catch (IOException e) {
            return java.util.Optional.empty();             // unknown: never report "safe"
        }
    }

    private static void refuseIfOpen(Opts opts, Path path, String what) throws VaultException {
        if (opts.has("force-insecure-fileperms") || !Files.isRegularFile(path)) {
            return;
        }
        java.util.Optional<Boolean> open = permissionsAreOpen(path);
        if (open.orElse(Boolean.TRUE)) {
            throw new VaultException(what + " " + path + " grants access beyond the owner (or its mode could"
                    + " not be read); run 'chmod 600 " + path + "'. Pass --force-insecure-fileperms only if"
                    + " this is deliberate.");
        }
    }
```

Update `SelfTest.java:945-952` to expect refusal by default and success only with `--force-insecure-fileperms`, and extend it to cover the keystore as well as the password file.

### SEC-08: Caller-supplied context echoed verbatim into an authentication error message

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information (related: CWE-532)
- **Location:** `SecureDataVault.java:631-635`

**Vulnerable code:**

```java
// SecureDataVault.java:631-635
            } catch (AEADBadTagException e) {
                throw new VaultException("authentication tag check failed: the envelope was tampered with, or the"
                        + " supplied context '" + context + "' is not the one it was encrypted with, or the key is"
                        + " wrong. Nothing was decrypted.", e);
            } catch (GeneralSecurityException e) {
```

**Why it is a problem:** `--context` is arbitrary caller-chosen text, and the only thing known about it in this code path is that it is wrong. The message is thrown to the CLI's failure path and reaches stderr, which in practice means it is captured into build logs, CI output, SIEM events and support tickets — so whatever the caller put in the context is copied into every one of those systems, unbidden, whenever a decrypt fails. Callers use the context precisely for identifying material (a customer id, a record key, a tenant name); the component has no way to know whether that material is sensitive, which is exactly why it should not be propagating it. The authors already had the right helper available and used it elsewhere: `describeStart` (`SecureDataVault.java:897-901`) deliberately truncates caller text to 32 characters for the same reason. Here even that restraint is absent, and the failure is on the *reject* path, where an attacker who can trigger failures (they can — flip a byte of the envelope) can push the operator's context values into logs at will. Low because the context is not itself a cryptographic secret by design and the volume is small, but it is an unnecessary disclosure on a path an attacker controls the timing of.

**Fix:** Name the parameter, never its value:

```java
            } catch (AEADBadTagException e) {
                throw new VaultException("authentication tag check failed: the envelope was tampered with, the"
                        + " value supplied via --context does not match the one used at encryption time, or the"
                        + " key is wrong. Nothing was decrypted. (context not echoed: it may be sensitive)", e);
            } catch (GeneralSecurityException e) {
```

If a diagnostic value is genuinely wanted for troubleshooting, reuse `describeStart(context)` rather than the raw string, and gate it behind an explicit `--verbose` flag that is off by default.

### SEC-09: Unbounded whole-input reads allow memory exhaustion before any crypto work

- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling (related: CWE-400)
- **Location:** `SecureDataVault.java:1371-1380` (also `SecureDataVault.java:1189` and `SecureDataVault.java:1328`)

**Vulnerable code:**

```java
// SecureDataVault.java:1371-1380
        String in = opts.get("in");
        if (in == null || "-".equals(in)) {
            return System.in.readAllBytes();
        }
        Path path = Paths.get(expandHome(in));
        if (!Files.isRegularFile(path)) {
            throw new VaultException("input file not found: " + path);
        }
        return Files.readAllBytes(path);
    }
```

**Why it is a problem:** Every input path materialises the whole payload in memory before anything else happens: `readInput` takes stdin or a file with `readAllBytes` (`SecureDataVault.java:1373`, `1379`), `commandRotate` slurps the entire envelope list with `Files.readAllLines` (`SecureDataVault.java:1189`), and the passphrase file is read whole as well (`SecureDataVault.java:1328`). On top of the raw bytes, `encryptBytes` builds a second full-size array for the ciphertext and `Envelope.toText` a third for the Base64 rendering, so peak heap is several multiples of the input; `rotate` additionally accumulates every re-encrypted line into a `StringBuilder` before writing. There is no `--max-input-bytes` and no streaming, so a misdirected `--in` (a database dump, a block device, a large log) or a hostile pipeline turns a secret-handling tool into an out-of-memory crash — or, on a shared host, an invocation that gets the JVM's cgroup killed while taking other work with it. `commandRotate` is the sharpest case because its input is a *list of envelopes* an attacker may well have influenced (a staging file assembled from ticket attachments), and it decrypts and re-encrypts every line in memory while holding all results. The realistic impact is availability only, and the attacker generally needs to already be able to hand the operator a file, which keeps this Low.

**Fix:** Bound the read at a configurable limit, one byte past the cap so the overflow is detectable:

```java
    /** Refuse inputs larger than this by default (64 MiB); --max-input-bytes overrides. */
    private static final long DEFAULT_MAX_INPUT_BYTES = 64L * 1024 * 1024;

    private static byte[] readLimited(java.io.InputStream in, long limit, String what)
            throws IOException, VaultException {
        byte[] bytes = in.readNBytes((int) Math.min(limit + 1, Integer.MAX_VALUE - 8));
        if (bytes.length > limit || in.read() != -1) {
            throw new VaultException(what + " exceeds the " + limit + " byte limit; pass --max-input-bytes to"
                    + " raise it or split the input");
        }
        return bytes;
    }
```

```java
        String in = opts.get("in");
        long limit = longOption(opts, "max-input-bytes", DEFAULT_MAX_INPUT_BYTES);
        Path path = in == null ? null : Paths.get(expandHome(in));
        if (path == null || "-".equals(in)) {
            return readLimited(System.in, limit, "stdin");
        }
        if (!Files.isRegularFile(path)) {
            throw new VaultException("input file not found: " + path);
        }
        try (java.io.InputStream stream = Files.newInputStream(path)) {
            return readLimited(stream, limit, path.toString());
        }
    }
```

Apply the same cap to `commandRotate`'s input and stream its output through a `BufferedWriter` instead of a `StringBuilder`, so re-keying a large envelope list has constant memory.

## 6. Verified Controls and Checks With No Finding

The following were checked against the applied skills and are correctly implemented.

Cryptographic construction (against `implementing-aes-encryption-for-data-at-rest` and `performing-cryptographic-audit-of-application`):

- AES in **GCM** mode with a 128-bit tag throughout (`GCM_TAG_BITS`, `SecureDataVault.java:583-597`). No ECB, no CBC-without-MAC, no hand-rolled MAC-then-encrypt; the skill's "Bad Cipher Mode" and "Weak/Missing Authentication" rows find nothing.
- **Fresh CSPRNG nonce per encryption.** `RANDOM` is a shared `SecureRandom` (`SecureDataVault.java:108-109`) and `RANDOM.nextBytes(iv)` runs inside every `encryptBytes` call (`SecureDataVault.java:583-584`); the salt is likewise CSPRNG-generated (`SecureDataVault.java:813-814`). The "Poor Entropy | time-based seeds, predictable IVs" row does not apply, and `SelfTest` exercises repeated encryptions under one key and asserts distinct envelopes. The nonce is stored ahead of the ciphertext as the skill prescribes, and is treated as non-secret.
- **AAD binds the envelope's own fields.** `additionalAuthenticatedData` (`SecureDataVault.java:662-673`) authenticates `HEADER + "|" + keyId [+ "|" + context]`, and because the version prefix and key id have fixed shapes, plus `context` is restricted to printable ASCII excluding `|` and space, the pipe-delimited fields cannot be reinterpreted. The AAD-shift and version-downgrade attacks are therefore closed, and `SelfTest` confirms that rewriting the key id, changing the context, or editing the payload all end in refusal with no plaintext written.
- **Constant-time key-id comparison** via `MessageDigest.isEqual` (`SecureDataVault.java:617`) rather than `String.equals`, so the pre-AEAD gate is not a timing side channel.
- **No hardcoded secrets in production code** — the skill's "Critical" row. All key material, passwords and passphrases in the repository live in `SelfTest.java` as fixtures (e.g. `SelfTest.java:420`, `512`, `557`); `SecureDataVault.java` contains no literal key, salt or password.

Key handling and lifecycle (against `implementing-rsa-key-pair-management` and the AES skill's key-management checklist):

- **Key material is wrapped and copy-guarded.** `KeyHandle` clones the key in and out, wipes on `close()`, and its `toString()` prints only the source and the non-secret fingerprint, so a key cannot leak through logging or string concatenation; `SelfTest.java:406-432` asserts the zeroisation and the `toString` content.
- **Key sources are single-use** — the passphrase and salt are wiped once consumed, so a second `load()` cannot silently reuse a secret the tool believes it has erased (`SelfTest.java:541-553`).
- **AES key length is validated** to 16/24/32 bytes, including a check against `Cipher.getMaxAllowedKeyBits`, so a truncated or oversized Base64 key from `--key-env` is refused rather than silently shortened.
- **Rotation is implemented and safe by default.** `commandRotate` (`SecureDataVault.java:1184-1229`) decrypts under the old key and re-encrypts under the new, refuses a destination key with the same id, and aborts the whole batch on the first unreadable line rather than emitting a partially rotated file; `SelfTest.java:872-892` covers both.
- **Keystore writes are owner-only and atomic.** `writeKeyStoreAtomically` (`SecureDataVault.java:781-803`) creates a sibling temp file, applies `ownerReadWrite()` *before* storing any key material, and publishes with `ATOMIC_MOVE`. The `REPLACE_EXISTING` fallback at `SecureDataVault.java:801` is a brief non-atomic window on filesystems without atomic rename, but it preserves the owner-only mode and is a residual risk rather than a finding; `SelfTest.java:626-634` asserts the resulting mode.
- **The tool verifies what it wrote.** `keygen` reloads the keystore and compares the stored key id against the one it generated (`SecureDataVault.java:1110-1113`) instead of trusting that `KeyStore.store` succeeded; `SelfTest.java:613-624` further confirms the raw AES key bytes do not appear verbatim in the keystore file.
- **Secrets are not printed.** `keygen` prints the Base64 key only under an explicit `--print-base64`, `keyinfo` prints the source and fingerprint only (`SecureDataVault.java:1231-1238`), and errors that could carry a secret name the variable rather than its value (`SecureDataVault.java:853-856`, `SelfTest.java:913-919`).

Authentication-input hygiene:

- **Strict Base64 decoding** for keys, salts and payloads via `decodeBase64Strict`, so trailing whitespace or a substituted alphabet is rejected rather than silently reinterpreted (`SelfTest.java:450-473`).
- **KDF records are shape-checked** — prefix, exactly five fields, numeric iteration count, `salt >= 16` bytes and a pinned `PBKDF2WithHmacSHA256` algorithm — so a malformed or substituted record fails closed (`SecureDataVault.java:373-391`, `SelfTest.java:474-509`). The *unauthenticated* aspect of the record is SEC-04; its parsing is sound.
- **Passwords and passphrases arrive only from environment, file, or an interactive `Console.readPassword`** (`SecureDataVault.java:1310-1361`), the file variant warns about permissions and wipes the raw buffer, and a present-but-empty variable is reported as empty rather than accepted as a zero-length secret.
- **The space-separated argv guard works as documented** for the form the harness tests — `--storepass hunter2` and `--key <b64>` are refused with an explanatory message (`SecureDataVault.java:1464-1467`, `SelfTest.java:768-772`). The inline `--storepass=hunter2` form is SEC-02.
- **JKS is rejected** with the correct reason ("JKS cannot hold a symmetric key") and unknown types are refused (`SecureDataVault.java:1424-1432`). Accepting legacy `JCEKS` is a deliberate interop allowance on an explicit opt-in; noted as residual risk, not a finding.
- **Wrong-context decryption leaves no output.** The plaintext is written only after `doFinal` returns successfully, so a failed tag check produces an error and no file; `SelfTest.java:774-789` asserts exactly that.
