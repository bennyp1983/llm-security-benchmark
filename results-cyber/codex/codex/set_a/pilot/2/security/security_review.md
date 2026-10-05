# Security Review: SensitiveDataCrypto

## Executive summary

The reviewed application is a small Java CLI for generating a 256-bit key and encrypting or decrypting stdin with AES-256-GCM. The cryptographic construction itself is appropriate: it uses `SecureRandom`, a fresh 96-bit nonce, a 128-bit authentication tag, authenticated format/version metadata, and rejects modified ciphertext before releasing plaintext.

Three security issues were identified, all involving key handling rather than the AES-GCM operation: one medium-severity key-file permission issue and two low-severity key-exposure issues. No critical or high-severity findings were identified.

| Severity | Finding | CWE | Evidence |
|---|---|---|---|
| Medium | Key files can be created or accepted without enforceable restrictive access controls | CWE-732 | `SensitiveDataCrypto.java:157-173`, `SensitiveDataCrypto.java:182-199` |
| Low | The encryption key can be exposed through the process environment | CWE-526 | `SensitiveDataCrypto.java:30`, `SensitiveDataCrypto.java:186-192` |
| Low | Key material is copied into immutable strings and is not cleared on every exit path | CWE-316 | `SensitiveDataCrypto.java:68-75`, `SensitiveDataCrypto.java:80-94`, `SensitiveDataCrypto.java:151-179`, `SensitiveDataCrypto.java:182-199` |

## Scope and file understanding

- `SensitiveDataCrypto.java` is the only source-code file. It implements the CLI dispatcher, AES-256-GCM encryption/decryption, random key generation, key loading from a file or environment variable, a Base64 ciphertext envelope, input-size enforcement, and user-facing error handling.
- `SensitiveDataCrypto.class` is the compiled Java bytecode artifact corresponding to the CLI; source-level findings are cited against `SensitiveDataCrypto.java`, where stable line evidence is available.
- `README.md` documents compilation, use, ciphertext layout, and key-management guidance.
- `.gitignore` excludes Java class files, key files, and encrypted output files from version control.
- `prompt.txt` and `cyber_prompt.txt` contain task prompts. `prompt_hash.txt` contains a prompt digest.
- `return.txt` and `cyber_return.txt` are prior execution transcripts. `result.md` is prior run metadata and a result summary. These are review artifacts, not executable application code.

Security-relevant behaviors reviewed were: symmetric cryptography, cipher mode and tag selection, nonce generation and reuse risk, randomness, key generation, key storage and loading, secret lifetime in memory, authenticated envelope parsing, Base64 decoding, file/path handling, input limits, and error behavior. There is no database access, network/TLS code, authentication/session logic, deserialization, dynamic code loading, or OS-command execution in the application.

## Findings

### 1. Medium — Key files can be created or accepted without enforceable restrictive access controls (CWE-732)

**Evidence:** `SensitiveDataCrypto.java:157-173` applies owner-only mode `0600` only when the filesystem exposes POSIX attributes. On every other filesystem, line 170 creates the key with inherited/default access controls and lines 171-172 merely print a warning after the key has already been written. Separately, `SensitiveDataCrypto.java:182-199` loads any caller-supplied key file without validating its type, owner, permissions, ACL, or whether it is a symbolic link.

**Why this is a problem:** The key protects every ciphertext produced with it. On a non-POSIX filesystem, an inherited ACL may expose a newly generated key to other users. On any platform, an existing key file may be group/world-readable or have an overly broad ACL, and the program silently accepts it. A user who follows the supported interface can therefore operate with an exposed key despite the generator's stated owner-only security goal. Anyone who obtains the key can decrypt data and create valid forged ciphertexts.

**Fix:** Create the key atomically with an owner-only ACL on each supported platform and fail closed when restrictive access cannot be established. When loading a file, use no-follow semantics, require a regular file owned by the expected account, and validate POSIX mode bits or the platform ACL before reading. If compatibility requires an override, make insecure-key-file use an explicit opt-in rather than a post-write warning. Continue refusing overwrites.

### 2. Low — The encryption key can be exposed through the process environment (CWE-526)

**Evidence:** `SensitiveDataCrypto.java:30` defines `APP_ENCRYPTION_KEY`, and `SensitiveDataCrypto.java:186-192` reads the complete Base64-encoded encryption key from that environment variable when no file is supplied.

**Why this is a problem:** Environment variables are commonly captured by process-inspection tools, crash/support bundles, container configuration and orchestration metadata, or inherited by child processes. Access is platform- and deployment-dependent, but disclosure of this long-lived raw AES key compromises all data encrypted with it. The README acknowledges that a mounted secret is less likely to leak, but the risky mechanism remains a first-class runtime interface.

**Fix:** Prefer an owner-restricted secret file, an OS credential/key store, or a KMS/secrets-manager integration, and remove the environment-variable key channel where possible. If it must remain for compatibility, clearly mark it as a weaker deployment option, ensure launch tooling does not persist or log the variable, avoid spawning children, and use a short-lived wrapped/data key rather than a long-lived master key.

### 3. Low — Key material is copied into immutable strings and is not cleared on every exit path (CWE-316)

**Evidence:** `SensitiveDataCrypto.java:154-155` calls `Base64.getEncoder().encodeToString(key)`, creating an immutable string containing a newly generated key. `SensitiveDataCrypto.java:183-199` loads file/environment key material into another immutable `String`. Those strings cannot be overwritten. In addition, the key cleanup blocks begin only after stdin reading or ciphertext parsing: `SensitiveDataCrypto.java:68-75` leaves the loaded key uncleared if `readLimitedStdin()` fails, and `SensitiveDataCrypto.java:80-94` leaves it uncleared if stdin reading or `decodeCiphertext()` fails. A decoded key with an invalid length at `SensitiveDataCrypto.java:194-198` is also abandoned without being cleared.

**Why this is a problem:** Extra cleartext copies extend the key's lifetime in JVM memory and can remain until garbage collection or longer in heap/core dumps. The program makes a best-effort claim to clear working arrays, but common malformed-input and I/O failure paths bypass that protection. This does not defeat AES-GCM directly; it increases the chance and duration of key recovery from process memory or diagnostics.

**Fix:** Keep Base64 key material in mutable byte/character arrays: use `Base64.getEncoder().encode(byte[])`, read a tightly bounded key file as bytes, trim ASCII whitespace without creating a `String`, and decode via byte-array APIs. Put the `try/finally` that clears a loaded key immediately after key acquisition so every subsequent failure path clears it. Clear decoded candidate keys on validation failure. Document that zeroization in a managed JVM remains best-effort, and disable or tightly protect heap/core dumps for deployments handling valuable keys.

## Checks that did not produce findings

- **Algorithm and mode:** `SensitiveDataCrypto.java:110-114` and `SensitiveDataCrypto.java:139-145` use `AES/GCM/NoPadding` with a 256-bit key and a 128-bit authentication tag; no weak cipher, ECB mode, unauthenticated encryption, or custom cryptography is present.
- **Nonce handling:** `SensitiveDataCrypto.java:107-108` generates a fresh 96-bit nonce using `SecureRandom`, and lines 116-119 store it with the ciphertext. Production users should still impose a per-key encryption limit and rotation policy so random-nonce collision risk remains negligible over the key lifetime.
- **Envelope authentication:** `SensitiveDataCrypto.java:113` and `SensitiveDataCrypto.java:142` authenticate the version marker as AAD. `SensitiveDataCrypto.java:128-145` validates framing and verifies the GCM tag before plaintext is returned.
- **Input/resource handling:** `SensitiveDataCrypto.java:217-223` caps stdin at 16 MiB. The small key file is read without an explicit size cap at line 185, but the path is supplied by the local CLI caller, so this was not treated as an independently exploitable denial of service. A bounded read would still improve robustness.
- **Hardcoded secrets and weak derivation:** No key or credential is embedded in the source. The generator uses 32 random bytes (`SensitiveDataCrypto.java:151-154`), and the program correctly refuses human passwords rather than applying an inadequate KDF.
- **Error behavior:** Authentication failures are reported without exposing unauthenticated plaintext (`SensitiveDataCrypto.java:43-44`). Other errors may include local filesystem details, but this is a local CLI and no remote trust boundary is present.
- **Injection and parsing:** There is no SQL, shell execution, network request, object deserialization, template rendering, or web output surface. Command names are matched against fixed cases, and key/ciphertext Base64 is strictly decoded.

File/path handling, bounded input, Base64 parsing, CLI argument handling, and error disclosure had no closely matching specialized skill in the library and were reviewed using general OWASP Top 10 and CWE secure-design knowledge.

## Skills applied

- `review-code-for-security-vulnerabilities` (routing workflow)
- `performing-cryptographic-audit-of-application`
- `implementing-aes-encryption-for-data-at-rest`
- `implementing-secrets-management-with-vault` (applied to the file/environment secret-delivery and long-lived-key concerns; no Vault deployment is assumed)

## Review limitations

This was a static review of the files in the folder. No deployment configuration, calling application, operating-system ACL policy, secrets-manager setup, or key-rotation policy was supplied. Those controls can materially raise or lower the practical severity of the key-handling findings.
