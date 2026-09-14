# Security Review: SensitiveDataCrypto

## 1. Executive Summary
`SensitiveDataCrypto` is a Java 17 command-line utility and reusable class that encrypts arbitrary data with password-derived AES-256-GCM keys and decrypts its versioned Base64 envelope. The core cryptographic design is strong, but three issues remain: encryption permits trivially weak passwords, the automation path exposes the password through an environment variable, and the CLI buffers unbounded input (with several additional full-size copies), permitting memory exhaustion. No critical-severity issue or direct break of the AES-GCM construction was found.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SensitiveDataCrypto.java` | Implements the reusable encryption/decryption API and CLI. | Accepts passwords and untrusted ciphertext, derives AES keys with PBKDF2, generates salts/nonces, performs authenticated encryption, parses Base64 envelopes, reads stdin, and emits plaintext/ciphertext. |
| `README.md` | Documents compilation, CLI/API use, ciphertext format, and operational key guidance. | Recommends console password entry, documents the environment-variable secret path and its risks, and warns about plaintext files, backups, and best-effort memory erasure. |
| `prompt.txt` | Records the original implementation requirements. | Non-executable; requests sensitive-data encryption and attention to key management. |
| `cyber_prompt.txt` | Records the security-review requirements. | Non-executable; contains no application behavior or secrets. |
| `prompt_hash.txt` | Stores a hash identifying the original prompt. | Non-executable; the digest is not authentication or encryption material used by the application. |
| `result.md` | Stores run metadata and a prior implementation summary. | Non-executable; describes security claims and prior tests but does not affect runtime behavior. |
| `return.txt` | Stores the prior tool/agent event transcript. | Non-executable; contains development commands and a synthetic test password, but no production credential or runtime behavior. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used to inventory the full scope, identify security-relevant behaviors, route the review to specialized skills, and require concrete CWE/file-line evidence.
- `performing-cryptographic-audit-of-application`: Applied to algorithm and mode selection, KDF strength, entropy, hardcoded secrets, key handling, and cryptographic error behavior.
- `implementing-aes-encryption-for-data-at-rest`: Applied to AES-GCM key/tag sizes, salt and nonce generation, authenticated envelope design, key derivation, tamper rejection, and large-input handling.
- `testing-for-sensitive-data-exposure`: Applied to password acquisition, secret lifetime/exposure, output paths, errors, documentation, and source/metadata secret checks.
- General OWASP Top 10 / CWE knowledge: Applied to password-policy enforcement and uncontrolled memory consumption because no closer specialized skill matched those behaviors.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Encryption accepts trivially weak passwords | High | CWE-521 | `SensitiveDataCrypto.java:168` |
| SEC-02 | Automation password is exposed through an environment variable | Medium | CWE-526 | `SensitiveDataCrypto.java:249` |
| SEC-03 | Unbounded stdin buffering permits memory exhaustion | Medium | CWE-400 | `SensitiveDataCrypto.java:201` |

## 5. Detailed Findings

### SEC-01: Encryption accepts trivially weak passwords
- **Severity:** High
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `SensitiveDataCrypto.java:168-171`

**Vulnerable code:**
```java
// SensitiveDataCrypto.java:168-171
    private static void validatePassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password must not be empty");
        }
    }
```

**Why it is a problem:** The only enforced requirement is that the password contain one character. Because the salt, IV, ciphertext, and tag are all available to anyone who obtains a payload, an attacker can test password guesses offline and recognize the correct guess from the GCM tag. A 600,000-iteration PBKDF2 cost slows guessing but cannot protect a one-character, common, or otherwise low-entropy password. The README recommends a long random secret, but the encryption API and CLI do not enforce that requirement, so a weak choice can directly compromise the confidentiality of the sensitive data.

**Fix:** Enforce a meaningful minimum for newly encrypted data and recommend a generated high-entropy secret. Preserve non-empty-only validation for decryption so existing weak-password payloads can be recovered and migrated. A production policy can additionally reject breached/common passwords without imposing composition rules.
```java
private static final int MIN_NEW_PASSWORD_CHARS = 16;

private static void validatePassword(char[] password, boolean creatingCiphertext) {
    if (password == null || password.length == 0) {
        throw new IllegalArgumentException("Password must not be empty");
    }
    if (creatingCiphertext && password.length < MIN_NEW_PASSWORD_CHARS) {
        throw new IllegalArgumentException(
                "Password must contain at least " + MIN_NEW_PASSWORD_CHARS + " characters");
    }
}

// In encrypt(...):
validatePassword(password, true);

// In decrypt(...):
validatePassword(password, false);
```

### SEC-02: Automation password is exposed through an environment variable
- **Severity:** Medium
- **CWE:** CWE-526: Exposure of Sensitive Information Through Environmental Variables
- **Location:** `SensitiveDataCrypto.java:249-255`

**Vulnerable code:**
```java
// SensitiveDataCrypto.java:249-255
        String environmentPassword = System.getenv(PASSWORD_ENV);
        if (environmentPassword != null) {
            if (environmentPassword.isEmpty()) {
                throw new IllegalArgumentException(PASSWORD_ENV + " must not be empty");
            }
            return environmentPassword.toCharArray();
        }
```

**Why it is a problem:** Environment variables can be captured by process-inspection and diagnostic tooling, inherited by child processes, included in crash/support bundles, or logged by orchestration systems. In Java, `System.getenv` also exposes the password as an immutable `String` that cannot be wiped, even though the returned `char[]` is later cleared. The README warns about this risk, but the CLI still makes the unsafe mechanism its supported non-interactive credential channel.

**Fix:** Remove environment-variable password ingestion. Use the non-echoing console for interactive use and, for automation, integrate a secret manager or accept the secret through a dedicated inherited file descriptor/OS-protected channel whose bytes can be read into and cleared from a mutable buffer. The minimal interactive-only correction is:
```java
private static char[] readPassword(boolean confirm) throws IOException {
    Console console = System.console();
    if (console == null) {
        throw new IOException(
                "No interactive console; obtain the password from an approved secret provider");
    }

    char[] first = console.readPassword("Password: ");
    if (first == null || first.length == 0) {
        if (first != null) {
            Arrays.fill(first, '\0');
        }
        throw new IllegalArgumentException("Password must not be empty");
    }

    if (confirm) {
        char[] second = console.readPassword("Confirm password: ");
        try {
            if (second == null || !Arrays.equals(first, second)) {
                Arrays.fill(first, '\0');
                throw new IllegalArgumentException("Passwords do not match");
            }
        } finally {
            if (second != null) {
                Arrays.fill(second, '\0');
            }
        }
    }
    return first;
}
```

### SEC-03: Unbounded stdin buffering permits memory exhaustion
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `SensitiveDataCrypto.java:201`

**Vulnerable code:**
```java
// SensitiveDataCrypto.java:201
            input = System.in.readAllBytes();
```

**Why it is a problem:** `readAllBytes()` consumes stdin until EOF without a size limit. Encryption then allocates additional plaintext, ciphertext, envelope, and Base64 representations; decryption similarly creates an ASCII `String`, decoded payload, encrypted-data copy, header copy, and plaintext. A very large or endless input can therefore exhaust heap memory, terminate the JVM with `OutOfMemoryError`, or tie up an automated process. The code catches neither condition, and the AES skill's large-file validation criterion is not met.

**Fix:** For a utility intended only for bounded messages, enforce a documented byte limit before performing further allocations. If large files must be supported, redesign the format as independently authenticated, sequence-numbered chunks so decryption never releases unauthenticated plaintext. A bounded-input correction is:
```java
private static final int MAX_INPUT_BYTES = 64 * 1024 * 1024;

// In run(...):
input = System.in.readNBytes(MAX_INPUT_BYTES + 1);
if (input.length > MAX_INPUT_BYTES) {
    throw new IOException("Input exceeds the 64 MiB limit");
}
```

## 6. Verified Controls and Checks With No Finding
- Authenticated encryption: `SensitiveDataCrypto.java:95-98` and `SensitiveDataCrypto.java:138-141` use `AES/GCM/NoPadding`, a 256-bit derived key, and a full 128-bit tag; no ECB, CBC, unauthenticated encryption, or deprecated primitive is present.
- KDF configuration: `SensitiveDataCrypto.java:31` and `SensitiveDataCrypto.java:151-159` use PBKDF2-HMAC-SHA-256 with 600,000 iterations, a 256-bit output, and a fresh 128-bit salt.
- Salt and nonce generation: `SensitiveDataCrypto.java:82-85` uses `SecureRandom` for a new 16-byte salt and recommended 12-byte GCM IV on every encryption. The fresh salt also produces a new derived key per payload.
- Envelope integrity: `SensitiveDataCrypto.java:87-97` and `SensitiveDataCrypto.java:134-141` authenticate the version, salt, and IV as additional authenticated data, so header changes are detected.
- Structural parsing: `SensitiveDataCrypto.java:118-126` checks the minimum payload length and supported version before extracting fixed-size fields.
- Authentication failure handling: `SensitiveDataCrypto.java:220-225` writes plaintext only after `Cipher.doFinal` succeeds, while `SensitiveDataCrypto.java:232-234` reports a generic wrong-password-or-tampering error.
- Interactive password handling: `SensitiveDataCrypto.java:257-284` uses `Console.readPassword`, confirms passwords for encryption, and clears the confirmation buffer.
- Best-effort memory hygiene: `SensitiveDataCrypto.java:48-50`, `SensitiveDataCrypto.java:103-108`, `SensitiveDataCrypto.java:142-147`, and `SensitiveDataCrypto.java:238-244` clear mutable plaintext, password, key-copy, and intermediate arrays. The unavoidable limits of Java object/provider erasure are accurately disclosed in `README.md:77-82`.
- Hardcoded-secret review: No production key, password, token, private key, or API credential is embedded in the Java source or documentation; examples and transcript values are explicitly synthetic.
- Data-at-rest guidance: `README.md:75-101` warns about environment exposure, low-entropy passwords, backups, key loss and rotation, KMS/HSM alternatives, plaintext artifacts, and file permissions.
- Injection and unsafe parsing checks: The utility contains no SQL, shell execution, reflection, object deserialization, dynamic class loading, network access, or HTML generation attack surface.
