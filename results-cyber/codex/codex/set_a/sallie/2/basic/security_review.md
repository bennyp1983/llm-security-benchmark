# Security Review: PII Encryption Demo

## 1. Executive Summary
The component is a Java command-line demonstration that reads a person's name and email address, serializes them, encrypts them with a newly generated AES-256 key in GCM mode, decrypts the result, and reconstructs the original values. The cryptographic construction uses appropriate key generation, nonce length, authentication-tag length, and authenticated metadata. One Medium-severity vulnerability was identified: after decryption, the program writes the full plaintext PII to standard output, where terminal history, CI systems, container runtimes, or session-recording/logging infrastructure may retain or disclose it.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `PiiEncryptionDemo.java` | Source for the PII encryption/decryption CLI. | Accepts PII from standard input; performs custom binary serialization; generates an AES key and GCM nonce; encrypts, authenticates, decodes, validates, and decrypts data; writes ciphertext and recovered PII to standard output. |
| `PiiEncryptionDemo.class` | Compiled JVM bytecode for the main class. | Generated executable artifact corresponding to the security-sensitive Java implementation; source-level findings and line evidence are reported against `PiiEncryptionDemo.java`. |
| `PiiEncryptionDemo$Person.class` | Compiled JVM bytecode for the nested PII value class. | Stores recovered name and email values as object fields at runtime; its source is the nested `Person` class in `PiiEncryptionDemo.java`. |
| `README.md` | Build, usage, design, and security documentation. | Documents AES-GCM/key/nonce behavior and explicitly warns against writing decrypted PII to logs or standard output. |
| `prompt.txt` | Original implementation request. | Describes the intended PII encryption/decryption behavior; it is non-executable and contains no secrets. |
| `cyber_prompt.txt` | Security-review task specification. | Non-executable review instructions with no application security behavior. |
| `return.txt` | Recorded transcript of the earlier implementation run. | Contains tool metadata and illustrative plaintext sample data/output; no encryption key or real credential was identified. |
| `result.md` | Summary metadata for the earlier implementation run. | Non-executable metadata; it references the source and documentation but contains no secrets. |
| `prompt_hash.txt` | Hash identifying the prompt content. | Non-executable SHA-256-style digest with no runtime behavior or secret material. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory every file, identify security-relevant behavior, select specialized skills, and require CWE and file:line evidence.
- `performing-cryptographic-audit-of-application`: Applied to algorithm selection, cipher mode, key size and generation, randomness, embedded secrets, and key-management behavior.
- `implementing-aes-encryption-for-data-at-rest`: Applied to AES-256-GCM use, nonce construction, authentication-tag strength, authenticated metadata, and ciphertext packaging/decryption.
- `testing-for-sensitive-data-exposure`: Applied to PII handling, console output, source/transcript secret exposure, masking, and disclosure paths.
- General OWASP Top 10 / CWE knowledge: Applied to custom binary parsing, input validation and resource use, error handling, terminal output, and dangerous injection sinks because no closer specialized skill matched those behaviors.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Decrypted PII is disclosed through standard output | Medium | CWE-359 | `PiiEncryptionDemo.java:52-54` |

## 5. Detailed Findings

### SEC-01: Decrypted PII is disclosed through standard output
- **Severity:** Medium
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **Location:** `PiiEncryptionDemo.java:52-54`

**Vulnerable code:**
```java
// PiiEncryptionDemo.java:52-54
            System.out.println("\nDecrypted PII:");
            System.out.println("Name: " + recovered.name);
            System.out.println("Email: " + recovered.email);
```

**Why it is a problem:** The program emits the complete decrypted name and email to standard output. Standard output is often retained outside the process in terminal scrollback, shell/session recordings, IDE consoles, CI job logs, container logs, or process supervisors. Anyone who can access those systems can recover the PII without defeating AES-GCM. This negates the confidentiality goal at the point where the data is most sensitive, and the project's own `README.md` warns that real applications should not write decrypted personal information to logs or standard output.

**Fix:** Verify the round trip without displaying either recovered field. If a user-facing workflow truly needs to reveal PII, send it only to an explicitly authorized and access-controlled destination, and apply masking where full disclosure is unnecessary.
```java
            Person recovered = deserialize(decrypted);
            if (!name.equals(recovered.name) || !email.equals(recovered.email)) {
                throw new GeneralSecurityException("Decrypted data did not match the input.");
            }

            System.out.println("\nDecryption and integrity verification succeeded.");
```

## 6. Verified Controls and Checks With No Finding
- Authenticated encryption: `PiiEncryptionDemo.java:97-100` and `PiiEncryptionDemo.java:133-136` use `AES/GCM/NoPadding`, so ciphertext integrity and authenticity are verified rather than relying on unauthenticated encryption.
- Key strength and entropy: `PiiEncryptionDemo.java:22` and `PiiEncryptionDemo.java:71-75` generate a fresh 256-bit AES key with `KeyGenerator` and `SecureRandom`; no hardcoded encryption key or credential was found.
- GCM nonce and tag parameters: `PiiEncryptionDemo.java:23-24` and `PiiEncryptionDemo.java:94-100` use a fresh random 12-byte nonce and a 128-bit authentication tag. The current program performs only one encryption with each newly generated key, so nonce reuse under a key was not found.
- Authenticated format metadata: `PiiEncryptionDemo.java:99` and `PiiEncryptionDemo.java:135` bind the format version as additional authenticated data, preventing undetected version manipulation.
- Ciphertext parsing: `PiiEncryptionDemo.java:111-136` rejects malformed Base64, undersized payloads, and unsupported versions before authenticated decryption; GCM tag verification occurs in `doFinal`.
- Binary record parsing: `PiiEncryptionDemo.java:139-157` bounds each declared string length by the authenticated buffer's remaining bytes, uses `readFully`, and rejects trailing data. It does not invoke Java native object deserialization or instantiate attacker-selected classes.
- Input validation: `PiiEncryptionDemo.java:64-69` rejects end-of-file, empty, and whitespace-only values. More restrictive email validation is not security-critical here because the email is not used in a query, command, path, network request, or message-delivery sink.
- Dangerous sinks: No SQL execution, operating-system command execution, filesystem path construction, HTML/template rendering, outbound network request, TLS configuration, dynamic class loading, or reflection was found in the application source.
- Error handling: `PiiEncryptionDemo.java:55-61` catches expected input, I/O, and cryptographic failures without printing stack traces, key material, plaintext buffers, or ciphertext internals.
- Supporting files and artifacts: `README.md`, `prompt.txt`, `cyber_prompt.txt`, `return.txt`, `result.md`, `prompt_hash.txt`, and the compiled class artifacts were checked for embedded credentials or key material; none was found. The PII in `return.txt` is clearly illustrative sample data, and its ciphertext cannot be decrypted without the absent ephemeral key.
