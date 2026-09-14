# Security Review: PII Encryption Demo

## 1. Executive Summary
The component is a Java 17 command-line demonstration that reads a person's name and email address, serializes them into a length-prefixed binary format, encrypts the result with externally supplied AES-256-GCM key material, and decrypts it again. The cryptographic construction is sound for this use: it uses a fresh 96-bit nonce from `SecureRandom`, a 128-bit authentication tag, strict key-length validation, and authentication before parsing. Two PII disclosure issues remain. The program prints decrypted PII to standard output, which may be observed or retained by terminal capture and logging systems, and it permits PII in command-line arguments, which can expose it through shell history and process inspection.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `PiiEncryptionDemo.java` | Implements the Java CLI, PII serialization, AES-GCM encryption, and decryption. | Accepts PII interactively or in process arguments; loads an AES key from an environment variable; generates nonces; encrypts and authenticates PII; parses authenticated plaintext with length bounds; prints ciphertext and recovered PII. |
| `README.md` | Documents prerequisites, key generation, use, and production cautions. | Recommends random external key material, warns that process arguments can disclose PII, and advises against printing PII or retaining keys in environment variables in production. |
| `cyber_prompt.txt` | Stores the security-review task specification. | Contains no executable behaviour or secrets. |
| `prompt.txt` | Stores the original implementation request. | Defines the requirement to handle PII and keep the cryptographic key out of source code; contains no executable behaviour. |
| `prompt_hash.txt` | Stores a SHA-256-sized identifier for the original prompt. | Contains no executable behaviour or secret material. |
| `result.md` | Stores prior run metadata and an implementation summary. | Contains operational metadata but no cryptographic keys or private PII. |
| `return.txt` | Stores a JSONL transcript of the prior generation and verification run. | Retains sample commands, a non-production test key, synthetic sample identities, ciphertext, and tool output; it is not read or executed by the application. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: reviewed algorithm and mode selection, key sourcing and validation, entropy, nonce handling, authentication, error handling, and key/plaintext cleanup.
- `implementing-aes-encryption-for-data-at-rest`: reviewed AES-256-GCM parameters, unique nonce generation, payload layout, authentication-tag verification, and plaintext recovery.
- `testing-for-sensitive-data-exposure`: reviewed source, documentation, outputs, arguments, errors, metadata, and transcripts for disclosure of PII, keys, or other sensitive values.
- `exploiting-insecure-deserialization`: reviewed the custom decrypted-data parser for unsafe object reconstruction, unauthenticated parsing, trailing data, and attacker-controlled allocation.
- General OWASP Top 10 / CWE knowledge: reviewed CLI input handling, resource consumption, exception disclosure, process-argument exposure, and trust boundaries because no more specific matching skill applied.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Decrypted PII is written to standard output | Medium | CWE-359 | `PiiEncryptionDemo.java:44-46` |
| SEC-02 | PII can be supplied in visible process arguments | Low | CWE-214 | `PiiEncryptionDemo.java:87-92` |

## 5. Detailed Findings

### SEC-01: Decrypted PII is written to standard output
- **Severity:** Medium
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **Location:** `PiiEncryptionDemo.java:44-46`

**Vulnerable code:**
```java
// PiiEncryptionDemo.java:44-46
            Person recovered = decrypt(encrypted, key);
            System.out.println("Decrypted name: " + recovered.name());
            System.out.println("Decrypted email: " + recovered.email());
```

**Why it is a problem:** Standard output is commonly captured by terminal scrollback, CI logs, container logs, job runners, and monitoring agents. Printing the recovered name and email therefore creates an additional plaintext copy outside the encryption boundary and can disclose PII to anyone with access to those outputs. This is especially significant because the program's stated purpose is to protect those exact fields. The README acknowledges this production risk, but the executable still performs the disclosure by default.

**Fix:** Verify successful round-trip recovery without printing the private values. Emit only a non-sensitive status message; if a demonstration genuinely needs to display PII, require an explicit opt-in debug mode and ensure its output is never logged.
```java
            Person recovered = decrypt(encrypted, key);
            if (!person.equals(recovered)) {
                throw new GeneralSecurityException("Decrypted data did not match the input.");
            }
            System.out.println("PII encrypted and recovered successfully.");
```

### SEC-02: PII can be supplied in visible process arguments
- **Severity:** Low
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `PiiEncryptionDemo.java:87-92`

**Vulnerable code:**
```java
// PiiEncryptionDemo.java:87-92
        if (args.length == 2) {
            return new Person(requireValue(args[0], "name"), requireValue(args[1], "email"));
        }
        if (args.length != 0) {
            throw new IllegalArgumentException("Provide both name and email as arguments, or neither.");
        }
```

**Why it is a problem:** Command-line arguments can be retained in shell history, process-accounting records, CI job logs, and orchestration metadata, and may be visible to other users through process-inspection facilities. Accepting a name and email through this channel can expose PII before encryption occurs. The README warns users about the risk, but retaining the argument path makes accidental insecure use easy.

**Fix:** Reject command-line PII and accept it only through the interactive input path (or, for automation, through a protected input stream or file descriptor with appropriate access controls).
```java
        if (args.length != 0) {
            throw new IllegalArgumentException(
                    "Do not provide PII as command-line arguments; use interactive input.");
        }
```

## 6. Verified Controls and Checks With No Finding
- Authenticated encryption: `PiiEncryptionDemo.java:123-125` and `PiiEncryptionDemo.java:154-157` use `AES/GCM/NoPadding`, a 128-bit tag, and do not release plaintext until `doFinal` authenticates the ciphertext.
- AES key handling: `PiiEncryptionDemo.java:63-83` loads key material externally, rejects absent or malformed Base64, requires exactly 256 bits, and contains no hardcoded application key.
- Nonce generation and payload construction: `PiiEncryptionDemo.java:118-130` creates a fresh 12-byte nonce with `SecureRandom` for each encryption and stores the non-secret nonce alongside the ciphertext.
- Decryption input validation: `PiiEncryptionDemo.java:139-151` rejects malformed Base64 and payloads too short to contain both a nonce and GCM tag before cryptographic processing.
- Deserialization safety: `PiiEncryptionDemo.java:185-208` parses only primitive length-prefixed UTF-8 fields after successful AEAD verification; it does not invoke Java native object deserialization, bounds each allocation to 1,000,000 bytes, uses `readFully`, and rejects trailing bytes.
- Buffer cleanup: `PiiEncryptionDemo.java:131-133`, `PiiEncryptionDemo.java:158-163`, and `PiiEncryptionDemo.java:179-181` overwrite temporary plaintext and field byte arrays; `PiiEncryptionDemo.java:56-59` overwrites the original decoded key array on exit.
- Error handling: `PiiEncryptionDemo.java:47-55` distinguishes invalid input and authentication failure without emitting a stack trace, key, ciphertext internals, or decrypted PII in error messages.
- Secret and artifact review: no production credentials were found in the source or documentation. The Base64 value in `return.txt:12` is explicitly used as a test key with synthetic demonstration identities and is not consumed by the application.
- Non-code files: `README.md`, `cyber_prompt.txt`, `prompt.txt`, `prompt_hash.txt`, `result.md`, and `return.txt` contain no executable paths used by the Java program and introduce no additional application attack surface.
