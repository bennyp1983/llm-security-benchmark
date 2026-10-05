# Security Review: SymmetricEncryptionApp

## 1. Executive Summary
The `SymmetricEncryptionApp` component is a standalone Java application providing symmetric data encryption and decryption capabilities using Java Cryptography Architecture (JCA) APIs. It implements AES-256 in Galois/Counter Mode (`AES/GCM/NoPadding`) for Authenticated Encryption with Associated Data (AEAD), along with password-based key derivation using `PBKDF2WithHmacSHA256`. The core cryptographic primitives, algorithm choices, 96-bit random IV generation via `SecureRandom`, 128-bit authentication tag verification, and tamper detection are robustly implemented according to modern cryptographic best practices.

However, the security review identified critical operational and memory handling vulnerabilities. Most notably, the command-line interface accepts raw cryptographic keys, passwords, and sensitive plaintext directly via process command-line arguments (`args[]`), exposing them to process listings (`ps aux`), shell history files, and system audit logs (CWE-214). In interactive mode, passwords and keys are read via `Scanner.nextLine()`, which echoes them to the terminal and retains them in immutable `String` objects (CWE-522). Additionally, `PBEKeySpec.clearPassword()` is omitted during key derivation, leaving password copies in heap memory (CWE-226), the PBKDF2 iteration count (310,000) falls short of current OWASP recommendations (600,000) (CWE-916), and hardcoded realistic credentials are embedded in the demonstration method (CWE-798).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SymmetricEncryptionApp.java` | Core application source file containing cryptographic APIs, CLI entry point, interactive menu, and automated verification routines. | AES-256-GCM encryption/decryption, PBKDF2 key derivation, `SecureRandom` IV and salt generation, Base64 encoding/decoding, CLI argument handling, interactive terminal I/O, and heap memory handling of keys and credentials. |
| `README.md` | Application documentation and user manual. | Documents cryptographic design, parameters, compilation, CLI usage commands with sample credentials, and programmatic integration examples. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit cryptographic primitives, cipher algorithms (`AES/GCM/NoPadding`), key lengths (256-bit), random number generation (`SecureRandom`), authentication tag length (128-bit), and key derivation parameters (PBKDF2).
- `implementing-aes-encryption-for-data-at-rest`: Applied to review AES-256-GCM wire format (`[IV] + [Ciphertext + Tag]`), nonce/IV freshness and uniqueness, authentication tag verification, key lifecycle, and in-memory key wiping.
- `testing-for-sensitive-data-exposure`: Applied to assess exposure of sensitive parameters (passwords, cryptographic keys, and plaintext) via process command-line arguments (`args[]`) and interactive console input.
- General OWASP Top 10 / CWE Knowledge: Applied to evaluate command-line argument disclosure (CWE-214), terminal echoing and cleartext memory storage of credentials (CWE-522, CWE-316), improper resource zeroization (`PBEKeySpec.clearPassword()`, CWE-226), and password derivation computational effort (CWE-916).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Exposure of Cryptographic Keys, Passwords, and Plaintext via Command-Line Arguments | High | CWE-214 | `SymmetricEncryptionApp.java:561-607` |
| SEC-02 | Insecure Interactive Password Input with Terminal Echo and String Retention | Medium | CWE-522 | `SymmetricEncryptionApp.java:459-468` |
| SEC-03 | Failure to Clear Sensitive PBEKeySpec and Key Material from Memory | Medium | CWE-226 | `SymmetricEncryptionApp.java:114-121` |
| SEC-04 | PBKDF2 Iteration Count Below Current Recommendation | Low | CWE-916 | `SymmetricEncryptionApp.java:44` |
| SEC-05 | Hardcoded Sensitive Demonstration Credentials and Passwords in Source Code | Low | CWE-798 | `SymmetricEncryptionApp.java:367-368` |

## 5. Detailed Findings

### SEC-01: Exposure of Cryptographic Keys, Passwords, and Plaintext via Command-Line Arguments
- **Severity:** High
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `SymmetricEncryptionApp.java:561-607`

**Vulnerable code:**
```java
// SymmetricEncryptionApp.java:561-607
                case "encrypt":
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for encrypt.");
                        System.err.println("Usage: java SymmetricEncryptionApp encrypt <plaintext> <base64Key>");
                        System.exit(1);
                    }
                    String plaintext = args[1];
                    String base64Key = args[2];
                    SecretKey secretKey = decodeKeyFromBase64(base64Key);
                    System.out.println(encryptString(plaintext, secretKey));
                    break;

                case "decrypt":
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for decrypt.");
                        System.err.println("Usage: java SymmetricEncryptionApp decrypt <base64Ciphertext> <base64Key>");
                        System.exit(1);
                    }
                    String ciphertext = args[1];
                    String decryptKeyBase64 = args[2];
                    SecretKey decKey = decodeKeyFromBase64(decryptKeyBase64);
                    System.out.println(decryptString(ciphertext, decKey));
                    break;

                case "encrypt-pw":
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for encrypt-pw.");
                        System.err.println("Usage: java SymmetricEncryptionApp encrypt-pw <plaintext> <password>");
                        System.exit(1);
                    }
                    char[] encPw = args[2].toCharArray();
                    String encResult = encryptWithPassword(args[1], encPw);
                    Arrays.fill(encPw, '0');
                    System.out.println(encResult);
                    break;

                case "decrypt-pw":
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for decrypt-pw.");
                        System.err.println("Usage: java SymmetricEncryptionApp decrypt-pw <ciphertext> <password>");
                        System.exit(1);
                    }
                    char[] decPw = args[2].toCharArray();
                    String decResult = decryptWithPassword(args[1], decPw);
                    Arrays.fill(decPw, '0');
                    System.out.println(decResult);
                    break;
```

**Why it is a problem:** The application accepts cryptographic keys, passwords, and sensitive plaintext directly through command-line arguments (`args[]`). On POSIX and Windows operating systems, command-line arguments are stored in the OS process table and are readable by any local unprivileged user via `ps aux`, `/proc/<pid>/cmdline`, Process Explorer, or Windows Task Manager. In addition, command-line arguments are recorded in plaintext in user shell history files (`~/.bash_history`, `~/.zsh_history`) and logged by system auditing services (`auditd`, Windows Security Event ID 4688, Sysmon Event ID 1). Although the application attempts to zero the character array with `Arrays.fill(encPw, '0')`, `args[2]` already resides on the JVM heap as an immutable `String` and has already been exposed to the OS environment.

**Fix:** Do not pass secret keys or passwords as command-line arguments. Instead, prompt the user interactively using `System.console().readPassword()`, or read secrets from standard input (`System.in`), environment variables, or secure credential files.
```java
                case "encrypt-pw":
                    if (args.length < 2) {
                        System.err.println("Error: Missing plaintext argument for encrypt-pw.");
                        System.err.println("Usage: java SymmetricEncryptionApp encrypt-pw <plaintext>");
                        System.exit(1);
                    }
                    char[] encPw;
                    if (System.console() != null) {
                        encPw = System.console().readPassword("Enter password: ");
                    } else {
                        System.err.println("Enter password via stdin:");
                        Scanner s = new Scanner(System.in);
                        encPw = s.nextLine().toCharArray();
                    }
                    try {
                        String encResult = encryptWithPassword(args[1], encPw);
                        System.out.println(encResult);
                    } finally {
                        Arrays.fill(encPw, '0');
                    }
                    break;
```

### SEC-02: Insecure Interactive Password Input with Terminal Echo and String Retention
- **Severity:** Medium
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `SymmetricEncryptionApp.java:459-468`

**Vulnerable code:**
```java
// SymmetricEncryptionApp.java:459-468
                        System.out.print("\nEnter password: ");
                        String password = scanner.nextLine();

                        System.out.print("Enter plaintext to encrypt: ");
                        String plaintext = scanner.nextLine();

                        char[] pwdChars = password.toCharArray();
                        String encrypted = encryptWithPassword(plaintext, pwdChars);
                        Arrays.fill(pwdChars, '0'); // clear password from memory
```

**Why it is a problem:** In `runInteractiveConsole()`, user passwords and Base64-encoded secret keys are read using `Scanner.nextLine()`. This introduces two significant security flaws:
1. `Scanner.nextLine()` reads from standard input with console echo enabled, causing the password to appear in plaintext on the terminal screen, exposing it to shoulder surfing, terminal session logs, and screen sharing.
2. `Scanner.nextLine()` returns an immutable `java.lang.String` object. In Java, strings cannot be zeroed or wiped from memory in-place. The password string remains indefinitely in heap memory until garbage collected, making the subsequent `Arrays.fill(pwdChars, '0')` ineffective at removing the secret from memory.

**Fix:** Use `System.console().readPassword()` when a console is attached. It suppresses terminal echoing and returns a mutable `char[]` that can be zeroed immediately after derivation.
```java
                        char[] pwdChars;
                        if (System.console() != null) {
                            pwdChars = System.console().readPassword("\nEnter password: ");
                        } else {
                            System.out.print("\nEnter password: ");
                            pwdChars = scanner.nextLine().toCharArray();
                        }
                        try {
                            System.out.print("Enter plaintext to encrypt: ");
                            String plaintext = scanner.nextLine();
                            String encrypted = encryptWithPassword(plaintext, pwdChars);
                            System.out.println("\nCiphertext (Base64):");
                            System.out.println(encrypted);
                        } finally {
                            Arrays.fill(pwdChars, '0');
                        }
```

### SEC-03: Failure to Clear Sensitive PBEKeySpec and Key Material from Memory
- **Severity:** Medium
- **CWE:** CWE-226: Sensitive Information in Resource Not Removed Before Reuse
- **Location:** `SymmetricEncryptionApp.java:114-121`

**Vulnerable code:**
```java
// SymmetricEncryptionApp.java:114-121
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new GeneralSecurityException("Failed to derive key from password: " + e.getMessage(), e);
        }
```

**Why it is a problem:** `PBEKeySpec` creates an internal copy of the `password` array upon instantiation. The official JCA documentation for `PBEKeySpec` states: "It is the caller's responsibility to clear the password after use by invoking clearPassword()." Because `spec.clearPassword()` is never invoked, a duplicate copy of the plaintext password remains permanently resident in the heap within the `PBEKeySpec` object. Furthermore, `keyBytes` contains the raw derived AES key material in a temporary byte array that is never wiped (`Arrays.fill(keyBytes, (byte) 0)`), exposing raw key material to process memory dumps and heap inspection.

**Fix:** Implement a `finally` block in `deriveKeyFromPassword` to invoke `spec.clearPassword()` and overwrite the intermediate `keyBytes` array with zeroes.
```java
        PBEKeySpec spec = null;
        byte[] keyBytes = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
            keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new GeneralSecurityException("Failed to derive key from password: " + e.getMessage(), e);
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
```

### SEC-04: PBKDF2 Iteration Count Below Current Recommendation
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `SymmetricEncryptionApp.java:44`

**Vulnerable code:**
```java
// SymmetricEncryptionApp.java:44
    public static final int PBKDF2_ITERATIONS = 310_000;    // Current OWASP recommendation for PBKDF2-HMAC-SHA256
```

**Why it is a problem:** The application defines `PBKDF2_ITERATIONS` as 310,000 for `PBKDF2WithHmacSHA256`. While 310,000 was recommended by OWASP in 2021, current OWASP Password Storage and Key Derivation guidelines recommend a minimum of 600,000 iterations for `PBKDF2-HMAC-SHA256` to resist high-speed GPU and ASIC offline password cracking attacks.

**Fix:** Update `PBKDF2_ITERATIONS` to at least 600,000 to adhere to current security benchmarks.
```java
    public static final int PBKDF2_ITERATIONS = 600_000;    // Current OWASP recommendation for PBKDF2-HMAC-SHA256
```

### SEC-05: Hardcoded Sensitive Demonstration Credentials and Passwords in Source Code
- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `SymmetricEncryptionApp.java:367-368`

**Vulnerable code:**
```java
// SymmetricEncryptionApp.java:367-368
            String password = "CorrectHorseBatteryStaple#2026";
            String secretMessage = "Confidential: Database credentials [host=prod-db.internal, user=admin, pass=secret]";
```

**Why it is a problem:** The automated demonstration routine includes hardcoded realistic credentials, including a plaintext password and production-style database credentials (`user=admin, pass=secret`). In compiled production binaries, embedding realistic credential patterns risks credential reuse, triggers static code analysis alerts, and risks exposure if demonstration routines are accidentally copied into production code.

**Fix:** Replace hardcoded passwords and credentials with obvious placeholder tokens or dynamically generated random demo strings.
```java
            String password = "test-demo-passphrase-" + System.currentTimeMillis();
            String secretMessage = "Sample non-sensitive demonstration payload";
```

## 6. Verified Controls and Checks With No Finding
- Authenticated Encryption Algorithm (`AES/GCM/NoPadding`): Verified that AES in Galois/Counter Mode is used without block padding (`SymmetricEncryptionApp.java:38`). GCM provides AEAD (Authenticated Encryption with Associated Data), guaranteeing data confidentiality, authenticity, and integrity, and eliminating padding oracle vulnerabilities (e.g., POODLE, Lucky Thirteen) common in CBC mode (CWE-327, CWE-347).
- Cryptographic Key Generation & Size (256-bit AES): Verified that `generateKey()` initializes `KeyGenerator` with 256 bits (`SymmetricEncryptionApp.java:60-62`), conforming to NIST SP 800-131A Rev. 2 and SP 800-57 recommendations for high-security symmetric keys (CWE-326).
- Cryptographically Secure Random Number Generation (`SecureRandom`): Verified that all random generation (IVs, salts, and AES keys) uses `java.security.SecureRandom` (`SymmetricEncryptionApp.java:47, 61, 149, 261`), avoiding predictable non-cryptographic PRNGs like `java.util.Random` (CWE-330, CWE-338).
- GCM Nonce / Initialization Vector (IV) Freshness and Length: Verified that `encrypt()` generates a fresh, unique 12-byte (96-bit) IV for every encryption call (`SymmetricEncryptionApp.java:148-149`), following NIST SP 800-38D recommendations and preventing catastrophic AES-GCM nonce reuse (CWE-323).
- Authentication Tag Verification & Integrity Enforcement: Verified that `decrypt()` configures `GCMParameterSpec` with a 128-bit authentication tag (`SymmetricEncryptionApp.java:42, 197`), and `cipher.doFinal()` cryptographically verifies the tag before returning plaintext. Any alteration raises `AEADBadTagException` (`SymmetricEncryptionApp.java:1, 200, 359-363`) (CWE-353, CWE-390).
- Cryptographic Salt for Password Derivation: Verified that `encryptWithPassword()` generates a fresh, random 16-byte (128-bit) salt per operation via `SecureRandom` (`SymmetricEncryptionApp.java:260-261`), preventing rainbow table and multi-target precomputation attacks (CWE-759, CWE-760).
- Cryptographic Hash Algorithm for KDF (`PBKDF2WithHmacSHA256`): Verified that `deriveKeyFromPassword()` uses HMAC-SHA256 as the pseudorandom function (`SymmetricEncryptionApp.java:45, 115`), avoiding deprecated hash algorithms like MD5 or SHA-1 (CWE-328).
- Payload Length and Boundary Validation: Verified that `decrypt()` and `decryptWithPassword()` perform explicit minimum length validation checks (`SymmetricEncryptionApp.java:180-184, 287-290`) prior to buffer slicing, preventing `BufferUnderflowException` or out-of-bounds indexing (CWE-125).
- Key Length Validation on Import: Verified that `decodeKeyFromBase64()` validates the decoded key length to strictly allow only valid AES key sizes (128, 192, or 256 bits) (`SymmetricEncryptionApp.java:90-94`), rejecting malformed or truncated keys.
- Input Null and Empty Checks: Verified that all public API methods perform strict null and empty argument validation (`SymmetricEncryptionApp.java:72, 86, 107, 110, 140, 143, 174, 177, 216, 233, 256, 282`), throwing `IllegalArgumentException` with descriptive error messages.
