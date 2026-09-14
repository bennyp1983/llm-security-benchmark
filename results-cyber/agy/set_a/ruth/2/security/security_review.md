# Security Review: SymmetricCryptoApp

## 1. Executive Summary
`SymmetricCryptoApp` is a Java application and library designed to perform authenticated symmetric encryption and decryption using AES-256-GCM. It includes a key management service based on PKCS#12 KeyStores, password-based key derivation via PBKDF2-HMAC-SHA256, and a command-line interface (CLI) for key generation, encryption, and decryption.

A comprehensive security review of the codebase identified **6 security findings** (2 High, 2 Medium, and 2 Low severity). The most critical vulnerabilities involve insecure keystore file creation that introduces a TOCTOU race condition exposing key material under default umask permissions, and accepting sensitive cryptographic passwords via command-line arguments, exposing them in process tables and shell history. Additionally, an uncontrolled iteration limit in untrusted payload containers enables Denial of Service attacks against PBKDF2 key derivation routines, and key derivation parameters lack minimum work factor enforcement. The core cryptographic primitives (AES-256-GCM, 12-byte IV generation with `SecureRandom`, 128-bit authentication tag validation, and AAD context binding) were verified as correctly implemented.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SymmetricCryptoApp.java` | Core application and library implementation for symmetric encryption, key derivation, KeyStore management, and CLI operations | Cryptographic algorithm selection (`AES/GCM/NoPadding`), random IV generation, PBKDF2 key derivation, PKCS#12 file operations, file permission enforcement, password/credential ingestion, memory wiping hygiene, and ciphertext container serialization |
| `README.md` | Technical documentation and user guide | Documents cryptographic architecture, security design rationale, payload wire formats, programmatic API usage, and command-line execution syntax |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit cryptographic primitives, cipher mode (`AES/GCM/NoPadding`), key sizes (256-bit AES), authentication tag verification (128-bit tag), random number generation (`SecureRandom`), PBKDF2 key derivation parameters, KeyStore integration, and in-memory credential sanitization.
- `implementing-aes-encryption-for-data-at-rest`: Applied to review AES-GCM AEAD encryption/decryption routines, nonce/IV generation and collision prevention, authenticated associated data (AAD) context binding, and binary/Base64 payload container structure.
- General OWASP Top 10 / CWE Knowledge: Applied to review file creation umask inheritance and race conditions (CWE-732 / CWE-378), process argument exposure of sensitive credentials (CWE-214 / CWE-200), algorithmic complexity and resource consumption in unauthenticated headers (CWE-400), and sensitive memory buffer retention (CWE-226).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Insecure KeyStore File Creation Permitting Unauthorized Read Access via Race Window | High | CWE-732 | `SymmetricCryptoApp.java:375-380` |
| SEC-02 | Exposure of Cryptographic Passwords and Passphrases via Command-Line Arguments | High | CWE-214 | `SymmetricCryptoApp.java:1015-1019` |
| SEC-03 | Denial of Service via Uncontrolled PBKDF2 Iteration Count in Untrusted Payloads | Medium | CWE-400 | `SymmetricCryptoApp.java:190-193` |
| SEC-04 | Insufficient Work Factor and Parameter Validation in Key Derivation Service | Medium | CWE-916 | `SymmetricCryptoApp.java:419-426` |
| SEC-05 | Insecure Default File Permissions on Decrypted Sensitive Output Files | Low | CWE-276 | `SymmetricCryptoApp.java:823-825` |
| SEC-06 | Residual Sensitive Plaintext Buffers Left Unwiped in CLI Handlers | Low | CWE-226 | `SymmetricCryptoApp.java:752-785` |

## 5. Detailed Findings

### SEC-01: Insecure KeyStore File Creation Permitting Unauthorized Read Access via Race Window
- **Severity:** High
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `SymmetricCryptoApp.java:375-380`

**Vulnerable code:**
```java
// SymmetricCryptoApp.java:375-380
            try (OutputStream os = Files.newOutputStream(path)) {
                keyStore.store(os, password);
            }

            // Enforce restrictive POSIX file permissions (owner read/write only: 0600)
            setOwnerOnlyPermissions(path);
```

**Why it is a problem:**
When `Files.newOutputStream(path)` creates the KeyStore file, the operating system creates it using the process's default umask permissions (typically `0644` or `0664`, granting read access to group and world users). The entire keystore—containing master cryptographic keys—is serialized and written to disk before `setOwnerOnlyPermissions(path)` is invoked. This introduces a Time-of-Check to Time-of-Use (TOCTOU) race condition during which other local unprivileged processes can open and read the keystore file. Furthermore, if `keyStore.store()` fails, throws an exception, or the process terminates abruptly during the write, `setOwnerOnlyPermissions()` is never reached, leaving the keystore permanently world-readable on disk.

**Fix:**
Create the file atomically with restrictive POSIX file permissions (`0600`) prior to opening the stream, using `Files.createFile` with `PosixFilePermissions.asFileAttribute`:
```java
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }

            if (!Files.exists(path)) {
                try {
                    if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                        Set<PosixFilePermission> permissions = EnumSet.of(
                                PosixFilePermission.OWNER_READ,
                                PosixFilePermission.OWNER_WRITE
                        );
                        Files.createFile(path, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(permissions));
                    } else {
                        Files.createFile(path);
                    }
                } catch (java.nio.file.FileAlreadyExistsException ignored) {
                    // Handled if created concurrently
                }
            }

            try (OutputStream os = Files.newOutputStream(path, java.nio.file.StandardOpenOption.WRITE, java.nio.file.StandardOpenOption.TRUNCATE_EXISTING)) {
                keyStore.store(os, password);
            }

            setOwnerOnlyPermissions(path);
```

---

### SEC-02: Exposure of Cryptographic Passwords and Passphrases via Command-Line Arguments
- **Severity:** High
- **CWE:** CWE-214: Invocation of Process Initializer with Untrusted/Sensitive Data
- **Location:** `SymmetricCryptoApp.java:1015-1019`

**Vulnerable code:**
```java
// SymmetricCryptoApp.java:1015-1019
    private static char[] getOptionalPassword(String[] args, String flagShort, String flagLong, String prompt) {
        String pwd = getOptionalArg(args, flagShort, flagLong);
        if (pwd != null) {
            return pwd.toCharArray();
        }
```

**Why it is a problem:**
The CLI parser allows users to pass sensitive KeyStore passwords, key entry passwords, and PBKDF2 encryption passphrases directly through command-line flags (`-p`, `--password`, `-kp`, `--keystore-pass`, `--key-pass`). Command-line arguments are visible across the system in the process table (e.g. via `ps aux`, `top`, or `/proc/<PID>/cmdline`) to any unprivileged user on multi-user operating systems. They are also permanently stored in plaintext shell history files (e.g., `~/.bash_history`), CI/CD logs, and system process audit records. Additionally, receiving passwords via CLI flags creates immutable `java.lang.String` instances in `args` within the JVM heap, bypassing the application's array-zeroing memory hygiene.

**Fix:**
Eliminate accepting passwords directly from command-line argument flags. Accept passwords through secure interactive prompts via `System.console().readPassword()` or through secure environment variables for automated workflows:
```java
    private static char[] getOptionalPassword(String[] args, String flagShort, String flagLong, String prompt) {
        // Read from environment variable for non-interactive automation
        String envVarName = flagLong.replace("--", "").toUpperCase().replace('-', '_');
        String envPwd = System.getenv(envVarName);
        if (envPwd != null && !envPwd.isEmpty()) {
            return envPwd.toCharArray();
        }

        // Prompt interactively if console is available
        Console console = System.console();
        if (console != null) {
            char[] read = console.readPassword(prompt);
            return read != null ? read : new char[0];
        }

        // Fallback for non-interactive / piped environments
        Scanner scanner = new Scanner(System.in);
        if (System.in != null && scanner.hasNextLine()) {
            System.out.print(prompt);
            String line = scanner.nextLine();
            return line.toCharArray();
        }

        return new char[0];
    }
```

---

### SEC-03: Denial of Service via Uncontrolled PBKDF2 Iteration Count in Untrusted Payloads
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `SymmetricCryptoApp.java:190-193`

**Vulnerable code:**
```java
// SymmetricCryptoApp.java:190-193
                int iters = buffer.getInt();
                if (iters <= 0 || iters > 10_000_000) {
                    throw new CryptoException("Invalid PBKDF2 iteration count in payload: " + iters);
                }
```

**Why it is a problem:**
When deserializing an encrypted payload, `fromByteArray` reads the iteration count `iters` from the unauthenticated payload header and accepts values up to 10,000,000. In `decryptWithPassword`, key derivation via `KeyDerivationService.deriveKey` must be performed *before* ciphertext decryption and GCM authentication tag verification can take place. An unauthenticated attacker sending crafted payloads with `iters = 10_000_000` forces the server to spend tens of seconds of 100% CPU computation per request on PBKDF2-HMAC-SHA256, causing severe thread and CPU starvation (algorithmic complexity DoS).

**Fix:**
Enforce strict upper and lower limits on the acceptable iteration count during payload deserialization, aligning with expected operational parameters:
```java
                int iters = buffer.getInt();
                // Enforce strict bounds on iteration count to prevent CPU exhaustion DoS attacks
                if (iters < 100_000 || iters > 1_000_000) {
                    throw new CryptoException("PBKDF2 iteration count out of safe operational bounds [100000, 1000000]: " + iters);
                }
```

---

### SEC-04: Insufficient Work Factor and Parameter Validation in Key Derivation Service
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `SymmetricCryptoApp.java:419-426`

**Vulnerable code:**
```java
// SymmetricCryptoApp.java:419-426
        public static SecretKey deriveKey(char[] password, byte[] salt, int iterations, int keyLengthBits) throws CryptoException {
            if (password == null || password.length == 0) {
                throw new CryptoException("Password cannot be null or empty.");
            }
            if (salt == null || salt.length < 16) {
                throw new CryptoException("Salt must be at least 16 bytes (128 bits).");
            }
```

**Why it is a problem:**
`KeyDerivationService.deriveKey` is a public service method that validates password presence and minimum salt length, but performs no validation on the `iterations` or `keyLengthBits` parameters. Downstream callers or integrations can provide low iteration counts (such as `iterations = 1` or `1000`) or truncated key lengths (e.g., 64 bits), producing cryptographically weak derived keys that are vulnerable to high-speed offline dictionary or brute-force cracking attacks.

**Fix:**
Validate that `iterations` meets minimum industry standards (at least 100,000 iterations for PBKDF2-HMAC-SHA256 per OWASP and NIST SP 800-132) and that `keyLengthBits` conforms to standard AES key sizes (128, 192, or 256 bits):
```java
        public static SecretKey deriveKey(char[] password, byte[] salt, int iterations, int keyLengthBits) throws CryptoException {
            if (password == null || password.length == 0) {
                throw new CryptoException("Password cannot be null or empty.");
            }
            if (salt == null || salt.length < 16) {
                throw new CryptoException("Salt must be at least 16 bytes (128 bits).");
            }
            if (iterations < 100_000) {
                throw new CryptoException("PBKDF2 iterations (" + iterations + ") below required minimum of 100,000.");
            }
            if (keyLengthBits != 128 && keyLengthBits != 192 && keyLengthBits != 256) {
                throw new CryptoException("Invalid AES key length: " + keyLengthBits + " bits. Must be 128, 192, or 256.");
            }
```

---

### SEC-05: Insecure Default File Permissions on Decrypted Sensitive Output Files
- **Severity:** Low
- **CWE:** CWE-276: Incorrect Default Permissions
- **Location:** `SymmetricCryptoApp.java:823-825`

**Vulnerable code:**
```java
// SymmetricCryptoApp.java:823-825
        if (outputFile != null) {
            Files.write(Paths.get(outputFile), decryptedBytes);
            System.out.println("Decrypted data written to: " + outputFile);
```

**Why it is a problem:**
When `handleDecrypt` writes decrypted sensitive data to a target file specified by `-o` / `--out`, it calls `Files.write(Paths.get(outputFile), decryptedBytes)`. Because no file attributes or permissions are specified, the file is created with the operating system's default umask permissions (e.g. `0644` or `0664`), allowing other local users to read the unprotected plaintext data.

**Fix:**
Create the output file with owner-only permissions (`0600`) or restrict permissions immediately upon file creation:
```java
        if (outputFile != null) {
            Path outPath = Paths.get(outputFile);
            if (!Files.exists(outPath)) {
                try {
                    if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                        Set<PosixFilePermission> permissions = EnumSet.of(
                                PosixFilePermission.OWNER_READ,
                                PosixFilePermission.OWNER_WRITE
                        );
                        Files.createFile(outPath, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(permissions));
                    } else {
                        Files.createFile(outPath);
                    }
                } catch (java.nio.file.FileAlreadyExistsException ignored) {}
            }
            Files.write(outPath, decryptedBytes);
            KeyStoreManager.setOwnerOnlyPermissions(outPath);
            System.out.println("Decrypted data written to: " + outputFile);
```

---

### SEC-06: Residual Sensitive Plaintext Buffers Left Unwiped in CLI Handlers
- **Severity:** Low
- **CWE:** CWE-226: Sensitive Information in Resource Not Removed Before Reuse
- **Location:** `SymmetricCryptoApp.java:752-785`

**Vulnerable code:**
```java
// SymmetricCryptoApp.java:752-785
        byte[] inputData = getInputBytes(args);
        String aadStr = getOptionalArg(args, "--aad");
        byte[] aad = aadStr != null ? aadStr.getBytes(StandardCharsets.UTF_8) : null;
        String outputFile = getOptionalArg(args, "-o", "--out");

        SymmetricEncryptionService service = new SymmetricEncryptionService();
        EncryptedPayload payload;

        String keystorePath = getOptionalArg(args, "-k", "--keystore");
        if (keystorePath != null) {
            String alias = getRequiredArg(args, "-a", "--alias");
            char[] ksPassword = getOptionalPassword(args, "-kp", "--keystore-pass", "Enter KeyStore master password: ");
            char[] keyPassword = getOptionalPassword(args, "-p", "--key-pass", "Enter protection password for key '" + alias + "': ");
            if (keyPassword.length == 0) keyPassword = ksPassword.clone();

            try {
                SecretKey key = KeyStoreManager.loadKey(Paths.get(keystorePath), ksPassword, alias, keyPassword);
                payload = service.encrypt(inputData, key, aad);
            } finally {
                wipe(ksPassword);
                wipe(keyPassword);
            }
        } else {
            // Password-based encryption mode
            char[] password = getOptionalPassword(args, "-p", "--password", "Enter encryption password: ");
            try {
                payload = service.encryptWithPassword(inputData, password, aad);
            } finally {
                wipe(password);
            }
        }

        outputResult(payload.toBase64(), outputFile);
```

**Why it is a problem:**
While `handleEncrypt` and `handleDecrypt` correctly wipe password `char[]` arrays in `finally` blocks, the raw plaintext byte arrays (`inputData` in `handleEncrypt` and `decryptedBytes` in `handleDecrypt`) are never cleared using `wipe()`. They linger in heap memory until overwritten or garbage collected, increasing exposure to memory scraping, process core dumps, or heap inspection.

**Fix:**
Enclose plaintext byte buffer processing in `try ... finally` blocks and ensure `wipe()` is called to zero out sensitive plaintext bytes after operation completion:
```java
        byte[] inputData = getInputBytes(args);
        try {
            String aadStr = getOptionalArg(args, "--aad");
            byte[] aad = aadStr != null ? aadStr.getBytes(StandardCharsets.UTF_8) : null;
            String outputFile = getOptionalArg(args, "-o", "--out");

            SymmetricEncryptionService service = new SymmetricEncryptionService();
            EncryptedPayload payload;

            String keystorePath = getOptionalArg(args, "-k", "--keystore");
            if (keystorePath != null) {
                String alias = getRequiredArg(args, "-a", "--alias");
                char[] ksPassword = getOptionalPassword(args, "-kp", "--keystore-pass", "Enter KeyStore master password: ");
                char[] keyPassword = getOptionalPassword(args, "-p", "--key-pass", "Enter protection password for key '" + alias + "': ");
                if (keyPassword.length == 0) keyPassword = ksPassword.clone();

                try {
                    SecretKey key = KeyStoreManager.loadKey(Paths.get(keystorePath), ksPassword, alias, keyPassword);
                    payload = service.encrypt(inputData, key, aad);
                } finally {
                    wipe(ksPassword);
                    wipe(keyPassword);
                }
            } else {
                char[] password = getOptionalPassword(args, "-p", "--password", "Enter encryption password: ");
                try {
                    payload = service.encryptWithPassword(inputData, password, aad);
                } finally {
                    wipe(password);
                }
            }

            outputResult(payload.toBase64(), outputFile);
        } finally {
            wipe(inputData);
        }
```

## 6. Verified Controls and Checks With No Finding
- **Cipher Algorithm & Operating Mode**: Verified that the application uniformly specifies `AES/GCM/NoPadding` (lines 43, 64, 480, 513, 540, 565). No insecure modes (such as ECB) or unauthenticated padding modes (such as CBC without MAC) are utilized.
- **Symmetric Key Strength**: Verified that symmetric keys are generated at 256 bits (`AES_KEY_SIZE_BITS = 256`, lines 68, 244) using standard Java `KeyGenerator` initialized with a strong CSPRNG, meeting FIPS 197 and modern cryptographic guidelines.
- **Initialization Vector (IV/Nonce) Freshness and Length**: Verified that every encryption operation generates a unique 12-byte (96-bit) IV using `SECURE_RANDOM.nextBytes()` (`generateIv()`, lines 456-460, 478, 538). Static or reused IVs are prevented.
- **Authentication Tag Length**: Verified that a full 128-bit authentication tag (`GCM_TAG_LENGTH_BITS = 128`, lines 70, 481, 514, 541, 566) is enforced, preventing authentication forgery attacks.
- **Cryptographic Randomness (CSPRNG)**: Verified that `createSecureRandom()` initializes `SecureRandom.getInstanceStrong()` with fallback to `new SecureRandom()`, avoiding predictable time-based seeds.
- **Authenticated Associated Data (AAD) Integration**: Verified that associated data is passed to `cipher.updateAAD()` in both encryption and decryption paths (lines 484-486, 517-519, 545-547, 569-571), ensuring context binding.
- **Integrity Validation on Decryption**: Verified that ciphertext tampering, corrupt bits, or mismatched AAD trigger `AEADBadTagException` and prevent unauthenticated plaintext emission (lines 522-525, 574-577, 901-915).
- **Key Derivation Algorithm**: Verified that PBKDF2 uses `PBKDF2WithHmacSHA256` (line 66) rather than deprecated algorithms like MD5 or SHA-1.
- **Salt Generation**: Verified that a fresh 16-byte (128-bit) cryptographically random salt is generated via `SECURE_RANDOM` for each PBKDF2 password derivation (lines 71, 408-414, 535), preventing rainbow table attacks.
- **KeyStore Format & Entry Protection**: Verified that `KeyStore.getInstance("PKCS12")` is used (line 65) with password protection on entries via `KeyStore.PasswordProtection`.
- **In-Memory Password Sanitization**: Verified that `PBEKeySpec.clearPassword()` is invoked in a `finally` block during key derivation (line 440), and password `char[]` arrays are wiped in CLI finally blocks.
