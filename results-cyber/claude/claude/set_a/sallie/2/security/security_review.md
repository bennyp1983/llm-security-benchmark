# Security Review: PiiEncryptor (AES-256-GCM PII encryption CLI)

## 1. Executive Summary
`PiiEncryptor.java` is a small Java 17 command-line program. It reads a person's name and email address from the console, encrypts each one with AES-256-GCM, decrypts them again and prints both results. The key is never in the source code. It is loaded at runtime from a file named by `PII_ENCRYPTION_KEY_FILE`, or else from the `PII_ENCRYPTION_KEY` environment variable. `README.md` explains how to set up and run the program.

The cryptography is sound. The cipher is AES/GCM/NoPadding with a 256-bit key, a fresh 12-byte IV from `SecureRandom` for every encryption, and a full 128-bit authentication tag. Each value is bound to its field label as associated data. The key has no default and its length is checked strictly, and the error messages don't leak anything useful. No Critical or High issues were found.

The remaining issues are about how the key and the plaintext are handled:
- **SEC-01 (Medium):** The key can be supplied through an environment variable, and the README tells users to `export` the raw key on the command line. This exposes the key through shell history, `/proc/<pid>/environ`, child processes and container metadata.
- **SEC-02 (Low):** The decrypted PII is printed to stdout, where it can end up in terminal scrollback, CI logs or redirected files.
- **SEC-03 (Low):** The associated data binds only the field name, not the record. A ciphertext can therefore be swapped between records without detection.
- **SEC-04 (Low):** The program doesn't check the key file's permissions, so a group- or world-readable key is accepted silently.
- **SEC-05 (Low):** The Base64 key and the plaintext PII stay in the heap as immutable `String` objects. The code zeroes some byte arrays, but that only partly clears them from memory.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `PiiEncryptor.java` | CLI and reusable class that encrypts and decrypts a name and email with AES-256-GCM, generates keys and loads the key from the environment | AES-GCM cipher setup, IV generation (`SecureRandom`), AAD binding, key generation (`KeyGenerator`), key loading from an env var or file, Base64 decoding, input validation (regex, length), memory zeroization, printing ciphertext/plaintext/key to stdout, exception handling and error messages |
| `README.md` | Plain-English guide to building, creating a key, supplying the key and running the program | Instructions for storing the key (env var `export`, key file with `umask 077`), piping PII on stdin, description of the ciphertext format |
| `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Task prompt and generation-run metadata (not code) | Read for context only. They contain no secrets or executable code |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Router workflow. Worked out what each file does, extracted keywords (cryptography, AES, key management, secrets in env/source, PII exposure, input validation) and selected the skills below.
- `performing-cryptographic-audit-of-application`: Checked every crypto touchpoint in `PiiEncryptor.java` against its weakness categories: weak algorithms, insecure modes, key size, hardcoded secrets, entropy/IV predictability, key storage and error handling. It also prompted the checks on env-var and file key loading (SEC-01, SEC-04).
- `implementing-aes-encryption-for-data-at-rest`: Checked the AES-256-GCM implementation: nonce size and uniqueness, CSPRNG, tag length, the IV || ciphertext || tag format, tamper detection, associated-data use and key wiping from memory (SEC-03, SEC-05).
- `testing-for-sensitive-data-exposure`: Checked how PII and secrets are handled in output, error messages and documentation: decrypted PII on stdout, the key printed by `--generate-key`, and exception messages (SEC-01, SEC-02).
- No library skill matched console input handling, CLI argument handling or regex complexity (ReDoS). These were reviewed against general OWASP Top 10 (A03 Injection, A04 Insecure Design, A05 Security Misconfiguration) and CWE knowledge (CWE-1333, CWE-150, CWE-214, CWE-209).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Encryption key accepted from an environment variable, and the README tells users to type it into the shell | Medium | CWE-526 | `PiiEncryptor.java:136` |
| SEC-02 | Decrypted PII written to standard output | Low | CWE-359 | `PiiEncryptor.java:236` |
| SEC-03 | AAD binds only the field name, so ciphertexts can be swapped between records | Low | CWE-345 | `PiiEncryptor.java:73` |
| SEC-04 | Key file permissions are not checked before the key is used | Low | CWE-732 | `PiiEncryptor.java:134` |
| SEC-05 | Key material and plaintext PII left in immutable Strings, so memory is only partly wiped | Low | CWE-316 | `PiiEncryptor.java:134` |

## 5. Detailed Findings

### SEC-01: Encryption key accepted from an environment variable, and the README tells users to type it into the shell
- **Severity:** Medium
- **CWE:** CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable
- **Location:** `PiiEncryptor.java:136-139`, `README.md:72`

**Vulnerable code:**
```java
// PiiEncryptor.java:136-139
        } else {
            encoded = System.getenv(KEY_ENV_VAR);
            source = KEY_ENV_VAR;
        }
```
```text
// README.md:72
export PII_ENCRYPTION_KEY="paste-your-key-here"
```

**Why it is a problem:** This one AES key protects all of the PII. When it is passed in `PII_ENCRYPTION_KEY`, the raw key can leak in several ways:
- It can be read from `/proc/<pid>/environ` by the same user or root.
- Every child process inherits it.
- It shows up in `docker inspect`, Kubernetes pod specs, crash reports and diagnostic dumps, which often capture the whole environment.
- Following the README literally (`export PII_ENCRYPTION_KEY="<key>"`) writes the key into `~/.bash_history` or the PowerShell history file.

The program also can't remove the value from its own environment after reading it. Anyone who gets the key can decrypt every stored name and email, and GCM ciphertexts give no protection once the key is known. The key file option (which the README recommends) avoids most of these problems. The env-var option weakens that design without warning the user.

**Fix:** Make the key file the only supported source, or at least refuse the env var unless it is explicitly enabled, and warn about the risk. Update the README so it never shows the key being typed on the command line. A secrets manager should inject the key as a mounted file (for example a tmpfs secret volume) rather than an environment variable.
```java
    /** Loads the key from a protected file. Never from a raw environment value or a built-in default. */
    static SecretKey loadKeyFromEnvironment() throws IOException {
        if (System.getenv(KEY_ENV_VAR) != null) {
            throw new IllegalStateException(KEY_ENV_VAR + " is not supported because environment variables"
                    + " leak easily. Put the key in a file readable only by you and set " + KEY_FILE_ENV_VAR + ".");
        }
        String keyFile = System.getenv(KEY_FILE_ENV_VAR);
        if (keyFile == null || keyFile.isBlank()) {
            throw new IllegalStateException("No encryption key found. Set " + KEY_FILE_ENV_VAR
                    + " to the path of the key file. Run with --generate-key to create a key.");
        }
        String source = "the file named in " + KEY_FILE_ENV_VAR;
        String encoded = Files.readString(Path.of(keyFile), StandardCharsets.US_ASCII);
        // ... continue with the existing Base64 decoding and length checks ...
    }
```

### SEC-02: Decrypted PII written to standard output
- **Severity:** Low
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **Location:** `PiiEncryptor.java:236-238`

**Vulnerable code:**
```java
// PiiEncryptor.java:236-238
            System.out.println("Decrypted data");
            System.out.println("  Name : " + decryptedName);
            System.out.println("  Email: " + decryptedEmail);
```

**Why it is a problem:** After decryption the program prints the plaintext name and email. Output like this ends up in terminal scrollback, `script`/tmux logs, CI job logs and files when stdout is redirected, and log shippers may collect it. None of these places are protected like the encrypted data. The README (`README.md:119-121`) says this is for demonstration only. Still, the code has no switch to turn it off, and the class is written to be reused. Copying `main` into a batch job would write PII to logs (see also CWE-532).

**Fix:** Check the round trip in memory and report only whether it succeeded. If a visual check is needed, show the plaintext only when explicitly asked, and mask it.
```java
            String decryptedName = encryptor.decrypt(encryptedName, "name");
            String decryptedEmail = encryptor.decrypt(encryptedEmail, "email");

            boolean matches = name.equals(decryptedName) && email.equals(decryptedEmail);
            if (Boolean.getBoolean("pii.showPlaintext")) {   // opt-in only: -Dpii.showPlaintext=true
                System.out.println("Decrypted data");
                System.out.println("  Name : " + mask(decryptedName));
                System.out.println("  Email: " + mask(decryptedEmail));
            }
            System.out.println("Round trip " + (matches ? "succeeded: the original data was recovered."
                                                         : "FAILED: decrypted data does not match."));

    private static String mask(String value) {
        return value.isEmpty() ? "" : value.charAt(0) + "*".repeat(Math.max(0, value.length() - 1));
    }
```

### SEC-03: AAD binds only the field name, so ciphertexts can be swapped between records
- **Severity:** Low
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **Location:** `PiiEncryptor.java:67-73`, `PiiEncryptor.java:106`

**Vulnerable code:**
```java
// PiiEncryptor.java:67-73
    public String encrypt(String plaintext, String fieldLabel) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        RANDOM.nextBytes(iv); // a fresh, unique IV for every encryption is mandatory with GCM

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        cipher.updateAAD(fieldLabel.getBytes(StandardCharsets.UTF_8));
```

**Why it is a problem:** The associated data is just the constant label `"name"` or `"email"`. This stops an email ciphertext from being decrypted as a name. It does not stop a valid ciphertext from being moved to a different record. Suppose an attacker has write access to the store holding these values (a SQL injection, a malicious DBA, a tampered backup). They can copy their own `email` ciphertext into a victim's row. It decrypts cleanly with no tag error, so password resets, notifications or data-subject exports for the victim then go to the attacker's address. The Javadoc says the AAD prevents substitution, which suggests a stronger guarantee than the code gives. It is Low only because the demo `main` stores nothing.

**Fix:** Add the record's stable identifier (for example the primary key or user ID) to the associated data. Encode it with length prefixes so that different label/ID pairs can never produce the same bytes. Pass the same values when decrypting.
```java
    public String encrypt(String plaintext, String fieldLabel, String recordId) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        cipher.updateAAD(associatedData(fieldLabel, recordId));
        // ... unchanged ...
    }

    public String decrypt(String encoded, String fieldLabel, String recordId) throws GeneralSecurityException {
        // ... unchanged up to cipher.init ...
        cipher.updateAAD(associatedData(fieldLabel, recordId));
        // ... unchanged ...
    }

    /** Length-prefixed encoding of (field, record) so distinct pairs never collide. */
    private static byte[] associatedData(String fieldLabel, String recordId) {
        byte[] field = fieldLabel.getBytes(StandardCharsets.UTF_8);
        byte[] record = recordId.getBytes(StandardCharsets.UTF_8);
        return java.nio.ByteBuffer.allocate(Integer.BYTES * 2 + field.length + record.length)
                .putInt(field.length).put(field)
                .putInt(record.length).put(record)
                .array();
    }
```

### SEC-04: Key file permissions are not checked before the key is used
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `PiiEncryptor.java:132-135`, `README.md:60-61`

**Vulnerable code:**
```java
// PiiEncryptor.java:132-135
        String keyFile = System.getenv(KEY_FILE_ENV_VAR);
        if (keyFile != null && !keyFile.isBlank()) {
            encoded = Files.readString(Path.of(keyFile), StandardCharsets.US_ASCII);
            source = "the file named in " + KEY_FILE_ENV_VAR;
```

**Why it is a problem:** The only thing keeping the key file private is the user remembering to run `umask 077` before `java PiiEncryptor --generate-key > pii.key` (README.md:60-61). With the usual default umask of `022`, the file is created `0644` and every local user can read it. The program then loads it without complaint, so nobody learns that the key is exposed. It also follows symlinks without checking, so the key path can be redirected to a file whose permissions nobody checked.

**Fix:** Before reading the key file, refuse it if it is a symlink or if group or others have any permission bits. This mirrors what OpenSSH does for private keys. On file systems without POSIX permissions, fall back to relying on ACLs.
```java
        String keyFile = System.getenv(KEY_FILE_ENV_VAR);
        if (keyFile != null && !keyFile.isBlank()) {
            Path keyPath = Path.of(keyFile);
            if (Files.isSymbolicLink(keyPath)) {
                throw new IllegalStateException("The key file must not be a symbolic link.");
            }
            try {
                java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
                        Files.getPosixFilePermissions(keyPath, java.nio.file.LinkOption.NOFOLLOW_LINKS);
                boolean exposed = perms.stream().anyMatch(p ->
                        p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"));
                if (exposed) {
                    throw new IllegalStateException("The key file is accessible to other users. Run: chmod 600 "
                            + keyPath);
                }
            } catch (UnsupportedOperationException e) {
                // Non-POSIX file system (e.g. Windows): rely on the file's ACLs.
            }
            encoded = Files.readString(keyPath, StandardCharsets.US_ASCII);
            source = "the file named in " + KEY_FILE_ENV_VAR;
```

### SEC-05: Key material and plaintext PII left in immutable Strings, so memory is only partly wiped
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `PiiEncryptor.java:134-160`, `PiiEncryptor.java:108-113`

**Vulnerable code:**
```java
// PiiEncryptor.java:146-160
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(encoded.strip());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("The key in " + source + " is not valid Base64.");
        }
        try {
            if (keyBytes.length != KEY_LENGTH_BYTES) {
                throw new IllegalStateException("The key in " + source + " must decode to "
                        + KEY_LENGTH_BYTES + " bytes (AES-256), but it is " + keyBytes.length + " bytes.");
            }
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(keyBytes, (byte) 0); // SecretKeySpec keeps its own copy
        }
```
```java
// PiiEncryptor.java:108-113
        byte[] plainBytes = cipher.doFinal(input, IV_LENGTH_BYTES, input.length - IV_LENGTH_BYTES);
        try {
            return new String(plainBytes, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plainBytes, (byte) 0);
        }
```

**Why it is a problem:** The code zeroes `keyBytes` and `plainBytes`, which suggests it tries to wipe secrets from memory. But the full key is still in the heap as the Base64 `String` `encoded` (line 134 or 137), plus the extra copy that `encoded.strip()` makes. Java Strings are immutable and interned in the heap, so these can't be cleared and stay until garbage collection. The same is true of the plaintext: `new String(plainBytes, ...)` and the `name`/`email` Strings keep the PII in memory whatever happens to the byte arrays. A heap dump (`jmap`, `-XX:+HeapDumpOnOutOfMemoryError`), a core file or swapped-out pages would reveal the key and PII. The partial zeroization gives a false sense of protection.

**Fix:** Read the key file as raw bytes, strip whitespace and decode it without ever creating a `String`, and zero every intermediate buffer. Keep the key as a `SecretKeySpec` only. Because `decrypt` has to return a `String`, add a `byte[]`-returning variant for callers that need to wipe the plaintext afterwards.
```java
    static SecretKey loadKeyFromFile(Path keyPath) throws IOException {
        byte[] raw = Files.readAllBytes(keyPath);
        byte[] trimmed = null;
        byte[] keyBytes = null;
        try {
            int start = 0;
            int end = raw.length;
            while (start < end && Character.isWhitespace(raw[start])) start++;
            while (end > start && Character.isWhitespace(raw[end - 1])) end--;
            trimmed = Arrays.copyOfRange(raw, start, end);
            try {
                keyBytes = Base64.getDecoder().decode(trimmed);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("The key file is not valid Base64.");
            }
            if (keyBytes.length != KEY_LENGTH_BYTES) {
                throw new IllegalStateException("The key must decode to " + KEY_LENGTH_BYTES + " bytes (AES-256).");
            }
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(raw, (byte) 0);
            if (trimmed != null) Arrays.fill(trimmed, (byte) 0);
            if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /** Caller is responsible for zeroing the returned array once finished with it. */
    public byte[] decryptToBytes(String encoded, String fieldLabel) throws GeneralSecurityException {
        // ... same validation and cipher setup as decrypt(...) ...
        return cipher.doFinal(input, IV_LENGTH_BYTES, input.length - IV_LENGTH_BYTES);
    }
```

## 6. Verified Controls and Checks With No Finding
- **Algorithm and mode:** `AES/GCM/NoPadding` is authenticated encryption (`PiiEncryptor.java:39`). No ECB, CBC without a MAC, DES/3DES/RC4, MD5 or SHA-1 anywhere in the code.
- **Key size:** A 256-bit key is enforced on generation (`KEY_LENGTH_BYTES * 8`, line 123) and on load (exact 32-byte check, lines 153-156). Shorter keys are rejected.
- **No hardcoded or default key:** The source contains no key, password or secret literal. `loadKeyFromEnvironment` throws if no key is set and never falls back to a built-in value (lines 141-144).
- **Key generation entropy:** `KeyGenerator.getInstance("AES")` is initialised with a `SecureRandom` CSPRNG (lines 49, 122-124).
- **IV/nonce handling:** A new 12-byte IV comes from `SecureRandom` on every `encrypt` call (lines 68-69). It is never reused, derived from a counter or time, or fixed. On decrypt, the IV is taken from the stored prefix (line 105).
- **Authentication tag:** The full 128-bit tag is used (line 42). `doFinal` checks the tag before any plaintext is returned (line 108). A tampered value, wrong key or wrong field raises `AEADBadTagException`.
- **Ciphertext input validation:** Invalid Base64 is turned into a `GeneralSecurityException` (lines 94-98). A minimum length of IV + tag is enforced before cipher setup, so short input can't cause an out-of-bounds read (lines 99-101).
- **Field binding with AAD:** The field label is authenticated as AAD on both encrypt and decrypt (lines 73, 106). This stops name/email field confusion. Binding to a record is covered separately in SEC-03.
- **Key type check:** The constructor rejects a null or non-AES key (lines 53-58).
- **Error messages and information leakage (CWE-209):** Tag failures and other `GeneralSecurityException`s produce generic messages (lines 246-258). The Base64 key error drops the exception cause, so no key fragment is echoed (line 150). The key-length message shows only the length, not the value. The `IOException` message at line 254 can show the key file path, but only to the operator who set it. No stack traces are printed.
- **PII on the command line (CWE-214):** Name and email are refused as CLI arguments, so they don't appear in `ps` or shell history (lines 211-217). Input is read from the console or stdin.
- **Input validation:** The name must be non-empty and at most 320 characters (lines 184-192). The email must be at most 320 characters and match a simple pattern (lines 194-199). No injection sink exists: there is no SQL, shell, file path, HTML or deserialization use of input, so the input only reaches `String.getBytes` for encryption.
- **Regular expression DoS (CWE-1333):** `^[^@\s]+@[^@\s]+\.[^@\s]+$` (line 47) can backtrack at most quadratically. The length check runs first and short-circuits (line 195), so the regex never sees more than 320 characters. The cost is negligible.
- **Terminal escape sequences (CWE-150):** Control characters in the name are echoed back (line 237). The input comes from the same operator whose terminal shows the output, so no trust boundary is crossed in this CLI. No finding.
- **Thread safety of RNG:** The shared static `SecureRandom` is thread-safe. A new `Cipher` instance is created for each operation (lines 71, 103), so no cipher state is shared.
- **Key output from `--generate-key`:** Printing the key to stdout is intended (line 208). The README pairs it with `umask 077` and redirection to a file and says to keep the file out of version control (README.md:57-66). The permission-enforcement gap is covered in SEC-04.
- **Supporting files:** `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt` and `prompt_hash.txt` were checked. They contain no credentials, keys or executable code.
