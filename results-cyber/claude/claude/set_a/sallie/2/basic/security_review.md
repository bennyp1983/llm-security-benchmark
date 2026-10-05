# Security Review: PiiEncryptor (AES-256-GCM PII encryption demo)

## 1. Executive Summary
`PiiEncryptor.java` is a small command-line Java program and reusable class. It takes a person's name and email address, encrypts each one with AES-256-GCM using a random per-run key, then decrypts them again and checks that the round trip works.

The cryptography itself is sound. The key comes from `KeyGenerator` backed by `SecureRandom`, each encryption gets a fresh random 96-bit IV, the tag is the full 128 bits, the field label is bound as associated data, short ciphertexts are rejected and no key is hardcoded. No Critical or High issues were found.

All findings are about how the PII is handled around the cryptography:
- **SEC-01 (Medium):** PII can be passed on the command line, so other local users can see it in the process list and it is saved in shell history.
- **SEC-02 (Low):** the decrypted PII is printed to stdout, and a rejected email is echoed to stderr without sanitisation.
- **SEC-03 (Low):** plaintext PII is kept in immutable `String` objects that cannot be wiped, so the byte-array zeroing gives only partial protection.
- **SEC-04 (Low):** the associated data only binds the field label, not a record identifier. If the class is reused for storage, ciphertexts can be swapped between records without being detected.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `PiiEncryptor.java` | CLI program and reusable class that encrypts and decrypts a name and email with AES-256-GCM | Key generation (`KeyGenerator`, `SecureRandom`); IV generation; GCM encrypt/decrypt with AAD; Base64 encoding and parsing; plaintext buffer zeroing; reading PII from argv or stdin; email regex validation; printing PII and error messages to the console |
| `README.md` | Plain-English user guide for the program | Documentation only. Describes key handling and warns about command-line history and printing PII. No executable code or secrets |
| `prompt.txt`, `cyber_prompt.txt` | Task prompts used to generate and review the code | No code. Not security-relevant |
| `result.md`, `return.txt`, `prompt_hash.txt` | Run metadata from code generation (summary, JSON usage stats, hash) | No code, credentials or keys. Not security-relevant |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: router workflow. Read every file, extracted keywords (cryptography, AES, GCM, IV/nonce, key management, RNG, PII / sensitive data exposure, input validation, console output) and selected the matching skills below.
- `performing-cryptographic-audit-of-application`: applied the manual crypto review workflow to every crypto touchpoint in `PiiEncryptor.java`. Checked algorithm choice, mode and padding, key size, key management and hardcoded keys, entropy source and error handling.
- `implementing-aes-encryption-for-data-at-rest`: checked the AES-GCM usage against NIST SP 800-38D and the skill's validation criteria. Covered the 12-byte nonce from a CSPRNG, no nonce reuse, 128-bit tag, the nonce‖ciphertext‖tag format, rejecting invalid tags without returning partial plaintext, and wiping sensitive material from memory.
- `testing-for-sensitive-data-exposure`: applied the PII exposure checks (PII in output, in error messages, in process arguments and history, and in memory) to the CLI's input and output handling.
- General OWASP Top 10 / CWE knowledge (no specific library skill matched): regex denial of service in `EMAIL_PATTERN`, terminal output neutralisation, robustness of the public `decrypt` API against malformed Base64, and confirming there is no injection, deserialization, file, command or network attack surface.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | PII accepted as command-line arguments (visible in process list and shell history) | Medium | CWE-214 | `PiiEncryptor.java:107` |
| SEC-02 | Decrypted PII printed to stdout, and unsanitised email echoed in an error message | Low | CWE-359 | `PiiEncryptor.java:145` |
| SEC-03 | Plaintext PII kept in immutable Strings that cannot be wiped from memory | Low | CWE-316 | `PiiEncryptor.java:97` |
| SEC-04 | AAD does not bind record context, so ciphertexts can be substituted between records | Low | CWE-345 | `PiiEncryptor.java:64` |

## 5. Detailed Findings

### SEC-01: PII accepted as command-line arguments (visible in process list and shell history)
- **Severity:** Medium
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `PiiEncryptor.java:107-109`

**Vulnerable code:**
```java
// PiiEncryptor.java:107-109
        if (args.length == 2) {
            name = args[0].trim();
            email = args[1].trim();
```

**Why it is a problem:** Command-line arguments are not private. On a shared host, any local user can read the name and email while the JVM runs, through `ps -ef`, `/proc/<pid>/cmdline` or Windows process listings. The arguments are also written to shell history files such as `~/.bash_history`, and may be captured by process-auditing tools (auditd `execve` records, EDR telemetry) and CI logs. So the PII this program is meant to protect leaks in cleartext before any encryption happens. The Usage text at `PiiEncryptor.java:21` and the README (Option B) actively promote this mode. The README warning only covers history, not process-list exposure.

**Fix:** Do not accept PII in argv. Read it only from stdin or an interactive console, which the program already supports, and reject positional arguments.
```java
        if (args.length != 0) {
            System.err.println("Usage: java PiiEncryptor");
            System.err.println("Personal data is read from standard input and is not accepted "
                    + "as command-line arguments, because arguments are visible to other users.");
            System.exit(2);
            return;
        }

        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
        System.out.print("Enter name: ");
        String name = scanner.hasNextLine() ? scanner.nextLine().trim() : "";
        System.out.print("Enter email address: ");
        String email = scanner.hasNextLine() ? scanner.nextLine().trim() : "";
```

### SEC-02: Decrypted PII printed to stdout, and unsanitised email echoed in an error message
- **Severity:** Low
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **Location:** `PiiEncryptor.java:145-148` and `PiiEncryptor.java:126-129`

**Vulnerable code:**
```java
// PiiEncryptor.java:145-148
            System.out.println();
            System.out.println("=== Decrypted ===");
            System.out.println("Name:  " + decryptedName);
            System.out.println("Email: " + decryptedEmail);
```
```java
// PiiEncryptor.java:126-129
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            System.err.println("Error: \"" + email + "\" is not a valid email address.");
            System.exit(1);
        }
```

**Why it is a problem:** The program writes the decrypted name and email to stdout and echoes the raw email input to stderr. If the tool runs from a script, cron job, CI pipeline or container, those streams are usually captured in log files and log aggregators that are retained longer, and are readable by more people, than the data itself. The PII therefore ends up in cleartext outside the encrypted form. The echoed email is also not sanitised. Input piped from an untrusted source can contain ANSI/terminal escape sequences (CWE-150) or newlines that forge extra log lines (CWE-117) when stderr is viewed or logged.

**Fix:** Report only whether the round trip succeeded, never the plaintext. Do not repeat rejected input in error messages.
```java
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            System.err.println("Error: the email address is not valid.");
            System.exit(1);
        }

        // ...

            String decryptedName = encryptor.decrypt("name", encryptedName);
            String decryptedEmail = encryptor.decrypt("email", encryptedEmail);

            boolean matches = name.equals(decryptedName) && email.equals(decryptedEmail);
            System.out.println();
            System.out.println("Round trip successful: " + matches);
            if (!matches) {
                System.exit(1);
            }
```

### SEC-03: Plaintext PII kept in immutable Strings that cannot be wiped from memory
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `PiiEncryptor.java:58`, `PiiEncryptor.java:96-100`, `PiiEncryptor.java:104-115`

**Vulnerable code:**
```java
// PiiEncryptor.java:96-100
        try {
            return new String(plainBytes, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plainBytes, (byte) 0);
        }
```

**Why it is a problem:** The class tries to limit how long plaintext stays in memory by zeroing byte arrays (`PiiEncryptor.java:75`, `PiiEncryptor.java:99`). However, both the public API and `main` pass the PII around as `java.lang.String` values (`plaintext`, `name`, `email`, and the `String` returned from `decrypt`). Strings are immutable and cannot be cleared. Copies stay on the heap until garbage collection, and possibly longer in the string table or deduplication structures. They can be recovered from heap dumps, core dumps, swap or `jmap` output. The zeroing therefore gives a false sense of protection, since a cleartext copy of every value always survives.

**Fix:** Add `char[]`-based overloads so callers can wipe the plaintext after use, and use them from `main`. The `String` API can stay for convenience, but should be documented as not wipeable.
```java
    public String encrypt(String fieldLabel, char[] plaintext) throws GeneralSecurityException {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(plaintext));
        byte[] plainBytes = new byte[encoded.remaining()];
        encoded.get(plainBytes);
        if (encoded.hasArray()) {
            Arrays.fill(encoded.array(), (byte) 0);
        }
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            cipher.updateAAD(fieldLabel.getBytes(StandardCharsets.UTF_8));
            byte[] cipherBytes = cipher.doFinal(plainBytes);
            return Base64.getEncoder().encodeToString(
                    ByteBuffer.allocate(iv.length + cipherBytes.length).put(iv).put(cipherBytes).array());
        } finally {
            Arrays.fill(plainBytes, (byte) 0);
        }
    }

    /** Caller must wipe the returned array with Arrays.fill(result, '\0') after use. */
    public char[] decryptToChars(String fieldLabel, String encoded) throws GeneralSecurityException {
        byte[] combined = Base64.getDecoder().decode(encoded);
        if (combined.length < IV_LENGTH_BYTES + TAG_LENGTH_BITS / 8) {
            throw new IllegalArgumentException("Encrypted value is too short");
        }
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key,
                new GCMParameterSpec(TAG_LENGTH_BITS, combined, 0, IV_LENGTH_BYTES));
        cipher.updateAAD(fieldLabel.getBytes(StandardCharsets.UTF_8));
        byte[] plainBytes = cipher.doFinal(combined, IV_LENGTH_BYTES, combined.length - IV_LENGTH_BYTES);
        try {
            java.nio.CharBuffer chars = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(plainBytes));
            char[] result = new char[chars.remaining()];
            chars.get(result);
            if (chars.hasArray()) {
                Arrays.fill(chars.array(), '\0');
            }
            return result;
        } finally {
            Arrays.fill(plainBytes, (byte) 0);
        }
    }
```

### SEC-04: AAD does not bind record context, so ciphertexts can be substituted between records
- **Severity:** Low
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **Location:** `PiiEncryptor.java:58-64` and `PiiEncryptor.java:84-93`

**Vulnerable code:**
```java
// PiiEncryptor.java:58-64
    public String encrypt(String fieldLabel, String plaintext) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        cipher.updateAAD(fieldLabel.getBytes(StandardCharsets.UTF_8));
```

**Why it is a problem:** `PiiEncryptor` is a public, reusable class whose Javadoc presents the AAD as protection against substitution. The AAD only contains the field label (`"name"` / `"email"`), though. If the class is used as intended for real data, with many people's records encrypted under one long-lived key, anyone who can write to the data store can copy person A's encrypted email into person B's record. It still decrypts cleanly and passes the tag check, because the label matches. This breaks integrity: for example, B's notifications or password resets could go to A's address, or one person's data could be shown as another's. In this demo the key is thrown away after one run, so the risk only appears when the class is reused, hence Low.

**Fix:** Require a record or context identifier (for example the database primary key) and bind it together with the field label in the AAD. Use unambiguous length-prefixed encoding so that different (id, label) pairs can never produce the same AAD bytes.
```java
    private static byte[] associatedData(String recordId, String fieldLabel) {
        byte[] id = recordId.getBytes(StandardCharsets.UTF_8);
        byte[] label = fieldLabel.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(8 + id.length + label.length)
                .putInt(id.length).put(id)
                .putInt(label.length).put(label)
                .array();
    }

    public String encrypt(String recordId, String fieldLabel, String plaintext) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        cipher.updateAAD(associatedData(recordId, fieldLabel));
        // ... remainder unchanged
    }

    public String decrypt(String recordId, String fieldLabel, String encoded) throws GeneralSecurityException {
        // ... length check unchanged
        cipher.updateAAD(associatedData(recordId, fieldLabel));
        // ... remainder unchanged
    }
```

## 6. Verified Controls and Checks With No Finding
- Algorithm and mode: `AES/GCM/NoPadding` is authenticated encryption (AEAD). No ECB, no unauthenticated CBC or CTR, and no padding oracle (`PiiEncryptor.java:25`, `:62`, `:90`).
- Key size and generation: 256-bit key from `KeyGenerator.getInstance("AES")` initialised with a `SecureRandom` CSPRNG, which meets NIST SP 800-57 (`PiiEncryptor.java:26`, `:33`, `:45-49`).
- Hardcoded secrets: no keys, passwords, salts or IVs are hardcoded anywhere in the source, README or metadata files.
- Key exposure: the key is never printed, logged, serialised or written to disk (`PiiEncryptor.java:131-159`). The constructor rejects null and non-AES keys (`PiiEncryptor.java:38-40`).
- IV/nonce handling: a fresh 12-byte (96-bit) IV from `SecureRandom` for every encryption, never a static or counter-derived value. With a random 96-bit IV, the chance of reusing a nonce under one key is negligible (`PiiEncryptor.java:27`, `:59-60`, `:63`).
- Tag length: the full 128-bit GCM tag, above the NIST SP 800-38D minimum of 96 bits (`PiiEncryptor.java:28`, `:63`, `:92`).
- Ciphertext format and parsing: IV‖ciphertext‖tag, Base64-encoded. Inputs shorter than IV plus tag (28 bytes) are rejected before decryption, and the IV is read with explicit offsets (`PiiEncryptor.java:69-73`, `:85-92`).
- Tamper detection: Java's GCM `doFinal` checks the tag before returning any plaintext and throws `AEADBadTagException` if it fails, so no unauthenticated partial plaintext is ever released (`PiiEncryptor.java:95`).
- Field-label binding: the label is included as AAD on both encrypt and decrypt, so a name ciphertext cannot be decrypted as an email (`PiiEncryptor.java:64`, `:93`). See SEC-04 for binding across records.
- Plaintext byte buffers: zeroed in `finally` blocks after use (`PiiEncryptor.java:74-76`, `:98-100`). See SEC-03 for the `String` limitation.
- Error handling: the `GeneralSecurityException` handler prints only the exception message (for example "Tag mismatch"), not the key, IV, plaintext or stack trace (`PiiEncryptor.java:156-158`).
- Thread safety: a new `Cipher` is created for each call rather than shared, and `SecureRandom` is thread-safe (`PiiEncryptor.java:33`, `:62`, `:90`).
- Malformed input to `decrypt`: invalid Base64 makes `Base64.Decoder.decode` throw `IllegalArgumentException` (unchecked). This fails safely with no data exposure, and callers of the public API should catch it (`PiiEncryptor.java:85`).
- Regex denial of service: `EMAIL_PATTERN` (`PiiEncryptor.java:30-31`) has no nested quantifiers. The worst case is polynomial backtracking in `[^@\s]+\.[^@\s]+`, and the input is a single line supplied locally by the operator, so there is no practical ReDoS risk.
- Input validation: empty names and malformed emails are rejected before encryption, and there is a usage check on argument count (`PiiEncryptor.java:116-129`).
- Injection and other attack surface: no SQL, OS command execution, file path handling, deserialization, XML parsing, reflection, network or TLS calls exist in the code, so CWE-89/78/22/502/611/295 do not apply.
- Non-code files: `README.md`, `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt` and `prompt_hash.txt` were read. They contain documentation and run metadata only, with no executable code, credentials or keys.
