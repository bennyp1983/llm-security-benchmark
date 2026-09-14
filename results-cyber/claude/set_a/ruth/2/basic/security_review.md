# Security Review: SecureDataCrypto (AES-256-GCM symmetric encryption CLI and library)

## 1. Executive Summary
`SecureDataCrypto.java` is a single-file Java program and library for symmetric encryption. It uses AES-256-GCM with a random 96-bit IV and a 128-bit tag, and it authenticates the header as AAD. Keys come either from a random 256-bit key file (`genkey`) or from a password through PBKDF2-HMAC-SHA256 (600,000 iterations and a random 16-byte salt for each message). The CLI reads plaintext or Base64 ciphertext from stdin or `--in` and writes to stdout or `--out`.

The cryptography itself is sound. The review found no weak algorithms, ECB/CBC modes, IV reuse, hardcoded production keys, insecure RNG or missing integrity protection. The most important finding is in how output files are handled (SEC-01, Medium). `decrypt --out` overwrites an existing file in place and keeps that file's owner and permissions. Decrypted secrets can therefore end up in a world-readable file, or in a file another local user created ahead of time. This contradicts the README's promise that output files get owner-only permissions. The same code path follows symlinks (SEC-02, Low). The other low-severity findings are:
- no minimum password strength when encrypting (SEC-03)
- a loose upper limit on the PBKDF2 iteration count that an attacker can set in the header, allowing CPU exhaustion (SEC-04)
- key material left in memory that cannot be wiped, despite the design goal of zeroising secrets (SEC-05)

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SecureDataCrypto.java` | CLI and library: `genkey`, `encrypt`, `decrypt`, `demo`; AES-256-GCM encryption with a key file or a password-derived key | Key generation (`KeyGenerator`, `SecureRandom`); AES/GCM encryption and decryption with AAD; PBKDF2 key derivation using salt and iteration count taken from untrusted ciphertext headers; reading and writing key files, password files and output files with POSIX permissions; interactive password prompt; zeroising memory; Base64 parsing; error messages |
| `README.md` | Documents the design, ciphertext format, build and usage | States security claims (0600 output files, wiping secrets from memory, no secrets on the command line) that were checked against the code |
| `prompt.txt`, `cyber_prompt.txt` | Task prompts used to generate and review the code | No executable code |
| `result.md`, `return.txt`, `prompt_hash.txt` | Run metadata and log of the generation session (`prompt_hash.txt` is empty) | No executable code; no credentials found |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: the router workflow. Understand the code, find matching skills by name and description, apply each one, then report.
- `performing-cryptographic-audit-of-application`: checked every crypto touchpoint for deprecated algorithms, insecure modes and padding, key size, hardcoded keys and passwords, KDF parameters, RNG and entropy, and crypto error handling (`SecureDataCrypto.java:55-73`, `96-163`, `170-248`, `283-287`).
- `implementing-aes-encryption-for-data-at-rest`: checked the AES-256-GCM implementation against NIST SP 800-38D and SP 800-132. Covered IV length and uniqueness, tag length, AAD coverage of the header, salt length, iteration count, no partial plaintext on tag failure, ciphertext format metadata, and wiping keys from memory (`SecureDataCrypto.java:147-267`, `289-299`).
- `testing-for-sensitive-data-exposure`: covered how plaintext, keys and passwords are stored and exposed. Checked output and key file permissions, secrets in source code and CLI arguments, leakage through error messages, and data left in memory (`SecureDataCrypto.java:110-144`, `305-387`, `468-556`, `559-598`).
- General OWASP Top 10 / CWE knowledge (no library skill matched): local file-system handling of `--out` (symlink following, CWE-59; permissions on pre-existing files, CWE-732), resource consumption from untrusted ciphertext headers (CWE-400), password strength policy (CWE-521), and parsing of command-line options. The `performing-directory-traversal-testing` skill was considered but not applied. It targets web file-path parameters, whereas here the paths are supplied by the local operator who runs the CLI.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Decrypted plaintext written into an existing `--out` file keeps that file's (possibly world-readable) permissions and owner | Medium | CWE-732 | `SecureDataCrypto.java:338` |
| SEC-02 | Overwriting an `--out` file follows symbolic links | Low | CWE-59 | `SecureDataCrypto.java:311` |
| SEC-03 | No minimum password strength when encrypting with a password | Low | CWE-521 | `SecureDataCrypto.java:185` |
| SEC-04 | PBKDF2 iteration count taken from the untrusted header is capped only at 10,000,000, allowing CPU exhaustion | Low | CWE-400 | `SecureDataCrypto.java:71` |
| SEC-05 | Key material left in an immutable `String` and in key objects that are never destroyed | Low | CWE-316 | `SecureDataCrypto.java:130` |

## 5. Detailed Findings

### SEC-01: Decrypted plaintext written into an existing `--out` file keeps that file's (possibly world-readable) permissions and owner
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `SecureDataCrypto.java:305-316`, `SecureDataCrypto.java:333-340`

**Vulnerable code:**
```java
// SecureDataCrypto.java:333-340
    private static void writeOutput(String outFile, byte[] data) throws IOException {
        if (outFile == null) {
            System.out.write(data);
            System.out.flush();
        } else {
            writeRestrictedFile(Path.of(outFile), data, true);
        }
    }
// SecureDataCrypto.java:305-316
    /**
     * Writes a file that may contain secrets. New files get 0600 permissions on
     * POSIX systems; existing files keep their current permissions.
     */
    private static void writeRestrictedFile(Path path, byte[] contents, boolean overwrite) throws IOException {
        Set<? extends OpenOption> options = overwrite
                ? EnumSet.of(StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)
                : EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        FileAttribute<?>[] attributes = path.getFileSystem().supportedFileAttributeViews().contains("posix")
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
                : new FileAttribute<?>[0];
        try (SeekableByteChannel channel = Files.newByteChannel(path, options, attributes)) {
```

**Why it is a problem:** `decrypt --out <file>` writes the recovered plaintext with `CREATE | TRUNCATE_EXISTING`. The `rw-------` attribute only takes effect when the file is newly created. If the target already exists, the plaintext goes into the existing inode and keeps that inode's permissions and owner. Two realistic cases:
- **Normal use:** a user re-decrypts into a file they made earlier with the default umask, such as `report.pdf` at mode 0644, or into a file created by an editor or `touch`. The decrypted secrets are then readable by every local user.
- **Local attack:** in a shared directory such as `/tmp` or a group-writable project directory, another user creates the expected output name ahead of time with mode 0666. The victim's plaintext is written into a file that user owns and can read.

The README tells users "It creates key files and output files with owner-only permissions (`0600`)", so they have no reason to expect this. The tool exists to protect sensitive data, so leaking the decrypted form defeats that purpose.

**Fix:** Never write secrets into an existing inode. Write to a new 0600 temporary file in the same directory, then atomically rename it over the target. The result is always a file owned by the caller with owner-only permissions. `rename(2)` replaces a symlink rather than following it, so this also fixes SEC-02.
```java
    private static void writeRestrictedFile(Path path, byte[] contents, boolean overwrite) throws IOException {
        FileAttribute<?>[] attributes = path.getFileSystem().supportedFileAttributeViews().contains("posix")
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
                : new FileAttribute<?>[0];
        if (!overwrite) {
            try (SeekableByteChannel channel = Files.newByteChannel(path,
                    EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attributes)) {
                writeFully(channel, contents);
            }
            return;
        }
        // Always produce a fresh owner-only file: write a new 0600 temp file in the same
        // directory, then atomically rename it over the target (replaces, never follows, links).
        Path directory = path.toAbsolutePath().getParent();
        Path temp = Files.createTempFile(directory, ".sdc-", ".tmp", attributes);
        try {
            try (SeekableByteChannel channel = Files.newByteChannel(temp, EnumSet.of(StandardOpenOption.WRITE))) {
                writeFully(channel, contents);
            }
            Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static void writeFully(SeekableByteChannel channel, byte[] contents) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(contents);
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    }
```

### SEC-02: Overwriting an `--out` file follows symbolic links
- **Severity:** Low
- **CWE:** CWE-59: Improper Link Resolution Before File Access ('Link Following')
- **Location:** `SecureDataCrypto.java:310-316`

**Vulnerable code:**
```java
// SecureDataCrypto.java:310-316
        Set<? extends OpenOption> options = overwrite
                ? EnumSet.of(StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)
                : EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        FileAttribute<?>[] attributes = path.getFileSystem().supportedFileAttributeViews().contains("posix")
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
                : new FileAttribute<?>[0];
        try (SeekableByteChannel channel = Files.newByteChannel(path, options, attributes)) {
```

**Why it is a problem:** In overwrite mode (used by both `encrypt --out` and `decrypt --out`), the file is opened without `NOFOLLOW_LINKS`. If an attacker plants a symlink at the output path in a directory they can write to, the tool follows it:
- The target can be a file the attacker can read, which exposes the plaintext as in SEC-01.
- The target can be a file the victim owns, such as `~/.bashrc` or another key or data file. That file is truncated and overwritten with attacker-influenced ciphertext or plaintext, which damages integrity or availability.

Linux `fs.protected_symlinks` blocks this only in world-writable sticky directories, not in other shared directories or on other platforms. Creating key files with `CREATE_NEW` is not affected, because it refuses existing paths, including symlinks.

**Fix:** The atomic temp-file-and-rename approach in SEC-01 is the preferred fix. As a minimal change, refuse to follow a symlink in the final path component:
```java
        Set<OpenOption> options = overwrite
                ? Set.of(StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
                : Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        FileAttribute<?>[] attributes = path.getFileSystem().supportedFileAttributeViews().contains("posix")
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
                : new FileAttribute<?>[0];
        try (SeekableByteChannel channel = Files.newByteChannel(path, options, attributes)) {
```

### SEC-03: No minimum password strength when encrypting with a password
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `SecureDataCrypto.java:185-188` (the only related check is at `SecureDataCrypto.java:148-150` and `352-356`)

**Vulnerable code:**
```java
// SecureDataCrypto.java:185-188
    public static byte[] encryptWithPassword(byte[] plaintext, char[] password) throws CryptoException {
        byte[] salt = randomBytes(SALT_BYTES);
        int iterations = DEFAULT_KDF_ITERATIONS;
        SecretKey key = deriveKey(password, salt, iterations);
```

**Why it is a problem:** Password-mode encryption, through the interactive prompt, `--password-file` or the public library API, only rejects an empty password (`deriveKey`, lines 148-150). A one-character or dictionary password is accepted. Ciphertext is meant to be stored, and the salt and iteration count sit in the clear in its header. Anyone who obtains the ciphertext can therefore brute-force the password offline with GPUs. PBKDF2 at 600,000 iterations only slows each guess down. It gives no real protection for a password of 4 to 8 characters. The README acknowledges this weakness but the code does not enforce anything.

**Fix:** Enforce a minimum length when encrypting only, so that existing ciphertexts can still be decrypted. Optionally add an entropy or blocklist check, or a memory-hard KDF such as Argon2id or scrypt if a provider is available.
```java
    private static final int MIN_PASSWORD_CHARS = 12;

    public static byte[] encryptWithPassword(byte[] plaintext, char[] password) throws CryptoException {
        if (password == null || password.length < MIN_PASSWORD_CHARS) {
            throw new CryptoException("Password must be at least " + MIN_PASSWORD_CHARS + " characters long");
        }
        byte[] salt = randomBytes(SALT_BYTES);
        int iterations = DEFAULT_KDF_ITERATIONS;
        SecretKey key = deriveKey(password, salt, iterations);
```

### SEC-04: PBKDF2 iteration count taken from the untrusted header is capped only at 10,000,000, allowing CPU exhaustion
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `SecureDataCrypto.java:69-71`, `SecureDataCrypto.java:207-211`

**Vulnerable code:**
```java
// SecureDataCrypto.java:69-71
    private static final int MIN_KDF_ITERATIONS = 100_000;
    /** Upper bound prevents a crafted header from forcing an extremely slow derivation. */
    private static final int MAX_KDF_ITERATIONS = 10_000_000;
```

**Why it is a problem:** `decryptWithPassword` reads the iteration count from the ciphertext header (line 207) and runs PBKDF2 with it (line 211). This happens before the GCM tag, which covers the header, can be checked. The header is therefore under attacker control during derivation. The cap is 10,000,000 iterations, about 16.7 times the 600,000 the code itself produces. Each crafted ciphertext therefore costs several seconds of CPU per attempt, and the password is kept in memory for that whole time. Suppose an application uses the public library API to decrypt ciphertext it receives from users, for example records stored by clients. A handful of concurrent forged blobs is then enough to tie up worker threads. The code never writes more than `DEFAULT_KDF_ITERATIONS`, so accepting up to 10M has no legitimate purpose.

**Fix:** Keep the cap tight around the values this program actually writes. Raise it only when the default is raised in a future format version.
```java
    private static final int MIN_KDF_ITERATIONS = 100_000;
    /** Upper bound prevents a crafted header from forcing an extremely slow derivation. */
    private static final int MAX_KDF_ITERATIONS = 2 * DEFAULT_KDF_ITERATIONS;
```

### SEC-05: Key material left in an immutable `String` and in key objects that are never destroyed
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `SecureDataCrypto.java:130-139`, `SecureDataCrypto.java:154-156`

**Vulnerable code:**
```java
// SecureDataCrypto.java:130-139
            String text = new String(fileBytes, StandardCharsets.US_ASCII).strip();
            try {
                raw = Base64.getDecoder().decode(text);
            } catch (IllegalArgumentException e) {
                throw new CryptoException("Key file is not valid Base64: " + path);
            }
            if (raw.length * 8 != KEY_BITS) {
                throw new CryptoException("Key file must contain a " + KEY_BITS + "-bit key: " + path);
            }
            return new SecretKeySpec(raw, KEY_ALGORITHM);
// SecureDataCrypto.java:154-156
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            raw = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(raw, KEY_ALGORITHM);
```

**Why it is a problem:** The design goes out of its way to zero key, password and plaintext buffers (see the README and the `wipe` calls), but it misses several copies:
- `loadKey` turns the whole Base64 key file into a `String` (and `strip()` may make a second one). A `String` cannot be wiped, so the encoded AES key stays on the heap until garbage collection. It can show up in heap dumps, core files or swap.
- In `deriveKey`, the intermediate `SecretKey` returned by `generateSecret(spec)` keeps its own copy of the password and the derived key, and it is never destroyed.
- The returned `SecretKeySpec` objects are never destroyed by the CLI.

These leftovers undermine the stated zeroisation guarantee. An attacker with memory access, such as a heap dump, crash dump or a co-located debugger, can recover the key.

**Fix:** Decode the key without going through a `String`. Destroy the intermediate PBKDF2 key where the provider supports it. Callers should also destroy the keys they use once finished.
```java
            int start = 0;
            int end = fileBytes.length;
            while (start < end && Character.isWhitespace(fileBytes[start])) {
                start++;
            }
            while (end > start && Character.isWhitespace(fileBytes[end - 1])) {
                end--;
            }
            byte[] encoded = Arrays.copyOfRange(fileBytes, start, end);
            try {
                raw = Base64.getDecoder().decode(encoded);
            } catch (IllegalArgumentException e) {
                throw new CryptoException("Key file is not valid Base64: " + path);
            } finally {
                wipe(encoded);
            }
            if (raw.length * 8 != KEY_BITS) {
                throw new CryptoException("Key file must contain a " + KEY_BITS + "-bit key: " + path);
            }
            return new SecretKeySpec(raw, KEY_ALGORITHM);

// deriveKey: destroy the intermediate PBKDF2 key object
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            SecretKey derived = factory.generateSecret(spec);
            try {
                raw = derived.getEncoded();
                return new SecretKeySpec(raw, KEY_ALGORITHM);
            } finally {
                try {
                    derived.destroy();
                } catch (javax.security.auth.DestroyFailedException ignored) {
                    // Provider does not support destruction; nothing more can be done here.
                }
            }
```

## 6. Verified Controls and Checks With No Finding
- **Cipher algorithm and mode:** `AES/GCM/NoPadding` with 256-bit keys (`SecureDataCrypto.java:59-63`). There is no ECB, CBC or unauthenticated mode, and no DES, 3DES, RC4, MD5 or SHA-1 used for security purposes. `MessageDigest.isEqual` in the demo is only a constant-time comparison.
- **IV/nonce handling:** a new 12-byte IV from `SecureRandom` for every `seal` call (`SecureDataCrypto.java:216`). The IV is stored with the ciphertext and is never reused or derived from the key.
- **Authentication tag:** 128-bit tag (`SecureDataCrypto.java:63`, `219`, `239`). Tampering is rejected through `AEADBadTagException` with a generic message (`242-244`). The JCE GCM decrypt releases no plaintext before the tag is verified.
- **Header integrity:** version, mode, salt and iteration count are all passed to `updateAAD` (`SecureDataCrypto.java:220`, `240`), so an attacker cannot downgrade or swap parameters without the tag failing.
- **Ciphertext parsing bounds:** length checks before reading the header, salt and iterations and before decryption (`SecureDataCrypto.java:202-204`, `234-236`, `251-253`) prevent buffer underflow and exception-based crashes. Version and mode are validated (`255-266`).
- **Key generation and randomness:** `KeyGenerator.getInstance("AES").init(256, SecureRandom)` (`SecureDataCrypto.java:96-104`). Salts and IVs come from a shared `SecureRandom` (`73`, `283-287`). No `java.util.Random` and no time-based seeds.
- **KDF parameters:** PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt per message, 256-bit output, which meets OWASP 2023+ and NIST SP 800-132 (`SecureDataCrypto.java:65-69`, `185-188`). Headers with fewer than 100,000 iterations are rejected (`208-210`).
- **Key validation:** `requireAesKey` enforces the AES algorithm and exactly 256 bits for encrypt and decrypt (`SecureDataCrypto.java:269-281`). `loadKey` rejects keys of the wrong length (`136-138`).
- **Key file creation:** `genkey` uses `CREATE_NEW` with 0600 POSIX permissions (`SecureDataCrypto.java:117`, `312-314`). This is atomic, refuses existing files and symlinks, and has no exploitable TOCTOU despite the earlier `Files.exists` check (`508`).
- **Secrets not on the command line:** passwords come only from `Console.readPassword` with no echo and a confirmation on encrypt (`SecureDataCrypto.java:346-367`), or from a password file (`370-387`). Plaintext comes from stdin or `--in`. There is no argv option for either, so nothing leaks into process lists or shell history.
- **Hardcoded secrets:** none in production paths. The only literals are the sample SSN/token and the password "correct horse battery staple" in `demoCommand` (`SecureDataCrypto.java:560-592`). These are clearly synthetic demo values and are not used for real data. `README.md` examples use placeholders only.
- **Error handling and information leakage:** decryption failures give a single generic message that does not separate a wrong key from modified data (`SecureDataCrypto.java:242-247`). The CLI prints only exception messages and never stack traces (`490-500`). Messages reveal only paths the operator supplied.
- **Memory hygiene (outside SEC-05):** raw key bytes, Base64 buffers, password arrays, `PBEKeySpec` and plaintext buffers are wiped in `finally` blocks (`SecureDataCrypto.java:118-122`, `140-143`, `159-162`, `360-363`, `379-382`, `528-531`, `552-555`).
- **Deserialization, injection, SSRF, command execution:** the code has no Java object deserialization, SQL, OS command execution, reflection or network access.
- **Path handling:** `--in`, `--out`, `--key` and `--password-file` are paths the local operator supplies. The program runs with that operator's own privileges and exposes no remote or privilege-boundary interface, so path traversal (CWE-22) does not apply. Link following and permission issues are covered in SEC-01 and SEC-02.
- **Option parsing:** exactly one key source is required. Missing option values and unknown options are rejected (`SecureDataCrypto.java:424-461`), with no out-of-bounds array access.
- **Input size:** the whole input is read into memory (`SecureDataCrypto.java:324-331`). The data comes from the local operator and the README documents the limit, so there is no finding. GCM's per-message limit (about 64 GiB) is well above Java's 2 GiB array limit.
