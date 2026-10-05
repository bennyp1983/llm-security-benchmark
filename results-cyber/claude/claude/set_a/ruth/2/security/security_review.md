# Security Review: SecureDataCrypto (AES-256-GCM encryption CLI with PKCS#12 key management)

## 1. Executive Summary
`SecureDataCrypto.java` is a single-file Java 17 command-line tool and library. It encrypts and decrypts application data with AES-256-GCM. It keeps randomly generated AES keys in a password-protected PKCS#12 keystore and supports key rotation, where each ciphertext carries an authenticated key ID, and key deletion. The keystore password comes from a password file, an environment variable or a no-echo console prompt.

The core cryptography is sound. It uses AES-256-GCM with a fresh 96-bit IV from `SecureRandom` for every message, a 128-bit tag, and the version and key-ID header bound in as AAD. Key IDs are checked against a strict pattern before lookup, AEAD errors are generic, and there are no hardcoded secrets and no passwords on the command line. No Critical or High issues were found.

The findings are about key storage and key lifecycle:
- **SEC-01 (Medium):** How strongly the keystore is protected depends on JVM defaults. On JDK 17 that is only 10,000 PBKDF2 iterations, and older JDKs or `-Dkeystore.pkcs12.legacy` fall back to SHA-1/3DES. The only rule for a new password is a 16-character minimum. A stolen keystore is therefore much cheaper to brute-force offline than it should be.
- **SEC-02 (Medium):** Keystore create and update is a read-modify-write with no lock, including a check-then-create race. Running `generate-key` or `delete-key` concurrently can silently drop keys or replace a whole keystore, and data encrypted under those keys is then permanently lost.
- **SEC-03 to SEC-05 (Low):**
  - The keystore password can be supplied through an environment variable.
  - Owner-only file permissions are neither enforced nor checked on file systems without POSIX permissions (e.g. Windows).
  - The active key is chosen by wall-clock creation time, so clock skew can keep a retired or compromised key in use after rotation.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SecureDataCrypto.java` | The whole application: AES-256-GCM envelope cipher (`DataCipher`), PKCS#12 key store and lifecycle (`KeyStoreManager`), password sourcing (`Passwords`), file I/O helpers (`SecureFiles`), CLI parsing and commands, built-in self-test | Symmetric encryption, IV/RNG handling, AAD binding; key generation, storage, rotation and deletion; keystore password-based protection (PBKDF via JDK PKCS12); password from file, env var or console; memory wiping; temp-file creation, permissions and atomic rename; input size limits; error messages |
| `README.md` | Documentation of commands, key-management design, ciphertext format, limitations | Documents the security assumptions checked against the code (e.g. "mode 600" output files, the env-var password risk, no coordination between concurrent key operations) |
| `prompt.txt` | The task prompt used to generate the code | None (not code) |
| `cyber_prompt.txt` | The instructions for this review | None (not code) |
| `result.md`, `return.txt` | Metadata and summary from the generation run | None (not code); checked for embedded secrets, none found |
| `prompt_hash.txt` | Empty file | None |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: the router workflow. It covered understanding the code, picking specialised skills by name and description, applying them, and writing the report.
- `performing-cryptographic-audit-of-application` (with its `references/standards.md` and `references/workflows.md`): applied to every crypto touchpoint in `SecureDataCrypto.java`. That covered algorithm and mode choice, key sizes, hardcoded keys, RNG and entropy, KDF parameters (the PKCS#12 keystore protection, which gave SEC-01), key storage and rotation (SEC-05), and error handling.
- `implementing-aes-encryption-for-data-at-rest` (with `references/standards.md`, NIST SP 800-38D / SP 800-132): applied to `DataCipher`, checking GCM IV length and uniqueness, tag length, authenticated header, plaintext size limits and tamper detection. It was also applied to password-based key protection (iteration count and salt, SEC-01) and to key wiping.
- `testing-for-sensitive-data-exposure`: applied to how secrets are sourced (environment variable, SEC-03), secrets in source and docs, sensitive data in error output, and plaintext files written to disk (SEC-04).
- General OWASP Top 10 / CWE knowledge was used where no library skill fit a local CLI:
  - Race conditions and TOCTOU in keystore file updates (CWE-362/367, SEC-02). The `exploiting-race-condition-vulnerabilities` skill is for web requests, so only its TOCTOU concept carried over.
  - File permissions on non-POSIX file systems (CWE-276).
  - Command-line argument parsing, path handling and symlinks, resource limits (CWE-400), and logging and error handling (CWE-209).
  - Injection, deserialization, command execution, SQL and network/TLS were checked and do not apply (see section 6).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Keystore protection relies on weak/overridable JVM PBE defaults and a length-only password policy | Medium | CWE-916 | `SecureDataCrypto.java:281-285` |
| SEC-02 | Unlocked read-modify-write and check-then-create race on the keystore can destroy keys | Medium | CWE-367 | `SecureDataCrypto.java:796-804` |
| SEC-03 | Keystore password accepted from an environment variable | Low | CWE-526 | `SecureDataCrypto.java:466-470` |
| SEC-04 | Owner-only permissions not enforced or verified on non-POSIX file systems | Low | CWE-276 | `SecureDataCrypto.java:593-611` |
| SEC-05 | Active encryption key chosen by wall-clock creation time; a rotated-out key can remain active | Low | CWE-324 | `SecureDataCrypto.java:364-370` |

## 5. Detailed Findings

### SEC-01: Keystore protection relies on weak/overridable JVM PBE defaults and a length-only password policy
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `SecureDataCrypto.java:281-285`, `SecureDataCrypto.java:405-409`, `SecureDataCrypto.java:478-482`

**Vulnerable code:**
```java
// SecureDataCrypto.java:281-285
        private KeyStoreManager(Path path, KeyStore keyStore, char[] password) {
            this.path = path;
            this.keyStore = keyStore;
            this.protection = new KeyStore.PasswordProtection(password); // stores its own copy
        }

// SecureDataCrypto.java:405-409
        private void save() throws AppException {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try {
                keyStore.store(buffer, protection.getPassword());
            } catch (IOException | GeneralSecurityException e) {

// SecureDataCrypto.java:478-482
            if (newKeystore && password.length < MIN_NEW_PASSWORD_CHARS) {
                wipe(password);
                throw new KeyFailure("a new keystore password must be at least " + MIN_NEW_PASSWORD_CHARS
                        + " characters; generate one, e.g.: openssl rand -base64 32");
            }
```

**Why it is a problem:** Every AES data key is only as safe as the keystore password. That password is stretched by whatever PBE settings the running JVM uses, because the code never sets any.
- **JDK 17 defaults are weak.** The defaults in `java.security` are `keystore.pkcs12.keyPbeIterationCount=10000` and `keystore.pkcs12.macIterationCount=10000`, with PBKDF2-HMAC-SHA256. That is 60 times fewer iterations than the 600,000 that OWASP and the applied AES skill (NIST SP 800-132 guidance) recommend. The file MAC uses the same 10,000 iterations, so an attacker with a copy of `app-keys.p12` (from a backup, a leaked volume or a container image) can test password guesses cheaply against the MAC.
- **The defaults can be weakened.** Running with `-Dkeystore.pkcs12.legacy`, an edited `java.security`, or a JDK older than 11.0.12 / 8u301 switches silently to `PBEWithSHA1AndDESede` and `HmacPBESHA1`. The code only states "Requires Java 17+" in a comment and never checks it at runtime.
- **The password rule is weak.** A new keystore only needs 16 characters, so `passwordpassword` or `aaaaaaaaaaaaaaaa` is accepted from the prompt, the environment variable or a file. The README's advice to use a random password is not enforced.
- **Old settings persist.** When an existing keystore is re-saved, the JDK keeps the MAC settings and the already-encrypted entries it loaded. A weakly protected keystore therefore stays weak until it is migrated.

**Fix:**
- Set the entry protection algorithm and iteration count explicitly, with a fresh salt for each entry.
- Pin the MAC settings through overriding system properties, and refuse legacy mode.
- Require a password with real entropy, not just a minimum length.
- Migrate existing keystores by copying their entries into a new keystore created with these settings.

Note: no JDK was available during this review, so this snippet (like the other fixes) has not been compiled. Run `self-test` after applying it.
```java
import javax.crypto.spec.PBEParameterSpec;

        private static final String TYPE = "PKCS12";
        private static final String KEY_PBE = "PBEWithHmacSHA256AndAES_256";
        private static final int PBE_ITERATIONS = 600_000;

        /** Call before KeyStore.getInstance/store so JVM or java.security defaults cannot weaken the file. */
        private static void pinPkcs12Protection() throws KeyFailure {
            if (System.getProperty("keystore.pkcs12.legacy") != null) {
                throw new KeyFailure("refusing to use keystore.pkcs12.legacy (SHA-1/3DES protection)");
            }
            // System properties take precedence over java.security values.
            System.setProperty("keystore.pkcs12.macAlgorithm", "HmacPBESHA256");
            System.setProperty("keystore.pkcs12.macIterationCount", Integer.toString(PBE_ITERATIONS));
        }

        /** Fresh salt and explicit algorithm/iterations for every new secret-key entry. */
        private KeyStore.PasswordProtection entryProtection() {
            byte[] salt = new byte[20];
            RANDOM.nextBytes(salt);
            return new KeyStore.PasswordProtection(protection.getPassword(), KEY_PBE,
                    new PBEParameterSpec(salt, PBE_ITERATIONS));
        }

        // in generateKey(...)
                keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(key), entryProtection());

        // in Passwords.obtain(...): reject low-diversity passwords, not just short ones
            long distinct = CharBuffer.wrap(password).chars().distinct().count();
            if (newKeystore && (password.length < MIN_NEW_PASSWORD_CHARS || distinct < 10)) {
                wipe(password);
                throw new KeyFailure("new keystore password is too weak; generate one with: openssl rand -base64 32");
            }
```

### SEC-02: Unlocked read-modify-write and check-then-create race on the keystore can destroy keys
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `SecureDataCrypto.java:796-804`, `SecureDataCrypto.java:405-413`, `SecureDataCrypto.java:574-578`

**Vulnerable code:**
```java
// SecureDataCrypto.java:796-804
    private static int generateKey(Options options) throws AppException {
        Path keystore = options.keystorePath();
        boolean isNew = !Files.exists(keystore);
        char[] password = Passwords.obtain(options.path("--password-file"), isNew);
        try (KeyStoreManager manager = isNew
                ? KeyStoreManager.create(keystore, password)
                : KeyStoreManager.open(keystore, password)) {
            Passwords.wipe(password);
            String alias = manager.generateKey(options.values.get("--alias"));

// SecureDataCrypto.java:574-578
                try {
                    Files.move(tmp, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, absolute, StandardCopyOption.REPLACE_EXISTING);
                }
```

**Why it is a problem:** `generate-key` and `delete-key` load the whole keystore, change it in memory and then rename a new file over the old one with `REPLACE_EXISTING`. No lock is held, so the last writer wins. The atomic rename prevents a half-written file but not lost updates. Two failures follow:
1. **Check-then-create.** `isNew` is computed before the password is obtained, and that can mean waiting on an interactive prompt for as long as a person takes to type. If another process creates the keystore in that window, this process builds a new empty keystore and renames it over the real one. Every existing key is gone, and all data encrypted with them can no longer be decrypted. The same happens if the keystore path is a dangling symlink, for example when a secret volume is not yet mounted, because `Files.exists` returns false.
2. **Lost update.** Suppose `generate-key` (A) and `delete-key --alias data-key-1` (B) run at the same time. B loads the file, A saves `data-key-2`, and an `encrypt` run starts using `data-key-2`. Then B saves its older copy, which has no `data-key-2`. The ciphertexts made with `data-key-2` are now permanently undecryptable. The next `generate-key` creates a *different* key under the same alias `data-key-2`, so the failure looks like tampering (`decryption failed`). Multiple replicas or CI jobs sharing a keystore volume make this realistic. The README admits the gap, but nothing in the code prevents it.

This breaks the design promise that "keys are never overwritten" (`SecureDataCrypto.java:323`).

**Fix:** Hold an exclusive OS file lock from the existence check through load, modify and save. When creating a keystore, refuse to replace an existing file.
```java
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;

    static final class KeystoreLock implements AutoCloseable {
        private final FileChannel channel;
        private final FileLock lock;

        private KeystoreLock(FileChannel channel, FileLock lock) {
            this.channel = channel;
            this.lock = lock;
        }

        static KeystoreLock acquire(Path keystore) throws IoFailure {
            Path lockFile = keystore.toAbsolutePath().resolveSibling(keystore.getFileName() + ".lock");
            try {
                FileChannel ch = FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                return new KeystoreLock(ch, ch.lock()); // blocks until other key-management runs finish
            } catch (IOException e) {
                throw new IoFailure("cannot lock " + lockFile, e);
            }
        }

        @Override
        public void close() {
            try {
                lock.release();
                channel.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    private static int generateKey(Options options) throws AppException {
        Path keystore = options.keystorePath();
        try (KeystoreLock lock = KeystoreLock.acquire(keystore)) {
            boolean isNew = !Files.exists(keystore, LinkOption.NOFOLLOW_LINKS);
            char[] password = Passwords.obtain(options.path("--password-file"), isNew);
            try (KeyStoreManager manager = isNew
                    ? KeyStoreManager.create(keystore, password)
                    : KeyStoreManager.open(keystore, password)) {
                Passwords.wipe(password);
                // save() for a new keystore must use Files.move(tmp, absolute, ATOMIC_MOVE) WITHOUT
                // REPLACE_EXISTING so an existing keystore is never replaced by an empty one.
                String alias = manager.generateKey(options.values.get("--alias"));
                System.err.println("Generated AES-256 key '" + alias + "'; it is now the active encryption key.");
                return EXIT_OK;
            } finally {
                Passwords.wipe(password);
            }
        }
    }
    // deleteKey(...) must likewise wrap openExisting/deleteKey/save in KeystoreLock.acquire(keystore).
```

### SEC-03: Keystore password accepted from an environment variable
- **Severity:** Low
- **CWE:** CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable
- **Location:** `SecureDataCrypto.java:466-470`

**Vulnerable code:**
```java
// SecureDataCrypto.java:466-470
            String envPassword = System.getenv(ENV_PASSWORD);
            if (passwordFile != null) {
                password = readFile(passwordFile);
            } else if (envPassword != null && !envPassword.isEmpty()) {
                password = envPassword.toCharArray();
```

**Why it is a problem:** The master secret that unlocks every data key can come from `APP_CRYPTO_KEYSTORE_PASSWORD`. Environment variables can be read through `/proc/<pid>/environ` by the same user and by root. They are passed to every child process, show up in `docker inspect`, Kubernetes pod specs, crash reports and CI logs, and are often dumped by diagnostics tooling. In Java the value is also an immutable `String` that cannot be wiped, which undoes the `char[]` wiping used everywhere else. The README warns about this, but the code still accepts it silently, and it ranks above the interactive prompt.

**Fix:** Remove the env-var password path, or at least refuse it unless the operator opts in explicitly. Point operators to `APP_CRYPTO_KEYSTORE_PASSWORD_FILE`, e.g. a Docker/Kubernetes secret file or systemd `LoadCredential`.
```java
            char[] password;
            if (passwordFile != null) {
                password = readFile(passwordFile);
            } else {
                if (System.getenv(ENV_PASSWORD) != null) {
                    throw new KeyFailure(ENV_PASSWORD + " is not supported because environment variables leak to "
                            + "child processes and /proc; store the password in a file and set " + ENV_PASSWORD_FILE);
                }
                password = prompt(newKeystore);
            }
```

### SEC-04: Owner-only permissions not enforced or verified on non-POSIX file systems
- **Severity:** Low
- **CWE:** CWE-276: Incorrect Default Permissions
- **Location:** `SecureDataCrypto.java:593-611`

**Vulnerable code:**
```java
// SecureDataCrypto.java:593-611
        private static Path createOwnerOnlyTempFile(Path dir) throws IOException {
            if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(OWNER_ONLY);
                return Files.createTempFile(dir, ".sdc-", ".tmp", attr);
            }
            return Files.createTempFile(dir, ".sdc-", ".tmp");
        }

        static boolean isAccessibleByOthers(Path file) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
                return perms.contains(PosixFilePermission.GROUP_READ)
                        || perms.contains(PosixFilePermission.GROUP_WRITE)
                        || perms.contains(PosixFilePermission.OTHERS_READ)
                        || perms.contains(PosixFilePermission.OTHERS_WRITE);
            } catch (UnsupportedOperationException | IOException e) {
                return false;
            }
        }
```

**Why it is a problem:** Every write goes through `createOwnerOnlyTempFile`: the keystore, and also the **decrypted plaintext** from `decrypt --out`. On file systems without POSIX permissions, most importantly NTFS on Windows, the file is created with default permissions and inherits the parent directory's ACL. If the output directory is shared (e.g. `C:\shared\` or a network share), other users can read the keystore or the decrypted customer data. The README says "Output files are created with mode 600". The check fails open as well: `isAccessibleByOthers` returns `false` when permissions cannot be read, so no warning appears. The self-test assertion that "keystore file is readable by other users" also passes without actually checking anything on those platforms.

**Fix:** On ACL file systems, create the file with an owner-only ACL. Refuse to write secrets where neither POSIX nor ACL permissions are available. When permissions cannot be checked, warn instead of reporting the file as safe.
```java
        private static Path createOwnerOnlyTempFile(Path dir) throws IOException {
            Set<String> views = dir.getFileSystem().supportedFileAttributeViews();
            if (views.contains("posix")) {
                return Files.createTempFile(dir, ".sdc-", ".tmp", PosixFilePermissions.asFileAttribute(OWNER_ONLY));
            }
            if (views.contains("acl")) {
                UserPrincipal owner = dir.getFileSystem().getUserPrincipalLookupService()
                        .lookupPrincipalByName(System.getProperty("user.name"));
                AclEntry ownerOnly = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner)
                        .setPermissions(EnumSet.allOf(AclEntryPermission.class)).build();
                FileAttribute<List<AclEntry>> acl = new FileAttribute<>() {
                    @Override
                    public String name() {
                        return "acl:acl";
                    }

                    @Override
                    public List<AclEntry> value() {
                        return List.of(ownerOnly);
                    }
                };
                return Files.createTempFile(dir, ".sdc-", ".tmp", acl);
            }
            throw new IOException("refusing to write secrets to " + dir + ": owner-only permissions are not supported");
        }

        static void warnIfAccessibleByOthers(Path file) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
                if (perms.contains(PosixFilePermission.GROUP_READ) || perms.contains(PosixFilePermission.GROUP_WRITE)
                        || perms.contains(PosixFilePermission.OTHERS_READ) || perms.contains(PosixFilePermission.OTHERS_WRITE)) {
                    System.err.println("WARNING: " + file + " is accessible by other users; run: chmod 600 " + file);
                }
            } catch (UnsupportedOperationException | IOException e) {
                System.err.println("WARNING: cannot verify that " + file + " is readable only by its owner");
            }
        }
```

### SEC-05: Active encryption key chosen by wall-clock creation time; a rotated-out key can remain active
- **Severity:** Low
- **CWE:** CWE-324: Use of a Key Past its Expiration Date
- **Location:** `SecureDataCrypto.java:364-370`, `SecureDataCrypto.java:384-390`, `SecureDataCrypto.java:808`

**Vulnerable code:**
```java
// SecureDataCrypto.java:364-370
                Map<String, Date> created = new HashMap<>();
                for (String alias : result) {
                    created.put(alias, keyStore.getCreationDate(alias));
                }
                result.sort(Comparator.comparing((String a) -> created.get(a))
                        .thenComparing(KeyStoreManager::aliasOrder));
                return result;

// SecureDataCrypto.java:384-390
        String activeAlias() throws KeyFailure {
            List<String> aliases = aliases();
            if (aliases.isEmpty()) {
                throw new KeyFailure("keystore " + path + " contains no keys (run: generate-key)");
            }
            return aliases.get(aliases.size() - 1);
        }

// SecureDataCrypto.java:808
            System.err.println("Generated AES-256 key '" + alias + "'; it is now the active encryption key.");
```

**Why it is a problem:** The "active" key for all new encryptions is whichever entry has the latest creation timestamp. The JDK PKCS#12 keystore records that timestamp from the local wall clock when the entry is added. Rotation can therefore fail without any error:
- the new key is generated on a host whose clock is behind the host that made the previous key (e.g. keystore copied between machines or containers);
- the clock was stepped backwards by NTP or a VM snapshot restore;
- two keys get the same millisecond and a custom `--alias` sorts lower.

In each case the new key is *not* active. The program still prints "it is now the active encryption key", and `encrypt` keeps using the old key. If that old key was rotated out because it was compromised, new sensitive data continues to be encrypted under the compromised key.

**Fix:** Don't trust the clock when rotating. Before storing a new key, reject it if its timestamp is not strictly later than every existing key's. After generating, confirm the new key really is active. (A sturdier alternative is to store an explicit, monotonically increasing key version or "active" marker.)
```java
        String generateKey(String alias) throws AppException {
            if (alias == null) {
                alias = nextDefaultAlias();
            }
            if (!DataCipher.isValidKeyId(alias)) {
                throw new UsageFailure("alias must match [a-z0-9][a-z0-9._-]{0,63}: " + alias);
            }
            try {
                if (keyStore.containsAlias(alias)) {
                    throw new KeyFailure("key '" + alias + "' already exists; keys are never overwritten");
                }
                Date now = new Date();
                for (String existing : aliases()) {
                    if (!now.after(keyStore.getCreationDate(existing))) {
                        throw new KeyFailure("system clock is not later than the creation time of key '" + existing
                                + "'; refusing to add a key that would not become the active key");
                    }
                }
                SecretKey key = DataCipher.generateKey();
                keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(key), protection);
                if (!activeAlias().equals(alias)) {
                    keyStore.deleteEntry(alias);
                    throw new KeyFailure("new key '" + alias + "' did not become the active key; keystore not saved");
                }
            } catch (KeyStoreException e) {
                throw new KeyFailure("cannot add key to keystore", e);
            }
            save();
            return alias;
        }
```

## 6. Verified Controls and Checks With No Finding
- Cipher, mode and padding: `AES/GCM/NoPadding` with 256-bit keys and a 128-bit tag (`SecureDataCrypto.java:157-160`). No ECB, CBC without MAC, DES, 3DES, RC4, MD5 or SHA-1 anywhere in the code.
- IV and nonce handling: a fresh 12-byte IV from a shared `SecureRandom` for every encryption (`SecureDataCrypto.java:71`, `184-185`). No IV reuse, no predictable or time-based seeds.
- Key generation: `KeyGenerator.getInstance("AES").init(256, RANDOM)` (`SecureDataCrypto.java:171-179`). Keys are never derived from a password and never hardcoded.
- Authenticated header: the version byte and key ID are passed as AAD on both encrypt and decrypt (`SecureDataCrypto.java:189`, `222`). Swapping the key ID or version, truncating the data or flipping a bit is detected, and the self-test checks this (`SecureDataCrypto.java:956-975`).
- Envelope parsing: length checks before indexing, an unsigned key-ID length, and a minimum size covering IV and tag (`SecureDataCrypto.java:199-210`). The version is checked strictly, so there is no downgrade. The key ID is validated against `[a-z0-9][a-z0-9._-]{0,63}` before it is looked up or put in any message (`SecureDataCrypto.java:162`, `211-214`). This pattern is lowercase-only, matching the PKCS#12 keystore's case-insensitive aliases.
- Key type and size: `requireAes256` rejects non-AES keys and keys that aren't 256 bits, and wipes the encoded copy (`SecureDataCrypto.java:241-253`).
- Generic errors: `AEADBadTagException` gives one vague message (`SecureDataCrypto.java:224-226`). `main` prints only `getMessage()`, never stack traces (`SecureDataCrypto.java:733-740`). No plaintext, key material or password ever appears in an error message.
- Hardcoded secrets: none in the source or docs. `card=4111 1111 1111 1111` in the self-test (`SecureDataCrypto.java:941`) is the standard public test card number. The self-test keystore password is random (`SecureDataCrypto.java:988-990`).
- Passwords never come from command-line arguments. The option parser only accepts allow-listed flags for each command (`SecureDataCrypto.java:665-689`, `749-756`). The console prompt uses `Console.readPassword` without echo and asks for confirmation when creating a keystore (`SecureDataCrypto.java:523-543`).
- Password file handling: must be a regular file, at most 4 KiB, strict UTF-8 decoding, trailing newline stripped, raw bytes and decoder buffer wiped in `finally` (`SecureDataCrypto.java:486-521`).
- Keys are never overwritten by alias: `containsAlias` is checked before `setEntry` (`SecureDataCrypto.java:322-324`), apart from the concurrency gap in SEC-02. Key deletion needs an explicit `--yes` (`SecureDataCrypto.java:875-878`).
- Atomic, owner-only writes on POSIX: the temp file is created with `O_EXCL` semantics and mode `rw-------` in the target directory, then renamed into place. The rename replaces a symlink at the target rather than following it, and the temp file is cleaned up if the write fails (`SecureDataCrypto.java:564-599`).
- Resource limits: input is capped at 64 MiB and checked while reading (`SecureDataCrypto.java:68`, `620-637`). That is far below the GCM limit of 2^39−256 bits per message.
- Memory hygiene: plaintext buffers and password arrays are wiped in `finally` blocks, and `PasswordProtection` is destroyed on close (`SecureDataCrypto.java:432-440`, `843-845`, `863-865`). Cached `SecretKey` objects cannot be destroyed in the JDK; the README notes this as a limitation of Java. No finding was raised because the process holds the keys only for the length of one command.
- Not present, so not applicable: SQL or database access, OS command execution, Java deserialization (`serialVersionUID` exists only on exception classes, and nothing is read with `ObjectInputStream`), XML parsing, network calls or TLS, web output or XSS, JWT or sessions, and reflection or dynamic class loading.
- Out of scope for code fixes: crypto-shredding with `delete-key` only removes the key from the current keystore file. Backups and older file copies still hold it under the same password, which ties back to the key-protection strength in SEC-01. The design is otherwise consistent with the README's advice to use a KMS or HSM for stronger guarantees.
