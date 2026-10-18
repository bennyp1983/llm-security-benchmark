## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 5cf69dde-35e9-435b-8fef-49a1733479da
- **Input tokens:** 162
- **Output tokens:** 21256
- **Thinking tokens:** 5841
- **Cached read tokens:** 135730
- **Cache creation tokens:** 28650
- **Total tokens:** 21418
- **Duration:** 4m 0.443s
- **Turns:** 7

---

I wrote the program and its README. It compiles cleanly on OpenJDK 17 with all warnings turned on, and every command path I tested behaves correctly. The one exception is the interactive password prompt, which I couldn't try because this session has no terminal.

**Files**
- `SecureDataCrypto.java`: a single source file with no dependencies beyond the standard Java crypto libraries.
- `README.md`: explains what the program does, the encryption design and data format, how to compile and run it, how to call it from other code, and how to handle keys safely.

**How it works**
- **Encryption:** AES-256-GCM. Every encryption uses a new random 12-byte IV and a 128-bit authentication tag, so the output is both secret and tamper-evident. The version, mode and salt header is also protected by the tag.
- **Two ways to supply the key:**
  - **Key file:** `genkey` creates a random 256-bit key. It won't overwrite an existing file, and it sets owner-only (`0600`) permissions.
  - **Password:** the key is derived with PBKDF2-HMAC-SHA256 (600,000 iterations, a new random salt for each message). The password is typed at a hidden prompt or read from a file. It is never taken as a command-line argument, where it would show up in shell history.
- **Commands:** `genkey`, `encrypt`, `decrypt` and `demo`. Input comes from stdin or `--in`, and output goes to stdout or `--out`. Ciphertext is written as Base64 text.
- **Use from code:** `encrypt`/`decrypt`, `encryptWithPassword`/`decryptWithPassword`, `generateKey`, `saveKey` and `loadKey`. Every failure throws a `CryptoException`.

**What I tested**
- `demo` passes all its checks: data decrypts back to the original, the same input encrypts differently each time, and a changed byte, the wrong key or the wrong password are all rejected.
- From the command line:
  - A text round trip with a key file.
  - A 100 KB random binary file that decrypts byte-for-byte identical.
  - Empty input.
  - A round trip with a password file.
  - Created key and output files get `0600` permissions.
- Error cases all give a clear message and a non-zero exit code:
  - wrong key or wrong password
  - trying to overwrite an existing key file
  - using a key file on password-encrypted data
  - invalid Base64
  - truncated ciphertext
  - no key or password option given
  - asking for a password prompt when no terminal is available

To build and run:
```sh
javac SecureDataCrypto.java
java SecureDataCrypto demo
```

The whole input is held in memory, so the tool suits secrets, config values and moderately sized files rather than multi-gigabyte streams. The README says this too.
