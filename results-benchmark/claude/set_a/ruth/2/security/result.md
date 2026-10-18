## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** d25dc278-07c2-4206-8d67-4afb7e1a7c7b
- **Input tokens:** 194
- **Output tokens:** 34610
- **Thinking tokens:** 12072
- **Cached read tokens:** 182960
- **Cache creation tokens:** 41785
- **Total tokens:** 34804
- **Duration:** 6m 42.256s
- **Turns:** 14

---

I wrote a Java program that encrypts and decrypts application data with AES-256-GCM, plus a README. It compiles with no warnings on JDK 17, and its built-in self-test passes. I also ran every command from the command line, including checks that tampered data, a wrong password and a too-short new password are all rejected.

**Files**
- `SecureDataCrypto.java`: the whole program in one file, using only the Java standard library.
- `README.md`: what the program does, how to compile and run it (with a full example and key rotation), how the key is handled, the ciphertext format, and limitations.

**How to run it**
```bash
javac -d out SecureDataCrypto.java
java -cp out SecureDataCrypto self-test
```
The commands are `generate-key`, `list-keys`, `encrypt`, `decrypt`, `delete-key` and `self-test`.

**How the key is handled**
- **Creation:** each key is a random 256-bit AES key from `KeyGenerator` and `SecureRandom`. Nothing is hardcoded or derived from a password, and an existing key is never overwritten.
- **Storage:** keys are kept in a password-protected PKCS#12 keystore file. The file is only readable by its owner and is saved in a way that can't leave it half-written. The program warns if the keystore or password file can be read by other users.
- **Unlocking:** the keystore password comes from a password file (recommended), an environment variable, or a hidden prompt. It is never taken as a command-line argument, and it is wiped from memory after use. A new keystore needs a password of at least 16 characters.
- **Rotation:** each ciphertext records which key encrypted it. New data uses the newest key, and older data still decrypts with its original key. Deleting a key requires `--yes`, because data encrypted with it can never be recovered.

**Encryption**
- A fresh random IV is used for every message, so the same plaintext encrypts differently each time.
- Changing any byte, cutting data off, or swapping in a different key ID makes decryption fail instead of returning garbage.
- Plaintext is read from stdin or a file, never from a command-line argument. Output files are also owner-only.

**Limitations** (also in the README)
- Each operation works in memory and is capped at 64 MiB.
- Wiping secrets from memory is only best effort in Java.
- Two key-management commands run at the same time on the same keystore can conflict.
- For production, keeping the main key in a cloud key service or hardware security module is stronger than a keystore file. The code has an interface where that can be plugged in.

**Other notes**
- The test files from my run are still in `/tmp/sdc`, including a test keystore and password; you can delete that folder.
- Google Drive is connected but not authorized, so it can't be used until you authorize it in your claude.ai connector settings. It wasn't needed for this task.
