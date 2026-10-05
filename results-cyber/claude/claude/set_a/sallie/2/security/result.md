## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 14944985-be5a-4a9c-aa3d-d52951977c4c
- **Input tokens:** 226
- **Output tokens:** 10516
- **Thinking tokens:** 1331
- **Cached read tokens:** 135127
- **Cache creation tokens:** 17009
- **Total tokens:** 10742
- **Duration:** 2m 4.531s
- **Turns:** 11

---

I wrote the program and a plain-English README. It compiles on Java 17 with no warnings, and all my tests passed.

**Files**
- `PiiEncryptor.java`: the program
- `README.md`: how it works, how to set up the key, how to run it, and its limits

**How it works**
- It uses **AES-256 in GCM mode**. This mode also catches tampering: if the data was changed or the key is wrong, decryption fails with an error. Each encryption uses a new random 12-byte IV, so the same input gives different output every time.
- **The key is not in the code.** It is read at startup from a file named by the `PII_ENCRYPTION_KEY_FILE` environment variable, or else from `PII_ENCRYPTION_KEY`. If neither is set, the program stops with an error; there is no built-in fallback key. `java PiiEncryptor --generate-key` creates a new random key.
- The name and email are typed in when the program asks for them, or piped in. They are deliberately not taken as command-line arguments, because those can show up in shell history and in process lists.
- Each encrypted value is tied to its field, so an encrypted email can't be decrypted as a name.
- It does basic checks on the input: the name can't be empty, the email must look like an email address, and both have a length limit.

**Tests I ran**
- **Encrypt and decrypt:** worked with the key in an environment variable and in a key file. Names with accents were recovered correctly.
- **Bad key setup:** a missing key, a key that isn't valid Base64, and a key of the wrong size (16 bytes) each gave a clear error.
- **Bad input:** an invalid email, an empty name, and a name and email passed as arguments were all rejected.
- **Tampering:** a separate test showed that changed data, the wrong key, the wrong field, too-short input and non-Base64 input all fail to decrypt. The same input also gave different encrypted output each time.

I ran the tests from a temporary folder that I've since deleted, along with the test key, so only the two files above were added.

**Worth knowing**
- On this machine, accented letters showed as `?` on screen because the terminal's language setting is empty. The data itself came back correctly; only the display was affected. The README covers this.
- As requested, the program prints the decrypted name and email. A real application should store the encrypted values and not print personal data; the README says this too.
