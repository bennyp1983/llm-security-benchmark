## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 40844026-5ff8-4b3a-a56e-909b53f8d1d4
- **Input tokens:** 162
- **Output tokens:** 6555
- **Thinking tokens:** 597
- **Cached read tokens:** 87337
- **Cache creation tokens:** 12285
- **Total tokens:** 6717
- **Duration:** 1m 25.598s
- **Turns:** 7

---

I wrote the Java program and a plain-English README. It compiles with no warnings on Java 17 and correctly encrypts and decrypts a name and email address.

**Files**
- `PiiEncryptor.java`: the program.
- `README.md`: what the program does, what you need, how to run it, sample output, how it works step by step, what the error messages mean, and what to change before using it on real data.

**How it works**
- It uses AES with a 256-bit key in GCM mode, which both hides the data and detects tampering. A new random key is made each time the program runs.
- Each encryption uses a fresh random starting value (IV), so the same name gives different encrypted text every time. The output is the IV plus the encrypted data, as Base64 text.
- The name and email are each tagged with their field label ("name" or "email"). Swapping the two encrypted values makes decryption fail instead of returning the wrong field.
- You can run it with arguments (`java PiiEncryptor "Jane Doe" jane.doe@example.com`) or with none, and it will ask for the name and email. It rejects an empty name, an invalid email and the wrong number of arguments.

**Testing**
- Both ways of giving input decrypted back to the original name and email. That included a name with accented letters: they showed as `?` in this sandbox's terminal, but the program's own check confirmed the text was unchanged.
- All three error cases gave the right message and exit code.
- In a separate throwaway test, decryption was rejected for changed data, a swapped field label and the wrong key. Encrypting the same input twice gave different output.

**Limitation:** the key is thrown away when the program ends, so nothing it encrypts can be decrypted later. That's fine for a demo. For real use, the key needs to be kept in a proper key store, which the README explains.

The Google Drive connector needs authorizing in your claude.ai connector settings before it can be used, but this task didn't need it.
