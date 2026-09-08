## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** d2f6863d-9383-435f-b43c-158ebc30ebcb
- **Input tokens:** 8
- **Output tokens:** 6669
- **Thinking tokens:** 353
- **Cached read tokens:** 57920
- **Cache creation tokens:** 13074
- **Total tokens:** 6677
- **Duration:** 1m 14.037s
- **Turns:** 4

---

`SecureData.java` — compiled and verified on JDK 17 (demo output and CLI roundtrips above).

**Design**
- **AES-256-GCM** (`AES/GCM/NoPadding`, 128-bit tag) — authenticated encryption, so tampering is detected rather than silently decrypted into garbage. Not ECB, not raw CBC.
- **Fresh random 96-bit IV per message** from `SecureRandom`; IV reuse under GCM is catastrophic, so it's never derived or fixed. The demo shows the same plaintext producing different ciphertext twice.
- **Self-describing message format**, Base64-wrapped: `[version][IV][ciphertext‖tag]` for raw-key mode, `[version][salt][IV][ciphertext‖tag]` for password mode. The version byte is passed as AAD, so it's covered by the tag.
- **Two key sources**: `generateKey()` for a random AES-256 key you store in a secret manager (`exportKey`/`importKey` handle Base64), and `deriveKey()` via PBKDF2-HMAC-SHA256 at 310k iterations with a per-message random salt for password-based use.
- Key and plaintext byte arrays are zeroed after use, and `PBEKeySpec.clearPassword()` is called.

**API**
```java
SecretKey key = SecureData.generateKey();
String sealed = SecureData.encrypt("card=4111...", key);
String opened = SecureData.decrypt(sealed, key);           // throws AEADBadTagException if altered

String pw = SecureData.encryptWithPassword("secret", password);
String out = SecureData.decryptWithPassword(pw, password);
```
Byte-array overloads exist for non-text payloads.

**CLI**
```
java SecureData keygen
java SecureData encrypt --key <base64-key> <plaintext>
java SecureData decrypt --key <base64-key> <base64-ciphertext>
java SecureData encrypt|decrypt --password <password> <input>
java SecureData demo
```

Two operational notes, not code bugs: passing keys or passwords as argv makes them visible in `ps` and shell history — for production use read them from an env var, a file, or `System.console().readPassword()`. And a single AES-GCM key should be rotated well before ~2³² messages, since IV-collision probability grows with message count.
