## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** c3bb374a-6a25-4152-8883-7c641fe887ce
- **Input tokens:** 163101
- **Output tokens:** 51437
- **Thinking tokens:** 13604
- **Cached read tokens:** 1027172
- **Cache creation tokens:** 
- **Total tokens:** 214538
- **Duration:** 4m 5.509s
- **Turns:** 1

---

A complete, production-grade Java symmetric cryptography solution has been implemented and saved to [`SymmetricCryptoApp.java`](file:///data/results/agy/set_a/ruth/2/security/SymmetricCryptoApp.java), accompanied by full documentation in [`README.md`](file:///data/results/agy/set_a/ruth/2/security/README.md).

---

### Core Security & Cryptographic Highlights

1. **Algorithm & Mode**:
   - **AES-256 in Galois/Counter Mode (`AES/GCM/NoPadding`)**: An Authenticated Encryption with Associated Data (AEAD) scheme providing both confidentiality and data integrity/authenticity.
   - Eliminates padding oracle attacks and prevents ciphertext bit-flipping attacks.
   - Uses a 128-bit authentication tag that immediately throws an `AEADBadTagException` if ciphertext or metadata is modified or corrupted.

2. **IV / Nonce Management**:
   - Unique 96-bit (12-byte) IV generated per encryption using `SecureRandom.getInstanceStrong()`.
   - Protects against GCM nonce-reuse attacks.

3. **Cryptographic Key Management**:
   - **Generation**: Cryptographically strong 256-bit AES keys generated via Java's standard `KeyGenerator`.
   - **Storage (`PKCS12`)**: Keys are stored in an industry-standard, password-protected PKCS#12 KeyStore file (`.p12`) with POSIX owner-only file permissions (`0600`).
   - **Lifecycle & Rotation**: Keys are managed under distinct aliases (e.g. `dek-v1`, `dek-v2`), facilitating key rotation without data downtime.
   - **Key Derivation (PBKDF2)**: When deriving keys from user passphrases, uses `PBKDF2WithHmacSHA256` with 310,000 iterations (OWASP recommendation) and a 128-bit random salt.
   - **In-Memory Hygiene**: Passwords and raw key bytes are handled in `char[]` and `byte[]` arrays rather than immutable `String` objects, and explicitly wiped (`Arrays.fill(..., 0)`) after use.

4. **Additional Authenticated Data (AAD)**:
   - Supports binding contextual metadata (e.g., tenant ID, account number) to the ciphertext to prevent cut-and-paste / context-swapping attacks.

5. **Self-Describing Container**:
   - Bundles format version, salt/iterations (if password-derived), IV, and ciphertext + authentication tag into a single binary payload or Base64 string for easy storage and transport.

---

### Quick Start Guide

#### 1. Compile

```bash
javac -Xlint:all SymmetricCryptoApp.java
```

#### 2. Run the Automated Verification & Demo
The program includes an automated end-to-end self-test verifying key generation, PKCS#12 KeyStore storage, AES-GCM encryption/decryption, bit-tampering detection, AAD context binding, and PBKDF2 derivation:

```bash
java SymmetricCryptoApp demo
```

#### 3. CLI Workflow (KeyStore Mode)

```bash
# Initialize a PKCS#12 KeyStore
java SymmetricCryptoApp init-keystore -k app_keystore.p12 -p MasterPass123!

# Generate a 256-bit AES key inside the KeyStore
java SymmetricCryptoApp generate-key -k app_keystore.p12 -a app-dek -kp MasterPass123! -p KeySecret456!

# Encrypt sensitive text
CIPHERTEXT=$(java SymmetricCryptoApp encrypt -k app_keystore.p12 -a app-dek -kp MasterPass123! -p KeySecret456! -t "SSN: 000-12-3456")
echo "$CIPHERTEXT"

# Decrypt back to original plaintext
java SymmetricCryptoApp decrypt -k app_keystore.p12 -a app-dek -kp MasterPass123! -p KeySecret456! -t "$CIPHERTEXT"
```

#### 4. Password-Based Encryption Mode (PBKDF2)

```bash
# Encrypt
CIPHERTEXT=$(java SymmetricCryptoApp encrypt -p "StrongPassphrase#2026" -t "Confidential Financial Record")

# Decrypt
java SymmetricCryptoApp decrypt -p "StrongPassphrase#2026" -t "$CIPHERTEXT"
```

---

### Programmatic Integration Example

The implementation exposes clean Java services ([`KeyStoreManager`](file:///data/results/agy/set_a/ruth/2/security/SymmetricCryptoApp.java#L192-L335) and [`SymmetricEncryptionService`](file:///data/results/agy/set_a/ruth/2/security/SymmetricCryptoApp.java#L370-L515)) ready to be embedded directly into application code:

```java
import javax.crypto.SecretKey;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

// 1. Retrieve key from PKCS#12 KeyStore
char[] ksPassword = "MasterPassword123!".toCharArray();
char[] keyPassword = "KeyPassword456!".toCharArray();
SecretKey key = SymmetricCryptoApp.KeyStoreManager.loadKey(
    Paths.get("app_keystore.p12"), ksPassword, "customer-dek", keyPassword
);

// 2. Encrypt sensitive data with context binding (AAD)
SymmetricCryptoApp.SymmetricEncryptionService crypto = new SymmetricCryptoApp.SymmetricEncryptionService();
byte[] aadContext = "account_id:ACC-99201".getBytes(StandardCharsets.UTF_8);

String ciphertext = crypto.encryptString("Sensitive Customer Data", key, aadContext);

// 3. Decrypt and verify integrity
String plaintext = crypto.decryptString(ciphertext, key, aadContext);

// 4. Wipe credentials from memory
SymmetricCryptoApp.wipe(ksPassword);
SymmetricCryptoApp.wipe(keyPassword);
```

For complete technical specifications and CLI documentation, refer to the project [README.md](file:///data/results/agy/set_a/ruth/2/security/README.md).

