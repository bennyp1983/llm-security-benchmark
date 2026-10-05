package com.example.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;

import com.example.crypto.SymmetricCrypto.CryptoException;
import com.example.crypto.SymmetricCrypto.KeySource;

/**
 * End-to-end walk-through of {@link SymmetricCrypto}: raw-key sealing, passphrase sealing, the
 * IV-uniqueness property, and the additional-authenticated-data binding.
 */
public final class Demo {

    public static void main(String[] args) throws Exception {
        System.exit(run(System.out));
    }

    static int run(java.io.PrintStream out) throws CryptoException {
        SymmetricCrypto crypto = new SymmetricCrypto();
        String secret = "postgres://app_user:S3cr3t-Passw0rd@db.internal:5432/billing";

        out.println("AES/" + SymmetricCrypto.AES_KEY_BITS + "-GCM symmetric encryption demo");
        out.println("plaintext : " + secret);
        out.println();

        // 1. A raw 256-bit key: what a service would hold in a secret manager.
        SecretKey key = SymmetricCrypto.newKey();
        KeySource raw = KeySource.of(key);
        String token = crypto.encryptToBase64(raw, secret, null);
        out.println("[raw AES key]");
        out.println("  key (base64) : " + Base64.getEncoder().encodeToString(key.getEncoded()));
        out.println("  ciphertext   : " + token);
        out.println("  envelope     : " + crypto.encrypt(raw, secret, null).length + " bytes for "
                + secret.length() + " bytes of plaintext (4 magic + 2 header + 12 IV + 16 tag)");
        out.println("  decrypted    : " + crypto.decryptBase64(raw, token, null));
        out.println();

        // 2. The same data sealed with a passphrase. PBKDF2 salt and work factor travel in the
        //    envelope, so decryption needs the passphrase and nothing else.
        char[] password = "correct horse battery staple".toCharArray();
        KeySource derived = KeySource.of(password, SymmetricCrypto.DEFAULT_PBKDF2_ITERATIONS);
        String passToken = crypto.encryptToBase64(derived, secret, null);
        out.println("[passphrase + PBKDF2-HmacSHA256]");
        out.println("  ciphertext   : " + shorten(passToken));
        out.println("  decrypted    : " + crypto.decryptBase64(derived, passToken, null));
        out.println("  salted twice : " + (crypto.encryptToBase64(derived, secret, null)
                .equals(crypto.encryptToBase64(derived, secret, null)) ? "same output (broken!)" : "different output"));
        SymmetricCrypto.wipe(password);
        out.println();

        // 3. Fresh IV per call, so equal plaintexts never produce equal ciphertexts.
        byte[] first = crypto.encrypt(raw, secret, null);
        byte[] second = crypto.encrypt(raw, secret, null);
        out.println("[IV uniqueness]");
        out.println("  two encryptions of the same data identical? "
                + (Arrays.equals(first, second) ? "yes (would leak equality)" : "no"));
        out.println("  both decrypt to the original?             "
                + (Arrays.equals(crypto.decrypt(raw, first, null), crypto.decrypt(raw, second, null))
                        ? "yes" : "no"));
        out.println();

        // 4. AAD binds a ciphertext to the record it belongs to, so a token copied between config
        //    keys is rejected instead of silently decrypting.
        String aad = "billing.database-url";
        String bound = crypto.encryptToBase64(raw, secret, aad);
        out.println("[authenticated context (AAD)]");
        out.println("  sealed for '" + aad + "' -> " + shorten(bound));
        out.println("  opened with same context : " + crypto.decryptBase64(raw, bound, aad));
        try {
            crypto.decryptBase64(raw, bound, "billing.replica-url");
            out.println("  opened with wrong context: UNEXPECTED SUCCESS");
            return 1;
        } catch (CryptoException e) {
            out.println("  opened with wrong context: rejected (" + e.getMessage() + ")");
        }
        out.println();

        // 5. Binary payloads round trip byte for byte.
        byte[] binary = new byte[4096];
        for (int i = 0; i < binary.length; i++) {
            binary[i] = (byte) i;
        }
        byte[] binaryToken = crypto.encrypt(raw, binary, "attachment".getBytes(StandardCharsets.UTF_8));
        byte[] back = crypto.decrypt(raw, binaryToken, "attachment".getBytes(StandardCharsets.UTF_8));
        out.println("[binary payload]");
        out.println("  4096 bytes -> " + binaryToken.length + " bytes -> " + back.length
                + " bytes, identical: " + Arrays.equals(binary, back));
        return 0;
    }

    private static String shorten(String token) {
        return token.length() <= 72 ? token : token.substring(0, 72) + "...(" + token.length() + " chars)";
    }

    private Demo() {
    }
}
