package com.example.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Checks the properties the design depends on: round-trip correctness, unique IVs, and
 * rejection of altered ciphertext, altered headers, mismatched associated data and wrong keys.
 * Run with {@code java com.example.crypto.Main selftest}.
 */
final class SelfTest {

    /** In-memory key source, so the self-test needs no keystore or environment set-up. */
    private record FixedKey(SecretKey key) implements KeyProvider {
        @Override public String id() { return "fixed:selftest"; }
        @Override public byte[] newParameters() { return new byte[0]; }
        @Override public SecretKey resolve(byte[] parameters) { return key; }
    }

    private static int failures = 0;

    static void run() throws Exception {
        SymmetricCipher cipher = new SymmetricCipher(new FixedKey(randomKey()));
        byte[] plaintext = "card=4111111111111111;cvv=737".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "account-42".getBytes(StandardCharsets.UTF_8);

        byte[] envelope = cipher.encrypt(plaintext, aad);
        check("round-trip", Arrays.equals(plaintext, cipher.decrypt(envelope, aad)));
        check("ciphertext differs from plaintext", indexOf(envelope, plaintext) < 0);

        byte[] second = cipher.encrypt(plaintext, aad);
        check("same plaintext encrypts differently", !Arrays.equals(envelope, second));

        check("empty plaintext", cipher.decrypt(cipher.encrypt(new byte[0], null), null).length == 0);

        byte[] large = new byte[1 << 20];
        new java.security.SecureRandom().nextBytes(large);
        check("1 MiB round-trip", Arrays.equals(large, cipher.decrypt(cipher.encrypt(large, null), null)));

        byte[] flippedTag = envelope.clone();
        flippedTag[flippedTag.length - 1] ^= 0x01;
        checkRejected("modified tag", cipher, flippedTag, aad);

        byte[] flippedBody = envelope.clone();
        flippedBody[envelope.length - 20] ^= 0x01;
        checkRejected("modified ciphertext", cipher, flippedBody, aad);

        byte[] flippedIv = envelope.clone();
        flippedIv[10] ^= 0x01; // inside the IV, which the header AAD covers
        checkRejected("modified IV", cipher, flippedIv, aad);

        checkRejected("wrong associated data", cipher, envelope,
                "account-43".getBytes(StandardCharsets.UTF_8));
        checkRejected("missing associated data", cipher, envelope, null);

        SymmetricCipher other = new SymmetricCipher(new FixedKey(randomKey()));
        checkRejected("wrong key", other, envelope, aad);

        checkRejected("truncated envelope", cipher, Arrays.copyOf(envelope, envelope.length - 4), aad);
        checkRejected("garbage input", cipher, new byte[] {1, 2, 3}, aad);

        if (failures == 0) {
            System.out.println("selftest: all checks passed");
        } else {
            System.out.println("selftest: " + failures + " check(s) FAILED");
            System.exit(1);
        }
    }

    private static SecretKey randomKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(SymmetricCipher.KEY_BITS);
        return generator.generateKey();
    }

    private static void checkRejected(String name, SymmetricCipher cipher, byte[] envelope, byte[] aad) {
        try {
            cipher.decrypt(envelope, aad);
            check(name + " rejected", false);
        } catch (AEADBadTagException e) {
            check(name + " rejected", true);
        } catch (GeneralSecurityException e) {
            check(name + " rejected", true);
        }
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + name);
        if (!ok) {
            failures++;
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private SelfTest() {}
}
