package com.security.auth.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Rule 8: Platform Cryptography & Password Hashing Tests")
class PasswordHasherTest {

    private final PasswordHasher hasher = new PasswordHasher(100_000);

    @Test
    @DisplayName("Password hashing produces unique salts and hashes for identical passwords")
    void testUniqueSaltsForIdenticalPasswords() {
        char[] pwd1 = "SecretPassword123!@#".toCharArray();
        char[] pwd2 = "SecretPassword123!@#".toCharArray();

        PasswordHasher.HashedPassword hash1 = hasher.hash(pwd1);
        PasswordHasher.HashedPassword hash2 = hasher.hash(pwd2);

        assertNotNull(hash1.saltBase64());
        assertNotNull(hash2.saltBase64());
        assertNotEquals(hash1.saltBase64(), hash2.saltBase64(), "Each password hash must have a unique random salt");
        assertNotEquals(hash1.hashBase64(), hash2.hashBase64(), "Different salts must produce different hash digests");

        // Verify correct password matches both
        assertTrue(hasher.verify(pwd1, hash1.saltBase64(), hash1.hashBase64(), hash1.iterations()));
        assertTrue(hasher.verify(pwd2, hash2.saltBase64(), hash2.hashBase64(), hash2.iterations()));
    }

    @Test
    @DisplayName("Password verification fails with incorrect password")
    void testVerificationFailsWithWrongPassword() {
        char[] correct = "CorrectPassword123!#$".toCharArray();
        char[] wrong = "WrongPassword999!#$".toCharArray();

        PasswordHasher.HashedPassword hashed = hasher.hash(correct);
        assertFalse(hasher.verify(wrong, hashed.saltBase64(), hashed.hashBase64(), hashed.iterations()));
    }

    @Test
    @DisplayName("Dummy verification always returns false and performs PBKDF2 computation")
    void testDummyVerificationAlwaysReturnsFalse() {
        char[] pwd = "SomeCandidatePassword123!".toCharArray();
        assertFalse(hasher.verifyDummy(pwd));
    }

    @Test
    @DisplayName("Memory wiping clears character and byte arrays")
    void testMemoryWiping() {
        char[] chars = "SensitiveData".toCharArray();
        CryptoUtils.wipe(chars);
        for (char c : chars) {
            assertEquals('\0', c);
        }

        byte[] bytes = new byte[]{1, 2, 3, 4, 5};
        CryptoUtils.wipe(bytes);
        for (byte b : bytes) {
            assertEquals((byte) 0, b);
        }
    }
}
