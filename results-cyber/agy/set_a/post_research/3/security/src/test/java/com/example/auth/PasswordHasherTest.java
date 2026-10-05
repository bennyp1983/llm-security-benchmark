package com.example.auth;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {

    @Test
    void testHashAndVerifySuccess() {
        PasswordHasher hasher = new PasswordHasher();
        char[] password = "CorrectHorseBatteryStaple!2026".toCharArray();

        HashResult result = hasher.hashPassword(password);

        assertNotNull(result);
        assertEquals(PasswordHasher.ALGORITHM, result.algorithm());
        assertEquals(PasswordHasher.DEFAULT_ITERATIONS, result.iterations());
        assertEquals(16, Base64.getDecoder().decode(result.saltBase64()).length);
        assertEquals(32, Base64.getDecoder().decode(result.hashBase64()).length);

        // Verification with correct password
        char[] candidate = "CorrectHorseBatteryStaple!2026".toCharArray();
        boolean matches = hasher.verifyPassword(candidate, result.saltBase64(), result.iterations(), result.hashBase64());
        assertTrue(matches);

        // Verification with wrong password
        char[] wrong = "WrongPassword#12345".toCharArray();
        boolean wrongMatches = hasher.verifyPassword(wrong, result.saltBase64(), result.iterations(), result.hashBase64());
        assertFalse(wrongMatches);
    }

    @Test
    void testVerifyFailsOnCorruptedData() {
        PasswordHasher hasher = new PasswordHasher();
        char[] password = "SecretPassword123!".toCharArray();
        HashResult result = hasher.hashPassword(password);

        // Corrupted Base64
        assertFalse(hasher.verifyPassword(password, "not-valid-base64!", result.iterations(), result.hashBase64()));
        assertFalse(hasher.verifyPassword(password, result.saltBase64(), result.iterations(), "not-valid-base64!"));

        // Null inputs
        assertFalse(hasher.verifyPassword(password, null, result.iterations(), result.hashBase64()));
        assertFalse(hasher.verifyPassword(password, result.saltBase64(), result.iterations(), null));

        // Tampered iteration count
        assertFalse(hasher.verifyPassword(password, result.saltBase64(), 500, result.hashBase64()));
    }

    @Test
    void testVerifyDummyPasswordAlwaysReturnsFalse() {
        PasswordHasher hasher = new PasswordHasher();
        char[] candidate = "someCandidatePassword".toCharArray();

        boolean result = hasher.verifyDummyPassword(candidate);
        assertFalse(result);

        // Even with null or empty
        assertFalse(hasher.verifyDummyPassword(null));
        assertFalse(hasher.verifyDummyPassword(new char[0]));
    }

    @Test
    void testSaltsAreGloballyUnique() {
        PasswordHasher hasher = new PasswordHasher();
        char[] pwd1 = "SamePassword123!".toCharArray();
        char[] pwd2 = "SamePassword123!".toCharArray();

        HashResult res1 = hasher.hashPassword(pwd1);
        HashResult res2 = hasher.hashPassword(pwd2);

        // Salts must be cryptographically distinct
        assertNotEquals(res1.saltBase64(), res2.saltBase64());
        // Consequently, PBKDF2 hashes must also be distinct
        assertNotEquals(res1.hashBase64(), res2.hashBase64());
    }
}
