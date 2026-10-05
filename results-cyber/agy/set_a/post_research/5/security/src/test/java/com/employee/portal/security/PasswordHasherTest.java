package com.employee.portal.security;

import com.employee.portal.security.crypto.PasswordHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Rule 8 & 6: PBKDF2 Hashing and Timing Resistance Tests")
class PasswordHasherTest {

    private PasswordHasher hasher;

    @BeforeEach
    void setUp() {
        // Use 100,000 iterations in unit test for swift execution while preserving cryptographic depth
        hasher = new PasswordHasher(100000, 32, 256);
    }

    @Test
    void testPasswordHashAndVerificationSuccess() {
        char[] password = "CorrectHorseBatteryStaple#2026".toCharArray();
        byte[] salt = hasher.generateSalt();
        byte[] hash = hasher.hashPassword(password, salt);

        assertNotNull(salt);
        assertEquals(32, salt.length);
        assertNotNull(hash);
        assertEquals(32, hash.length);

        assertTrue(hasher.verifyPassword(password, salt, hash, 100000));
    }

    @Test
    void testPasswordVerificationFailureOnWrongPassword() {
        char[] correctPassword = "CorrectHorseBatteryStaple#2026".toCharArray();
        char[] wrongPassword = "WrongPassword#9999999999".toCharArray();
        byte[] salt = hasher.generateSalt();
        byte[] hash = hasher.hashPassword(correctPassword, salt);

        assertFalse(hasher.verifyPassword(wrongPassword, salt, hash, 100000));
    }

    @Test
    void testSaltUniquenessProducesDifferentHashes() {
        char[] password = "SharedEmployeePassword#2026".toCharArray();
        byte[] salt1 = hasher.generateSalt();
        byte[] salt2 = hasher.generateSalt();

        assertFalse(Arrays.equals(salt1, salt2));

        byte[] hash1 = hasher.hashPassword(password, salt1);
        byte[] hash2 = hasher.hashPassword(password, salt2);

        assertFalse(Arrays.equals(hash1, hash2));
    }

    @Test
    void testDummyVerificationExecutesCleanly() {
        char[] testPwd = "TestingTimingDummy#123".toCharArray();
        assertDoesNotThrow(() -> hasher.dummyVerify(testPwd));
    }

    @Test
    void testDummyVerificationHandlesNullSafely() {
        assertDoesNotThrow(() -> hasher.dummyVerify(null));
    }
}
