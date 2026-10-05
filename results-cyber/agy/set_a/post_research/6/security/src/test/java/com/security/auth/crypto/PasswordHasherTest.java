package com.security.auth.crypto;

import com.security.auth.model.AccountStatus;
import com.security.auth.model.UserRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("PasswordHasher Security & Cryptographic Tests (Rule 6 & Rule 8)")
class PasswordHasherTest {

    // Use 10,000 iterations for swift test execution while testing actual PBKDF2 logic
    private final Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(10_000);

    @Test
    @DisplayName("Should successfully hash and verify matching password")
    void testHashAndVerifySuccess() {
        char[] password = "SecureCorrectPassword123!".toCharArray();
        byte[] salt = hasher.generateSalt(16);
        byte[] hash = hasher.hashPassword(password, salt, 10_000);

        UserRecord record = new UserRecord("testuser", hash, salt, 10_000, Pbkdf2PasswordHasher.ALGORITHM, AccountStatus.ACTIVE);

        assertTrue(hasher.verifyPassword(password, record));
    }

    @Test
    @DisplayName("Should fail verification on incorrect password")
    void testVerifyIncorrectPassword() {
        char[] correctPassword = "SecureCorrectPassword123!".toCharArray();
        char[] wrongPassword = "WrongPassword999!".toCharArray();
        byte[] salt = hasher.generateSalt(16);
        byte[] hash = hasher.hashPassword(correctPassword, salt, 10_000);

        UserRecord record = new UserRecord("testuser", hash, salt, 10_000, Pbkdf2PasswordHasher.ALGORITHM, AccountStatus.ACTIVE);

        assertFalse(hasher.verifyPassword(wrongPassword, record));
    }

    @Test
    @DisplayName("Should generate unique cryptographic salts using SecureRandom")
    void testUniqueSalts() {
        byte[] salt1 = hasher.generateSalt(16);
        byte[] salt2 = hasher.generateSalt(16);

        assertEquals(16, salt1.length);
        assertEquals(16, salt2.length);
        assertFalse(Arrays.equals(salt1, salt2));
    }

    @Test
    @DisplayName("Should execute dummy verification without exception for null or dummy input")
    void testDummyVerificationExecution() {
        assertDoesNotThrow(() -> hasher.performDummyVerification("SomePassword".toCharArray()));
        assertDoesNotThrow(() -> hasher.performDummyVerification(null));
        assertDoesNotThrow(() -> hasher.performDummyVerification(new char[0]));
    }

    @Test
    @DisplayName("Should fail closed when input password or record is null")
    void testFailClosedOnNulls() {
        byte[] salt = hasher.generateSalt(16);
        byte[] hash = hasher.hashPassword("password123".toCharArray(), salt, 10_000);
        UserRecord record = new UserRecord("testuser", hash, salt, 10_000, Pbkdf2PasswordHasher.ALGORITHM, AccountStatus.ACTIVE);

        assertFalse(hasher.verifyPassword(null, record));
        assertFalse(hasher.verifyPassword("password123".toCharArray(), null));
    }
}
