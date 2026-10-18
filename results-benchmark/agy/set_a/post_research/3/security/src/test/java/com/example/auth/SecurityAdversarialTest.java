package com.example.auth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Adversarial test suite simulating real-world attack vectors against the authentication system.
 */
class SecurityAdversarialTest {

    private DatabaseManager dbManager;
    private AuthenticationService authService;

    @BeforeEach
    void setUp() {
        String uniqueDbUrl = "jdbc:h2:mem:adversarial_" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1";
        dbManager = new DatabaseManager(uniqueDbUrl, "sa", "");
        authService = new AuthenticationService(dbManager);
    }

    @AfterEach
    void tearDown() {
        dbManager.close();
    }

    @Test
    void testTimingInvarianceBetweenExistingAndNonExistentUsers() {
        // Register an existing user
        String existingEmail = "target.user@domain.com";
        char[] regPassword = "TargetValidPassword#2026".toCharArray();
        assertTrue(authService.registerUser(existingEmail, regPassword));

        // Measure time for existing user with wrong password
        long startExisting = System.nanoTime();
        authService.authenticate(existingEmail, "WrongPassword#1".toCharArray(), "bench-source-1");
        long durationExistingMs = (System.nanoTime() - startExisting) / 1_000_000;

        // Measure time for non-existent user
        long startNonExistent = System.nanoTime();
        authService.authenticate("nonexistent.user@domain.com", "WrongPassword#1".toCharArray(), "bench-source-2");
        long durationNonExistentMs = (System.nanoTime() - startNonExistent) / 1_000_000;

        // Both operations must have performed real PBKDF2 work (e.g. > 10ms),
        // preventing sub-millisecond enumeration of accounts!
        assertTrue(durationExistingMs > 5, "Existing user check should perform PBKDF2 work");
        assertTrue(durationNonExistentMs > 5, "Non-existent user check must perform dummy PBKDF2 work");

        // The difference in timing should not be orders of magnitude apart
        double ratio = (double) Math.max(durationExistingMs, durationNonExistentMs)
                / Math.max(1, Math.min(durationExistingMs, durationNonExistentMs));
        assertTrue(ratio < 4.0, "Timing ratio between existing and non-existent accounts must be comparable, actual ratio: " + ratio);
    }

    @Test
    void testAccountEnumerationResistanceAcrossAllFailureModes() {
        authService.registerUser("alice@company.com", "Password#12345".toCharArray());

        String[] testEmails = {
                "alice@company.com",           // existing user, wrong password
                "bob@company.com",             // non-existent user
                "invalid-format-email",        // invalid format
                "admin' OR '1'='1",            // SQL injection attempt
                "a@b.com"                      // another non-existent user
        };

        for (String testEmail : testEmails) {
            AuthenticationResult result = authService.authenticate(
                    testEmail,
                    "SomeAttemptPassword#1".toCharArray(),
                    "attacker-ip-" + UUID.randomUUID()
            );

            assertFalse(result.isSuccess(), "Attempt for " + testEmail + " should fail");
            assertEquals(AuthenticationResult.Status.INVALID_CREDENTIALS, result.getStatus(),
                    "Status must be identical for " + testEmail);
            assertEquals(AuthenticationResult.MSG_INVALID_CREDENTIALS, result.getUserMessage(),
                    "User message must be identical for " + testEmail);
        }
    }

    @Test
    void testCrlfInjectionNeutralizationInLogger() {
        String crlfPayload = "admin@victim.com\r\n[INFO] AUDIT [AUTH_SUCCESS] User=fakeadmin@victim.com Source=10.0.0.1";
        String sanitized = SecurityLogger.sanitizeCrlf(crlfPayload);

        assertFalse(sanitized.contains("\r"));
        assertFalse(sanitized.contains("\n"));
        assertTrue(sanitized.contains("_"));
    }

    @Test
    void testEmailMaskingProtectsPii() {
        assertEquals("a***e@e***e.com", SecurityLogger.maskEmail("alice@example.com"));
        assertEquals("b***b@d***n.org", SecurityLogger.maskEmail("bob@domain.org"));
        assertEquals("[EMPTY_EMAIL]", SecurityLogger.maskEmail(null));
        assertEquals("[MALFORMED_EMAIL]", SecurityLogger.maskEmail("not-an-email"));
    }

    @Test
    void testTokenMaskingSuppressesSecret() {
        String token = "abcdef1234567890abcdef1234567890abcdef12";
        String masked = SecurityLogger.maskToken(token);

        assertTrue(masked.startsWith("abcd..."));
        assertFalse(masked.contains("1234567890"));
    }

    @Test
    void testDenialOfServiceLockoutAttackIsDefeated() {
        String victimEmail = "ceo@enterprise.com";
        char[] ceoPassword = "CeoSuperStrongSecret#2026!".toCharArray();
        assertTrue(authService.registerUser(victimEmail, ceoPassword));

        String attackerIp = "198.51.100.99";
        String ceoIp = "192.168.1.10";

        // Attacker blasts 5 wrong passwords to try to lock out the CEO
        for (int i = 0; i < 5; i++) {
            authService.authenticate(victimEmail, "AttackerGuess123!".toCharArray(), attackerIp);
        }

        // Attacker is now rate limited
        AuthenticationResult attackerAttempt = authService.authenticate(
                victimEmail, "AttackerGuess123!".toCharArray(), attackerIp);
        assertEquals(AuthenticationResult.Status.RATE_LIMITED, attackerAttempt.getStatus());

        // The CEO connects from their IP and enters their real password
        AuthenticationResult ceoAttempt = authService.authenticate(
                victimEmail, "CeoSuperStrongSecret#2026!".toCharArray(), ceoIp);

        // Authentication succeeds! The CEO was NOT locked out by the attacker!
        assertTrue(ceoAttempt.isSuccess(), "Legitimate user must authenticate successfully despite attacker flooding");
    }
}
