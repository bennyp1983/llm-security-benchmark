package com.security.auth.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Rule 4: Secure Identifiers and Tokens Tests")
class TokenGeneratorTest {

    private final TokenGenerator tokenGenerator = new TokenGenerator();

    @Test
    @DisplayName("Generated tokens conform to high-entropy 256-bit URL-safe format")
    void testTokenFormatAndEntropy() {
        String token = tokenGenerator.generateSecureToken();
        assertNotNull(token);
        assertEquals(43, token.length(), "32 raw bytes Base64URL-encoded without padding must be 43 chars");
        assertTrue(tokenGenerator.isValidTokenFormat(token));
    }

    @Test
    @DisplayName("Generated tokens are unique with high entropy")
    void testTokenUniqueness() {
        Set<String> generatedTokens = new HashSet<>();
        int count = 1000;
        for (int i = 0; i < count; i++) {
            String token = tokenGenerator.generateSecureToken();
            assertTrue(generatedTokens.add(token), "Generated token collision detected!");
        }
        assertEquals(count, generatedTokens.size());
    }

    @Test
    @DisplayName("Token hashing produces consistent 64-character SHA-256 hex digest")
    void testTokenHashing() {
        String token = tokenGenerator.generateSecureToken();
        String hash1 = tokenGenerator.hashToken(token);
        String hash2 = tokenGenerator.hashToken(token);

        assertEquals(64, hash1.length());
        assertEquals(hash1, hash2);
        assertNotEquals(token, hash1);
    }

    @Test
    @DisplayName("Invalid token formats are rejected")
    void testInvalidTokenFormats() {
        assertFalse(tokenGenerator.isValidTokenFormat(null));
        assertFalse(tokenGenerator.isValidTokenFormat(""));
        assertFalse(tokenGenerator.isValidTokenFormat("too-short"));
        assertFalse(tokenGenerator.isValidTokenFormat("this_token_has_invalid_symbols_!@#$%^&*()_+="));
    }
}
