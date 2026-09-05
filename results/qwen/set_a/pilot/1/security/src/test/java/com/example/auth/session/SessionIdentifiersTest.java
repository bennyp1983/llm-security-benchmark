package com.example.auth.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SessionIdentifiersTest {

    @Test
    void identifiersAreDistinct() {
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < 5000; i++) {
            assertTrue(ids.add(SessionIdentifiers.newSessionId()), "duplicate identifier produced");
        }
    }

    @Test
    void identifiersAreCookieSafeAndCarryEnoughEntropy() {
        for (int i = 0; i < 500; i++) {
            String id = SessionIdentifiers.newSessionId();
            // 32 bytes, base64url without padding.
            assertEquals(43, id.length());
            // Anything we hand the cookie factory has to survive its value validation.
            assertEquals(id, SessionCookieFactory.forSession(SessionCookieConfig.DEFAULTS, id).getValue());
        }
    }

    @Test
    void identifiersShareNoPrefixThatAnAttackerCouldExtrapolate() {
        Set<String> firstSix = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            firstSix.add(SessionIdentifiers.newSessionId().substring(0, 6));
        }
        assertTrue(firstSix.size() > 450, "first characters look far too repetitive: " + firstSix.size());
    }
}
