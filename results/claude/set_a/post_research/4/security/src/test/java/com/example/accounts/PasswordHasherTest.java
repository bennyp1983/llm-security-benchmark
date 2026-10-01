package com.example.accounts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PasswordHasherTest {

    private static final Config.Argon2Settings CHEAP = new Config.Argon2Settings(19_456, 2, 1);

    private static PasswordHasher hasher() {
        return new PasswordHasher(CHEAP, new byte[0]);
    }

    @Test
    void verifiesTheCorrectPassword() {
        PasswordHasher hasher = hasher();
        String encoded = hasher.hash("pewter-rhubarb-glacier".toCharArray());
        assertTrue(hasher.verify("pewter-rhubarb-glacier".toCharArray(), encoded));
    }

    @Test
    void rejectsTheWrongPassword() {
        PasswordHasher hasher = hasher();
        String encoded = hasher.hash("pewter-rhubarb-glacier".toCharArray());
        assertFalse(hasher.verify("pewter-rhubarb-glacie".toCharArray(), encoded));
        assertFalse(hasher.verify("Pewter-rhubarb-glacier".toCharArray(), encoded));
    }

    @Test
    void producesAPhcStringWithTheConfiguredParameters() {
        String encoded = hasher().hash("pewter-rhubarb-glacier".toCharArray());
        assertTrue(encoded.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"), encoded);
        assertEquals(6, encoded.split("\\$", -1).length);
    }

    @Test
    void saltsEveryHashIndependently() {
        PasswordHasher hasher = hasher();
        String first = hasher.hash("pewter-rhubarb-glacier".toCharArray());
        String second = hasher.hash("pewter-rhubarb-glacier".toCharArray());
        assertNotEquals(first, second, "identical passwords must not produce identical hashes");
    }

    @Test
    void aPepperChangesTheResultAndIsRequiredToVerify() {
        byte[] pepper = new byte[32];
        for (int i = 0; i < pepper.length; i++) {
            pepper[i] = (byte) i;
        }
        PasswordHasher peppered = new PasswordHasher(CHEAP, pepper);
        String encoded = peppered.hash("pewter-rhubarb-glacier".toCharArray());
        assertTrue(peppered.verify("pewter-rhubarb-glacier".toCharArray(), encoded));
        // A database thief without the pepper cannot verify a guess against the stolen hash.
        assertFalse(hasher().verify("pewter-rhubarb-glacier".toCharArray(), encoded));
    }

    @Test
    void doesNotLeakThePepperIntoTheEncodedHash() {
        byte[] pepper = "pepper-value-not-in-output".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String encoded = new PasswordHasher(CHEAP, pepper).hash("pewter-rhubarb".toCharArray());
        assertFalse(encoded.contains("pepper"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "not-a-hash",
        "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ",
        "$argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ",
        "$argon2id$v=19$m=19456,t=2$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ",
        "$argon2id$v=19$m=19456,t=2,p=1$!!!$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ",
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2hvcnQ",
    })
    void failsClosedOnAnUnparsableStoredHash(String stored) {
        assertFalse(hasher().verify("pewter-rhubarb-glacier".toCharArray(), stored));
    }

    @Test
    void refusesHostileCostParametersFromTheDatabase() {
        // A tampered row asking for 64 GiB must not be honoured -- that would be a memory DoS
        // triggered by whoever can write to the database.
        String hostile = "$argon2id$v=19$m=67108864,t=2,p=1"
                + "$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
        assertFalse(hasher().verify("pewter-rhubarb-glacier".toCharArray(), hostile));
        String hostileIterations = "$argon2id$v=19$m=19456,t=2000000,p=1"
                + "$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
        assertFalse(hasher().verify("pewter-rhubarb-glacier".toCharArray(), hostileIterations));
    }

    @Test
    void flagsHashesWeakerThanCurrentSettingsForRehash() {
        PasswordHasher strong = new PasswordHasher(new Config.Argon2Settings(65_536, 3, 1), new byte[0]);
        String weak = hasher().hash("pewter-rhubarb-glacier".toCharArray());
        assertTrue(strong.needsRehash(weak));
        assertFalse(hasher().needsRehash(hasher().hash("pewter-rhubarb-glacier".toCharArray())));
        assertTrue(hasher().needsRehash("garbage"));
    }

    @Test
    void acceptsLongAndUnicodePasswords() {
        PasswordHasher hasher = hasher();
        char[] password = new char[InputValidator.PASSWORD_MAX_LENGTH];
        for (int i = 0; i < password.length; i++) {
            password[i] = (char) ('\u00c0' + (i % 50));
        }
        String encoded = hasher.hash(password.clone());
        assertTrue(hasher.verify(password.clone(), encoded));
    }

    @Test
    void decoyHashesAreVerifiableButNeverMatchAUserPassword() {
        PasswordHasher hasher = hasher();
        String decoy = hasher.newDecoyHash();
        assertTrue(decoy.startsWith("$argon2id$"));
        assertFalse(hasher.verify("pewter-rhubarb-glacier".toCharArray(), decoy));
    }
}
