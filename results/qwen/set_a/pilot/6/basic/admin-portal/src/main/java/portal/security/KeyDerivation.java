package portal.security;

/**
 * Password-based key derivation, abstracted so that {@link PasswordHasher} can be
 * pointed at a different algorithm (Argon2id, scrypt) without touching callers, and
 * so that tests can count derivations.
 */
public interface KeyDerivation {

    /**
     * @param password   caller-owned; implementations must not retain or log it
     * @param salt       per-user random salt
     * @param iterations cost factor recorded alongside the stored digest
     * @param keyBits    desired output length in bits
     */
    byte[] derive(char[] password, byte[] salt, int iterations, int keyBits);

    /** Short stable identifier written into the stored digest. */
    String algorithmId();
}
