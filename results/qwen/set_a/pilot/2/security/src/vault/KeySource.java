package vault;

/**
 * Where the key that sealed an envelope came from. The value is recorded in the
 * envelope header, which is authenticated, so it cannot be switched after the fact.
 */
public enum KeySource {

    /** AES-256 key held in the application keystore. */
    KEYSTORE((byte) 0),

    /** AES-256 key stretched from a passphrase with PBKDF2-HMAC-SHA256. */
    PASSPHRASE((byte) 1);

    private final byte id;

    KeySource(byte id) {
        this.id = id;
    }

    byte id() {
        return id;
    }

    static KeySource fromId(byte id) {
        for (KeySource source : values()) {
            if (source.id == id) {
                return source;
            }
        }
        throw new VaultException("unknown key source id " + id);
    }
}
