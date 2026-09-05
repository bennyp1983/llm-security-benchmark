package com.example.crypto;

import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reads a base64-encoded AES-256 key from an environment variable.
 *
 * <p>This suits container platforms where a secret manager injects the key at start-up
 * (Kubernetes secrets, ECS task secrets, systemd credentials). The key exists only in the
 * process environment, so it is never committed to source control or baked into an image --
 * but note that the environment of a process is visible to anyone who can read
 * {@code /proc/<pid>/environ} as the same user or as root, and it is commonly copied into
 * crash dumps and child processes. A keystore file is the stronger option where one is
 * practical; see {@link KeyStoreKeyProvider}.
 */
public final class EnvironmentKeyProvider implements KeyProvider {

    public static final String KEY_ENV = "SDC_KEY";
    private static final byte[] NO_PARAMETERS = new byte[0];

    private final String envVar;

    public EnvironmentKeyProvider(String envVar) {
        this.envVar = envVar;
    }

    @Override
    public String id() {
        return "env:" + envVar;
    }

    @Override
    public byte[] newParameters() {
        return NO_PARAMETERS;
    }

    @Override
    public SecretKey resolve(byte[] parameters) throws GeneralSecurityException {
        String encoded = System.getenv(envVar);
        if (encoded == null || encoded.isBlank()) {
            throw new GeneralSecurityException(envVar + " is not set (generate one with: genkey --provider env)");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(encoded.trim());
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException(envVar + " is not valid base64", e);
        }
        try {
            if (raw.length != SymmetricCipher.KEY_BITS / 8) {
                throw new GeneralSecurityException(
                        envVar + " must decode to " + SymmetricCipher.KEY_BITS / 8
                                + " bytes, got " + raw.length);
            }
            return new SecretKeySpec(raw, "AES");
        } finally {
            Secrets.wipe(raw);
        }
    }
}
