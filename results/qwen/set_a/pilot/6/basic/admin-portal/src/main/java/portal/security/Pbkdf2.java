package portal.security;

import java.security.GeneralSecurityException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** PBKDF2-HMAC-SHA256, supplied by the JDK ({@code PBKDF2WithHmacSHA256}). */
public final class Pbkdf2 implements KeyDerivation {

    private static final String JDK_ALGORITHM = "PBKDF2WithHmacSHA256";

    @Override
    public byte[] derive(char[] password, byte[] salt, int iterations, int keyBits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(JDK_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 is unavailable on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }

    @Override
    public String algorithmId() {
        return "PBKDF2-SHA256";
    }
}
