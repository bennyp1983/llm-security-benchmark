package vault;

/**
 * Single failure type for the vault. Messages are safe to show a caller: they
 * describe what went wrong without ever echoing key material or plaintext.
 */
public class VaultException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    VaultException(String message) {
        super(message);
    }

    VaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
