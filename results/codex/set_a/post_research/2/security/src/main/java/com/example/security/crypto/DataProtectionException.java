package com.example.security.crypto;

/**
 * A deliberately generic failure from an encryption or decryption operation.
 * The message never distinguishes malformed input, an unknown key, or failed
 * authentication.
 */
public final class DataProtectionException extends Exception {
    private static final long serialVersionUID = 1L;
    private static final String GENERIC_MESSAGE = "Data protection operation failed";

    DataProtectionException() {
        super(GENERIC_MESSAGE, null, false, false);
    }
}
