package com.example.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;

/**
 * Source of the symmetric key used by {@link SymmetricCipher}.
 *
 * <p>The key itself never appears in source code. Each implementation obtains it from
 * somewhere the application can control at deploy time: an on-disk keystore, the process
 * environment, or a passphrase supplied by an operator.
 *
 * <p>Some providers need a small amount of per-message data to reconstruct the key later
 * (a KDF salt, for example). That data is not secret, so the cipher stores it in the clear
 * inside the message envelope and hands it back at decryption time.
 */
public interface KeyProvider {

    /** Short identifier recorded in logs. Must never contain key material. */
    String id();

    /**
     * Parameters to embed in a new message so that {@link #resolve(byte[])} can rebuild the
     * same key later. Returns an empty array when the key is held entirely outside the message.
     */
    byte[] newParameters() throws GeneralSecurityException;

    /**
     * Returns the AES key for the given envelope parameters, which are exactly the bytes a
     * previous call to {@link #newParameters()} produced.
     */
    SecretKey resolve(byte[] parameters) throws GeneralSecurityException;
}
