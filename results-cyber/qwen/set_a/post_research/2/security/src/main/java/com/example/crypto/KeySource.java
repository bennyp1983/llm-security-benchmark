package com.example.crypto;

/**
 * Where a key comes from.
 *
 * <p>Every implementation loads a <em>fresh</em> {@link KeyMaterial} on each call and keeps none
 * cached. That is a deliberate cost: caching key material is the usual way a "hardened" component
 * ends up with the key resident in the heap for the life of the JVM, which is exactly what
 * {@link KeyMaterial#destroy()} exists to prevent. Call the returned object's {@code close()} as soon
 * as the operation is done.
 *
 * <p>Implementations must fail closed. A missing, unreadable or malformed source throws
 * {@link CryptoException}; it must never return a default key, a zero key, or a key derived from a
 * constant.
 */
public interface KeySource {

    /**
     * Loads key material.
     *
     * @throws CryptoException if the key is absent, malformed, not usable, or stored somewhere whose
     *     privacy this component cannot verify
     */
    KeyMaterial load() throws CryptoException;

    /**
     * Human-readable identity for logs and error details. Must identify the <em>source</em> (for
     * example {@code "env:APP_DATA_KEY"}) and must never contain the key, a password, or the value it
     * read.
     */
    String describe();

    @Override
    boolean equals(Object o);

    @Override
    int hashCode();
}
