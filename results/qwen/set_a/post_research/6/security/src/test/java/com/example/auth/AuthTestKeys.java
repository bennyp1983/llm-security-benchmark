package com.example.auth;

/** Fixed test-only keystore identifiers; not secrets used anywhere in production. */
final class AuthTestKeys {

    static final String ALIAS = "auth-pepper";
    static final char[] STORE_PASSWORD = "Keystore-Fixture-Pass-91".toCharArray();

    private AuthTestKeys() {
    }
}
