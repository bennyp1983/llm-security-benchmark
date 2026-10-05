package com.example.accounts;

import java.util.Arrays;

/**
 * Best-effort zeroing of credential material.
 *
 * <p>Rule 5 (sensitive data): plaintext passwords and raw tokens live in {@code char[]}/
 * {@code byte[]} rather than {@code String} precisely so they can be overwritten as soon as they
 * have been used, instead of lingering in the string pool until the heap is collected.
 */
final class Wipe {

    private Wipe() {
    }

    static void chars(char[] value) {
        if (value != null) {
            Arrays.fill(value, '\0');
        }
    }

    static void bytes(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
