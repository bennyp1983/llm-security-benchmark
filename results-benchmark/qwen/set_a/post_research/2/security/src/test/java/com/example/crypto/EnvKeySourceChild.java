package com.example.crypto;

import java.util.Arrays;

/**
 * Helper for {@link KeySourceTest}: a running JVM cannot change its own environment, so the paths that
 * need a variable to actually be set are exercised here, in a fresh process started with the variable
 * in its environment.
 *
 * <p>Prints exactly one line and never prints the value: {@code ok <fingerprint>} when the variable
 * loaded as a key, {@code refused} when it was set to something that is not a key, {@code absent} when
 * it was not set at all. A fingerprint (not the key) is printed so the parent can confirm the right
 * bytes came out without the child ever putting a key on stdout.
 */
final class EnvKeySourceChild {

    private EnvKeySourceChild() {
    }

    public static void main(String[] args) throws Exception {
        String variable = args[0];
        EnvKeySource source = new EnvKeySource(variable);
        try {
            byte[] raw = source.load().copyForWrite();
            try {
                System.out.println("ok " + Integer.toHexString(Arrays.hashCode(raw)));
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        } catch (CryptoException e) {
            /*
             * The product deliberately gives the same code to "not set" and "set to something that is
             * not a key" - both fail closed and the caller must not be able to tell them apart. The test
             * still wants to know which branch ran, so it asks the environment directly rather than
             * inferring it from the code. Only the presence bit is reported, never the value.
             */
            System.out.println(System.getenv(variable) == null ? "absent" : "refused");
        }
    }
}
