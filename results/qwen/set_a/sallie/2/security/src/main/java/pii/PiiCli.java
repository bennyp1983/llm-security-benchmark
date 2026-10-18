package pii;

import java.util.Arrays;

/**
 * Command line demo: take a name and an email, encrypt them, decrypt them again and
 * show that the original information came back unchanged.
 *
 * <pre>
 *   java pii.PiiCli --name "Ada Lovelace" --email ada@example.com
 * </pre>
 *
 * <p>The key comes from the environment or a key file (see {@link KeyProvider}), never
 * from this file. Run {@code java pii.PiiKeygen} first to create one.
 */
public final class PiiCli {

    private PiiCli() {
    }

    public static void main(String[] args) {
        String name = null;
        String email = null;
        String key = null;
        String keyFile = null;

        try {
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "--name" -> name = value(args, ++i, arg);
                    case "--email" -> email = value(args, ++i, arg);
                    case "--key" -> key = value(args, ++i, arg);
                    case "--key-file" -> keyFile = value(args, ++i, arg);
                    case "--help", "-h" -> {
                        usage(System.out);
                        return;
                    }
                    default -> throw new IllegalArgumentException("Unknown option: " + arg);
                }
            }
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            usage(System.err);
            System.exit(2);
            return;
        }

        if (name == null || email == null) {
            System.err.println("Both --name and --email are required.");
            usage(System.err);
            System.exit(2);
            return;
        }

        byte[] keyBytes = null;
        try {
            keyBytes = KeyProvider.loadKey(key, keyFile);
            runDemo(new PiiRecord(name, email), keyBytes);
        } catch (IllegalArgumentException e) {
            System.err.println("Input rejected: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("Failed: " + e.getMessage());
            if (!(e instanceof java.security.GeneralSecurityException)) {
                e.printStackTrace(System.err);
            }
            System.exit(4);
        } finally {
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    private static void runDemo(PiiRecord original, byte[] keyBytes) throws Exception {
        System.out.println("The key was loaded at runtime - " + KeyProvider.NOT_EMBEDDED_NOTE);
        System.out.println();
        System.out.println("1. Original information");
        System.out.println("   name : " + original.name());
        System.out.println("   email: " + original.email());

        try (PiiCipher cipher = new PiiCipher(keyBytes)) {
            ProtectedPii envelope = cipher.encrypt(original);
            String stored = envelope.toBase64();

            System.out.println();
            System.out.println("2. Encrypted with " + PiiCipher.describeKey(keyBytes) + " / GCM, "
                    + envelope.ciphertext().length + " bytes of ciphertext + a "
                    + envelope.tag().length + " byte authentication tag");
            System.out.println("   iv     : " + toHex(envelope.iv()));
            System.out.println("   stored : " + stored);

            String second = cipher.protect(original);
            System.out.println();
            System.out.println("3. The same person encrypted again gives different text, because every call");
            System.out.println("   draws a fresh random initialisation vector. Neither value leaks the other.");
            System.out.println("   stored : " + second);
            System.out.println("   same text as step 2? " + (stored.equals(second) ? "yes (unexpected)" : "no (as expected)"));

            System.out.println();
            System.out.println("4. Decrypted again");
            PiiRecord first = cipher.reveal(stored);
            PiiRecord recovered = cipher.reveal(second);
            System.out.println("   name : " + recovered.name());
            System.out.println("   email: " + recovered.email());
            System.out.println();
            boolean same = first.equals(original) && recovered.equals(original);
            System.out.println("5. Round trip " + (same ? "OK" : "FAILED") + ": the decrypted record is "
                    + (same ? "identical" : "NOT identical") + " to the original.");
            if (!same) {
                System.exit(4);
            }
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return hex.toString();
    }

    private static void usage(java.io.PrintStream out) {
        out.println("Usage: java pii.PiiCli --name NAME --email EMAIL [--key-file PATH | --key BASE64]");
        out.println();
        out.println("Encrypts NAME and EMAIL with AES-256/GCM, prints the protected text, then");
        out.println("decrypts it and prints the recovered values.");
        out.println();
        out.println("The key is never in the code. It is read from PII_KEY_FILE, PII_KEY, --key-file");
        out.println("or --key, in that order. Create a key with: java pii.PiiKeygen");
    }

    private static String value(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new IllegalArgumentException(option + " needs a value");
        }
        return args[index];
    }
}
