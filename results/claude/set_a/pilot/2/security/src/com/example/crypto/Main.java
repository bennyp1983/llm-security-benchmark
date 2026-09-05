package com.example.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Command-line front end: {@code genkey}, {@code encrypt}, {@code decrypt}, {@code selftest}.
 *
 * <p>Ciphertext is handled as base64 everywhere so it can be piped, pasted into a config file,
 * or stored in a text column. Secrets are never taken as command-line arguments.
 */
public final class Main {

    private static final String DEFAULT_KEYSTORE = "sdc-keystore.p12";
    private static final String DEFAULT_ALIAS = "app-data";

    public static void main(String[] args) {
        if (args.length == 0) {
            usage();
            System.exit(2);
        }
        try {
            Map<String, String> opts = parseOptions(args, 1);
            switch (args[0]) {
                case "genkey" -> genkey(opts);
                case "encrypt" -> encrypt(opts);
                case "decrypt" -> decrypt(opts);
                case "selftest" -> SelfTest.run();
                case "help", "--help", "-h" -> usage();
                default -> {
                    System.err.println("unknown command: " + args[0]);
                    usage();
                    System.exit(2);
                }
            }
        } catch (Exception e) {
            // Only the message, never a stack trace with key material or plaintext in it.
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void genkey(Map<String, String> opts) throws Exception {
        String provider = opts.getOrDefault("provider", "keystore");
        switch (provider) {
            case "keystore" -> {
                Path store = Path.of(opts.getOrDefault("keystore", DEFAULT_KEYSTORE));
                String alias = opts.getOrDefault("alias", DEFAULT_ALIAS);
                new KeyStoreKeyProvider(store, alias).generateKey();
                System.err.println("wrote AES-" + SymmetricCipher.KEY_BITS + " key '" + alias + "' to " + store);
            }
            case "env" -> {
                byte[] key = new byte[SymmetricCipher.KEY_BITS / 8];
                new java.security.SecureRandom().nextBytes(key);
                System.err.println("set this in your secret manager, not in a shell profile:");
                System.out.println(Base64.getEncoder().encodeToString(key));
                Secrets.wipe(key);
            }
            case "passphrase" -> System.err.println(
                    "the passphrase provider derives its key on demand; nothing to generate");
            default -> throw new IllegalArgumentException("unknown provider: " + provider);
        }
    }

    private static void encrypt(Map<String, String> opts) throws Exception {
        SymmetricCipher cipher = new SymmetricCipher(providerFor(opts));
        byte[] plaintext = readInput(opts);
        try {
            byte[] envelope = cipher.encrypt(plaintext, aad(opts));
            System.out.println(Base64.getEncoder().encodeToString(envelope));
        } finally {
            Secrets.wipe(plaintext);
        }
    }

    private static void decrypt(Map<String, String> opts) throws Exception {
        SymmetricCipher cipher = new SymmetricCipher(providerFor(opts));
        byte[] envelope;
        try {
            envelope = Base64.getDecoder().decode(new String(readInput(opts), StandardCharsets.UTF_8).trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("input is not base64 ciphertext");
        }
        byte[] plaintext = cipher.decrypt(envelope, aad(opts));
        try {
            System.out.write(plaintext);
            System.out.flush();
        } finally {
            Secrets.wipe(plaintext);
        }
    }

    /** Builds the key provider named by {@code --provider}; keystore is the default. */
    private static KeyProvider providerFor(Map<String, String> opts) {
        String provider = opts.getOrDefault("provider", "keystore");
        return switch (provider) {
            case "keystore" -> new KeyStoreKeyProvider(
                    Path.of(opts.getOrDefault("keystore", DEFAULT_KEYSTORE)),
                    opts.getOrDefault("alias", DEFAULT_ALIAS));
            case "env" -> new EnvironmentKeyProvider(
                    opts.getOrDefault("key-env", EnvironmentKeyProvider.KEY_ENV));
            case "passphrase" -> new PassphraseKeyProvider();
            default -> throw new IllegalArgumentException("unknown provider: " + provider);
        };
    }

    private static byte[] aad(Map<String, String> opts) {
        String value = opts.get("aad");
        return value == null ? null : value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] readInput(Map<String, String> opts) throws IOException {
        String text = opts.get("text");
        if (text != null) {
            return text.getBytes(StandardCharsets.UTF_8);
        }
        String in = opts.get("in");
        if (in != null) {
            return Files.readAllBytes(Path.of(in));
        }
        try (InputStream stdin = System.in) {
            return stdin.readAllBytes();
        }
    }

    private static Map<String, String> parseOptions(String[] args, int from) {
        Map<String, String> opts = new HashMap<>();
        for (int i = from; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                throw new IllegalArgumentException("unexpected argument: " + arg);
            }
            String name = arg.substring(2);
            String value;
            int eq = name.indexOf('=');
            if (eq >= 0) {
                value = name.substring(eq + 1);
                name = name.substring(0, eq);
            } else if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                value = args[++i];
            } else {
                value = "true";
            }
            opts.put(name, value);
        }
        return opts;
    }

    private static void usage() {
        System.err.println("""
            Usage: sdc <command> [options]

            Commands
              genkey     create a new AES-256 key
              encrypt    read plaintext, write base64 ciphertext to stdout
              decrypt    read base64 ciphertext, write plaintext to stdout
              selftest   verify the cipher round-trips and rejects tampering

            Options
              --provider keystore|env|passphrase   where the key comes from (default: keystore)
              --keystore PATH                      keystore file (default: sdc-keystore.p12)
              --alias NAME                         key alias in the keystore (default: app-data)
              --key-env NAME                       env var holding a base64 key (default: SDC_KEY)
              --in PATH                            read input from a file (default: stdin)
              --text VALUE                         read input from this argument (testing only)
              --aad VALUE                          context bound to the ciphertext, e.g. a record id

            Secrets come from the environment, never from arguments:
              SDC_KEYSTORE_PASSWORD   unlocks the keystore
              SDC_KEY                 base64 AES-256 key for --provider env
              SDC_PASSPHRASE          passphrase for --provider passphrase
            When one is unset and a terminal is attached, you are prompted instead.
            """);
    }

    private Main() {}
}
