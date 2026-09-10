package vault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

/**
 * Command-line front end: key custody plus seal/open for bytes and files.
 *
 * <pre>
 * usage: vault &lt;command&gt; [options]
 *
 *   init      create the keystore and its default key
 *   keys      list key aliases
 *   keygen    add a new random AES-256 key
 *   keyrm     delete a key (payloads sealed under it become unreadable)
 *   seal      encrypt a file, or stdin when no input is given
 *   open      decrypt a sealed file, or stdin when no input is given
 *   info      show which key a sealed payload names, without decrypting it
 *   rekey     re-seal a payload under a different alias
 * </pre>
 *
 * <p>Secrets come from the environment or a terminal prompt, never from an argument - see
 * {@link Passwords}.
 */
public final class VaultCli {

    private static final String DEFAULT_KEYSTORE = "vault-keystore.p12";
    private static final String DEFAULT_ALIAS = "app-data";

    private VaultCli() {
    }

    public static void main(String[] args) {
        try {
            int code = new VaultCli().run(args);
            if (code != 0) {
                System.exit(code);
            }
        } catch (VaultException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(2);
        }
    }

    int run(String[] args) throws IOException {
        if (args.length == 0 || isHelp(args[0])) {
            printUsage();
            return args.length == 0 ? 2 : 0;
        }
        Options options = Options.parse(Arrays.copyOfRange(args, 1, args.length));
        return switch (args[0]) {
            case "init" -> init(options);
            case "keys" -> keys(options);
            case "keygen" -> keygen(options);
            case "keyrm" -> keyrm(options);
            case "seal" -> seal(options);
            case "open" -> open(options);
            case "info" -> info(options);
            case "rekey" -> rekey(options);
            default -> {
                System.err.println("unknown command: " + args[0]);
                printUsage();
                yield 2;
            }
        };
    }

    private int init(Options options) {
        char[] password = Passwords.keystorePassword();
        try {
            try (KeyVault vault = KeyVault.open(options.keystore(), password)) {
                String alias = options.alias();
                boolean created = !vault.contains(alias);
                if (created) {
                    vault.generate(alias);
                }
                System.out.println("keystore : " + vault.storePath()
                        + (FilePermissions.isPosix(vault.storePath()) && FilePermissions.worldOrGroupReadable(
                                vault.storePath()) ? "  WARNING: readable beyond the owner" : ""));
                System.out.println("alias    : " + alias + (created ? " (created)" : " (already present)"));
                System.out.println("protection: PKCS#12 store, password from " + Passwords.describeSources());
            }
            return 0;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private int keys(Options options) {
        char[] password = Passwords.keystorePassword();
        try (KeyVault vault = KeyVault.openExisting(options.keystore(), password)) {
            if (vault.aliases().isEmpty()) {
                System.out.println("no keys; run: vault init");
                return 1;
            }
            for (String alias : vault.aliases()) {
                System.out.println(alias);
            }
            return 0;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private int keygen(Options options) {
        char[] password = Passwords.keystorePassword();
        try (KeyVault vault = KeyVault.openExisting(options.keystore(), password)) {
            vault.generate(options.alias());
            System.out.println("generated AES-" + KeyVault.KEY_LENGTH_BITS + " key '" + options.alias() + "'");
            return 0;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private int keyrm(Options options) {
        char[] password = Passwords.keystorePassword();
        try (KeyVault vault = KeyVault.openExisting(options.keystore(), password)) {
            if (!vault.contains(options.alias())) {
                System.err.println("no such alias: " + options.alias());
                return 1;
            }
            vault.delete(options.alias());
            System.out.println("deleted '" + options.alias() + "'; anything sealed under it is now unreadable");
            return 0;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private int seal(Options options) throws IOException {
        byte[] plaintext = options.hasInput() ? Files.readAllBytes(options.input()) : readAll(System.in);
        try (DataVault vault = vault(options)) {
            Envelope envelope = vault.seal(plaintext);
            Arrays.fill(plaintext, (byte) 0);
            if (options.hasOutput()) {
                try (var out = FilePermissions.newOwnerOnlyOutputStream(options.output())) {
                    out.write(envelope.toBytes());
                }
                System.err.println("sealed " + envelope.ciphertext().length + " bytes -> " + options.output()
                        + " using " + vault.keyDescription(envelope));
            } else {
                System.out.println(Base64.getEncoder().encodeToString(envelope.toBytes()));
            }
            return 0;
        }
    }

    private int open(Options options) throws IOException {
        byte[] sealed = options.hasInput() ? Files.readAllBytes(options.input()) : decodeStdin();
        try (DataVault vault = vault(options)) {
            Envelope envelope = Envelope.fromBytes(sealed);
            Arrays.fill(sealed, (byte) 0);
            byte[] plaintext;
            try (DataVault.Opened opened = vault.open(envelope)) {
                plaintext = opened.data();
            }
            if (options.hasOutput()) {
                try (var out = FilePermissions.newOwnerOnlyOutputStream(options.output())) {
                    out.write(plaintext);
                }
                Arrays.fill(plaintext, (byte) 0);
                System.err.println("opened -> " + options.output() + " using " + vault.keyDescription(envelope));
            } else {
                System.out.write(plaintext);
                System.out.flush();
                Arrays.fill(plaintext, (byte) 0);
            }
            return 0;
        }
    }

    private int info(Options options) throws IOException {
        Path source = options.hasInput() ? options.input() : null;
        if (source == null) {
            System.err.println("info needs a sealed file");
            return 2;
        }
        AesGcmCipher cipher = AesGcmCipher.withSystemRandom();
        Envelope envelope = cipher.readEnvelopeHeader(source);
        long sealedBytes = Files.size(source) - envelope.headerLength();
        System.out.println("key source : " + envelope.keySource());
        System.out.println("alias      : " + envelope.alias());
        if (envelope.keySource() == KeySource.PASSPHRASE) {
            System.out.println("kdf        : " + KeyVault.PBKDF2_ALGORITHM);
            System.out.println("iterations : " + envelope.iterations());
            System.out.println("salt bytes : " + envelope.salt().length);
        }
        System.out.println("sealed bytes: " + sealedBytes + " (includes " + Envelope.TAG_LENGTH
                + "-byte GCM tag, so plaintext is " + Math.max(sealedBytes - Envelope.TAG_LENGTH, 0) + ")");
        return 0;
    }

    private int rekey(Options options) {
        if (!options.hasInput() || !options.hasOutput()) {
            System.err.println("rekey needs --in and --out");
            return 2;
        }
        try (DataVault vault = vault(options)) {
            if (!vault.keyVault().contains(options.alias())) {
                vault.keyVault().generate(options.alias());
                System.err.println("created target alias " + options.alias());
            }
            vault.rekeyFile(options.input(), options.output(), options.alias());
            System.out.println("re-sealed " + options.input() + " -> " + options.output() + " under "
                    + options.alias());
            return 0;
        }
    }

    private DataVault vault(Options options) {
        char[] password = Passwords.required(Passwords.keystorePassword(), Passwords.ENV_KEYSTORE_PASSWORD,
                Passwords.ENV_KEYSTORE_PASSWORD_FILE);
        try {
            KeyVault keyVault = KeyVault.openExisting(options.keystore(), password);
            return new DataVault(keyVault, options.alias());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static byte[] decodeStdin() throws IOException {
        String text = new String(readAll(System.in), StandardCharsets.UTF_8).trim();
        try {
            return Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException notBase64) {
            throw new VaultException("stdin is not base64; pass a sealed file with --in", notBase64);
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = in.read(chunk)) > 0) {
            buffer.write(chunk, 0, read);
        }
        return buffer.toByteArray();
    }

    private static boolean isHelp(String command) {
        return command.equals("-h") || command.equals("--help") || command.equals("help");
    }

    private static void printUsage() {
        System.out.printf("""
                usage: vault <command> [options]

                commands:
                  init                 create the keystore and its default key
                  keys                 list key aliases
                  keygen               add a new random AES-256 key
                  keyrm                delete a key (payloads under it become unreadable)
                  seal                 encrypt --in (or stdin) to --out (or base64 stdout)
                  open                 decrypt --in (or base64 stdin) to --out (or stdout)
                  info                 show which key a sealed payload names, no decryption
                  rekey                re-seal --in under --alias, writing --out

                options:
                  --keystore PATH      keystore file          (default vault-keystore.p12)
                  --alias NAME         key alias              (default app-data)
                  --in PATH            input file             ('-' or absent means stdin)
                  --out PATH           output file

                The CLI seals with an AES-256 key held in the keystore. Passphrase-derived
                keys (PBKDF2-HMAC-SHA256) are available through the API, see Demo.

                secrets are read from the environment, a mounted secret file, or a terminal
                prompt, never from an argument:
                  %s
                """, Passwords.describeSources());
    }

    /** Minimal flag parser; unknown flags are an error rather than a silent ignore. */
    private static final class Options {

        private final Path keystore;
        private final String alias;
        private final Path input;
        private final Path output;

        Options(Path keystore, String alias, Path input, Path output) {
            this.keystore = keystore;
            this.alias = alias;
            this.input = input;
            this.output = output;
        }

        static Options parse(String[] args) {
            Path keystore = Path.of(System.getProperty("vault.keystore", DEFAULT_KEYSTORE));
            String alias = System.getProperty("vault.alias", DEFAULT_ALIAS);
            Path input = null;
            Path output = null;
            for (int i = 0; i < args.length; i++) {
                String flag = args[i];
                switch (flag) {
                    case "--keystore", "--alias", "--in", "--out" -> {
                        if (i + 1 >= args.length) {
                            throw new VaultException(flag + " needs a value");
                        }
                        String value = args[++i];
                        switch (flag) {
                            case "--keystore" -> keystore = Path.of(value);
                            case "--alias" -> alias = value;
                            case "--in" -> input = value.equals("-") ? null : Path.of(value);
                            case "--out" -> output = Path.of(value);
                            default -> throw new VaultException("unreachable");
                        }
                    }
                    case "-h", "--help" -> {
                        return new Options(keystore, alias, null, null);
                    }
                    default -> throw new VaultException("unknown option: " + flag);
                }
            }
            return new Options(keystore, alias, input, output);
        }

        Path keystore() {
            return keystore;
        }

        String alias() {
            return alias;
        }

        Path input() {
            return input;
        }

        Path output() {
            return output;
        }

        boolean hasInput() {
            return input != null;
        }

        boolean hasOutput() {
            return output != null;
        }
    }
}
