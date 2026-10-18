package com.example.crypto;

import java.io.BufferedOutputStream;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import com.example.crypto.SymmetricCrypto.CryptoException;
import com.example.crypto.SymmetricCrypto.KeySource;

/**
 * Command line front end over {@link SymmetricCrypto}: generate keys, seal a secret into a base64
 * token, and open a token back into the original bytes.
 */
public final class App {

    private static final Set<String> SWITCHES = Set.of("--stdin", "--force", "--help");
    private static final Set<String> VALUE_OPTIONS = Set.of("--key", "--key-env", "--key-file",
            "--password", "--password-env", "--iterations", "--aad", "--text", "--file", "--out");

    public static void main(String[] args) throws IOException {
        PrintStream out = utf8Stream(FileDescriptor.out);
        PrintStream err = utf8Stream(FileDescriptor.err);
        int status;
        try {
            status = run(args, System.in, out, err);
        } catch (CryptoException e) {
            err.println("error: " + e.getMessage());
            status = e.isAuthenticationFailure() ? 3 : 2;
        } catch (IllegalArgumentException e) {
            err.println("error: " + e.getMessage());
            status = 2;
        } catch (IOException e) {
            err.println("io error: " + e.getMessage());
            status = 4;
        } catch (Exception e) {
            err.println("unexpected failure: " + e);
            e.printStackTrace(err);
            status = 5;
        }
        out.flush();
        err.flush();
        System.exit(status);
    }

    static int run(String[] argv, InputStream in, PrintStream out, PrintStream err) throws Exception {
        Command command = Command.parse(argv);
        if (command.switches.contains("help")) {
            out.println(USAGE);
            return 0;
        }
        if (command.name == null) {
            err.println("error: no command given");
            err.println();
            err.println(USAGE);
            return 1;
        }
        switch (command.name) {
            case "keygen":
                return keygen(command, out, err);
            case "encrypt":
                return encrypt(command, in, out, err);
            case "decrypt":
                return decrypt(command, in, out, err);
            case "demo":
                return Demo.run(out);
            case "selftest":
                return SelfTest.run(out);
            default:
                err.println("error: unknown command '" + command.name + "'");
                err.println();
                err.println(USAGE);
                return 1;
        }
    }

    private static final String USAGE = """
            Symmetric encryption of application secrets (AES-256-GCM).

            Usage:
              java com.example.crypto.App keygen   [--out <file>] [--force]
              java com.example.crypto.App encrypt  <key option> [--aad <context>] \\
                                                 (--text <plaintext> | --file <in> | --stdin)
              java com.example.crypto.App decrypt  <key option> [--aad <context>] \\
                                                 (--text <token> | --file <in> | --stdin) [--out <file>]
              java com.example.crypto.App demo
              java com.example.crypto.App selftest

            Key options (exactly one):
              --key-env <VAR>      base64 AES key in environment variable <VAR>   (preferred)
              --key-file <path>    base64 (or raw 32-byte) AES key read from a file
              --key <base64>       key on the command line - visible in 'ps', avoid it
              --password-env <VAR> passphrase in environment variable <VAR>, stretched with PBKDF2
              --password <pw>      passphrase on the command line - visible in 'ps', avoid it
              --iterations <n>     PBKDF2 work factor for sealing (default 310000, minimum 100000)

            Input / output:
              --text <s>   literal argument (fine for tokens, poor for secrets)
              --file <p>   read raw bytes from a file (byte exact, use for binary payloads)
              --stdin      read the payload from stdin, byte exact (use shell redirection)
              --out <p>    decrypt: write plaintext bytes to a file instead of stdout
              --aad <ctx>  extra authenticated context, e.g. the config key being protected.
                           Decryption must pass the identical value or the tag check fails.

            Encrypt prints a base64 envelope; decrypt turns it back into the original data.
            Exit status: 0 ok, 1 usage, 2 bad input/key, 3 authentication failure, 4 I/O.
            """;

    private static int keygen(Command command, PrintStream out, PrintStream err) throws Exception {
        command.requireNoneOf("--text", "--file", "--stdin", "--aad");
        SecretKey key = SymmetricCrypto.newKey();
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        String target = command.options.get("out");
        if (target == null) {
            out.println(encoded);
            err.println("Store this key outside the repo (secret manager, 0600 key file, or an env var).");
            return 0;
        }
        Path path = Path.of(target);
        if (Files.exists(path) && !command.switches.contains("force")) {
            err.println("error: " + path + " already exists, pass --force to overwrite");
            return 1;
        }
        Files.writeString(path, encoded + System.lineSeparator(), StandardCharsets.UTF_8);
        restrictToOwner(path, err);
        out.println("Wrote a new 256-bit AES key to " + path.toAbsolutePath());
        return 0;
    }

    private static int encrypt(Command command, InputStream in, PrintStream out, PrintStream err)
            throws Exception {
        command.requireNoneOf("--out");
        byte[] plaintext = readInput(command, in);
        byte[] aad = aad(command);
        byte[] envelope = new SymmetricCrypto().encrypt(keySource(command, err), plaintext, aad);
        out.println(Base64.getEncoder().encodeToString(envelope));
        return 0;
    }

    private static int decrypt(Command command, InputStream in, PrintStream out, PrintStream err)
            throws Exception {
        byte[] token = readInput(command, in);
        byte[] aad = aad(command);
        byte[] plaintext = new SymmetricCrypto().decryptBase64Bytes(keySource(command, err),
                new String(token, StandardCharsets.UTF_8).trim(), aad);
        String target = command.options.get("out");
        if (target == null) {
            // No trailing newline: stdout is byte-exact, mirroring 'openssl enc'.
            out.write(plaintext);
        } else {
            Files.write(Path.of(target), plaintext);
            err.println("Wrote " + plaintext.length + " bytes to " + Path.of(target).toAbsolutePath());
        }
        return 0;
    }

    /**
     * Reads the payload for {@code --text} / {@code --file} / {@code --stdin}. All three are byte
     * exact, so a shell redirection can carry a binary payload unchanged; a trailing newline from
     * {@code echo} encrypts as part of the data.
     */
    private static byte[] readInput(Command command, InputStream in) throws IOException {
        String text = command.options.get("text");
        String file = command.options.get("file");
        boolean stdin = command.switches.contains("stdin");
        int supplied = (text != null ? 1 : 0) + (file != null ? 1 : 0) + (stdin ? 1 : 0);
        if (supplied == 0) {
            throw new IllegalArgumentException("no input: pass --text, --file, or --stdin");
        }
        if (supplied > 1) {
            throw new IllegalArgumentException("pass only one of --text, --file, --stdin");
        }
        if (text != null) {
            return text.getBytes(StandardCharsets.UTF_8);
        }
        if (file != null) {
            return Files.readAllBytes(Path.of(file));
        }
        return in.readAllBytes();
    }

    private static byte[] aad(Command command) {
        String context = command.options.get("aad");
        return context == null ? null : context.getBytes(StandardCharsets.UTF_8);
    }

    /** Resolves the key/passphrase option, preferring sources that never touch the argv list. */
    private static KeySource keySource(Command command, PrintStream err) throws IOException {
        String keyOption = firstPresent(command, "key", "key-env", "key-file");
        String passwordOption = firstPresent(command, "password", "password-env");
        if (keyOption != null && passwordOption != null) {
            throw new IllegalArgumentException("choose either an AES key or a passphrase, not both");
        }
        if (keyOption == null && passwordOption == null) {
            throw new IllegalArgumentException("no key: pass --key-env, --key-file, --key, "
                    + "--password-env, or --password");
        }

        if (passwordOption != null) {
            char[] password;
            if ("password-env".equals(passwordOption)) {
                password = requireEnv(command.options.get("password-env")).toCharArray();
            } else {
                err.println("warning: --password is visible in the process list; prefer --password-env");
                password = command.options.get("password").toCharArray();
            }
            String raw = command.options.get("iterations");
            KeySource source = raw == null
                    ? KeySource.of(password)
                    : KeySource.of(password, parseIterations(raw));
            SymmetricCrypto.wipe(password);
            return source;
        }

        if (command.options.containsKey("iterations")) {
            throw new IllegalArgumentException("--iterations only applies to a passphrase");
        }

        byte[] encoded;
        if ("key-env".equals(keyOption)) {
            encoded = decodeKey(requireEnv(command.options.get("key-env")), "environment variable");
        } else if ("key-file".equals(keyOption)) {
            Path path = Path.of(command.options.get("key-file"));
            warnIfWorldReadable(path, err);
            encoded = decodeKey(new String(Files.readAllBytes(path), StandardCharsets.UTF_8).trim(),
                    path.toString());
        } else {
            err.println("warning: --key is visible in the process list; prefer --key-env or --key-file");
            encoded = decodeKey(command.options.get("key"), "the --key argument");
        }
        return KeySource.of(SymmetricCrypto.keyFromBytes(encoded));
    }

    private static int parseIterations(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("--iterations must be a whole number, got '" + value + "'");
        }
    }

    /** Accepts base64 text, or a raw 32-byte file, and returns the key bytes. */
    private static byte[] decodeKey(String value, String origin) {
        String candidate = value.replaceAll("\\s", "");
        if (candidate.isEmpty()) {
            throw new IllegalArgumentException("no AES key found in " + origin);
        }
        try {
            byte[] decoded = Base64.getMimeDecoder().decode(candidate);
            if (decoded.length == 32) {
                return decoded;
            }
        } catch (IllegalArgumentException ignored) {
            // fall through to the raw-bytes interpretation
        }
        byte[] raw = candidate.getBytes(StandardCharsets.ISO_8859_1);
        if (raw.length == 32) {
            return raw;
        }
        throw new IllegalArgumentException(origin + " does not hold a 256-bit AES key "
                + "(expected 44 base64 characters or 32 raw bytes)");
    }

    private static String firstPresent(Command command, String... names) {
        for (String name : names) {
            if (command.options.containsKey(name)) {
                return name;
            }
        }
        return null;
    }

    private static String requireEnv(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("expected an environment variable name");
        }
        String value = System.getenv(name);
        if (value == null) {
            throw new IllegalArgumentException("environment variable " + name + " is not set");
        }
        return value;
    }

    private static void restrictToOwner(Path path, PrintStream err) {
        if (!path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            err.println("warning: could not set permissions on " + path + "; do it manually");
            return;
        }
        try {
            Files.setPosixFilePermissions(path, Set.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        } catch (IOException | UnsupportedOperationException e) {
            err.println("warning: could not set 0600 on " + path + ": " + e.getMessage());
        }
    }

    private static void warnIfWorldReadable(Path path, PrintStream err) {
        if (!path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return;
        }
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            boolean exposed = permissions.contains(PosixFilePermission.GROUP_READ)
                    || permissions.contains(PosixFilePermission.OTHERS_READ);
            if (exposed) {
                err.println("warning: " + path + " is readable by others, run 'chmod 600 " + path + "'");
            }
        } catch (IOException | UnsupportedOperationException e) {
            err.println("warning: could not inspect permissions of " + path + ": " + e.getMessage());
        }
    }

    private static PrintStream utf8Stream(FileDescriptor descriptor) {
        return new PrintStream(new BufferedOutputStream(new FileOutputStream(descriptor)), true,
                StandardCharsets.UTF_8);
    }

    /** Flat flag bag: {@code --name value} options plus standalone switches. */
    private static final class Command {

        private final String name;
        private final Map<String, String> options;
        private final Set<String> switches;

        Command(String name, Map<String, String> options, Set<String> switches) {
            this.name = name;
            this.options = options;
            this.switches = switches;
        }

        static Command parse(String[] argv) {
            Map<String, String> options = new LinkedHashMap<>();
            Set<String> switches = new LinkedHashSet<>();
            String name = null;
            for (int i = 0; i < argv.length; i++) {
                String argument = argv[i];
                if (!argument.startsWith("--")) {
                    if (name != null) {
                        throw new IllegalArgumentException("unexpected argument '" + argument + "'");
                    }
                    name = argument;
                    continue;
                }
                String flag = argument.substring(2);
                if (SWITCHES.contains(argument)) {
                    switches.add(flag);
                    continue;
                }
                if (VALUE_OPTIONS.contains(argument)) {
                    if (i + 1 >= argv.length) {
                        throw new IllegalArgumentException(argument + " needs a value");
                    }
                    if (options.containsKey(flag)) {
                        throw new IllegalArgumentException(argument + " was given twice");
                    }
                    options.put(flag, argv[++i]);
                    continue;
                }
                throw new IllegalArgumentException("unknown option " + argument);
            }
            return new Command(name, options, switches);
        }

        void requireNoneOf(String... forbidden) {
            for (String flag : forbidden) {
                String key = flag.substring(2);
                if (options.containsKey(key) || switches.contains(key)) {
                    throw new IllegalArgumentException(name + " does not accept " + flag);
                }
            }
        }
    }

    private App() {
    }
}
