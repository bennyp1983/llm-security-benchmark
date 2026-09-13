package pii;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;

/**
 * Creates the AES key that {@link KeyProvider} later loads. Nothing here is baked
 * into the tool: run it once, keep the file somewhere outside the source tree.
 *
 * <pre>
 *   java pii.PiiKeygen                        # writes ./pii-key.bin, prints export lines
 *   java pii.PiiKeygen --out /secrets/pii.key # writes a chosen path
 *   java pii.PiiKeygen --print                # also prints the Base64 key, for a secret store
 * </pre>
 */
public final class PiiKeygen {

    public static final String DEFAULT_FILE = "pii-key.bin";

    private PiiKeygen() {
    }

    public static void main(String[] args) throws Exception {
        String out = System.getProperty("user.dir") + java.io.File.separator + DEFAULT_FILE;
        boolean print = false;
        boolean force = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--out" -> out = requireValue(args, ++i, "--out");
                case "--out=" -> out = args[i].substring("--out=".length());
                case "--print" -> print = true;
                case "--force" -> force = true;
                case "--help", "-h" -> {
                    System.out.println("Usage: java pii.PiiKeygen [--out PATH] [--print] [--force]");
                    System.out.println("  --out PATH   where to write the key file (default ./" + DEFAULT_FILE + ")");
                    System.out.println("  --print      also print the Base64 key so it can go into a secret store");
                    System.out.println("  --force      overwrite an existing key file");
                    return;
                }
                default -> {
                    System.err.println("Unknown option: " + args[i] + " (try --help)");
                    System.exit(2);
                    return;
                }
            }
        }

        Path file = Path.of(out).toAbsolutePath();
        if (Files.exists(file) && !force) {
            System.err.println("Refusing to overwrite the existing key file " + file
                    + " - that would make every value already encrypted with the old key unreadable.");
            System.err.println("Pass --force only if you are sure nothing protected by it still matters.");
            System.exit(3);
            return;
        }

        byte[] key = KeyProvider.newKey(new SecureRandom());
        String encoded = Base64.getEncoder().encodeToString(key);
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(file, encoded.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            restrictToOwner(file);
        } finally {
            Arrays.fill(key, (byte) 0);
        }

        System.out.println("Wrote a new AES-256 key (" + KeyProvider.KEY_BYTES + " random bytes) to " + file);
        System.out.println("Keep this file out of version control and out of the source tree.");
        System.out.println();
        System.out.println("Point the tool at it with one of:");
        System.out.println("  export PII_KEY_FILE=" + file);
        System.out.println("  java pii.PiiCli --key-file " + file + " ...");
        if (print) {
            System.out.println();
            System.out.println("PII_KEY=" + encoded);
            System.out.println("(You asked for this with --print: the key is now on screen and in any scrollback"
                    + " or job log. Prefer the file above where you can.)");
        }
    }

    private static void restrictToOwner(Path file) {
        Set<PosixFilePermission> ownerOnly = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        try {
            Files.setPosixFilePermissions(file, ownerOnly);
            System.out.println("Permissions set to rw------- (owner only).");
        } catch (UnsupportedOperationException e) {
            System.out.println("This filesystem does not support POSIX permissions - protect " + file + " some other way.");
        } catch (java.io.IOException e) {
            System.out.println("Could not tighten permissions on " + file + " (" + e.getMessage() + ") - do it manually.");
        }
    }

    private static String requireValue(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new IllegalArgumentException(option + " needs a value");
        }
        return args[index];
    }
}
