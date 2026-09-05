package vault;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

/**
 * End-to-end walkthrough of the vault: keystore-backed keys, passphrase-derived keys, file
 * streaming, tamper detection, and key rotation. Run with {@code java -cp build vault.Demo}.
 */
public final class Demo {

    private static final char[] KEYSTORE_PASSWORD = "keystore-integrity-password".toCharArray();
    private static final char[] DATA_PASSPHRASE = "correct horse battery staple".toCharArray();
    private static final String ALIAS = "app-data";

    private Demo() {
    }

    public static void main(String[] args) throws Exception {
        Path workdir = Path.of(args.length > 0 ? args[0] : "demo-work");
        Files.createDirectories(workdir);
        Path keystore = workdir.resolve("app-keystore.p12");
        Files.deleteIfExists(keystore);

        System.out.println("=== symmetric encryption demo (AES-256-GCM) ===\n");

        try (KeyVault keys = KeyVault.open(keystore, KEYSTORE_PASSWORD)) {
            System.out.println("[1] key custody");
            System.out.println("    " + keys.describe());
            System.out.println("    store file permissions: "
                    + (FilePermissions.isPosix(keystore) ? Files.getPosixFilePermissions(keystore)
                            : "not a POSIX filesystem"));
            System.out.println("    the keystore password is the only secret an operator supplies;");
            System.out.println("    keys themselves are never printed, logged, or passed on a command line.\n");

            keys.generate(ALIAS);
            System.out.println("    generated AES-" + KeyVault.KEY_LENGTH_BITS + " key '" + ALIAS + "'");
            System.out.println("    aliases now: " + keys.aliases() + "\n");

            System.out.println("[2] seal and open a secret with the keystore key");
            String secret = "{\"card\":\"4111 1111 1111 1111\",\"exp\":\"12/31\",\"cvc\":\"737\"}";
            try (DataVault vault = new DataVault(keys, ALIAS)) {
                Envelope envelope = vault.seal(secret.getBytes(StandardCharsets.UTF_8));
                byte[] sealed = envelope.toBytes();
                System.out.println("    plaintext  : " + secret.length() + " bytes");
                System.out.println("    sealed     : " + sealed.length + " bytes ("
                        + envelope.headerLength() + " B header + ciphertext + " + Envelope.TAG_LENGTH
                        + " B GCM tag)");
                System.out.println("    base64     : " + Base64.getEncoder().encodeToString(sealed));
                System.out.println("    key used   : " + vault.keyDescription(envelope));
                try (DataVault.Opened opened = vault.open(envelope)) {
                    String recovered = new String(opened.data(), StandardCharsets.UTF_8);
                    System.out.println("    round-trip : " + (recovered.equals(secret) ? "matches original"
                            : "MISMATCH"));
                }
                System.out.println();

                System.out.println("[3] a sealed payload cannot be quietly rewritten");
                byte[] tampered = sealed.clone();
                tampered[tampered.length - 1] ^= 0x01;
                reportRejection(vault, tampered, "flipping one ciphertext bit");
                byte[] swappedHeader = sealed.clone();
                swappedHeader[7] = 'x';
                reportRejection(vault, swappedHeader, "editing the key alias in the header");
                System.out.println("    (an edited alias fails at key lookup; an edit to bytes the alias does");
                System.out.println("     not cover fails the GCM tag - both refuse to return plaintext)");
                System.out.println();

                System.out.println("[4] encrypting a file without holding it in memory");
                Path plaintext = workdir.resolve("config.yaml");
                Path sealedFile = workdir.resolve("config.yaml.sealed");
                Files.writeString(plaintext, "db.password: s3cr3t\napi.token: abc.def\n");
                Envelope fileEnvelope = vault.sealFileTo(plaintext, sealedFile);
                System.out.println("    sealed " + Files.size(plaintext) + " B -> " + Files.size(sealedFile)
                        + " B at " + sealedFile.getFileName());
                Path restored = workdir.resolve("config.yaml.clear");
                vault.openFile(sealedFile, restored);
                System.out.println("    reopened equals original: "
                        + Arrays.equals(Files.readAllBytes(plaintext), Files.readAllBytes(restored)) + "\n");

                System.out.println("[5] rotating the key");
                keys.generate("app-data-2026");
                Path rotated = workdir.resolve("config.yaml.rotated");
                vault.rekeyFile(sealedFile, rotated, "app-data-2026");
                System.out.println("    re-sealed under 'app-data-2026'; store is now " + keys.aliases());

                keys.delete(ALIAS);
                System.out.println("    deleted the old alias '" + ALIAS + "'");
                Path rotatedClear = workdir.resolve("config.yaml.rotated.clear");
                vault.openFile(rotated, rotatedClear);
                System.out.println("    the rotated file still opens, because its header names the new key");
                System.out.println("    rotated content matches original: "
                        + Arrays.equals(Files.readAllBytes(plaintext), Files.readAllBytes(rotatedClear)));
                try {
                    vault.openFile(sealedFile, workdir.resolve("stranded.clear"));
                    System.out.println("    UNEXPECTED: the pre-rotation file opened after its key was deleted");
                } catch (VaultException e) {
                    System.out.println("    the pre-rotation file is now unreadable, which is why re-sealing "
                            + "comes first:\n    " + e.getMessage());
                }
                System.out.println();
            }

            System.out.println("[6] passphrase-derived key (PBKDF2-HMAC-SHA256)");
            try (DataVault passphraseVault = new DataVault(keys, () -> DATA_PASSPHRASE.clone())) {
                Envelope envelope = passphraseVault.sealWithPassphrase(
                        "backup archive key material".getBytes(StandardCharsets.UTF_8));
                System.out.println("    " + passphraseVault.keyDescription(envelope));
                System.out.println("    salt and iteration count travel in the authenticated header, so the");
                System.out.println("    key is rebuilt on open and never stored anywhere.");
                try (DataVault.Opened opened = passphraseVault.open(envelope)) {
                    System.out.println("    round-trip : \"" + new String(opened.data(), StandardCharsets.UTF_8)
                            + "\"");
                }
                try (DataVault wrong = new DataVault(keys, () -> "wrong passphrase".toCharArray())) {
                    wrong.open(envelope);
                    System.out.println("    UNEXPECTED: wrong passphrase opened the payload");
                } catch (VaultException e) {
                    System.out.println("    wrong passphrase rejected: " + e.getMessage());
                }
            }
        }

        System.out.println("\ndemo files left in " + workdir.toAbsolutePath());
        Arrays.fill(KEYSTORE_PASSWORD, '\0');
        Arrays.fill(DATA_PASSPHRASE, '\0');
    }

    private static void reportRejection(DataVault vault, byte[] payload, String what) {
        try {
            vault.open(payload);
            System.out.println("    UNEXPECTED: " + what + " was accepted");
        } catch (VaultException e) {
            System.out.println("    rejected " + what + ": " + e.getMessage());
        }
    }
}
