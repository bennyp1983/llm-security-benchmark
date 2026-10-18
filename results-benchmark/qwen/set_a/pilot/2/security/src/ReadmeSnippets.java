import static java.nio.charset.StandardCharsets.UTF_8;

import java.nio.file.Files;
import java.nio.file.Path;
import vault.DataVault;
import vault.Envelope;
import vault.KeyVault;

/** Compiles the README snippets to prove the documented public API is real. */
public final class ReadmeSnippets {

    private ReadmeSnippets() {
    }

    public static void main(String[] args) throws Exception {
        Path dir = Path.of(args.length > 0 ? args[0] : "readme-work");
        Files.createDirectories(dir);
        Path store = dir.resolve("app.p12");
        Files.deleteIfExists(store);
        char[] storePassword = "readme-store-password".toCharArray();
        byte[] secret = "secret".getBytes(UTF_8);
        byte[] payload = "payload".getBytes(UTF_8);

        try (KeyVault keys = KeyVault.open(store, storePassword);
                DataVault vault = new DataVault(keys, "app-data")) {

            vault.ensureDefaultKey();
            Files.writeString(Path.of(dir.toString(), "config.yaml"), "db: 1\n");

            Envelope sealed = vault.seal(secret);
            Files.write(Path.of(dir.toString(), "secret.bin"), sealed.toBytes());

            try (DataVault.Opened opened = vault.open(
                    Envelope.fromBytes(Files.readAllBytes(Path.of(dir.toString(), "secret.bin"))))) {
                String clear = new String(opened.data(), UTF_8);
                System.out.println("snippet 1 ok: " + clear.equals("secret"));
            }

            vault.sealFileTo(Path.of(dir.toString(), "config.yaml"),
                    Path.of(dir.toString(), "config.yaml.sealed"));
            vault.openFile(Path.of(dir.toString(), "config.yaml.sealed"),
                    Path.of(dir.toString(), "config.yaml.clear"));
            System.out.println("snippet 2 ok: "
                    + Files.exists(Path.of(dir.toString(), "config.yaml.clear")));
        }

        Files.writeString(Path.of(dir.toString(), "config.yaml"), "db: 1\n");
        try (KeyVault keys = KeyVault.open(store, storePassword);
                DataVault vault = new DataVault(keys, () -> "pass".toCharArray())) {
            Envelope sealed = vault.sealWithPassphrase(payload);
            vault.open(sealed);
            System.out.println("snippet 3 ok");
        }
    }
}
