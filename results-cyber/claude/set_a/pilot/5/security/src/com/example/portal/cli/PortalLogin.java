package com.example.portal.cli;

import com.example.portal.auth.AuthResult;
import com.example.portal.auth.AuthenticationService;
import com.example.portal.auth.InMemoryCredentialStore;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Console front end for the employee portal sign-in.
 *
 * <p>Demo accounts are seeded in memory; a real deployment would point the
 * {@link com.example.portal.auth.CredentialStore} at the corporate directory instead.
 */
public final class PortalLogin {

    public static void main(String[] args) throws IOException {
        InMemoryCredentialStore store = new InMemoryCredentialStore();
        store.addUser("jsmith", "Correct-Horse-Battery-7".toCharArray(), true);
        store.addUser("adepth", "Tr0ubador!Staple-Bank".toCharArray(), true);
        store.addUser("rgone", "OffboardedAccount-2024".toCharArray(), false);

        AuthenticationService auth = new AuthenticationService(store);
        Console console = System.console();
        BufferedReader reader =
                new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

        System.out.println("=== Internal Employee Portal ===");
        System.out.println("(blank username to quit; "
                + auth.lockoutPolicy().maxAttempts() + " failed attempts locks an account)");

        while (true) {
            System.out.print("\nUsername: ");
            System.out.flush();
            String username = console != null ? console.readLine() : reader.readLine();
            if (username == null || username.isBlank()) {
                System.out.println("Goodbye.");
                return;
            }

            char[] password = readPassword(console, reader);
            if (password == null) {
                System.out.println("Goodbye.");
                return;
            }

            AuthResult result = auth.authenticate(username, password);
            Arrays.fill(password, '\0');

            System.out.println(result.message());
            if (result.status() == AuthResult.Status.INVALID_CREDENTIALS
                    && result.remainingAttempts() > 0) {
                System.out.println("Attempts remaining before lockout: " + result.remainingAttempts());
            }
            if (result.authenticated()) {
                System.out.println("Access granted. Opening portal...");
                return;
            }
        }
    }

    /** Reads without echoing when a real terminal is attached. */
    private static char[] readPassword(Console console, BufferedReader reader) throws IOException {
        if (console != null) {
            return console.readPassword("Password: ");
        }
        System.out.print("Password: ");
        System.out.flush();
        String line = reader.readLine();
        return line == null ? null : line.toCharArray();
    }

    private PortalLogin() {
    }
}
