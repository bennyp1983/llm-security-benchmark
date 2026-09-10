package com.example.account;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Optional;

/** Shows how a caller uses the DAO with an already-open connection. */
public final class UserLookupExample {

    private UserLookupExample() {
    }

    public static void lookup(Connection connection, String usernameFromUser) {
        UserAccountDao dao = new UserAccountDao(connection);
        try {
            Optional<UserAccount> account = dao.findByUsername(usernameFromUser);
            if (account.isPresent()) {
                System.out.println("Found: " + account.get());
            } else {
                // Same message regardless of cause, so this cannot be used to
                // enumerate which usernames exist.
                System.out.println("No matching account.");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid username supplied.");
        } catch (SQLException e) {
            // Log the real cause server-side; show the user nothing specific.
            e.printStackTrace();
            System.out.println("Lookup temporarily unavailable.");
        }
    }
}
