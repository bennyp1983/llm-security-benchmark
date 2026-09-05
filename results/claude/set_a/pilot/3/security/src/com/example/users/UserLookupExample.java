package com.example.users;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Optional;

/** Minimal example of calling the DAO with an already-open {@link Connection}. */
public final class UserLookupExample {

    private UserLookupExample() {
    }

    public static void lookup(Connection connection, String usernameFromUser) throws SQLException {
        UserAccountDao dao = new UserAccountDao(connection);

        Optional<UserAccount> account = dao.findByUsername(usernameFromUser);
        if (account.isPresent()) {
            System.out.println("Found: " + account.get());
        } else {
            // Same message regardless of the reason, so the response cannot be used to
            // enumerate which usernames exist.
            System.out.println("No matching account.");
        }
    }
}
