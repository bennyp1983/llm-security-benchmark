package com.example.auth;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

/**
 * Hands out JDBC connections. Credentials come from {@link AuthConfig} and are passed
 * through driver properties, never embedded in the URL (which tends to end up in logs).
 */
public final class Database {

    private final AuthConfig config;

    public Database(AuthConfig config) {
        this.config = config;
    }

    /** Opens a connection with auto-commit off, so callers control transactions. */
    public Connection openTransaction() throws SQLException {
        Properties props = new Properties();
        if (!config.dbUser().isEmpty()) {
            props.setProperty("user", config.dbUser());
        }
        char[] password = config.dbPassword();
        if (password.length > 0) {
            props.setProperty("password", new String(password));
        }
        Connection connection = DriverManager.getConnection(config.jdbcUrl(), props);
        props.clear();
        try {
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            return connection;
        } catch (SQLException e) {
            connection.close();
            throw e;
        }
    }
}
