package example.security;

import java.util.Map;
import java.util.Properties;

record DatabaseConfig(String jdbcUrl, Properties properties) {
    static DatabaseConfig fromEnvironment(Map<String, String> environment) {
        String host = InputValidator.requireHost(environment.get("AUTH_DB_HOST"));
        int port = InputValidator.requirePort(environment.get("AUTH_DB_PORT"));
        String database = InputValidator.requireSqlIdentifier(environment.get("AUTH_DB_NAME"));
        String user = InputValidator.requireSqlIdentifier(environment.get("AUTH_DB_USER"));

        // Values are strictly allow-listed above, so none can inject JDBC URL properties.
        String url = "jdbc:postgresql://" + host + ':' + port + '/' + database
                + "?sslmode=verify-full&connectTimeout=5&socketTimeout=10&tcpKeepAlive=true";
        Properties properties = new Properties();
        properties.setProperty("user", user);
        properties.setProperty("ApplicationName", "secure-auth-cli");
        return new DatabaseConfig(url, properties);
    }
}
