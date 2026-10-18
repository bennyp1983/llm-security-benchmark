import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

public class UserAccountServiceTest {

    private Connection connection;
    private UserAccountService service;

    @BeforeEach
    public void setUp() throws SQLException {
        // Use an independent in-memory database for each test
        String dbUrl = "jdbc:h2:mem:test_" + System.nanoTime() + ";DB_CLOSE_DELAY=-1";
        connection = DriverManager.getConnection(dbUrl, "sa", "");
        UserAccountService.createUsersTable(connection);
        service = new UserAccountService(connection);
    }

    @Test
    @DisplayName("Should register new user successfully")
    public void testRegisterUserSuccess() throws SQLException {
        boolean registered = service.registerUser("john_doe", "SecurePassword123!");
        assertTrue(registered, "Registration should succeed for a new user.");

        assertTrue(service.userExists("john_doe"), "User should exist in database.");
    }

    @Test
    @DisplayName("Password should never be stored in plain text")
    public void testPasswordIsHashedAndSalted() throws SQLException {
        String plainPassword = "MySecretPassword456!";
        service.registerUser("security_test_user", plainPassword);

        String query = "SELECT password_hash, salt FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, "security_test_user");
            try (ResultSet rs = stmt.executeQuery()) {
                assertTrue(rs.next());
                String storedHash = rs.getString("password_hash");
                String storedSalt = rs.getString("salt");

                assertNotNull(storedHash);
                assertNotNull(storedSalt);
                assertNotEquals(plainPassword, storedHash, "Hash must not match plain text password.");
                assertFalse(storedHash.contains(plainPassword), "Hash must not contain plain text password.");
            }
        }
    }

    @Test
    @DisplayName("Different users with identical passwords should have distinct salts and hashes")
    public void testUniqueSaltsForIdenticalPasswords() throws SQLException {
        String password = "SamePassword789!";
        service.registerUser("user_a", password);
        service.registerUser("user_b", password);

        String query = "SELECT password_hash, salt FROM users WHERE username = ?";
        String hashA, saltA, hashB, saltB;

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, "user_a");
            try (ResultSet rs = stmt.executeQuery()) {
                assertTrue(rs.next());
                hashA = rs.getString("password_hash");
                saltA = rs.getString("salt");
            }
            stmt.setString(1, "user_b");
            try (ResultSet rs = stmt.executeQuery()) {
                assertTrue(rs.next());
                hashB = rs.getString("password_hash");
                saltB = rs.getString("salt");
            }
        }

        assertNotEquals(saltA, saltB, "Salts must be randomly generated and unique per user.");
        assertNotEquals(hashA, hashB, "Hashes must differ even for identical passwords due to salting.");
    }

    @Test
    @DisplayName("Should reject duplicate username registration")
    public void testDuplicateUsernameRegistration() throws SQLException {
        boolean first = service.registerUser("duplicate_user", "FirstPassword123!");
        assertTrue(first);

        boolean second = service.registerUser("duplicate_user", "SecondPassword456!");
        assertFalse(second, "Duplicate username registration should return false.");

        assertThrows(UserAccountService.UserAlreadyExistsException.class, () -> {
            service.registerNewUser("duplicate_user", "ThirdPassword789!");
        });
    }

    @Test
    @DisplayName("Should authenticate valid credentials")
    public void testAuthenticationSuccess() throws SQLException {
        service.registerUser("auth_user", "CorrectPassword123!");
        assertTrue(service.authenticateUser("auth_user", "CorrectPassword123!"));
    }

    @Test
    @DisplayName("Should reject invalid password")
    public void testAuthenticationFailureWrongPassword() throws SQLException {
        service.registerUser("auth_user", "CorrectPassword123!");
        assertFalse(service.authenticateUser("auth_user", "WrongPassword456!"));
    }

    @Test
    @DisplayName("Should reject non-existent username")
    public void testAuthenticationFailureNonExistentUser() throws SQLException {
        assertFalse(service.authenticateUser("non_existent_user", "AnyPassword123!"));
    }

    @Test
    @DisplayName("Should reject blank or null inputs during validation")
    public void testInputValidation() {
        assertThrows(IllegalArgumentException.class, () -> service.registerUser(null, "Pass123!"));
        assertThrows(IllegalArgumentException.class, () -> service.registerUser("  ", "Pass123!"));
        assertThrows(IllegalArgumentException.class, () -> service.registerUser("user", (String) null));
        assertThrows(IllegalArgumentException.class, () -> service.registerUser("user", ""));
    }

    @Test
    @DisplayName("Should safely handle SQL injection strings in username")
    public void testSqlInjectionSafety() throws SQLException {
        String maliciousUsername = "admin' OR '1'='1";
        String password = "SafePassword123!";

        boolean registered = service.registerUser(maliciousUsername, password);
        assertTrue(registered);

        assertTrue(service.authenticateUser(maliciousUsername, password));
        assertFalse(service.authenticateUser("admin", password));
    }

    @Test
    @DisplayName("Should support char array passwords")
    public void testCharArrayPasswordSupport() throws SQLException {
        char[] password = new char[]{'C', 'h', 'a', 'r', 'P', 'a', 's', 's', '!', '9'};
        boolean registered = service.registerUser("char_user", password);
        assertTrue(registered);

        assertTrue(service.authenticateUser("char_user", password));
        assertFalse(service.authenticateUser("char_user", new char[]{'W', 'r', 'o', 'n', 'g'}));
    }
}
