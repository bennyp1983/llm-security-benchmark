import java.sql.Connection;

/**
 * Semantic subclass and alias for {@link UserLoginService} ensuring direct compatibility
 * with applications referencing either {@code LoginService} or {@code UserLoginService}.
 */
public class LoginService extends UserLoginService {

    public LoginService() {
        super();
    }

    public LoginService(AccountRepository repository) {
        super(repository);
    }

    public LoginService(AccountRepository repository, LoginPolicy policy) {
        super(repository, policy);
    }

    public LoginService(Connection connection) {
        super(connection);
    }

    public LoginService(Connection connection, LoginPolicy policy) {
        super(connection, policy);
    }

    public static void main(String[] args) {
        UserLoginService.main(args);
    }
}
