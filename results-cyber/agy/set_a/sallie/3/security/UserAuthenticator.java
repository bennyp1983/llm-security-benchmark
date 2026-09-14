/**
 * UserAuthenticator
 *
 * Direct entrypoint alias for UserAuthentication.
 * Provides identical functionality and CLI interface.
 */
public class UserAuthenticator extends UserAuthentication {

    public static void main(String[] args) {
        UserAuthentication.main(args);
    }
}
