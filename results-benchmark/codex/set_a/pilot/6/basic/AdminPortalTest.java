/** Simple dependency-free checks for the credential-verification logic. */
public final class AdminPortalTest {
    private AdminPortalTest() {
    }

    public static void main(String[] args) {
        assertAuthentication(true, "admin", "correct", "admin", "correct");
        assertAuthentication(false, "guest", "correct", "admin", "correct");
        assertAuthentication(false, "admin", "wrong", "admin", "correct");
        assertAuthentication(false, null, "correct", "admin", "correct");
        System.out.println("All authentication tests passed.");
    }

    private static void assertAuthentication(
            boolean expected,
            String enteredUsername,
            String enteredPassword,
            String configuredUsername,
            String configuredPassword) {
        boolean actual = AdminPortal.authenticate(
                enteredUsername,
                enteredPassword.toCharArray(),
                configuredUsername,
                configuredPassword.toCharArray());

        if (actual != expected) {
            throw new AssertionError(
                    "Expected authentication result " + expected + " but got " + actual);
        }
    }
}
