package portal.admin;

/** Raised when a caller is not signed in, or is signed in without the required permission. */
public final class AccessDeniedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final AdminRole.Permission permission;

    public AccessDeniedException(String message, AdminRole.Permission permission) {
        super(message);
        this.permission = permission;
    }

    public AdminRole.Permission permission() {
        return permission;
    }
}
