package hbp.mip.utils.Exceptions;

public class UserIdentityConflictException extends RuntimeException {

    public static final String MESSAGE = "This username belongs to another account. Contact the MIP operators.";

    public UserIdentityConflictException() {
        super(MESSAGE);
    }
}
