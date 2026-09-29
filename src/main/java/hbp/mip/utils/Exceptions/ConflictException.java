package hbp.mip.utils.Exceptions;

/**
 * Thrown when the request is well formed but collides with an existing resource, such as a folder or
 * set name already taken in the same namespace. Mapped to 409.
 */
public class ConflictException extends RuntimeException {

    public ConflictException(String msg) {
        super(msg);
    }
}
