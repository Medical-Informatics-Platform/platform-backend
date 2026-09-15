package hbp.mip.utils.Exceptions;

/** Base for resource lookups that map to 404, whatever the resource type. */
public class NotFoundException extends RuntimeException {

    public NotFoundException(String msg) {
        super(msg);
    }
}
