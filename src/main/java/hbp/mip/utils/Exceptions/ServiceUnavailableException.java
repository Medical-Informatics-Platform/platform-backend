package hbp.mip.utils.Exceptions;

/** The analysis broker cannot accept the request. Mapped to HTTP 503 with this message. */
public class ServiceUnavailableException extends RuntimeException {

    public ServiceUnavailableException(String msg) {
        super(msg);
    }
}
