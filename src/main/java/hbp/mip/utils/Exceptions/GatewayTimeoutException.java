package hbp.mip.utils.Exceptions;

/** The broker accepted the analysis and no reply arrived in time. Mapped to HTTP 504 with this message. */
public class GatewayTimeoutException extends RuntimeException {

    public GatewayTimeoutException(String msg) {
        super(msg);
    }
}
