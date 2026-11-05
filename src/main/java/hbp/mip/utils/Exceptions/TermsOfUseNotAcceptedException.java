package hbp.mip.utils.Exceptions;

public class TermsOfUseNotAcceptedException extends RuntimeException {

    public static final String MESSAGE = "Accept the MIP terms of use in the portal before using the API";

    public TermsOfUseNotAcceptedException() {
        super(MESSAGE);
    }
}
