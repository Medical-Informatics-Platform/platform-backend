package hbp.mip.utils.Exceptions;

/** Thrown when the set asked for is not one of the folder's sets. Mapped to 404. */
public class ExperimentSetNotFoundException extends ExperimentNotFoundException {

    public ExperimentSetNotFoundException(String msg) {
        super(msg);
    }
}
