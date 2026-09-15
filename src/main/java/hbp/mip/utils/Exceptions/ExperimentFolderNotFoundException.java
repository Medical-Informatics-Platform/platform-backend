package hbp.mip.utils.Exceptions;

/**
 * Thrown when the folder asked for does not exist or belongs to somebody else. Both answers map to
 * 404 on purpose: the API must not tell a caller that another user's folder id is real.
 */
public class ExperimentFolderNotFoundException extends ExperimentNotFoundException {

    public ExperimentFolderNotFoundException(String msg) {
        super(msg);
    }
}
