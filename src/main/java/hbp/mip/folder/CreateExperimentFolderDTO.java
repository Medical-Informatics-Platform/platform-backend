package hbp.mip.folder;

/**
 * Request body of "create folder". The id and the order are assigned by the service.
 *
 * The experiment is optional, exactly like a set: "put this run in a new folder" is one gesture in the
 * row menu, and one request means a failed second call can never leave an empty folder behind.
 */
public record CreateExperimentFolderDTO(String name, String experimentUuid) {
}
