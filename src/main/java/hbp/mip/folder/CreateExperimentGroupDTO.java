package hbp.mip.folder;

/**
 * Request body of "create folder" and "create set". The id and the order are assigned by the service.
 *
 * The experiment is optional: "put this run in a new folder/set" is one gesture in the row menu, and one
 * request means a failed second call can never leave an empty folder or set behind.
 */
public record CreateExperimentGroupDTO(String name, String experimentUuid) {
}
