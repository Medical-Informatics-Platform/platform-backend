package hbp.mip.folder;

/** Request body of "rename folder". Only the name is editable, and it follows the create rules. */
public record RenameExperimentFolderDTO(String name) {
}
