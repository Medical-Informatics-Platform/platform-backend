package hbp.mip.folder;

/** Request body of "rename folder" and "rename set". Only the name is editable, and it follows the create rules. */
public record RenameExperimentGroupDTO(String name) {
}
