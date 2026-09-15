package hbp.mip.folder;

/** Request body of "rename set". Only the name is editable; membership moves through set membership. */
public record RenameExperimentSetDTO(String name) {
}
