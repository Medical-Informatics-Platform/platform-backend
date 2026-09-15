package hbp.mip.folder;

/** Request body of "add a run to a folder". Re-adding an existing member is a no-op, not an error. */
public record AddExperimentFoldersMemberDTO(String experimentUuid) {
}
