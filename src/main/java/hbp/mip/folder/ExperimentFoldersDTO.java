package hbp.mip.folder;

import java.util.List;

/** Response shape of the collection endpoint. An owner with no folders gets an empty list, not a 404. */
public record ExperimentFoldersDTO(List<ExperimentFolderDTO> folders) {

    public static ExperimentFoldersDTO from(List<ExperimentFolderDAO> folders) {
        return new ExperimentFoldersDTO(folders.stream().map(ExperimentFolderDTO::from).toList());
    }
}
