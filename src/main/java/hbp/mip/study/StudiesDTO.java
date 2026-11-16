package hbp.mip.study;

import java.util.List;

/** Response shape of the collection endpoint. An owner with no studies gets an empty list, not a 404. */
public record StudiesDTO(List<StudyDTO> studies) {

    public static StudiesDTO from(List<StudyDAO> studies) {
        return new StudiesDTO(studies.stream().map(StudyDTO::from).toList());
    }
}
