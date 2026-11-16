package hbp.mip.study;

/** Creates a Study, optionally with its first Analysis, in one transaction. */
public record CreateStudyDTO(String name, String analysisId) {
}
