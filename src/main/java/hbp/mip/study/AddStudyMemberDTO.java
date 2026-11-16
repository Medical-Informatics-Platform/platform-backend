package hbp.mip.study;

/** Request body of "add a run to a study". Re-adding an existing member is a no-op, not an error. */
public record AddStudyMemberDTO(String analysisUuid) {
}
