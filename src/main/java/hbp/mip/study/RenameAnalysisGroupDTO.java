package hbp.mip.study;

/** Request body of "rename study" and "rename group". Only the name is editable, and it follows the create rules. */
public record RenameAnalysisGroupDTO(String name) {
}
