package hbp.mip.study;

/**
 * Request body of "which group holds this run".
 *
 * A null or blank groupId means "ungroup": the run stays in the study and leaves its group. One body
 * covers both the move and the way out, and the strict partition means a move never needs to name
 * the group it leaves.
 */
public record UpdateAnalysisGroupMembershipDTO(String groupId) {
}
