package hbp.mip.folder;

/**
 * Request body of "which set holds this run".
 *
 * A null or blank setId means "ungroup": the run stays in the folder and leaves its set. One body
 * covers both the move and the way out, and the strict partition means a move never needs to name
 * the set it leaves.
 */
public record UpdateExperimentSetMembershipDTO(String setId) {
}
