package hbp.mip.study;

/**
 * Creates an Analysis Group. The id and order are assigned by the service.
 *
 * An optional Analysis joins the Study and group in the same transaction.
 */
public record CreateAnalysisGroupDTO(String name, String analysisId) {
}
