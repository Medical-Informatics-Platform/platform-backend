package hbp.mip.study;

/**
 * Request body of "create study" and "create group". The id and the order are assigned by the service.
 *
 * The analysis is optional: "put this run in a new study/group" is one gesture in the row menu, and one
 * request means a failed second call can never leave an empty study or group behind.
 */
public record CreateAnalysisGroupDTO(String name, String analysisUuid) {
}
