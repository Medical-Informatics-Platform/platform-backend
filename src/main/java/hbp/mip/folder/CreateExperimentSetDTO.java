package hbp.mip.folder;

/**
 * Request body of "create set". The experiment is optional: a set is often created empty and filled
 * later. When it is given it joins the folder and the new set in the same request, which is what the
 * "select runs, group them" gesture needs to avoid a second round trip.
 */
public record CreateExperimentSetDTO(String name, String experimentUuid) {
}
