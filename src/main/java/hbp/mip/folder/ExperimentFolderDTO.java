package hbp.mip.folder;

import java.util.Comparator;
import java.util.List;

/**
 * Response shape of a folder. Matches the frontend ExperimentFolder model exactly, so swapping the
 * localStorage service for this API is a transport change and not a model change.
 *
 * experimentIds is ordered by folder_position, sets by sort_order, and each set's experimentIds by
 * set_position. Members in no set appear only in experimentIds — that is the implicit Ungrouped
 * group the compare workspace derives.
 */
public record ExperimentFolderDTO(
        String id,
        String name,
        List<String> experimentIds,
        List<ExperimentSetDTO> sets) {

    public static ExperimentFolderDTO from(ExperimentFolderDAO folder) {
        List<ExperimentFolderMemberDAO> members = folder.getMembers().stream()
                .sorted(Comparator.comparing(ExperimentFolderMemberDAO::getFolderPosition,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();

        List<ExperimentSetDTO> sets = folder.getSets().stream()
                .sorted(Comparator.comparing(ExperimentSetDAO::getSortOrder,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .map(set -> ExperimentSetDTO.from(set, members))
                .toList();

        return new ExperimentFolderDTO(
                folder.getId().toString(),
                folder.getName(),
                members.stream().map(member -> member.getExperiment().getUuid().toString()).toList(),
                sets);
    }
}
