package hbp.mip.folder;

import java.util.Comparator;
import java.util.List;

/**
 * Response shape of a set. Matches the frontend ExperimentSet model: id, name, member ids only —
 * never experiment copies, so a folder can never serve a stale run.
 *
 * experimentIds is ordered by set_position; nulls sort last so an unpositioned row cannot scramble
 * the section.
 */
public record ExperimentSetDTO(String id, String name, List<String> experimentIds) {

    public static ExperimentSetDTO from(ExperimentSetDAO set, List<ExperimentFolderMemberDAO> members) {
        List<String> memberIds = members.stream()
                .filter(member -> member.getExperimentSet() != null
                        && member.getExperimentSet().getId() != null
                        && member.getExperimentSet().getId().equals(set.getId()))
                .sorted(Comparator.comparing(ExperimentFolderMemberDAO::getSetPosition,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .map(member -> member.getExperiment().getUuid().toString())
                .toList();

        return new ExperimentSetDTO(set.getId().toString(), set.getName(), memberIds);
    }
}
