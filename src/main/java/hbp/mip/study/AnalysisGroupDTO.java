package hbp.mip.study;

import java.util.Comparator;
import java.util.List;

/**
 * Response shape of a group. Matches the frontend AnalysisGroup model: id, name, member ids only —
 * never analysis copies, so a study can never serve a stale run.
 *
 * analysisIds is ordered by group_position; nulls sort last so an unpositioned row cannot scramble
 * the section.
 */
public record AnalysisGroupDTO(String id, String name, List<String> analysisIds) {

    public static AnalysisGroupDTO from(AnalysisGroupDAO group, List<StudyMemberDAO> members) {
        List<String> memberIds = members.stream()
                .filter(member -> member.isIn(group))
                .sorted(Comparator.comparing(StudyMemberDAO::getGroupPosition,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .map(member -> member.getAnalysis().getUuid().toString())
                .toList();

        return new AnalysisGroupDTO(group.getId().toString(), group.getName(), memberIds);
    }
}
