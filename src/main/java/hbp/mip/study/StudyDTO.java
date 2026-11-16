package hbp.mip.study;

import java.util.Comparator;
import java.util.List;

/**
 * Ordered Study membership and group references for the frontend contract.
 *
 * analysisIds is ordered by study_position, groups by sort_order, and each group's analysisIds by
 * group_position. Members in no group appear only in analysisIds — that is the implicit Ungrouped
 * group the compare workspace derives.
 */
public record StudyDTO(
        String id,
        String name,
        List<String> analysisIds,
        List<AnalysisGroupDTO> groups) {

    public static StudyDTO from(StudyDAO study) {
        List<StudyMemberDAO> members = study.getMembers().stream()
                .sorted(Comparator.comparing(StudyMemberDAO::getStudyPosition,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();

        List<AnalysisGroupDTO> groups = study.getGroups().stream()
                .sorted(Comparator.comparing(AnalysisGroupDAO::getSortOrder,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .map(group -> AnalysisGroupDTO.from(group, members))
                .toList();

        return new StudyDTO(
                study.getId().toString(),
                study.getName(),
                members.stream().map(member -> member.getAnalysis().getUuid().toString()).toList(),
                groups);
    }
}
