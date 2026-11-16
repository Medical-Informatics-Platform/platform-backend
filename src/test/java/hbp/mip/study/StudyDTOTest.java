package hbp.mip.study;

import hbp.mip.analysis.AnalysisDAO;
import hbp.mip.user.UserDAO;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mapping is the contract: three orderings have to survive the trip from the position columns to
 * the arrays the dashboard renders, and an empty study has to answer with empty arrays rather than
 * nulls (null fields are dropped from the JSON, which would break `study.groups.map(...)`).
 */
class StudyDTOTest {

    @Test
    void mapsMembersGroupsAndGroupMembersToTheirStoredOrder() {
        StudyDAO study = new StudyDAO(
                new UserDAO("user", "User", "user@example.org", "subject"), "My analysis group", 1);

        AnalysisGroupDAO first = new AnalysisGroupDAO(study, "First", 1);
        AnalysisGroupDAO second = new AnalysisGroupDAO(study, "Second", 2);
        study.getGroups().add(second);
        study.getGroups().add(first);

        UUID inFirstLow = uuid();
        UUID inFirstHigh = uuid();
        UUID ungrouped = uuid();
        UUID lateUngrouped = uuid();

        // Added out of order on purpose: the response must follow the position columns, not insertion.
        study.getMembers().add(member(study, inFirstHigh, first, 3, 2));
        study.getMembers().add(member(study, ungrouped, null, 1, null));
        study.getMembers().add(member(study, inFirstLow, second, 2, 1));
        study.getMembers().add(member(study, lateUngrouped, null, null, null));
        study.getMembers().get(2).setAnalysisGroup(first);

        var dto = StudyDTO.from(study);

        assertThat(dto.id()).isEqualTo(study.getId().toString());
        assertThat(dto.name()).isEqualTo("My analysis group");
        assertThat(dto.analysisIds()).containsExactly(ungrouped.toString(), inFirstLow.toString(),
                inFirstHigh.toString(), lateUngrouped.toString());

        assertThat(dto.groups()).extracting(AnalysisGroupDTO::name).containsExactly("First", "Second");
        assertThat(dto.groups().get(0).id()).isEqualTo(first.getId().toString());
        assertThat(dto.groups().get(0).analysisIds())
                .containsExactly(inFirstLow.toString(), inFirstHigh.toString());
        assertThat(dto.groups().get(1).analysisIds()).isEmpty();
    }

    @Test
    void mapsAFreshStudyToEmptyArrays() {
        StudyDAO study = new StudyDAO(
                new UserDAO("user", "User", "user@example.org", "subject"), "Empty", 1);

        var dto = StudyDTO.from(study);
        var collection = StudiesDTO.from(List.of(study));

        assertThat(dto.analysisIds()).isEmpty();
        assertThat(dto.groups()).isEmpty();
        assertThat(collection.studies()).singleElement().satisfies(studyDto -> {
            assertThat(studyDto.analysisIds()).isEmpty();
            assertThat(studyDto.groups()).isEmpty();
        });
    }

    private StudyMemberDAO member(StudyDAO study, UUID analysisId, AnalysisGroupDAO group,
            Integer studyPosition, Integer groupPosition) {
        AnalysisDAO analysis = new AnalysisDAO();
        analysis.setUuid(analysisId);

        StudyMemberDAO member = new StudyMemberDAO(study, analysis, studyPosition);
        member.setAnalysisGroup(group);
        member.setGroupPosition(groupPosition);
        return member;
    }

    private UUID uuid() {
        return UUID.randomUUID();
    }
}
