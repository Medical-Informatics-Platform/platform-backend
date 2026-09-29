package hbp.mip.folder;

import hbp.mip.experiment.ExperimentDAO;
import hbp.mip.user.UserDAO;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mapping is the contract: three orderings have to survive the trip from the position columns to
 * the arrays the dashboard renders, and an empty folder has to answer with empty arrays rather than
 * nulls (null fields are dropped from the JSON, which would break `folder.sets.map(...)`).
 */
class ExperimentFolderDTOTest {

    @Test
    void mapsMembersSetsAndSetMembersToTheirStoredOrder() {
        ExperimentFolderDAO folder = new ExperimentFolderDAO(
                new UserDAO("user", "User", "user@example.org", "subject"), "My analysis set", 1);

        ExperimentSetDAO first = new ExperimentSetDAO(folder, "First", 1);
        ExperimentSetDAO second = new ExperimentSetDAO(folder, "Second", 2);
        folder.getSets().add(second);
        folder.getSets().add(first);

        UUID inFirstLow = uuid();
        UUID inFirstHigh = uuid();
        UUID ungrouped = uuid();
        UUID lateUngrouped = uuid();

        // Added out of order on purpose: the response must follow the position columns, not insertion.
        folder.getMembers().add(member(folder, inFirstHigh, first, 3, 2));
        folder.getMembers().add(member(folder, ungrouped, null, 1, null));
        folder.getMembers().add(member(folder, inFirstLow, second, 2, 1));
        folder.getMembers().add(member(folder, lateUngrouped, null, null, null));
        folder.getMembers().get(2).setExperimentSet(first);

        var dto = ExperimentFolderDTO.from(folder);

        assertThat(dto.id()).isEqualTo(folder.getId().toString());
        assertThat(dto.name()).isEqualTo("My analysis set");
        assertThat(dto.experimentIds()).containsExactly(ungrouped.toString(), inFirstLow.toString(),
                inFirstHigh.toString(), lateUngrouped.toString());

        assertThat(dto.sets()).extracting(ExperimentSetDTO::name).containsExactly("First", "Second");
        assertThat(dto.sets().get(0).id()).isEqualTo(first.getId().toString());
        assertThat(dto.sets().get(0).experimentIds())
                .containsExactly(inFirstLow.toString(), inFirstHigh.toString());
        assertThat(dto.sets().get(1).experimentIds()).isEmpty();
    }

    @Test
    void mapsAFreshFolderToEmptyArrays() {
        ExperimentFolderDAO folder = new ExperimentFolderDAO(
                new UserDAO("user", "User", "user@example.org", "subject"), "Empty", 1);

        var dto = ExperimentFolderDTO.from(folder);
        var collection = ExperimentFoldersDTO.from(List.of(folder));

        assertThat(dto.experimentIds()).isEmpty();
        assertThat(dto.sets()).isEmpty();
        assertThat(collection.folders()).singleElement().satisfies(folderDto -> {
            assertThat(folderDto.experimentIds()).isEmpty();
            assertThat(folderDto.sets()).isEmpty();
        });
    }

    private ExperimentFolderMemberDAO member(ExperimentFolderDAO folder, UUID experimentUuid, ExperimentSetDAO set,
            Integer folderPosition, Integer setPosition) {
        ExperimentDAO experiment = new ExperimentDAO();
        experiment.setUuid(experimentUuid);

        ExperimentFolderMemberDAO member = new ExperimentFolderMemberDAO(folder, experiment, folderPosition);
        member.setExperimentSet(set);
        member.setSetPosition(setPosition);
        return member;
    }

    private UUID uuid() {
        return UUID.randomUUID();
    }
}
